//! One authenticated connection. A dedicated thread owns the stream and the session: it polls for incoming cells
//! (200 ms ticks, partial cells are buffered, never lost), sends queued messages and keepalives, and ends on any error,
//! on an idle timeout (no cell from the peer for `idle`) or when told to close.
use crate::{
    engine::{ConnEvent, Event, In, Timing},
    file::{self, Offer, Xid},
    proto::{self, Assembler, Incoming},
    transport::BoxStream,
};
use nerd_chat_core::{identity::ContactIdentity, session::{Session, WIRE_CELL_LEN}};
use std::{
    io::{ErrorKind, Read, Write},
    sync::{atomic::{AtomicBool, Ordering}, mpsc::{Receiver, Sender, TryRecvError}, Arc},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// A file ready to send: `padded` is the full stream (`len | content | zeros`); `hash` covers the true content only.
pub struct FileOut { pub xid: Xid, pub bucket: u32, pub mode: u8, pub hash: [u8; 32], pub padded: Zeroizing<Vec<u8>> }

pub enum Out { Text { mid: proto::MsgId, text: Zeroizing<String> }, Ack(proto::MsgId), File(FileOut), Reply { xid: Xid, accept: bool }, Rotate { kind: u8, keys: [u8; 64] }, Close }

const OFFER_WAIT: Duration = Duration::from_secs(120);
const RECV_IDLE: Duration = Duration::from_secs(60);
const CHUNKS_PER_TURN: usize = 32;

enum OutState { WaitAccept(Instant), Sending(usize) }
struct OutXfer { f: FileOut, st: OutState }
enum InState { Pending(Instant), Receiving(Instant) }
struct InXfer { o: Offer, padded: usize, buf: Zeroizing<Vec<u8>>, st: InState }


/// Wraps a stream for the HANDSHAKE: one TOTAL deadline (a per-read timeout lets a slow-drip peer hold a slot for hours,
/// R6-M2) and an abort flag so the engine can evict the oldest unauthenticated handshake when slots run out.
pub(crate) struct DeadlineStream<'a> { pub s: &'a mut BoxStream, pub end: Instant, pub abort: Arc<AtomicBool> }

const SLICE: Duration = Duration::from_millis(250);

impl DeadlineStream<'_> {
    fn left(&self) -> std::io::Result<Duration> {
        let left = self.end.saturating_duration_since(Instant::now());
        if left.is_zero() || self.abort.load(Ordering::SeqCst) { return Err(std::io::Error::new(ErrorKind::TimedOut, "handshake deadline or aborted")); }
        Ok(left.min(SLICE))
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let d = self.left()?;
            self.s.set_read_timeout_(Some(d))?;
            match self.s.read(b) { Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue, r => return r }
        }
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        loop {
            let d = self.left()?;
            self.s.set_write_timeout_(Some(d))?;
            match self.s.write(b) { Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue, r => return r }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> { self.s.flush() }
}

/// Accumulates bytes until a full cell is available. A read timeout is "no data yet", not an error.
#[derive(Default)]
pub struct CellReader { buf: Vec<u8> }

impl CellReader {
    pub fn poll<R: Read>(&mut self, r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
        let mut tmp = [0u8; WIRE_CELL_LEN];
        let want = WIRE_CELL_LEN - self.buf.len();
        match r.read(&mut tmp[..want]) {
            Ok(0) => Err(std::io::Error::new(ErrorKind::UnexpectedEof, "peer closed")),
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                if self.buf.len() == WIRE_CELL_LEN { Ok(Some(std::mem::take(&mut self.buf))) } else { Ok(None) }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn send_body(stream: &mut BoxStream, sess: &mut Session, me: &ContactIdentity, body: &[u8]) -> bool {
    match sess.send(me, body) { Ok(w) => stream.write_all(&w).and_then(|_| stream.flush()).is_ok(), Err(_) => false }
}

/// Runs until the connection ends, then reports `Down`. `id`/`gen` identify this connection to the engine.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(mut stream: BoxStream, mut sess: Session, me: ContactIdentity, out_rx: Receiver<Out>, ev: Sender<In>, id: [u8; 8], gen: u64, t: Timing) {
    let _ = stream.set_read_timeout_(Some(t.poll));
    let _ = stream.set_write_timeout_(Some(Duration::from_secs(10)));
    let (mut rd, mut asm) = (CellReader::default(), Assembler::new());
    let (mut last_rx, mut last_tx) = (Instant::now(), Instant::now());
    let (mut outx, mut inx): (Option<OutXfer>, Option<InXfer>) = (None, None);
    // A contact must not be able to flood the status line (C6-flood): at most 6 notices per minute per connection.
    let (n_count, n_window) = (std::cell::Cell::new(0u32), std::cell::Cell::new(Instant::now()));
    let notice = |ev: &Sender<In>, text: &str| {
        if n_window.get().elapsed() > Duration::from_secs(60) { n_window.set(Instant::now()); n_count.set(0); }
        n_count.set(n_count.get() + 1);
        if n_count.get() > 6 { return true; }
        ev.send(In::Conn(ConnEvent::Ev { id, gen, ev: Event::Notice { id: Some(id), text: text.into(), alert: false } })).is_ok()
    };
    // security-relevant notices (integrity failure, refused content) are never rate-limited away
    let alert = |ev: &Sender<In>, text: &str| ev.send(In::Conn(ConnEvent::Ev { id, gen, ev: Event::Notice { id: Some(id), text: text.into(), alert: true } })).is_ok();
    let cancelled = |ev: &Sender<In>| ev.send(In::Conn(ConnEvent::Ev { id, gen, ev: Event::FileCancelled { id } })).is_ok();
    let mut bad_frames = 0u32;
    let mut rot_frames = 0u32;
    'conn: loop {
        loop {
            match out_rx.try_recv() {
                Ok(Out::Text { mid, text }) => {
                    // every chunk carries the id (a short text stays ONE cell); the receiver confirms it once its UI has the text
                    for body in proto::encode_text_with_id(&text, &mid) { if !send_body(&mut stream, &mut sess, &me, &body) { break 'conn; } }
                    last_tx = Instant::now();
                }
                Ok(Out::Ack(mid)) => {
                    let Some(frame) = proto::encode_msg_acks(&[mid]) else { continue };
                    if !send_body(&mut stream, &mut sess, &me, &frame) { break 'conn; }
                    last_tx = Instant::now();
                }
                Ok(Out::File(f)) => {
                    if outx.is_some() { notice(&ev, "a file transfer is already running on this connection"); continue; }
                    let o = Offer { xid: f.xid, bucket: f.bucket, mode: f.mode, hash: f.hash };
                    if !send_body(&mut stream, &mut sess, &me, &file::encode_offer(&o)) { break 'conn; }
                    last_tx = Instant::now();
                    outx = Some(OutXfer { f, st: OutState::WaitAccept(Instant::now() + OFFER_WAIT) });
                }
                Ok(Out::Reply { xid, accept }) => {
                    let ours = inx.as_ref().is_some_and(|x| x.o.xid == xid && matches!(x.st, InState::Pending(_)));
                    if ours {
                        if accept {
                            if let Some(x) = inx.as_mut() { x.st = InState::Receiving(Instant::now() + RECV_IDLE); }
                            if !send_body(&mut stream, &mut sess, &me, &file::encode_ctl(file::KIND_FILE_ACCEPT, &xid)) { break 'conn; }
                        } else {
                            inx = None;
                            if !send_body(&mut stream, &mut sess, &me, &file::encode_ctl(file::KIND_FILE_REJECT, &xid)) { break 'conn; }
                        }
                        last_tx = Instant::now();
                    }
                }
                Ok(Out::Rotate { kind, keys }) => {
                    if !send_body(&mut stream, &mut sess, &me, &proto::encode_rotate(kind, &keys)) { break 'conn; }
                    last_tx = Instant::now();
                }
                Ok(Out::Close) | Err(TryRecvError::Disconnected) => break 'conn,
                Err(TryRecvError::Empty) => break,
            }
        }
        // outgoing file: a few chunks per turn so receiving, replies and keepalives are never starved
        if let Some(x) = outx.as_mut() {
            match &mut x.st {
                OutState::WaitAccept(dl) => if Instant::now() > *dl { outx = None; if !notice(&ev, "file offer timed out (not accepted)") { break; } },
                OutState::Sending(pos) => {
                    for _ in 0..CHUNKS_PER_TURN {
                        if *pos >= x.f.padded.len() { break; }
                        let end = (*pos + file::CHUNK_DATA).min(x.f.padded.len());
                        let body = Zeroizing::new(file::encode_chunk(&x.f.xid, &x.f.padded[*pos..end]));
                        if !send_body(&mut stream, &mut sess, &me, &body) { break 'conn; }
                        *pos = end;
                        last_tx = Instant::now();
                    }
                    if *pos >= x.f.padded.len() { outx = None; if ev.send(In::Conn(ConnEvent::Ev { id, gen, ev: Event::FileSent { id } })).is_err() { break; } }
                }
            }
        }
        // incoming file timeouts
        if let Some(x) = inx.as_ref() {
            match x.st {
                InState::Pending(dl) if Instant::now() > dl => {
                    let xid = x.o.xid; inx = None;
                    if !send_body(&mut stream, &mut sess, &me, &file::encode_ctl(file::KIND_FILE_REJECT, &xid)) { break; }
                    if !notice(&ev, "a file offer expired unanswered and was declined") || !cancelled(&ev) { break; }
                }
                InState::Receiving(dl) if Instant::now() > dl => { inx = None; if !notice(&ev, "file transfer stalled and was cancelled") || !cancelled(&ev) { break; } }
                _ => {}
            }
        }
        if last_tx.elapsed() >= t.keepalive {
            if !send_body(&mut stream, &mut sess, &me, &proto::keepalive()) { break; }
            last_tx = Instant::now();
        }
        match rd.poll(&mut stream) {
            Ok(Some(cell)) => {
                last_rx = Instant::now();
                let Ok(m) = sess.recv(&me, &cell) else { break }; // bad signature / replay / reorder: drop the connection
                match m.body.first().copied() {
                    Some(file::KIND_FILE_OFFER) => {
                        let Some(o) = file::parse_offer(&m.body) else { break };
                        let pl = file::valid_bucket(o.bucket as usize);
                        if inx.is_some() || !pl {
                            // busy or out of policy: decline at once (no state kept)
                            if !send_body(&mut stream, &mut sess, &me, &file::encode_ctl(file::KIND_FILE_REJECT, &o.xid)) { break; }
                            last_tx = Instant::now();
                        } else {
                            inx = Some(InXfer { o, padded: o.bucket as usize, buf: Zeroizing::new(Vec::new()), st: InState::Pending(Instant::now() + OFFER_WAIT) });
                            if ev.send(In::Conn(ConnEvent::Ev { id, gen, ev: Event::FileOffer { id, xid: o.xid, bucket: o.bucket } })).is_err() { break; }
                        }
                    }
                    Some(file::KIND_FILE_ACCEPT) => {
                        if let (Some(xid), Some(x)) = (file::parse_ctl(&m.body), outx.as_mut()) {
                            if x.f.xid == xid && matches!(x.st, OutState::WaitAccept(_)) { x.st = OutState::Sending(0); }
                        }
                    }
                    Some(file::KIND_FILE_REJECT) => {
                        if let Some(xid) = file::parse_ctl(&m.body) {
                            if outx.as_ref().is_some_and(|x| x.f.xid == xid) { outx = None; if !notice(&ev, "the contact declined the file") { break; } }
                        }
                    }
                    Some(file::KIND_FILE_CHUNK) => {
                        let mut done = None;
                        let mut bad = false;
                        match (file::parse_chunk(&m.body), inx.as_mut()) {
                            (Some((xid, data)), Some(x)) if x.o.xid == xid && matches!(x.st, InState::Receiving(_)) && x.buf.len() + data.len() <= x.padded => {
                                if x.buf.capacity() == 0 { x.buf = Zeroizing::new(Vec::with_capacity(x.padded)); } // exact, never reallocates
                                x.buf.extend_from_slice(data);
                                x.st = InState::Receiving(Instant::now() + RECV_IDLE);
                                if x.buf.len() == x.padded { done = Some(()); }
                            }
                            _ => bad = true, // unsolicited, wrong id, too long, malformed: cancel whatever is running
                        }
                        if bad {
                            inx = None; bad_frames += 1;
                            if bad_frames > 5 { break; } // an authenticated peer that keeps sending garbage is cut off
                            if !notice(&ev, "unexpected file data: transfer cancelled") || !cancelled(&ev) { break; }
                        }
                        if done.is_some() {
                            let x = inx.take().expect("set above");
                            let mode = if x.o.mode == file::MODE_TEXT { nerd_chat_strip::Mode::PlainText } else { nerd_chat_strip::Mode::Auto };
                            match file::parse_stream(&x.buf) {
                                Some(content) if file::hash(content) == x.o.hash => {
                                    // quarantine: re-clean ourselves, never trust the sender's cleaning
                                    match nerd_chat_strip::clean_hooked(content, mode) {
                                        Ok(c) => {
                                            let resanitised = c.data.len() != content.len() || (mode == nerd_chat_strip::Mode::Auto && !c.report.is_empty());
                                            let data = Zeroizing::new(c.data);
                                            if ev.send(In::Conn(ConnEvent::Ev { id, gen, ev: Event::File { id, data, format: c.format, report: c.report, resanitised } })).is_err() { break; }
                                        }
                                        Err(e) => { if !alert(&ev, &format!("received file refused ({e})")) || !cancelled(&ev) { break; } }
                                    }
                                }
                                _ => { if !alert(&ev, "received file failed its integrity check and was discarded") || !cancelled(&ev) { break; } }
                            }
                        }
                    }
                    Some(k @ (proto::KIND_ROTATE_OFFER | proto::KIND_ROTATE_ACK | proto::KIND_ROTATE_DONE)) => {
                        // few per connection: a peer cannot make us churn services or the vault
                        rot_frames += 1;
                        let Some(keys) = proto::parse_rotate(&m.body) else { break };
                        if rot_frames > 6 { break; }
                        if ev.send(In::Conn(ConnEvent::Rotate { id, kind: k, keys })).is_err() { break; }
                    }
                    Some(proto::KIND_MSG_ACK) => {
                        let Some(mids) = proto::parse_msg_acks(&m.body) else { break };
                        if ev.send(In::Conn(ConnEvent::Acked { id, mids })).is_err() { break; }
                    }
                    _ => match asm.feed(&m.body) {
                        Ok(Incoming::Text(text, mid)) => { if ev.send(In::Conn(ConnEvent::Text { id, gen, mid, text })).is_err() { break; } }
                        Ok(_) => {}
                        Err(_) => break,
                    },
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
        if last_rx.elapsed() > t.idle { break; }
    }
    let _ = ev.send(In::Conn(ConnEvent::Down { id, gen }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A reader that hands out data in tiny pieces and interleaves timeouts.
    struct Drip { data: Vec<u8>, pos: usize, tick: usize }
    impl Read for Drip {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.tick += 1;
            if self.tick.is_multiple_of(2) { return Err(ErrorKind::TimedOut.into()); }
            if self.pos >= self.data.len() { return Ok(0); }
            let n = 7.min(b.len()).min(self.data.len() - self.pos);
            b[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn cell_reader_survives_timeouts_and_partial_reads() {
        let cell: Vec<u8> = (0..WIRE_CELL_LEN).map(|i| (i % 251) as u8).collect();
        let mut r = Drip { data: [cell.clone(), cell.clone()].concat(), pos: 0, tick: 0 };
        let mut rd = CellReader::default();
        let mut got = vec![];
        for _ in 0..5000 { if let Some(c) = rd.poll(&mut r).unwrap() { got.push(c); } if got.len() == 2 { break; } }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], cell);
        assert_eq!(got[1], cell);
        assert!(rd.poll(&mut Cursor::new(Vec::<u8>::new())).is_err(), "EOF is an error");
    }
}
