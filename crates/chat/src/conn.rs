//! One authenticated connection. A dedicated thread owns the stream and the session: it polls for incoming cells
//! (200 ms ticks, partial cells are buffered, never lost), sends queued messages and keepalives, and ends on any error,
//! on an idle timeout (no cell from the peer for `idle`) or when told to close.
use crate::{
    engine::{ConnEvent, In, Timing},
    proto::{self, Assembler, Incoming},
    transport::BoxStream,
};
use seburity_core::{identity::ContactIdentity, session::{Session, WIRE_CELL_LEN}};
use std::{
    io::{ErrorKind, Read, Write},
    sync::{atomic::{AtomicBool, Ordering}, mpsc::{Receiver, Sender, TryRecvError}, Arc},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub enum Out { Text(Zeroizing<String>), Close }

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
    'conn: loop {
        loop {
            match out_rx.try_recv() {
                Ok(Out::Text(text)) => {
                    for body in proto::encode_text(&text) { if !send_body(&mut stream, &mut sess, &me, &body) { break 'conn; } }
                    last_tx = Instant::now();
                }
                Ok(Out::Close) | Err(TryRecvError::Disconnected) => break 'conn,
                Err(TryRecvError::Empty) => break,
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
                match asm.feed(&m.body) {
                    Ok(Incoming::Text(text)) => { if ev.send(In::Conn(ConnEvent::Msg { id, gen, text })).is_err() { break; } }
                    Ok(_) => {}
                    Err(_) => break,
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
            if self.tick % 2 == 0 { return Err(ErrorKind::TimedOut.into()); }
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
