//! The message HISTORY file (`hist.bin`): what the phone keeps of a conversation, and how it hides WHEN messages were sent.
//! Design and the reasons: docs/HISTORY_AND_TIMING_PLAN.md. In short:
//!
//!  * A PRE-ALLOCATED file of two equal SLOTS, written IN PLACE (never temp file + rename: a rename gives the file a new birth time = the real write time).
//!    Each slot is `nonce[24] | AEAD(slot key)(gen | hwm | body | zero padding)`, always exactly the same length, random-filled when unused. The reader opens
//!    both and takes the valid one with the higher generation, so a torn write falls back to the older slot.
//!  * The body is a list of 6-hour BUCKETS. Each bucket's messages are encrypted under their own random key `HK`; `HK` is stored wrapped by a PLATFORM key
//!    that belongs to the 24-hour EPOCH of the bucket and can be DESTROYED without the password (Android Keystore). Deleting that key makes the bucket unreadable
//!    even for someone with the password and an old copy of the file. Where there is no such key (Linux) deletion is a best-effort overwrite.
//!  * Nothing touches the file except `tick`, which the app calls on a fixed GRID (every 5 s): dirty data is written, otherwise the file is only touched
//!    (`futimens`). A message never causes a file operation by itself, so mtime/ctime of the file are always grid times, never message times.
//!  * Stored time is the BUCKET (UTC seconds / 21,600), never a time per message; `hwm` is the highest time ever seen (a clock moved back never extends a life).
#![allow(clippy::too_many_arguments)]
use crate::StoreError;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use std::{fs, io, os::unix::fs::{FileExt, OpenOptionsExt}, path::{Path, PathBuf}, sync::Arc, time::{Instant, SystemTime, UNIX_EPOCH}};
use zeroize::{Zeroize, Zeroizing};

pub const BUCKET_SECS: u64 = 6 * 3600;
pub const EPOCH_SECS: u64 = 24 * 3600;
/// Default size of ONE slot (the file is two of them): 1 MiB, so the file is always 2 MiB whatever it holds.
pub const SLOT_LEN: usize = 1 << 20;
const SLOT_AAD: &[u8] = b"nerd-chat-history-slot-v1";
const BUCKET_AAD: &[u8] = b"nerd-chat-history-bucket-v1";
const MAX_TEXT: usize = 32 * 1024;
/// At most this many messages per contact (the same as the chat view's cap).
pub const MAX_LINES_PER_CONTACT: usize = 500;

/// What the user chose to keep on the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persist {
    /// nothing: messages exist only in RAM
    Off,
    /// only messages we SENT that the contact has not confirmed yet (the encrypted outbox)
    Outbox,
    /// everything, deleted after about a day (24-30 h)
    Day,
    /// everything, deleted after about a week
    Week,
}

impl Persist {
    /// Seconds a bucket lives AFTER it ended. `None`: nothing but unconfirmed texts is kept.
    pub fn retention_secs(self) -> Option<u64> { match self { Persist::Off | Persist::Outbox => None, Persist::Day => Some(24 * 3600), Persist::Week => Some(7 * 24 * 3600) } }
    pub fn keeps_anything(self) -> bool { self != Persist::Off }
    pub fn keeps_everything(self) -> bool { matches!(self, Persist::Day | Persist::Week) }
}

/// The platform's deletable key store (Android Keystore). `wrap`/`unwrap` protect one bucket key under the key of its EPOCH; `erase` destroys that key for good.
pub trait PlatformKeys: Send + Sync {
    fn wrap(&self, epoch: u32, key: &[u8; 32]) -> Option<Vec<u8>>;
    /// `None`: the epoch key is gone (erased) or the blob is not ours: the bucket is unreadable.
    fn unwrap(&self, epoch: u32, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>>;
    fn erase(&self, epoch: u32);
}

/// No platform key store (Linux): the bucket key is stored as is inside the slot, which is encrypted under the vault's subkey.
pub struct NoPlatformKeys;
impl PlatformKeys for NoPlatformKeys {
    fn wrap(&self, _: u32, key: &[u8; 32]) -> Option<Vec<u8>> { Some(key.to_vec()) }
    fn unwrap(&self, _: u32, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>> { let a: [u8; 32] = blob.try_into().ok()?; Some(Zeroizing::new(a)) }
    fn erase(&self, _: u32) {}
}

/// A job that knows nothing about the history (the Android erase job, which runs while the app is locked) may destroy the key of epoch `E` once
/// `E + ERASE_AFTER_EPOCHS < the current epoch`. A bucket never outlives `the end of its epoch + the longest retention`: see the test `the_erase_job_bound_covers_the_longest_life`.
pub const ERASE_AFTER_EPOCHS: u32 = 9;

/// Time. `wall` = seconds since 1970 (the device clock, never a network clock); `mono` = monotonic seconds (a clock moved by hand does not move it).
pub trait Clock: Send + Sync { fn wall(&self) -> u64; fn mono(&self) -> u64; }
pub struct SystemClock(Instant);
impl SystemClock { pub fn new() -> Self { Self(Instant::now()) } }
impl Default for SystemClock { fn default() -> Self { Self::new() } }
impl Clock for SystemClock {
    fn wall(&self) -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) }
    fn mono(&self) -> u64 { self.0.elapsed().as_secs() }
}

/// What happened to a message. `Received` is a text from the contact; the rest are texts we sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Received, Queued, Delivered, Unsent, Unconfirmed, Expired }
impl State {
    fn code(self) -> u8 { match self { State::Received => 0, State::Queued => 1, State::Delivered => 2, State::Unsent => 3, State::Unconfirmed => 4, State::Expired => 5 } }
    fn from_code(c: u8) -> Option<Self> { Some(match c { 0 => State::Received, 1 => State::Queued, 2 => State::Delivered, 3 => State::Unsent, 4 => State::Unconfirmed, 5 => State::Expired, _ => return None }) }
}

#[derive(Clone)]
pub struct Line { pub contact: [u8; 8], pub state: State, pub mid: Option<[u8; 8]>, pub text: Zeroizing<String> }
impl Line { pub fn mine(&self) -> bool { self.state != State::Received } }

struct Bucket { id: u32, epoch: u32, hk: Zeroizing<[u8; 32]>, /** the key wrapped by the platform: made once (a hardware key store is slow), reused at every write */ wrapped: Option<Vec<u8>>, msgs: Vec<Line> }

/// What a sweep removed.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Swept {
    pub buckets: usize,
    /// texts we sent that were still unconfirmed when their bucket expired: they will NEVER be sent now (the engine must forget them)
    pub expired_queued: Vec<([u8; 8], [u8; 8])>,
    pub epochs_erased: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Tick { Wrote, Touched }

pub struct History {
    path: PathBuf,
    file: fs::File,
    slot_len: usize,
    fk: Zeroizing<[u8; 32]>,
    platform: Arc<dyn PlatformKeys>,
    clock: Arc<dyn Clock>,
    buckets: Vec<Bucket>,
    gen: u64,
    /// the slot (0/1) that holds the current generation (None: neither does yet)
    active: Option<usize>,
    hwm: u64,
    hwm_at_open: u64,
    mono_at_open: u64,
    dirty: bool,
    /// the older generation may still hold keys that were just erased: overwrite it in the next write
    scrub_other: bool,
    persist: Persist,
}

fn io(e: io::Error) -> StoreError { StoreError::Io(e.to_string()) }

fn aead(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("OS RNG unavailable");
    let ct = XChaCha20Poly1305::new(key.into()).encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad }).expect("encrypt");
    [nonce.as_slice(), ct.as_slice()].concat()
}
fn unaead(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if blob.len() < 24 + 16 { return None; }
    XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(&blob[..24]), Payload { msg: &blob[24..], aad }).ok().map(Zeroizing::new)
}
fn random(n: usize) -> Vec<u8> { let mut v = vec![0u8; n]; getrandom::fill(&mut v).expect("OS RNG unavailable"); v }

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> { if self.0.len() < n { return None; } let (a, b) = self.0.split_at(n); self.0 = b; Some(a) }
    fn u16(&mut self) -> Option<usize> { Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize) }
    fn u32(&mut self) -> Option<usize> { Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize) }
    fn u64(&mut self) -> Option<u64> { Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?)) }
}

impl History {
    /// Open (or create) the history file next to the vault. `fk` is the vault's subkey for this file. `slot_len` is `SLOT_LEN` except in tests.
    pub fn open(path: &Path, slot_len: usize, fk: Zeroizing<[u8; 32]>, platform: Arc<dyn PlatformKeys>, clock: Arc<dyn Clock>, persist: Persist) -> Result<Self, StoreError> {
        assert!(slot_len >= 4096, "slot too small");
        let exists = fs::symlink_metadata(path).is_ok();
        let file = if exists {
            let f = fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(io)?;
            let md = f.metadata().map_err(io)?;
            if !md.is_file() || md.len() != 2 * slot_len as u64 { return Err(StoreError::Corrupt); }
            f
        } else {
            let f = fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path).map_err(io)?;
            // both slots start as random bytes: an unused slot looks exactly like a used one
            for slot in 0..2 { f.write_all_at(&random(slot_len), (slot * slot_len) as u64).map_err(io)?; }
            f.sync_all().map_err(io)?;
            f
        };
        let mut h = Self { path: path.to_path_buf(), file, slot_len, fk, platform, clock, buckets: Vec::new(), gen: 0, active: None, hwm: 0, hwm_at_open: 0, mono_at_open: 0, dirty: false, scrub_other: false, persist };
        h.load()?;
        h.hwm_at_open = h.hwm.max(h.clock.wall());
        h.hwm = h.hwm_at_open;
        h.mono_at_open = h.clock.mono();
        Ok(h)
    }

    fn read_slot(&self, slot: usize) -> Option<(u64, u64, Zeroizing<Vec<u8>>)> {
        let mut buf = Zeroizing::new(vec![0u8; self.slot_len]);
        self.file.read_exact_at(&mut buf, (slot * self.slot_len) as u64).ok()?;
        let pt = unaead(&self.fk, SLOT_AAD, &buf)?;
        if pt.len() < 8 + 8 + 4 { return None; }
        let mut r = R(&pt);
        let (gen, hwm, used) = (r.u64()?, r.u64()?, r.u32()?);
        if used > pt.len() - 20 { return None; }
        Some((gen, hwm, Zeroizing::new(pt[20..20 + used].to_vec())))
    }

    fn load(&mut self) -> Result<(), StoreError> {
        let best = [0usize, 1].into_iter().filter_map(|s| self.read_slot(s).map(|x| (s, x))).max_by_key(|(_, x)| x.0);
        let Some((slot, (gen, hwm, body))) = best else { return Ok(()) };
        let mut r = R(&body);
        let n = r.u16().ok_or(StoreError::Corrupt)?;
        let mut lost = false;
        for _ in 0..n {
            let (id, epoch) = (r.u32().ok_or(StoreError::Corrupt)? as u32, r.u32().ok_or(StoreError::Corrupt)? as u32);
            let wl = r.u16().ok_or(StoreError::Corrupt)?;
            let wrapped = r.take(wl).ok_or(StoreError::Corrupt)?;
            let cl = r.u32().ok_or(StoreError::Corrupt)?;
            let ct = r.take(cl).ok_or(StoreError::Corrupt)?;
            // a bucket whose epoch key was erased (or that does not decrypt) is simply gone
            let Some(hk) = self.platform.unwrap(epoch, wrapped) else { lost = true; continue };
            let Some(pt) = unaead(&hk, &[BUCKET_AAD, &id.to_be_bytes()].concat(), ct) else { lost = true; continue };
            let Some(msgs) = parse_msgs(&pt) else { lost = true; continue };
            self.buckets.push(Bucket { id, epoch, hk, wrapped: Some(wrapped.to_vec()), msgs });
        }
        self.gen = gen; self.hwm = hwm; self.active = Some(slot);
        if lost { self.dirty = true; self.scrub_other = true; }
        Ok(())
    }

    pub fn persist(&self) -> Persist { self.persist }
    /// Change what is kept. Narrowing to `Outbox` forgets everything but unconfirmed texts right away.
    pub fn set_persist(&mut self, p: Persist) {
        if p == self.persist { return; }
        self.persist = p;
        if p == Persist::Outbox { for b in &mut self.buckets { b.msgs.retain(|m| m.state == State::Queued); } self.drop_empty_buckets(); }
        self.dirty = true;
    }
    pub fn path(&self) -> &Path { &self.path }
    pub fn is_dirty(&self) -> bool { self.dirty }
    pub fn generation(&self) -> u64 { self.gen }

    /// The time retention is measured with: never earlier than the highest time ever seen, and it keeps running by the MONOTONIC clock even if the wall clock is moved back.
    /// Moving the clock back therefore never makes a message live longer; moving it forward only makes messages expire sooner.
    pub fn now(&mut self) -> u64 {
        let by_mono = self.hwm_at_open + self.clock.mono().saturating_sub(self.mono_at_open);
        let n = self.clock.wall().max(self.hwm).max(by_mono);
        if n > self.hwm { self.hwm = n; }
        n
    }

    fn bucket_for(&mut self, now: u64) -> usize {
        let id = ((now / BUCKET_SECS) as u32).max(self.buckets.last().map_or(0, |b| b.id));
        if let Some(i) = self.buckets.iter().position(|b| b.id == id) { return i; }
        let epoch = ((id as u64 * BUCKET_SECS) / EPOCH_SECS) as u32;
        let mut hk = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *hk).expect("OS RNG unavailable");
        self.buckets.push(Bucket { id, epoch, hk, wrapped: None, msgs: Vec::new() });
        self.buckets.len() - 1
    }

    /// Record a message. Only what the chosen mode keeps is stored (`Outbox`: only texts we sent that are still unconfirmed). Not written until the next `tick`.
    pub fn push(&mut self, contact: [u8; 8], state: State, mid: Option<[u8; 8]>, text: &str) {
        if text.is_empty() || text.len() > MAX_TEXT { return; }
        let keep = match self.persist { Persist::Off => false, Persist::Outbox => state == State::Queued, _ => true };
        if !keep { return; }
        let now = self.now();
        let b = self.bucket_for(now);
        self.buckets[b].msgs.push(Line { contact, state, mid, text: Zeroizing::new(text.to_string()) });
        self.cap_contact(contact);
        self.dirty = true;
    }

    /// At most `MAX_LINES_PER_CONTACT` per contact: the oldest line that is not an unconfirmed text goes first.
    fn cap_contact(&mut self, contact: [u8; 8]) {
        loop {
            let n: usize = self.buckets.iter().map(|b| b.msgs.iter().filter(|m| m.contact == contact).count()).sum();
            if n <= MAX_LINES_PER_CONTACT { return; }
            let victim = self.buckets.iter().enumerate().flat_map(|(bi, b)| b.msgs.iter().enumerate().filter(|(_, m)| m.contact == contact).map(move |(mi, m)| (bi, mi, m.state == State::Queued))).min_by_key(|&(bi, mi, q)| (q, bi, mi));
            let Some((bi, mi, _)) = victim else { return };
            self.buckets[bi].msgs.remove(mi);
        }
    }

    /// The state of a sent text changed (confirmed, refused, maybe-lost). In `Outbox` mode a text that is no longer unconfirmed is forgotten at once.
    pub fn set_state(&mut self, contact: [u8; 8], mid: [u8; 8], state: State) -> bool {
        let drop_it = self.persist == Persist::Outbox && state != State::Queued;
        for b in &mut self.buckets {
            if let Some(i) = b.msgs.iter().position(|m| m.contact == contact && m.mid == Some(mid)) {
                if drop_it { b.msgs.remove(i); } else { b.msgs[i].state = state; }
                self.dirty = true;
                return true;
            }
        }
        false
    }

    /// Texts of this contact that were sent but not confirmed (oldest first): what the engine is given when it starts.
    pub fn queued(&self, contact: [u8; 8]) -> Vec<([u8; 8], Zeroizing<String>)> {
        self.buckets.iter().flat_map(|b| b.msgs.iter()).filter(|m| m.contact == contact && m.state == State::Queued).filter_map(|m| m.mid.map(|id| (id, m.text.clone()))).collect()
    }
    pub fn all_queued_mids(&self) -> Vec<([u8; 8], [u8; 8])> {
        self.buckets.iter().flat_map(|b| b.msgs.iter()).filter(|m| m.state == State::Queued).filter_map(|m| m.mid.map(|id| (m.contact, id))).collect()
    }
    pub fn has_queued(&self, contact: [u8; 8], mid: [u8; 8]) -> bool { self.buckets.iter().flat_map(|b| b.msgs.iter()).any(|m| m.contact == contact && m.mid == Some(mid) && m.state == State::Queued) }

    /// The remembered conversation with a contact, oldest first.
    pub fn lines(&self, contact: [u8; 8]) -> Vec<Line> { self.buckets.iter().flat_map(|b| b.msgs.iter()).filter(|m| m.contact == contact).cloned().collect() }
    pub fn len(&self) -> usize { self.buckets.iter().map(|b| b.msgs.len()).sum() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Forget everything of one contact (the contact was deleted).
    pub fn remove_contact(&mut self, contact: [u8; 8]) {
        for b in &mut self.buckets { let n = b.msgs.len(); b.msgs.retain(|m| m.contact != contact); if b.msgs.len() != n { self.dirty = true; } }
        self.drop_empty_buckets();
    }

    fn drop_empty_buckets(&mut self) {
        let before: Vec<u32> = self.buckets.iter().map(|b| b.epoch).collect();
        self.buckets.retain(|b| !b.msgs.is_empty());
        if self.buckets.len() != before.len() { self.dirty = true; self.scrub_other = true; self.erase_unused_epochs(&before); }
    }

    fn erase_unused_epochs(&mut self, before: &[u32]) -> Vec<u32> {
        let mut gone: Vec<u32> = before.iter().copied().filter(|e| !self.buckets.iter().any(|b| b.epoch == *e)).collect();
        gone.sort_unstable(); gone.dedup();
        for e in &gone { self.platform.erase(*e); }
        gone
    }

    /// Delete what has expired: buckets that ended more than the retention ago (and, in `Outbox` mode, nothing but confirmed texts are ever kept).
    /// Returns the unconfirmed texts that expired with them (they will never be sent) and the epoch keys that were destroyed.
    pub fn sweep(&mut self) -> Swept {
        let now = self.now();
        let Some(ret) = self.persist.retention_secs() else { return Swept::default() };
        let before: Vec<u32> = self.buckets.iter().map(|b| b.epoch).collect();
        let mut out = Swept::default();
        let mut i = 0;
        while i < self.buckets.len() {
            let end = (self.buckets[i].id as u64 + 1) * BUCKET_SECS;
            if end + ret <= now {
                let b = self.buckets.remove(i);
                out.expired_queued.extend(b.msgs.iter().filter(|m| m.state == State::Queued).filter_map(|m| m.mid.map(|id| (m.contact, id))));
                out.buckets += 1;
            } else { i += 1; }
        }
        if out.buckets > 0 { self.dirty = true; self.scrub_other = true; out.epochs_erased = self.erase_unused_epochs(&before); }
        out
    }

    /// The grid tick. Dirty data is written (in place, into the slot that does NOT hold the current generation, then synced); otherwise the file is only TOUCHED so that its
    /// times keep moving on the grid. Call it on a fixed clock (every 5 s) and from nowhere else.
    pub fn tick(&mut self) -> Result<Tick, StoreError> {
        let _ = self.now();
        if !self.dirty { self.file.set_modified(SystemTime::now()).map_err(io)?; return Ok(Tick::Touched); }
        let cap = self.slot_len - 24 - 16 - 20;
        if self.estimate() > cap { self.evict_to_fit(cap); }
        let Some(body) = self.serialize() else { return Err(StoreError::Io("the platform key store could not protect a key: nothing was written".into())) };
        assert!(body.len() <= cap, "the estimate is an upper bound");
        let target = match self.active { Some(0) => 1, _ => 0 };
        let gen = self.gen + 1;
        let mut pt = Zeroizing::new(Vec::with_capacity(self.slot_len - 24 - 16));
        pt.extend_from_slice(&gen.to_be_bytes()); pt.extend_from_slice(&self.hwm.to_be_bytes()); pt.extend_from_slice(&(body.len() as u32).to_be_bytes());
        pt.extend_from_slice(&body);
        pt.resize(self.slot_len - 24 - 16, 0);
        let slot = aead(&self.fk, SLOT_AAD, &pt);
        debug_assert_eq!(slot.len(), self.slot_len);
        self.file.write_all_at(&slot, (target * self.slot_len) as u64).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        self.gen = gen; self.active = Some(target); self.dirty = false;
        if self.scrub_other {
            // the other slot still holds the previous generation, with keys that were just erased: overwrite it so that only the new generation exists
            self.file.write_all_at(&random(self.slot_len), ((1 - target) * self.slot_len) as u64).map_err(io)?;
            self.file.sync_data().map_err(io)?;
            self.scrub_other = false;
        }
        Ok(Tick::Wrote)
    }

    /// `None` if the platform key store refused to wrap a bucket key: writing a bucket with an unusable key would lose it silently, so nothing is written (the data stays dirty and is retried).
    fn serialize(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let mut v = Zeroizing::new(Vec::new());
        v.extend_from_slice(&(self.buckets.len() as u16).to_be_bytes());
        for b in &mut self.buckets {
            if b.wrapped.is_none() { b.wrapped = Some(self.platform.wrap(b.epoch, &b.hk).filter(|w| !w.is_empty() && w.len() <= 4096)?); }
            let mut m = Zeroizing::new(Vec::new());
            m.extend_from_slice(&(b.msgs.len() as u16).to_be_bytes());
            for l in &b.msgs {
                m.extend_from_slice(&l.contact);
                m.push(l.state.code() | (l.mid.is_some() as u8) << 4);
                if let Some(id) = l.mid { m.extend_from_slice(&id); }
                m.extend_from_slice(&(l.text.len() as u16).to_be_bytes());
                m.extend_from_slice(l.text.as_bytes());
            }
            let ct = aead(&b.hk, &[BUCKET_AAD, &b.id.to_be_bytes()].concat(), &m);
            let wrapped = b.wrapped.as_deref().unwrap_or_default();
            v.extend_from_slice(&b.id.to_be_bytes()); v.extend_from_slice(&b.epoch.to_be_bytes());
            v.extend_from_slice(&(wrapped.len() as u16).to_be_bytes()); v.extend_from_slice(wrapped);
            v.extend_from_slice(&(ct.len() as u32).to_be_bytes()); v.extend_from_slice(&ct);
        }
        Some(v)
    }

    /// A close upper bound of the serialized size without encrypting anything (so that eviction does not re-encrypt the whole file at every step).
    fn estimate(&self) -> usize {
        2 + self.buckets.iter().map(|b| 4 + 4 + 2 + 128 + 4 + 24 + 16 + 2 + b.msgs.iter().map(|m| 8 + 1 + 8 + 2 + m.text.len()).sum::<usize>()).sum::<usize>()
    }

    /// Over the slot capacity: drop the oldest lines (an unconfirmed text is the last to go) until it fits.
    fn evict_to_fit(&mut self, cap: usize) {
        while self.estimate() > cap {
            let victim = self.buckets.iter().enumerate().flat_map(|(bi, b)| b.msgs.iter().enumerate().map(move |(mi, m)| (bi, mi, m.state == State::Queued))).min_by_key(|&(bi, mi, q)| (q, bi, mi));
            let Some((bi, mi, _)) = victim else { return };
            self.buckets[bi].msgs.remove(mi);
            if self.buckets[bi].msgs.is_empty() { self.buckets.remove(bi); }
        }
    }

    /// Purge: overwrite the file with random bytes and delete it.
    pub fn shred(self) -> Result<(), StoreError> {
        let len = 2 * self.slot_len;
        for _ in 0..2 { self.file.write_all_at(&random(len), 0).map_err(io)?; self.file.sync_all().map_err(io)?; }
        fs::remove_file(&self.path).map_err(io)
    }
}

impl Drop for History { fn drop(&mut self) { self.fk.zeroize(); } }

fn parse_msgs(pt: &[u8]) -> Option<Vec<Line>> {
    let mut r = R(pt);
    let n = r.u16()?;
    let mut v = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let contact: [u8; 8] = r.take(8)?.try_into().ok()?;
        let f = r.take(1)?[0];
        if f & !0b1_0111 != 0 { return None; }
        let state = State::from_code(f & 0b111)?;
        let mid = if f & 0b1_0000 != 0 { Some(<[u8; 8]>::try_from(r.take(8)?).ok()?) } else { None };
        let len = r.u16()?;
        if len == 0 || len > MAX_TEXT { return None; }
        let text = std::str::from_utf8(r.take(len)?).ok()?;
        v.push(Line { contact, state, mid, text: Zeroizing::new(text.to_string()) });
    }
    if !r.0.is_empty() { return None; }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex};

    struct TestClock { wall: Mutex<u64>, mono: Mutex<u64> }
    impl TestClock {
        fn new(wall: u64) -> Arc<Self> { Arc::new(Self { wall: Mutex::new(wall), mono: Mutex::new(0) }) }
        fn advance(&self, s: u64) { *self.wall.lock().unwrap() += s; *self.mono.lock().unwrap() += s; }
        fn set_wall(&self, w: u64) { *self.wall.lock().unwrap() = w; }
    }
    impl Clock for TestClock { fn wall(&self) -> u64 { *self.wall.lock().unwrap() } fn mono(&self) -> u64 { *self.mono.lock().unwrap() } }

    /// A platform key store in memory: one AEAD key per epoch; `erase` destroys it.
    #[derive(Default)]
    struct MemKeys { keys: Mutex<HashMap<u32, [u8; 32]>>, erased: Mutex<Vec<u32>> }
    impl PlatformKeys for MemKeys {
        fn wrap(&self, epoch: u32, key: &[u8; 32]) -> Option<Vec<u8>> {
            let mut m = self.keys.lock().unwrap();
            let k = *m.entry(epoch).or_insert_with(|| { let mut k = [0u8; 32]; getrandom::fill(&mut k).unwrap(); k });
            Some(aead(&k, b"wrap", key))
        }
        fn unwrap(&self, epoch: u32, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
            let k = *self.keys.lock().unwrap().get(&epoch)?;
            let pt = unaead(&k, b"wrap", blob)?;
            Some(Zeroizing::new(<[u8; 32]>::try_from(&pt[..]).ok()?))
        }
        fn erase(&self, epoch: u32) { self.keys.lock().unwrap().remove(&epoch); self.erased.lock().unwrap().push(epoch); }
    }

    /// A key store that refuses every wrap.
    struct DeadKeys;
    impl PlatformKeys for DeadKeys {
        fn wrap(&self, _: u32, _: &[u8; 32]) -> Option<Vec<u8>> { None }
        fn unwrap(&self, _: u32, _: &[u8]) -> Option<Zeroizing<[u8; 32]>> { None }
        fn erase(&self, _: u32) {}
    }

    #[test]
    fn the_erase_job_bound_covers_the_longest_life() {
        // a bucket of epoch E ends by (E+1)*EPOCH and is deleted `retention` later; the job acts from epoch E + ERASE_AFTER + 1 on
        let last_use = EPOCH_SECS + Persist::Week.retention_secs().unwrap();
        let job_acts = (ERASE_AFTER_EPOCHS as u64 + 1) * EPOCH_SECS;
        assert!(job_acts >= last_use + EPOCH_SECS, "at least a day of margin: {job_acts} vs {last_use}");
    }

    #[test]
    fn a_key_store_that_refuses_writes_nothing_and_loses_nothing() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let clock = TestClock::new(T0);
        let mut h = History::open(&p, SLOT, fk(), Arc::new(DeadKeys), clock.clone(), Persist::Day).unwrap();
        h.push([1u8; 8], State::Received, None, "hello");
        assert!(h.tick().is_err(), "a refused wrap must be an error, not a silently unreadable bucket");
        assert!(h.tick().is_err(), "still dirty: retried");
        assert_eq!(h.lines([1u8; 8]).len(), 1, "the line is still in memory");
    }

    const SLOT: usize = 64 * 1024;
    const T0: u64 = 1_800_000_000; // a fixed "now"
    fn fk() -> Zeroizing<[u8; 32]> { Zeroizing::new([9u8; 32]) }
    fn open(p: &Path, clock: &Arc<TestClock>, keys: &Arc<MemKeys>, persist: Persist) -> History {
        History::open(p, SLOT, fk(), keys.clone(), clock.clone(), persist).unwrap()
    }
    const A: [u8; 8] = [1; 8];
    const B: [u8; 8] = [2; 8];

    #[test]
    fn messages_survive_a_restart_in_order_and_the_file_has_a_fixed_size() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "hello");
        h.push(A, State::Queued, Some([7; 8]), "hi back \u{1F600}");
        h.push(B, State::Received, None, "other contact");
        assert_eq!(h.tick().unwrap(), Tick::Wrote);
        assert_eq!(fs::metadata(&p).unwrap().len(), 2 * SLOT as u64);
        drop(h);
        let h = open(&p, &clock, &keys, Persist::Day);
        let l = h.lines(A);
        assert_eq!(l.iter().map(|x| (x.state, x.text.to_string())).collect::<Vec<_>>(), vec![(State::Received, "hello".into()), (State::Queued, "hi back \u{1F600}".into())]);
        assert_eq!(h.lines(B).len(), 1);
        assert_eq!(h.queued(A).len(), 1);
        assert_eq!(fs::metadata(&p).unwrap().len(), 2 * SLOT as u64, "size never changes");
    }

    #[test]
    fn a_clean_tick_only_touches_and_a_dirty_tick_writes_in_place_without_a_new_inode() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        let ino = fs::metadata(&p).unwrap().ino();
        let birth = fs::metadata(&p).unwrap().created().ok();
        assert_eq!(h.tick().unwrap(), Tick::Touched, "nothing to write");
        h.push(A, State::Received, None, "x");
        assert!(h.is_dirty());
        assert_eq!(h.tick().unwrap(), Tick::Wrote);
        assert_eq!(h.tick().unwrap(), Tick::Touched);
        let md = fs::metadata(&p).unwrap();
        assert_eq!(md.ino(), ino, "the same inode: no rename, no new birth time");
        assert_eq!(md.created().ok(), birth);
    }

    #[test]
    fn a_torn_write_falls_back_to_the_previous_generation() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "first"); h.tick().unwrap();
        h.push(A, State::Received, None, "second"); h.tick().unwrap();
        let newest = h.active.unwrap();
        drop(h);
        // power loss in the middle of writing the newest slot: half of it is garbage
        let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.write_all_at(&random(SLOT / 2), (newest * SLOT + SLOT / 4) as u64).unwrap();
        let h = open(&p, &clock, &keys, Persist::Day);
        assert_eq!(h.lines(A).iter().map(|l| l.text.to_string()).collect::<Vec<_>>(), vec!["first"], "the older, intact generation is used");
    }

    #[test]
    fn a_wrong_key_or_a_garbage_file_reads_as_empty_never_as_someone_elses_messages() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "secret"); h.tick().unwrap(); drop(h);
        let h = History::open(&p, SLOT, Zeroizing::new([1u8; 32]), keys.clone(), clock.clone(), Persist::Day).unwrap();
        assert!(h.is_empty(), "another key opens nothing");
        let q = d.path().join("junk.bin");
        fs::write(&q, random(2 * SLOT)).unwrap();
        assert!(open(&q, &clock, &keys, Persist::Day).is_empty());
        let short = d.path().join("short.bin"); fs::write(&short, [0u8; 100]).unwrap();
        assert!(matches!(History::open(&short, SLOT, fk(), keys.clone(), clock.clone(), Persist::Day), Err(StoreError::Corrupt)), "a file of the wrong size is refused");
    }

    #[test]
    fn expiry_removes_whole_buckets_destroys_the_epoch_key_and_scrubs_the_old_generation() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "old");
        h.tick().unwrap();
        let epoch0 = (((T0 / BUCKET_SECS) * BUCKET_SECS) / EPOCH_SECS) as u32;
        clock.advance(20 * 3600);               // still inside the day
        assert_eq!(h.sweep(), Swept::default(), "nothing expires early");
        clock.advance(11 * 3600);               // bucket end + 24 h has passed
        h.push(A, State::Received, None, "new");
        let s = h.sweep();
        assert_eq!(s.buckets, 1); assert!(s.epochs_erased.contains(&epoch0), "{s:?}");
        assert!(keys.keys.lock().unwrap().get(&epoch0).is_none(), "the epoch key is destroyed");
        h.tick().unwrap();
        assert_eq!(h.lines(A).iter().map(|l| l.text.to_string()).collect::<Vec<_>>(), vec!["new"]);
        // the previous generation (which still held the old bucket and its key) was overwritten in the same tick: only the new generation exists
        let active = h.active.unwrap();
        assert!(h.read_slot(1 - active).is_none(), "the other slot is random bytes now, not the old generation");
        assert!(h.read_slot(active).is_some());
    }

    #[test]
    fn an_old_copy_of_the_file_cannot_bring_back_a_bucket_whose_key_was_erased() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin"); let copy = d.path().join("copy.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "sensitive"); h.tick().unwrap();
        fs::copy(&p, &copy).unwrap();                       // a backup / flash remnant made BEFORE expiry
        clock.advance(2 * 86400);
        h.sweep(); h.tick().unwrap(); drop(h);
        // the attacker has the old copy AND the vault key (the password): the epoch key in the platform key store is gone
        let old = open(&copy, &clock, &keys, Persist::Day);
        assert!(old.is_empty(), "the bucket is unreadable without the erased platform key");
    }

    #[test]
    fn the_clock_cannot_extend_a_life_and_a_forward_jump_only_expires_sooner() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "m"); h.tick().unwrap();
        clock.advance(30 * 3600);
        clock.set_wall(T0 - 10 * 86400);                    // the wall clock is moved BACK a lot: the message must still expire
        let s = h.sweep();
        assert_eq!(s.buckets, 1, "moving the clock back did not keep the message");
        // after a restart the stored high-water mark keeps `now` from going back
        h.push(A, State::Received, None, "n"); h.tick().unwrap(); drop(h);
        let mut h = open(&p, &clock, &keys, Persist::Day);
        assert!(h.now() >= T0 + 30 * 3600, "now never goes below the stored high-water mark");
    }

    #[test]
    fn outbox_mode_keeps_only_unconfirmed_texts_and_forgets_them_when_confirmed() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Outbox);
        h.push(A, State::Received, None, "never kept");
        h.push(A, State::Delivered, Some([1; 8]), "never kept either");
        h.push(A, State::Queued, Some([2; 8]), "kept until confirmed");
        assert_eq!(h.len(), 1);
        assert!(h.set_state(A, [2; 8], State::Delivered));
        assert!(h.is_empty(), "confirmed: gone");
        assert!(h.sweep().buckets == 0, "outbox mode has no time-based expiry");
        let mut off = open(&d.path().join("off.bin"), &clock, &keys, Persist::Off);
        off.push(A, State::Queued, Some([3; 8]), "x");
        assert!(off.is_empty(), "off keeps nothing");
    }

    #[test]
    fn an_unconfirmed_text_that_expires_is_reported_so_the_engine_can_forget_it() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Queued, Some([4; 8]), "never delivered");
        clock.advance(40 * 3600);
        let s = h.sweep();
        assert_eq!(s.expired_queued, vec![(A, [4; 8])]);
        assert!(h.queued(A).is_empty());
    }

    #[test]
    fn caps_per_contact_and_in_total_drop_the_oldest_confirmed_lines_first() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Queued, Some([9; 8]), "unconfirmed oldest");
        for i in 0..(MAX_LINES_PER_CONTACT + 20) { h.push(A, State::Received, None, &format!("m{i}")); }
        assert_eq!(h.lines(A).len(), MAX_LINES_PER_CONTACT);
        assert!(h.has_queued(A, [9; 8]), "an unconfirmed text is the LAST to go");
        assert_eq!(h.lines(A).last().unwrap().text.as_str(), format!("m{}", MAX_LINES_PER_CONTACT + 19));
        // total capacity of a small slot: pushing far more than fits still writes a valid, bounded file
        for i in 0..400 { h.push(B, State::Received, None, &"z".repeat(500 + i % 50)); }
        h.tick().unwrap();
        drop(h);
        let h = open(&p, &clock, &keys, Persist::Day);
        assert!(h.len() > 0 && h.has_queued(A, [9; 8]));
        assert_eq!(fs::metadata(&p).unwrap().len(), 2 * SLOT as u64);
    }

    #[test]
    fn removing_a_contact_and_shredding_remove_their_messages() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().join("hist.bin");
        let (clock, keys) = (TestClock::new(T0), Arc::new(MemKeys::default()));
        let mut h = open(&p, &clock, &keys, Persist::Day);
        h.push(A, State::Received, None, "a"); h.push(B, State::Received, None, "b");
        h.remove_contact(A);
        assert!(h.lines(A).is_empty() && h.lines(B).len() == 1);
        h.tick().unwrap();
        h.shred().unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn hostile_message_blocks_are_refused() {
        // a bucket body with an unknown state, a zero length, trailing bytes, or an invalid UTF-8 text must not parse
        let good = { let mut m = vec![0u8, 1]; m.extend_from_slice(&A); m.push(0); m.extend_from_slice(&[0, 1]); m.push(b'x'); m };
        assert!(parse_msgs(&good).is_some());
        let mut bad = good.clone(); bad[10] = 0b110; assert!(parse_msgs(&bad).is_none(), "unknown state");
        let mut bad = good.clone(); bad[11] = 0; bad[12] = 0; assert!(parse_msgs(&bad).is_none(), "zero length");
        let mut bad = good.clone(); bad.push(0); assert!(parse_msgs(&bad).is_none(), "trailing data");
        let mut bad = good.clone(); *bad.last_mut().unwrap() = 0xff; assert!(parse_msgs(&bad).is_none(), "invalid UTF-8");
        assert!(parse_msgs(&good[..good.len() - 1]).is_none(), "truncated");
    }
}
