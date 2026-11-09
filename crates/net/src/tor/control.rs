//! Tor control-port client (spec: control-spec). Strict byte-level reply parsing, no command injection (every
//! argument is validated), SAFECOOKIE with server verification, and NO authentication to a peer whose identity
//! has not been verified (see `trust`).
use super::{trust, Target, TorError};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use nerd_chat_core::onion::{base32_encode, parse_onion_address, service_id};
use sha2::Sha256;
use std::{io::{Read, Write}, net::SocketAddr, path::{Path, PathBuf}};
use zeroize::Zeroizing;

const MAX_LINE: usize = 8192;
const MAX_LINES: usize = 256;
const MAX_REPLY: usize = 256 * 1024;
const MAX_SKIPPED_EVENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub methods: Vec<String>,
    pub cookie_file: Option<String>,
    pub version: Option<String>,
}

/// How we authenticate. `peer_verified` MUST be set by the caller only after checking who owns the control endpoint
/// (`trust::check_*`), or because WE created it (spawn mode), or on explicit user opt-in. Without it nothing is sent.
#[derive(Default)]
pub struct AuthPref {
    pub password: Option<Zeroizing<String>>,
    /// Explicit cookie path (user choice / spawn mode). Otherwise only the well-known system paths are accepted.
    pub cookie_path: Option<PathBuf>,
    pub peer_verified: bool,
}

pub struct Controller<S: Read + Write> {
    s: S,
    buf: Vec<u8>,
    pub authenticated: bool,
    /// Set after any I/O or protocol error: the stream may hold stale/partial replies, so it is never reused.
    broken: bool,
}

/// Replace control characters so peer-supplied text can never drive the user's terminal.
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).take(300).collect()
}

fn check_bytes(a: &[u8]) -> Result<(), TorError> {
    if a.is_empty() || a.len() > 8192 || a.iter().any(|&b| b < 0x20 || b == 0x7f || b >= 0x80) {
        return Err(TorError::Protocol("illegal characters in control command".into()));
    }
    Ok(())
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts { m.update(p); }
    m.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Read a cookie file of EXACTLY 32 bytes: regular file, no symlink at the last component, never blocks, never
/// becomes our controlling terminal. Which path is read is decided by `trust::cookie_path_allowed`, not by the peer.
pub fn read_cookie(path: &Path) -> Result<Zeroizing<Vec<u8>>, TorError> {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.is_absolute() { return Err(TorError::Auth("cookie path is not absolute".into())); }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY).open(path)
        .map_err(|e| TorError::Auth(format!("cannot read cookie file {}: {e}", path.display())))?;
    let md = f.metadata()?;
    if !md.is_file() || md.len() != 32 { return Err(TorError::Auth("cookie file is not a regular 32-byte file".into())); }
    let mut v = Zeroizing::new(Vec::with_capacity(32));
    f.take(33).read_to_end(&mut v)?;
    if v.len() != 32 { return Err(TorError::Auth("cookie file has the wrong size".into())); }
    Ok(v)
}

/// Tor's quoted strings: `\\`, `\"`, `\n`, `\r`, `\t` and 1-3 digit octal escapes (used for non-ASCII bytes).
fn unquote(s: &str) -> Option<String> {
    let s = s.strip_prefix('"')?.strip_suffix('"')?;
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        if b[i] != b'\\' { out.push(b[i]); i += 1; continue; }
        i += 1;
        match *b.get(i)? {
            b'n' => { out.push(b'\n'); i += 1; }
            b'r' => { out.push(b'\r'); i += 1; }
            b't' => { out.push(b'\t'); i += 1; }
            c @ (b'\\' | b'"') => { out.push(c); i += 1; }
            b'0'..=b'7' => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 3 && b.get(i).is_some_and(|c| (b'0'..=b'7').contains(c)) { v = v * 8 + (b[i] - b'0') as u32; i += 1; n += 1; }
                out.push(u8::try_from(v).ok()?);
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

pub fn parse_protocolinfo(r: &Reply) -> ProtocolInfo {
    let mut p = ProtocolInfo::default();
    for l in &r.lines {
        if let Some(rest) = l.strip_prefix("AUTH ") {
            for tok in split_args(rest) {
                if let Some(m) = tok.strip_prefix("METHODS=") { p.methods = m.split(',').map(str::to_string).collect(); }
                if let Some(c) = tok.strip_prefix("COOKIEFILE=") { p.cookie_file = unquote(c); }
            }
        } else if let Some(rest) = l.strip_prefix("VERSION ") {
            for tok in split_args(rest) { if let Some(v) = tok.strip_prefix("Tor=") { p.version = unquote(v).or_else(|| Some(v.to_string())); } }
        }
    }
    p
}

/// Split on spaces outside double quotes.
fn split_args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut q, mut esc) = (vec![], String::new(), false, false);
    for c in s.chars() {
        if esc { cur.push(c); esc = false; continue; }
        match c {
            '\\' if q => { cur.push(c); esc = true; }
            '"' => { q = !q; cur.push(c); }
            ' ' if !q => { if !cur.is_empty() { out.push(std::mem::take(&mut cur)); } }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}

fn secret_cmd(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum::<usize>() + 16));
    for p in parts { v.extend_from_slice(p); }
    v
}

/// base64 into a wiped buffer (no un-wiped String temporaries holding secrets).
fn b64_secret(key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(vec![0u8; key.len().div_ceil(3) * 4]);
    let n = STANDARD.encode_slice(key, &mut b[..]).expect("buffer sized exactly");
    b.truncate(n);
    b
}

impl Controller<Box<dyn super::Stream>> {
    /// How long `poll_event` waits for an event.
    pub fn set_poll_timeout(&mut self, d: std::time::Duration) -> std::io::Result<()> { self.s.set_timeout(Some(d)) }
}

impl<S: Read + Write> Controller<S> {
    pub fn new(s: S) -> Self { Self { s, buf: Vec::new(), authenticated: false, broken: false } }
    pub fn into_inner(self) -> S { self.s }
    /// True after any I/O or protocol error (the connection is never reused).
    pub fn is_broken(&self) -> bool { self.broken }

    fn fail<T>(&mut self, e: TorError) -> Result<T, TorError> { self.broken = true; Err(e) }

    fn send(&mut self, line: &[u8]) -> Result<(), TorError> {
        if self.broken { return Err(TorError::Io("control connection is in an unusable state after an earlier error".into())); }
        check_bytes(line)?; // argument errors do NOT poison the connection: nothing was sent
        let r = self.s.write_all(line).and_then(|_| self.s.write_all(b"\r\n")).and_then(|_| self.s.flush());
        match r { Ok(()) => Ok(()), Err(e) => self.fail(e.into()) }
    }

    fn read_line(&mut self) -> Result<String, TorError> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..i + 2).take(i).collect();
                // control characters (other than TAB) never occur in legitimate replies; refusing them here keeps
                // peer-supplied text from ever steering a terminal (R5-L1)
                if line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) { return self.fail(TorError::Protocol("control characters in reply".into())); }
                return match String::from_utf8(line) { Ok(s) => Ok(s), Err(_) => self.fail(TorError::Protocol("non-UTF-8 reply".into())) };
            }
            if self.buf.len() > MAX_LINE { return self.fail(TorError::Protocol("control reply line too long".into())); }
            let mut chunk = [0u8; 4096];
            match self.s.read(&mut chunk) {
                Ok(0) => return self.fail(TorError::Io("control connection closed".into())),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) => return self.fail(e.into()),
            }
        }
    }

    /// Read one complete reply (handles `-`, `+` data blocks and the final ` ` line).
    pub fn read_reply(&mut self) -> Result<Reply, TorError> {
        let (mut code, mut lines, mut total) = (None, Vec::new(), 0usize);
        loop {
            let l = self.read_line()?;
            total += l.len();
            let b = l.as_bytes();
            // byte-level checks BEFORE any str slicing (R5-M1: slicing at a non-char-boundary panics)
            if b.len() < 4 || total > MAX_REPLY || lines.len() >= MAX_LINES || !b[..3].iter().all(u8::is_ascii_digit) || !b[3].is_ascii() {
                return self.fail(TorError::Protocol("malformed or oversized control reply".into()));
            }
            let c = (b[0] - b'0') as u16 * 100 + (b[1] - b'0') as u16 * 10 + (b[2] - b'0') as u16;
            if *code.get_or_insert(c) != c { return self.fail(TorError::Protocol("mixed reply codes".into())); }
            let text = l[4..].to_string(); // safe: b[3] is ASCII so index 4 is a char boundary
            match b[3] {
                b'-' => lines.push(text),
                b' ' => { lines.push(text); return Ok(Reply { code: c, lines }); }
                b'+' => {
                    lines.push(text);
                    loop {
                        let d = self.read_line()?;
                        total += d.len();
                        if total > MAX_REPLY || lines.len() >= MAX_LINES { return self.fail(TorError::Protocol("oversized data block".into())); }
                        if d == "." { break; }
                        lines.push(if d.starts_with("..") { d[1..].to_string() } else { d });
                    }
                }
                _ => return self.fail(TorError::Protocol("bad reply separator".into())),
            }
        }
    }

    /// Send a command and return its reply; non-2xx becomes `Rejected`. Asynchronous 6xx events are skipped.
    pub fn command(&mut self, cmd: &str) -> Result<Reply, TorError> { self.command_bytes(cmd.as_bytes()) }

    pub fn command_bytes(&mut self, cmd: &[u8]) -> Result<Reply, TorError> {
        self.send(cmd)?;
        self.expect_ok()
    }

    fn expect_ok(&mut self) -> Result<Reply, TorError> {
        for _ in 0..MAX_SKIPPED_EVENTS {
            let r = self.read_reply()?;
            if (600..700).contains(&r.code) { continue; }
            if (200..300).contains(&r.code) { return Ok(r); }
            return Err(TorError::Rejected { code: r.code, msg: sanitize(r.lines.first().map_or("", |s| s.as_str())) });
        }
        self.fail(TorError::Protocol("too many asynchronous events".into()))
    }

    pub fn protocolinfo(&mut self) -> Result<ProtocolInfo, TorError> {
        let r = self.command("PROTOCOLINFO 1")?;
        Ok(parse_protocolinfo(&r))
    }

    /// PROTOCOLINFO + authenticate. (Tor allows PROTOCOLINFO only once before authentication.)
    pub fn authenticate(&mut self, pref: &AuthPref) -> Result<(), TorError> {
        let info = self.protocolinfo()?;
        self.authenticate_with(&info, pref)
    }

    /// Authenticate using an already fetched PROTOCOLINFO. Refuses unless the peer was verified (R5-H1/L10).
    pub fn authenticate_with(&mut self, info: &ProtocolInfo, pref: &AuthPref) -> Result<(), TorError> {
        if !pref.peer_verified {
            return Err(TorError::Auth("refusing to authenticate: the identity of the control port's owner was not verified (a local squatter could steal the onion secret keys). Use a unix socket owned by tor, spawn mode, or --tor-trust-control if you trust this machine's control port".into()));
        }
        let has = |m: &str| info.methods.iter().any(|x| x == m);
        if has("SAFECOOKIE") {
            let announced = info.cookie_file.as_ref().map(PathBuf::from);
            let path = match (&pref.cookie_path, &announced) {
                (Some(p), _) => p.clone(),
                (None, Some(a)) if trust::cookie_path_allowed(a, None) => a.clone(),
                (None, Some(a)) => return Err(TorError::Auth(format!("tor announced the cookie file {} which is not a known system location; pass --tor-cookie PATH if it is right", sanitize(&a.display().to_string())))),
                (None, None) => return Err(TorError::Auth("tor announced no cookie file".into())),
            };
            let cookie = read_cookie(&path)?;
            let mut cn = [0u8; 32];
            getrandom::fill(&mut cn).map_err(|_| TorError::Other("no OS randomness".into()))?;
            let r = self.command(&format!("AUTHCHALLENGE SAFECOOKIE {}", hex(&cn)))?;
            let line = r.lines.first().ok_or_else(|| TorError::Protocol("empty AUTHCHALLENGE reply".into()))?;
            let rest = line.strip_prefix("AUTHCHALLENGE ").ok_or_else(|| TorError::Protocol("unexpected AUTHCHALLENGE reply".into()))?;
            let (mut sh, mut sn) = (None, None);
            for tok in rest.split(' ') {
                if let Some(v) = tok.strip_prefix("SERVERHASH=") { sh = unhex(v); }
                if let Some(v) = tok.strip_prefix("SERVERNONCE=") { sn = unhex(v); }
            }
            let (sh, sn) = (sh.ok_or_else(|| TorError::Protocol("no SERVERHASH".into()))?, sn.ok_or_else(|| TorError::Protocol("no SERVERNONCE".into()))?);
            if sn.len() != 32 { return Err(TorError::Protocol("SERVERNONCE must be 32 bytes".into())); }
            // Verify the SERVER knows the cookie before revealing that we do.
            let expect = hmac(b"Tor safe cookie authentication server-to-controller hash", &[&cookie, &cn, &sn]);
            if !ct_eq(&expect, &sh) { self.broken = true; return Err(TorError::Auth("control port failed to prove it knows the cookie (is this really tor?)".into())); }
            let mine = hmac(b"Tor safe cookie authentication controller-to-server hash", &[&cookie, &cn, &sn]);
            self.command(&format!("AUTHENTICATE {}", hex(&mine)))?;
        } else if has("NULL") {
            self.command("AUTHENTICATE")?;
        } else if has("HASHEDPASSWORD") {
            let pw = pref.password.as_ref().ok_or_else(|| TorError::Auth("tor requires a control password; none configured".into()))?;
            let q = secret_cmd(&[b"AUTHENTICATE \"", pw.replace('\\', "\\\\").replace('"', "\\\"").as_bytes(), b"\""]);
            self.command_bytes(&q)?;
        } else if has("COOKIE") {
            return Err(TorError::Auth("only legacy COOKIE auth offered; refusing (no server proof)".into()));
        } else {
            return Err(TorError::Auth(format!("no usable authentication method (offered: {})", sanitize(&info.methods.join(",")))));
        }
        self.authenticated = true;
        Ok(())
    }

    pub fn get_info(&mut self, key: &str) -> Result<String, TorError> {
        if !key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'/' || b == b'-' || b == b'_') { return Err(TorError::Protocol("bad GETINFO key".into())); }
        let r = self.command(&format!("GETINFO {key}"))?;
        let first = r.lines.first().ok_or_else(|| TorError::Protocol("empty GETINFO".into()))?;
        let v = first.strip_prefix(&format!("{key}=")).ok_or_else(|| TorError::Protocol("unexpected GETINFO reply".into()))?;
        if r.lines.len() > 2 { Ok(r.lines[1..r.lines.len() - 1].join("\n")) } else { Ok(v.to_string()) }
    }

    pub fn socks_listeners(&mut self) -> Result<Vec<super::Addr>, TorError> {
        let v = self.get_info("net/listeners/socks")?;
        Ok(split_args(&v).iter().filter_map(|q| {
            let a = unquote(q).unwrap_or_else(|| q.clone());
            if let Some(p) = a.strip_prefix("unix:") { Some(super::Addr::Unix(PathBuf::from(p))) } else { a.parse::<SocketAddr>().ok().map(super::Addr::Tcp) }
        }).collect())
    }

    /// 0..=100
    pub fn bootstrap_progress(&mut self) -> Result<u8, TorError> {
        let v = self.get_info("status/bootstrap-phase")?;
        v.split(' ').find_map(|t| t.strip_prefix("PROGRESS=")).and_then(|p| p.parse().ok()).ok_or_else(|| TorError::Protocol("no bootstrap PROGRESS".into()))
    }

    /// Host an onion service (v3, client authorization REQUIRED). Dies with this control connection (no `Detach`).
    /// First tries with proof-of-work defence and a stream cap; older tors that reject those get the plain form.
    pub fn add_onion(&mut self, expanded_key: &[u8; 64], virt_port: u16, target: &Target, authorized: &[[u8; 32]], expected_pub: &[u8; 32]) -> Result<String, TorError> {
        if authorized.is_empty() { return Err(TorError::Other("refusing to host an onion service without client authorization".into())); }
        let key = b64_secret(expanded_key);
        let build = |hardened: bool| {
            let mut v = secret_cmd(&[b"ADD_ONION ED25519-V3:", &key, b" Flags=V3Auth"]);
            if hardened { v.extend_from_slice(b" MaxStreams=16 PoWDefensesEnabled=1"); }
            v.extend_from_slice(format!(" Port={virt_port},{}", target.arg().unwrap_or_default()).as_bytes());
            for a in authorized { v.extend_from_slice(format!(" ClientAuthV3={}", base32_encode(a, true)).as_bytes()); }
            v
        };
        target.arg()?; // validate once, up front
        let r = match self.command_bytes(&build(true)) {
            Err(TorError::Rejected { code, .. }) if (500..600).contains(&code) => self.command_bytes(&build(false))?,
            other => other?,
        };
        let id = r.lines.iter().find_map(|l| l.strip_prefix("ServiceID=")).ok_or_else(|| TorError::Protocol("no ServiceID in ADD_ONION reply".into()))?;
        if id != service_id(expected_pub) { return Err(TorError::Protocol("tor created a different onion address than expected".into())); }
        Ok(id.to_string())
    }

    /// Host the ONE-SHOT PAIRING service (docs/superpowers/specs/2026-11-09-tor-pairing-spec.md): a v3 onion service WITHOUT client
    /// authorization (the joiner has no key yet; the pairing code, proven by SPAKE2, is the secret). A separate method on purpose:
    /// `add_onion` keeps refusing an empty authorization list, so "no auth" can never be reached by accident. `DiscardPK`: this
    /// process never sees the key. Never `Detach` (the service dies with this control connection), never `NonAnonymous`. One stream
    /// at a time. Returns the validated service id.
    pub fn add_public_ephemeral_onion(&mut self, virt_port: u16, target: &Target) -> Result<String, TorError> {
        let tgt = target.arg()?;
        let build = |pow: bool| format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,MaxStreamsCloseCircuit MaxStreams=1{} Port={virt_port},{tgt}", if pow { " PoWDefensesEnabled=1" } else { "" });
        let r = match self.command(&build(true)) {
            Err(TorError::Rejected { code, .. }) if (500..600).contains(&code) && code != 510 => self.command(&build(false))?,
            other => other?,
        };
        let id = r.lines.iter().find_map(|l| l.strip_prefix("ServiceID=")).ok_or_else(|| TorError::Protocol("no ServiceID in ADD_ONION reply".into()))?;
        parse_onion_address(id).map_err(|_| TorError::Protocol("tor returned an invalid service id".into()))?;
        Ok(id.to_string())
    }

    /// Ask tor for asynchronous events (`HS_DESC`, `CIRC`...). They are read with `poll_event`.
    pub fn set_events(&mut self, events: &[&str]) -> Result<(), TorError> {
        if events.iter().any(|e| !e.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')) { return Err(TorError::Other("bad event name".into())); }
        self.command(&format!("SETEVENTS {}", events.join(" "))).map(|_| ())
    }

    /// Wait up to the stream's read timeout for one asynchronous (6xx) event; `Ok(None)` = nothing arrived. Anything that is not an
    /// event is a protocol error. A timeout while NOTHING was buffered does not poison the connection.
    pub fn poll_event(&mut self) -> Result<Option<Vec<String>>, TorError> {
        if self.broken { return Err(TorError::Io("control connection is in an unusable state after an earlier error".into())); }
        if self.buf.is_empty() {
            let mut chunk = [0u8; 4096];
            match self.s.read(&mut chunk) {
                Ok(0) => return self.fail(TorError::Io("control connection closed".into())),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(None),
                Err(e) => return self.fail(e.into()),
            }
        }
        let r = self.read_reply()?;
        if (600..700).contains(&r.code) { Ok(Some(r.lines)) } else { self.fail(TorError::Protocol(format!("unexpected reply {} while waiting for an event", r.code))) }
    }

    pub fn del_onion(&mut self, id: &str) -> Result<(), TorError> {
        if parse_onion_address(id).is_err() { return Err(TorError::Protocol("bad onion id".into())); }
        self.command(&format!("DEL_ONION {id}")).map(|_| ())
    }

    /// Remove a client-authorization credential from tor (R6-M3: it must not outlive the contact/session).
    pub fn client_auth_remove(&mut self, onion_id: &str) -> Result<(), TorError> {
        if parse_onion_address(onion_id).is_err() { return Err(TorError::Protocol("bad onion id".into())); }
        self.command(&format!("ONION_CLIENT_AUTH_REMOVE {onion_id}")).map(|_| ())
    }

    /// Give tor our private client-authorization key for a peer's onion service (kept in memory only).
    pub fn client_auth_add(&mut self, onion_id: &str, x25519_secret: &[u8; 32]) -> Result<(), TorError> {
        if parse_onion_address(onion_id).is_err() { return Err(TorError::Protocol("bad onion id".into())); }
        let k = b64_secret(x25519_secret);
        let cmd = secret_cmd(&[b"ONION_CLIENT_AUTH_ADD ", onion_id.as_bytes(), b" x25519:", &k]);
        self.command_bytes(&cmd).map(|_| ())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, thread};

    pub fn verified() -> AuthPref { AuthPref { peer_verified: true, ..Default::default() } }

    /// Scripted fake tor: reads one command line at a time and answers with the next canned reply.
    pub fn fake(script: Vec<(&'static str, String)>) -> (Controller<UnixStream>, thread::JoinHandle<Vec<String>>) {
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || {
            let mut seen = vec![];
            let mut c = Controller::new(b);
            for (expect_prefix, reply) in script {
                let line = c.read_line().unwrap();
                assert!(line.starts_with(expect_prefix), "got {line:?}, wanted prefix {expect_prefix:?}");
                seen.push(line);
                c.s.write_all(reply.as_bytes()).unwrap();
            }
            seen
        });
        (Controller::new(a), h)
    }

    #[test]
    fn reply_parsing_multiline_data_and_events() {
        let (mut c, h) = fake(vec![("GETINFO", "650 BW 1 2\r\n250+net/x=\r\nline1\r\n..dotted\r\n.\r\n250 OK\r\n".into())]);
        let r = c.command("GETINFO net/x").unwrap();
        assert_eq!(r.lines, vec!["net/x=", "line1", ".dotted", "OK"]);
        h.join().unwrap();
    }

    #[test]
    fn rejects_malformed_replies_and_nonzero_codes() {
        for bad in ["25\r\n", "abc OK\r\n", "250-a\r\n251 b\r\n", "250?x\r\n"] {
            let (mut c, h) = fake(vec![("X", bad.into())]);
            assert!(matches!(c.command("X"), Err(TorError::Protocol(_))), "{bad:?}");
            h.join().unwrap();
        }
        let (mut c, h) = fake(vec![("X", "515 Authentication failed\r\n".into())]);
        assert!(matches!(c.command("X"), Err(TorError::Rejected { code: 515, .. })));
        h.join().unwrap();
        let (mut c, h) = fake(vec![("X", format!("250 {}\r\n", "a".repeat(20_000)))]);
        assert!(c.command("X").is_err());
        let _ = h.join();
    }

    /// R5-M1: peer-controlled non-ASCII in the first 4 bytes used to panic (and panic=abort kills the app).
    #[test]
    fn non_ascii_replies_never_panic() {
        for bad in ["ab€x\r\n", "250€\r\n", "€€€€\r\n", "2€0 x\r\n", "25€ x\r\n", "250\u{0301}x\r\n"] {
            let (mut c, h) = fake(vec![("X", bad.into())]);
            assert!(matches!(c.command("X"), Err(TorError::Protocol(_))), "{bad:?}");
            h.join().unwrap();
        }
    }

    /// R5-L1: escape sequences from a fake control port must never reach the terminal.
    #[test]
    fn control_characters_in_replies_are_rejected_and_displayed_text_sanitized() {
        let (mut c, h) = fake(vec![("X", "250 \x1b]0;pwned\x07 OK\r\n".into())]);
        assert!(matches!(c.command("X"), Err(TorError::Protocol(_))));
        h.join().unwrap();
        assert_eq!(sanitize("a\x1b[2Jb\x07"), "a?[2Jb?");
        assert!(sanitize(&"x".repeat(1000)).len() <= 300);
    }

    /// R5-L5: after an error the stream may hold stale data; it must not be reused.
    #[test]
    fn controller_is_poisoned_after_an_io_error() {
        let (a, mut b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(std::time::Duration::from_millis(100))).unwrap();
        let mut c = Controller::new(a);
        b.write_all(b"250-partial").unwrap(); // no CRLF: the reply never completes
        assert!(c.command("X").is_err());
        b.write_all(b"\r\n250 OK\r\n").unwrap(); // the late tail of the OLD reply arrives
        let e = c.command("Y").unwrap_err();
        assert!(matches!(e, TorError::Io(ref m) if m.contains("unusable")), "{e}");
        // but a rejected argument (nothing sent) does not poison
        let (a, _b) = UnixStream::pair().unwrap();
        let mut c = Controller::new(a);
        assert!(c.command("A\nB").is_err());
        assert!(!c.broken);
    }

    #[test]
    fn command_injection_is_impossible() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut c = Controller::new(a);
        for bad in ["GETINFO x\r\nSIGNAL SHUTDOWN", "A\nB", "A\0B", "ÄÖ", ""] { assert!(c.command(bad).is_err(), "{bad:?}"); }
        assert!(c.get_info("net/x\r\nQUIT").is_err());
        assert!(c.del_onion("nonsense").is_err());
        assert!(c.client_auth_add("x\r\nQUIT", &[0; 32]).is_err());
    }

    #[test]
    fn protocolinfo_parsing_and_octal_escapes() {
        let r = Reply { code: 250, lines: vec!["PROTOCOLINFO 1".into(), r#"AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE="/run/tor/control.authcookie""#.into(), r#"VERSION Tor="0.4.8.12""#.into(), "OK".into()] };
        let p = parse_protocolinfo(&r);
        assert_eq!(p.methods, vec!["COOKIE", "SAFECOOKIE", "HASHEDPASSWORD"]);
        assert_eq!(p.cookie_file.as_deref(), Some("/run/tor/control.authcookie"));
        assert_eq!(p.version.as_deref(), Some("0.4.8.12"));
        // R5-L9: tor escapes non-ASCII bytes as octal, \r and \n are used too
        assert_eq!(unquote(r#""/home/j\303\274rgen/c""#).as_deref(), Some("/home/jürgen/c"));
        assert_eq!(unquote(r#""a\r\nb""#).as_deref(), Some("a\r\nb"));
        assert_eq!(unquote(r#""bad\q""#), None);
        assert_eq!(unquote(r#""\777""#), None, "octal above 0xff");
    }

    fn protocolinfo_reply(methods: &str, cookie: &str) -> String {
        format!("250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods} COOKIEFILE=\"{cookie}\"\r\n250-VERSION Tor=\"0.4.8.12\"\r\n250 OK\r\n")
    }

    fn cookie_file(dir: &Path) -> (PathBuf, [u8; 32]) {
        let cookie = [0x5au8; 32];
        let p = dir.join("cookie");
        std::fs::write(&p, cookie).unwrap();
        (p, cookie)
    }

    /// Fake tor implementing the SAFECOOKIE server side; `lie` sends a wrong server hash. Refuses a SECOND PROTOCOLINFO
    /// like the real tor does (R5-M3).
    fn safecookie_server(cookie: [u8; 32], cookie_path: String, lie: bool) -> (Controller<UnixStream>, thread::JoinHandle<()>) {
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || {
            let mut s = Controller::new(b);
            assert_eq!(s.read_line().unwrap(), "PROTOCOLINFO 1");
            s.s.write_all(protocolinfo_reply("COOKIE,SAFECOOKIE", &cookie_path).as_bytes()).unwrap();
            let l = s.read_line().unwrap();
            if l.starts_with("PROTOCOLINFO") { s.s.write_all(b"514 Authentication required.\r\n").unwrap(); return; }
            let cn = unhex(l.strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap()).unwrap();
            let sn = [0x33u8; 32];
            let mut sh = hmac(b"Tor safe cookie authentication server-to-controller hash", &[&cookie, &cn, &sn]);
            if lie { sh[0] ^= 1; }
            s.s.write_all(format!("250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n", hex(&sh), hex(&sn)).as_bytes()).unwrap();
            if lie { return; }
            let l = s.read_line().unwrap();
            let want = hmac(b"Tor safe cookie authentication controller-to-server hash", &[&cookie, &cn, &sn]);
            assert_eq!(l, format!("AUTHENTICATE {}", hex(&want)));
            s.s.write_all(b"250 OK\r\n").unwrap();
        });
        (Controller::new(a), h)
    }

    #[test]
    fn safecookie_succeeds_and_rejects_a_lying_control_port() {
        let d = tempfile::tempdir().unwrap();
        let (p, cookie) = cookie_file(d.path());
        let pref = AuthPref { cookie_path: Some(p.clone()), peer_verified: true, ..Default::default() };
        let (mut c, h) = safecookie_server(cookie, p.display().to_string(), false);
        c.authenticate(&pref).unwrap();
        assert!(c.authenticated);
        h.join().unwrap();
        let (mut c, h) = safecookie_server(cookie, p.display().to_string(), true);
        let e = c.authenticate(&pref).unwrap_err();
        assert!(matches!(e, TorError::Auth(ref m) if m.contains("prove")), "{e}");
        assert!(!c.authenticated);
        h.join().unwrap();
    }

    /// R5-M3: probing fetches PROTOCOLINFO itself and must reuse it (tor refuses a second one).
    #[test]
    fn authenticate_with_does_not_send_a_second_protocolinfo() {
        let d = tempfile::tempdir().unwrap();
        let (p, cookie) = cookie_file(d.path());
        let pref = AuthPref { cookie_path: Some(p.clone()), peer_verified: true, ..Default::default() };
        let (mut c, h) = safecookie_server(cookie, p.display().to_string(), false);
        let info = c.protocolinfo().unwrap();
        c.authenticate_with(&info, &pref).unwrap();
        h.join().unwrap();
        // the old double-PROTOCOLINFO path is refused by the strict server
        let (mut c, h) = safecookie_server(cookie, p.display().to_string(), false);
        let _ = c.protocolinfo().unwrap();
        assert!(c.authenticate(&pref).is_err());
        h.join().unwrap();
    }

    /// R5-H1: nothing may be sent to an unverified control endpoint; NULL/password need verification too.
    #[test]
    fn unverified_peers_get_no_authentication_and_no_secrets() {
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || { let mut s = Controller::new(b); let _ = s.read_line(); s.s.write_all(protocolinfo_reply("NULL", "/x").as_bytes()).unwrap(); s.s.set_read_timeout(Some(std::time::Duration::from_millis(300))).unwrap(); s.read_line().is_err() });
        let mut c = Controller::new(a);
        let e = c.authenticate(&AuthPref::default()).unwrap_err();
        assert!(matches!(e, TorError::Auth(ref m) if m.contains("not verified")), "{e}");
        assert!(!c.authenticated);
        assert!(h.join().unwrap(), "nothing (no AUTHENTICATE, no ADD_ONION) may follow the PROTOCOLINFO exchange");
    }

    #[test]
    fn cookie_path_announced_by_the_peer_must_be_a_known_location() {
        // a hostile port announces a path to some private 32-byte file: must be refused, never opened
        let d = tempfile::tempdir().unwrap();
        let (p, _) = cookie_file(d.path());
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("SAFECOOKIE", &p.display().to_string()))]);
        let e = c.authenticate(&verified()).unwrap_err();
        assert!(matches!(e, TorError::Auth(ref m) if m.contains("not a known system location")), "{e}");
        h.join().unwrap();
    }

    #[test]
    fn hostile_cookie_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_cookie(Path::new("relative/cookie")).is_err());
        std::fs::write(d.path().join("big"), [0u8; 64]).unwrap();
        assert!(read_cookie(&d.path().join("big")).is_err(), "must be exactly 32 bytes");
        std::os::unix::fs::symlink(d.path().join("big"), d.path().join("l")).unwrap();
        assert!(read_cookie(&d.path().join("l")).is_err(), "no symlinks");
        assert!(read_cookie(Path::new("/dev/zero")).is_err());
        assert!(read_cookie(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn null_and_password_auth_with_verified_peer_and_refusal_of_legacy_cookie() {
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("NULL", "/x")), ("AUTHENTICATE", "250 OK\r\n".into())]);
        c.authenticate(&verified()).unwrap();
        h.join().unwrap();
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("HASHEDPASSWORD", "/x")), ("AUTHENTICATE \"pa\\\"ss\\\\w\"", "250 OK\r\n".into())]);
        c.authenticate(&AuthPref { password: Some(Zeroizing::new("pa\"ss\\w".into())), peer_verified: true, ..Default::default() }).unwrap();
        h.join().unwrap();
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("HASHEDPASSWORD", "/x"))]);
        assert!(c.authenticate(&verified()).is_err());
        h.join().unwrap();
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("COOKIE", "/x"))]);
        assert!(matches!(c.authenticate(&verified()), Err(TorError::Auth(_))), "legacy COOKIE gives no server proof");
        h.join().unwrap();
    }

    #[test]
    fn add_onion_exact_command_checks_and_pow_fallback() {
        use nerd_chat_core::identity::ContactIdentity;
        let id = ContactIdentity::generate();
        let peer_auth = [9u8; 32];
        let sid = service_id(&id.onion_public());
        let target = Target::Tcp("127.0.0.1:4242".parse().unwrap());
        let (mut c, h) = fake(vec![("ADD_ONION ED25519-V3:", format!("250-ServiceID={sid}\r\n250 OK\r\n"))]);
        assert_eq!(c.add_onion(&id.onion_expanded_secret(), 7345, &target, &[peer_auth], &id.onion_public()).unwrap(), sid);
        let line = h.join().unwrap().remove(0);
        assert!(line.contains(" Flags=V3Auth MaxStreams=16 PoWDefensesEnabled=1 Port=7345,127.0.0.1:4242 ClientAuthV3="), "{line}");
        assert!(line.ends_with(&base32_encode(&peer_auth, true)));
        assert!(!line.contains("Detach"), "service must die with the control connection");
        // an older tor rejects the PoW options: we retry once WITHOUT them
        let (mut c, h) = fake(vec![("ADD_ONION", "512 Unrecognized option\r\n".into()), ("ADD_ONION", format!("250-ServiceID={sid}\r\n250 OK\r\n"))]);
        c.add_onion(&id.onion_expanded_secret(), 7345, &target, &[peer_auth], &id.onion_public()).unwrap();
        let seen = h.join().unwrap();
        assert!(seen[0].contains("PoWDefensesEnabled") && !seen[1].contains("PoWDefensesEnabled") && seen[1].contains("Flags=V3Auth"));
        // unix target
        let (mut c, h) = fake(vec![("ADD_ONION", format!("250-ServiceID={sid}\r\n250 OK\r\n"))]);
        c.add_onion(&id.onion_expanded_secret(), 1, &Target::Unix("/dev/shm/nerd-chat-ab/app.sock".into()), &[peer_auth], &id.onion_public()).unwrap();
        assert!(h.join().unwrap()[0].contains("Port=1,unix:/dev/shm/nerd-chat-ab/app.sock"));
        // wrong id from tor, no auth clients, unsafe unix path: all refused
        let (mut c, h) = fake(vec![("ADD_ONION", "250-ServiceID=aaaa\r\n250 OK\r\n".into())]);
        assert!(c.add_onion(&id.onion_expanded_secret(), 1, &target, &[peer_auth], &id.onion_public()).is_err());
        h.join().unwrap();
        let (mut c, _h) = fake(vec![]);
        assert!(c.add_onion(&id.onion_expanded_secret(), 1, &target, &[], &id.onion_public()).is_err());
        for bad in ["relative/p", "/a b", "/a\"b", "/a\nb"] {
            assert!(c.add_onion(&id.onion_expanded_secret(), 1, &Target::Unix(bad.into()), &[peer_auth], &id.onion_public()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn client_auth_remove_command_and_validation() {
        let pk = [5u8; 32];
        let id = service_id(&pk);
        let (mut c, h) = fake(vec![("ONION_CLIENT_AUTH_REMOVE ", "250 OK\r\n".into())]);
        c.client_auth_remove(&id).unwrap();
        assert_eq!(h.join().unwrap()[0], format!("ONION_CLIENT_AUTH_REMOVE {id}"));
        let (mut c, _h) = fake(vec![]);
        assert!(c.client_auth_remove("nonsense").is_err() && c.client_auth_remove("x\r\nQUIT").is_err());
    }

    #[test]
    fn socks_listener_and_bootstrap_parsing() {
        let (mut c, h) = fake(vec![
            ("GETINFO net/listeners/socks", "250-net/listeners/socks=\"127.0.0.1:9050\" \"unix:/run/tor/socks\" \"[::1]:9150\"\r\n250 OK\r\n".into()),
            ("GETINFO status/bootstrap-phase", "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=85 TAG=ap_conn SUMMARY=\"x\"\r\n250 OK\r\n".into()),
        ]);
        let l = c.socks_listeners().unwrap();
        assert_eq!(l.len(), 3);
        assert_eq!(l[0], super::super::Addr::Tcp("127.0.0.1:9050".parse().unwrap()));
        assert_eq!(l[1], super::super::Addr::Unix("/run/tor/socks".into()));
        assert_eq!(c.bootstrap_progress().unwrap(), 85);
        h.join().unwrap();
    }
}
