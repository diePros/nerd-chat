//! Tor control-port client (spec: control-spec). Strict reply parsing, no command injection
//! (every argument is validated), SAFECOOKIE authentication with server verification.
use super::TorError;
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use seburity_core::onion::{base32_encode, parse_onion_address, service_id};
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
    /// Text of every line (after `250-`, `250+`, `250 `), plus data-block lines.
    pub lines: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub methods: Vec<String>,
    pub cookie_file: Option<String>,
    pub version: Option<String>,
}

/// How we are willing to authenticate.
#[derive(Default)]
pub struct AuthPref {
    /// Password for HASHEDPASSWORD (only used if tor offers it and no cookie method works).
    pub password: Option<Zeroizing<String>>,
    /// Overrides the cookie path tor announces (e.g. a path we know is right).
    pub cookie_path: Option<PathBuf>,
}

pub struct Controller<S: Read + Write> {
    s: S,
    buf: Vec<u8>,
    pub authenticated: bool,
}

/// Reject anything that could smuggle a second command or control characters.
fn check_arg(a: &str) -> Result<(), TorError> {
    if a.is_empty() || a.len() > 4096 || a.bytes().any(|b| b < 0x20 || b == 0x7f || b >= 0x80) {
        return Err(TorError::Protocol("illegal characters in control command".into()));
    }
    Ok(())
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts { m.update(p); }
    m.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Read a cookie file of EXACTLY 32 bytes without following symlinks or blocking on FIFOs.
/// The path comes from the (possibly hostile) control peer, so the exact-size rule limits what it can make us hash.
pub fn read_cookie(path: &Path) -> Result<Zeroizing<Vec<u8>>, TorError> {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.is_absolute() { return Err(TorError::Auth("cookie path is not absolute".into())); }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        .map_err(|e| TorError::Auth(format!("cannot read cookie file {}: {e}", path.display())))?;
    let md = f.metadata()?;
    if !md.is_file() || md.len() != 32 { return Err(TorError::Auth("cookie file is not a regular 32-byte file".into())); }
    let mut v = Zeroizing::new(Vec::with_capacity(32));
    f.take(33).read_to_end(&mut v)?;
    if v.len() != 32 { return Err(TorError::Auth("cookie file has the wrong size".into())); }
    Ok(v)
}

fn unquote(s: &str) -> Option<String> {
    let s = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' { out.push(match it.next()? { 'n' => '\n', 't' => '\t', c @ ('\\' | '"') => c, _ => return None }); } else { out.push(c); }
    }
    Some(out)
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

impl<S: Read + Write> Controller<S> {
    pub fn new(s: S) -> Self { Self { s, buf: Vec::new(), authenticated: false } }
    pub fn into_inner(self) -> S { self.s }

    fn send(&mut self, line: &str) -> Result<(), TorError> {
        check_arg(line)?;
        self.s.write_all(line.as_bytes())?;
        self.s.write_all(b"\r\n")?;
        self.s.flush()?;
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, TorError> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..i + 2).take(i).collect();
                return String::from_utf8(line).map_err(|_| TorError::Protocol("non-UTF-8 reply".into()));
            }
            if self.buf.len() > MAX_LINE { return Err(TorError::Protocol("control reply line too long".into())); }
            let mut chunk = [0u8; 4096];
            let n = self.s.read(&mut chunk)?;
            if n == 0 { return Err(TorError::Io("control connection closed".into())); }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read one complete reply (handles `-`, `+` data blocks and the final ` ` line).
    pub fn read_reply(&mut self) -> Result<Reply, TorError> {
        let (mut code, mut lines, mut total) = (None, Vec::new(), 0usize);
        loop {
            let l = self.read_line()?;
            total += l.len();
            if l.len() < 4 || total > MAX_REPLY || lines.len() >= MAX_LINES { return Err(TorError::Protocol("malformed or oversized control reply".into())); }
            let c: u16 = l[..3].parse().map_err(|_| TorError::Protocol("bad reply code".into()))?;
            if l.as_bytes()[..3].iter().any(|b| !b.is_ascii_digit()) { return Err(TorError::Protocol("bad reply code".into())); }
            if *code.get_or_insert(c) != c { return Err(TorError::Protocol("mixed reply codes".into())); }
            let text = l[4..].to_string();
            match l.as_bytes()[3] {
                b'-' => lines.push(text),
                b' ' => { lines.push(text); return Ok(Reply { code: c, lines }); }
                b'+' => {
                    lines.push(text);
                    loop {
                        let d = self.read_line()?;
                        total += d.len();
                        if total > MAX_REPLY || lines.len() >= MAX_LINES { return Err(TorError::Protocol("oversized data block".into())); }
                        if d == "." { break; }
                        lines.push(d.strip_prefix('.').filter(|_| d.starts_with("..")).unwrap_or(&d).to_string());
                    }
                }
                _ => return Err(TorError::Protocol("bad reply separator".into())),
            }
        }
    }

    /// Send a command and return its reply; non-2xx becomes `Rejected`. Asynchronous 6xx events are skipped.
    pub fn command(&mut self, cmd: &str) -> Result<Reply, TorError> {
        self.send(cmd)?;
        self.expect_ok()
    }

    fn expect_ok(&mut self) -> Result<Reply, TorError> {
        for _ in 0..MAX_SKIPPED_EVENTS {
            let r = self.read_reply()?;
            if (600..700).contains(&r.code) { continue; }
            if (200..300).contains(&r.code) { return Ok(r); }
            return Err(TorError::Rejected { code: r.code, msg: r.lines.first().cloned().unwrap_or_default() });
        }
        Err(TorError::Protocol("too many asynchronous events".into()))
    }

    pub fn protocolinfo(&mut self) -> Result<ProtocolInfo, TorError> {
        let r = self.command("PROTOCOLINFO 1")?;
        Ok(parse_protocolinfo(&r))
    }

    /// Authenticate: NULL if offered, else SAFECOOKIE (verifying tor's proof), else HASHEDPASSWORD.
    pub fn authenticate(&mut self, pref: &AuthPref) -> Result<(), TorError> {
        let info = self.protocolinfo()?;
        let has = |m: &str| info.methods.iter().any(|x| x == m);
        if has("NULL") {
            self.command("AUTHENTICATE")?;
        } else if has("SAFECOOKIE") {
            let path = pref.cookie_path.clone().or_else(|| info.cookie_file.as_ref().map(PathBuf::from))
                .ok_or_else(|| TorError::Auth("tor announced no cookie file".into()))?;
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
            // Verify the SERVER knows the cookie before revealing that we do (stops a fake control port).
            let expect = hmac(b"Tor safe cookie authentication server-to-controller hash", &[&cookie, &cn, &sn]);
            if !ct_eq(&expect, &sh) { return Err(TorError::Auth("control port failed to prove it knows the cookie (is this really tor?)".into())); }
            let mine = hmac(b"Tor safe cookie authentication controller-to-server hash", &[&cookie, &cn, &sn]);
            self.command(&format!("AUTHENTICATE {}", hex(&mine)))?;
        } else if has("HASHEDPASSWORD") {
            let pw = pref.password.as_ref().ok_or_else(|| TorError::Auth("tor requires a control password; none configured".into()))?;
            let q = Zeroizing::new(format!("AUTHENTICATE \"{}\"", pw.replace('\\', "\\\\").replace('"', "\\\"")));
            self.command(&q)?;
        } else if has("COOKIE") {
            return Err(TorError::Auth("only legacy COOKIE auth offered; refusing (no server proof)".into()));
        } else {
            return Err(TorError::Auth(format!("no usable authentication method (offered: {})", info.methods.join(","))));
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

    /// SOCKS listeners the running tor offers (TCP only is returned; unix ones are listed separately).
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

    /// Host an onion service (v3, client authorization REQUIRED). The service lives only as long as
    /// this control connection (no `Detach`). `expected_id` is checked against tor's reply.
    pub fn add_onion(&mut self, expanded_key: &[u8; 64], virt_port: u16, target: SocketAddr, authorized: &[[u8; 32]], expected_pub: &[u8; 32]) -> Result<String, TorError> {
        if authorized.is_empty() { return Err(TorError::Other("refusing to host an onion service without client authorization".into())); }
        let mut cmd = Zeroizing::new(format!("ADD_ONION ED25519-V3:{} Flags=V3Auth Port={virt_port},{target}", STANDARD.encode(expanded_key)));
        for a in authorized { cmd.push_str(&format!(" ClientAuthV3={}", base32_encode(a, true))); }
        let r = self.command(&cmd)?;
        let id = r.lines.iter().find_map(|l| l.strip_prefix("ServiceID=")).ok_or_else(|| TorError::Protocol("no ServiceID in ADD_ONION reply".into()))?;
        if id != service_id(expected_pub) { return Err(TorError::Protocol("tor created a different onion address than expected".into())); }
        Ok(id.to_string())
    }

    pub fn del_onion(&mut self, id: &str) -> Result<(), TorError> {
        if parse_onion_address(id).is_err() { return Err(TorError::Protocol("bad onion id".into())); }
        self.command(&format!("DEL_ONION {id}")).map(|_| ())
    }

    /// Tell tor the private client-authorization key for a peer's onion service (kept in memory only).
    pub fn client_auth_add(&mut self, onion_id: &str, x25519_secret: &[u8; 32]) -> Result<(), TorError> {
        if parse_onion_address(onion_id).is_err() { return Err(TorError::Protocol("bad onion id".into())); }
        let cmd = Zeroizing::new(format!("ONION_CLIENT_AUTH_ADD {onion_id} x25519:{}", STANDARD.encode(x25519_secret)));
        self.command(&cmd).map(|_| ())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, thread};

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
        // overlong line
        let (mut c, h) = fake(vec![("X", format!("250 {}\r\n", "a".repeat(20_000)))]);
        assert!(c.command("X").is_err());
        let _ = h.join();
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
    fn protocolinfo_parsing() {
        let r = Reply { code: 250, lines: vec!["PROTOCOLINFO 1".into(), r#"AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE="/run/tor/control.authcookie""#.into(), r#"VERSION Tor="0.4.8.12""#.into(), "OK".into()] };
        let p = parse_protocolinfo(&r);
        assert_eq!(p.methods, vec!["COOKIE", "SAFECOOKIE", "HASHEDPASSWORD"]);
        assert_eq!(p.cookie_file.as_deref(), Some("/run/tor/control.authcookie"));
        assert_eq!(p.version.as_deref(), Some("0.4.8.12"));
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

    /// Fake tor that implements the SAFECOOKIE server side; `lie` makes it send a wrong server hash.
    fn safecookie_server(cookie: [u8; 32], cookie_path: String, lie: bool) -> (Controller<UnixStream>, thread::JoinHandle<()>) {
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || {
            let mut s = Controller::new(b);
            assert_eq!(s.read_line().unwrap(), "PROTOCOLINFO 1");
            s.s.write_all(protocolinfo_reply("COOKIE,SAFECOOKIE", &cookie_path).as_bytes()).unwrap();
            let l = s.read_line().unwrap();
            let cn = unhex(l.strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap()).unwrap();
            let sn = [0x33u8; 32];
            let mut sh = hmac(b"Tor safe cookie authentication server-to-controller hash", &[&cookie, &cn, &sn]);
            if lie { sh[0] ^= 1; }
            s.s.write_all(format!("250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n", hex(&sh), hex(&sn)).as_bytes()).unwrap();
            if lie { return; } // a correct client must hang up before sending AUTHENTICATE
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
        let (mut c, h) = safecookie_server(cookie, p.display().to_string(), false);
        c.authenticate(&AuthPref::default()).unwrap();
        assert!(c.authenticated);
        h.join().unwrap();
        let (mut c, h) = safecookie_server(cookie, p.display().to_string(), true);
        let e = c.authenticate(&AuthPref::default()).unwrap_err();
        assert!(matches!(e, TorError::Auth(ref m) if m.contains("prove")), "{e}");
        assert!(!c.authenticated);
        h.join().unwrap();
    }

    #[test]
    fn hostile_cookie_paths_are_refused() {
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
    fn null_and_password_auth_and_refusal_of_legacy_cookie() {
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("NULL", "/x")), ("AUTHENTICATE", "250 OK\r\n".into())]);
        c.authenticate(&AuthPref::default()).unwrap();
        h.join().unwrap();
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("HASHEDPASSWORD", "/x")), ("AUTHENTICATE \"pa\\\"ss\\\\w\"", "250 OK\r\n".into())]);
        c.authenticate(&AuthPref { password: Some(Zeroizing::new("pa\"ss\\w".into())), cookie_path: None }).unwrap();
        h.join().unwrap();
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("HASHEDPASSWORD", "/x"))]);
        assert!(c.authenticate(&AuthPref::default()).is_err());
        h.join().unwrap();
        let (mut c, h) = fake(vec![("PROTOCOLINFO", protocolinfo_reply("COOKIE", "/x"))]);
        assert!(matches!(c.authenticate(&AuthPref::default()), Err(TorError::Auth(_))), "legacy COOKIE gives no server proof");
        h.join().unwrap();
    }

    #[test]
    fn add_onion_exact_command_and_checks() {
        use seburity_core::identity::ContactIdentity;
        let id = ContactIdentity::generate();
        let peer_auth = [9u8; 32];
        let sid = service_id(&id.onion_public());
        let target: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let (mut c, h) = fake(vec![("ADD_ONION ED25519-V3:", format!("250-ServiceID={sid}\r\n250 OK\r\n"))]);
        let got = c.add_onion(&id.onion_expanded_secret(), 7345, target, &[peer_auth], &id.onion_public()).unwrap();
        assert_eq!(got, sid);
        let seen = h.join().unwrap();
        let line = &seen[0];
        assert!(line.contains(" Flags=V3Auth Port=7345,127.0.0.1:4242 ClientAuthV3="), "{line}");
        assert!(line.ends_with(&base32_encode(&peer_auth, true)));
        assert!(!line.contains("Detach"), "service must die with the control connection");
        // tor answering with a different id is an error; no authorized client is refused outright
        let (mut c, h) = fake(vec![("ADD_ONION", "250-ServiceID=aaaa\r\n250 OK\r\n".into())]);
        assert!(c.add_onion(&id.onion_expanded_secret(), 1, target, &[peer_auth], &id.onion_public()).is_err());
        h.join().unwrap();
        let (mut c, _h) = fake(vec![]);
        assert!(c.add_onion(&id.onion_expanded_secret(), 1, target, &[], &id.onion_public()).is_err());
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
