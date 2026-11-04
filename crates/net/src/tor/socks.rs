//! Minimal strict SOCKS5 client (RFC 1928 / 1929) with Tor's extended error codes.
//! Hostnames (incl. .onion) are passed to tor UNRESOLVED (ATYP 3): we never resolve anything locally.
//! Username/password are used only for tor's stream isolation (different creds => different circuits).
use std::io::{Read, Write};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(String),
    #[error("malformed SOCKS reply")]
    Malformed,
    #[error("proxy rejected authentication")]
    AuthRejected,
    #[error("invalid argument")]
    BadArg,
    #[error("onion service not found / descriptor unavailable (peer offline?)")]
    OnionNotFound,
    #[error("onion service rejected our client authorization key (peer has not authorized this contact, or keys mismatch)")]
    ClientAuth,
    #[error("could not reach the onion service (introduction/rendezvous failed or timed out)")]
    OnionUnreachable,
    #[error("connection refused by the target")]
    Refused,
    #[error("SOCKS error code {0}")]
    Other(u8),
}

fn io<E: std::fmt::Display>(e: E) -> SocksError { SocksError::Io(e.to_string()) }

fn rd<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>, SocksError> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).map_err(io)?;
    Ok(v)
}

pub fn connect<S: Read + Write>(s: &mut S, host: &str, port: u16, creds: Option<(&[u8], &[u8])>) -> Result<(), SocksError> {
    if host.is_empty() || host.len() > 255 || host.bytes().any(|b| b < 0x21 || b > 0x7e) { return Err(SocksError::BadArg); }
    if let Some((u, p)) = creds { if u.is_empty() || u.len() > 255 || p.is_empty() || p.len() > 255 { return Err(SocksError::BadArg); } }

    // greeting: offer exactly one method
    let method = if creds.is_some() { 0x02 } else { 0x00 };
    s.write_all(&[5, 1, method]).map_err(io)?;
    let r = rd(s, 2)?;
    if r[0] != 5 || r[1] != method { return Err(SocksError::Malformed); }
    if let Some((u, p)) = creds {
        let mut m = vec![1, u.len() as u8];
        m.extend_from_slice(u);
        m.push(p.len() as u8);
        m.extend_from_slice(p);
        s.write_all(&m).map_err(io)?;
        let r = rd(s, 2)?;
        if r[0] != 1 { return Err(SocksError::Malformed); }
        if r[1] != 0 { return Err(SocksError::AuthRejected); }
    }

    // CONNECT with a domain-name address
    let mut m = vec![5, 1, 0, 3, host.len() as u8];
    m.extend_from_slice(host.as_bytes());
    m.extend_from_slice(&port.to_be_bytes());
    s.write_all(&m).map_err(io)?;
    s.flush().map_err(io)?;

    let h = rd(s, 4)?;
    if h[0] != 5 || h[2] != 0 { return Err(SocksError::Malformed); }
    match h[1] {
        0x00 => {}
        0x04 | 0xF0 | 0xF1 => return Err(SocksError::OnionNotFound),
        0xF4 | 0xF5 => return Err(SocksError::ClientAuth),
        0xF2 | 0xF3 | 0xF7 | 0x06 => return Err(SocksError::OnionUnreachable),
        0x05 => return Err(SocksError::Refused),
        c => return Err(SocksError::Other(c)),
    }
    // consume the bound address so the stream is positioned at the start of application data
    let skip = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => rd(s, 1)?[0] as usize + 2,
        _ => return Err(SocksError::Malformed),
    };
    rd(s, skip)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, thread};

    /// Fake proxy: checks the client bytes against `expect` pieces and answers with `replies`.
    fn proxy(steps: Vec<(usize, Vec<u8>)>) -> (UnixStream, thread::JoinHandle<Vec<Vec<u8>>>) {
        let (a, mut b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || {
            let mut got = vec![];
            for (n, reply) in steps {
                let mut v = vec![0u8; n];
                if b.read_exact(&mut v).is_err() { break; }
                got.push(v);
                b.write_all(&reply).unwrap();
            }
            got
        });
        (a, h)
    }

    #[test]
    fn connect_with_isolation_creds_to_an_onion() {
        let host = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
        let (mut s, h) = proxy(vec![
            (3, vec![5, 2]),
            (1 + 1 + 4 + 1 + 4, vec![1, 0]),
            (4 + 1 + host.len() + 2, vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        ]);
        connect(&mut s, host, 7345, Some((b"user", b"pass"))).unwrap();
        let got = h.join().unwrap();
        assert_eq!(got[0], vec![5, 1, 2]);
        assert_eq!(&got[1], &[&[1u8, 4][..], b"user", &[4], b"pass"].concat());
        assert_eq!(&got[2][..5], &[5, 1, 0, 3, host.len() as u8]);
        assert_eq!(&got[2][5..5 + host.len()], host.as_bytes(), "hostname sent unresolved");
        assert_eq!(&got[2][5 + host.len()..], &7345u16.to_be_bytes());
    }

    fn fail_with(code: u8) -> Result<(), SocksError> {
        let (mut s, h) = proxy(vec![(3, vec![5, 0]), (4 + 1 + 3 + 2, vec![5, code, 0, 1, 0, 0, 0, 0, 0, 0])]);
        let r = connect(&mut s, "a.b", 1, None);
        let _ = h.join();
        r
    }

    #[test]
    fn tor_extended_error_codes_are_mapped() {
        assert_eq!(fail_with(0xF0), Err(SocksError::OnionNotFound));
        assert_eq!(fail_with(0xF4), Err(SocksError::ClientAuth));
        assert_eq!(fail_with(0xF5), Err(SocksError::ClientAuth));
        assert_eq!(fail_with(0xF2), Err(SocksError::OnionUnreachable));
        assert_eq!(fail_with(0xF7), Err(SocksError::OnionUnreachable));
        assert_eq!(fail_with(0x05), Err(SocksError::Refused));
        assert_eq!(fail_with(0x77), Err(SocksError::Other(0x77)));
    }

    #[test]
    fn malformed_and_rejected_replies() {
        let (mut s, h) = proxy(vec![(3, vec![4, 0])]);
        assert_eq!(connect(&mut s, "a.b", 1, None), Err(SocksError::Malformed));
        let _ = h.join();
        let (mut s, h) = proxy(vec![(3, vec![5, 0xff])]);
        assert_eq!(connect(&mut s, "a.b", 1, None), Err(SocksError::Malformed), "no acceptable method");
        let _ = h.join();
        let (mut s, h) = proxy(vec![(3, vec![5, 2]), (1 + 1 + 1 + 1 + 1, vec![1, 1])]);
        assert_eq!(connect(&mut s, "a.b", 1, Some((b"u", b"p"))), Err(SocksError::AuthRejected));
        let _ = h.join();
        let (mut s, h) = proxy(vec![(3, vec![5, 0]), (4 + 1 + 3 + 2, vec![5, 0, 1, 1])]);
        assert_eq!(connect(&mut s, "a.b", 1, None), Err(SocksError::Malformed), "RSV must be 0");
        let _ = h.join();
        let (mut s, h) = proxy(vec![(3, vec![5, 0]), (4 + 1 + 3 + 2, vec![5, 0, 0, 9])]);
        assert_eq!(connect(&mut s, "a.b", 1, None), Err(SocksError::Malformed), "unknown ATYP");
        let _ = h.join();
    }

    #[test]
    fn argument_validation_and_truncation() {
        let (mut s, _h) = proxy(vec![]);
        for bad in ["", "a b", "a\r\nb", &"x".repeat(256)] { assert_eq!(connect(&mut s, bad, 1, None), Err(SocksError::BadArg), "{bad:?}"); }
        assert_eq!(connect(&mut s, "a.b", 1, Some((b"", b"p"))), Err(SocksError::BadArg));
        assert_eq!(connect(&mut s, "a.b", 1, Some((&[b'u'; 256], b"p"))), Err(SocksError::BadArg));
        let (mut s, h) = proxy(vec![(3, vec![5])]); // proxy hangs up mid-reply
        assert!(matches!(connect(&mut s, "a.b", 1, None), Err(SocksError::Io(_))));
        let _ = h.join();
    }
}
