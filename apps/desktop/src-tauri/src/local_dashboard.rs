//! Transfer an authenticated local session to the browser without putting it in a URL.
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

pub struct Handoff {
    listener: TcpListener,
    session: String,
    nonce: String,
    dashboard_port: u16,
}

impl Handoff {
    pub fn new(session: &str, nonce: &str, dashboard_port: u16) -> io::Result<Self> {
        let safe = |value: &str| value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
        if session.len() != 48 || !session.starts_with("oass_") || !safe(session)
            || nonce.len() != 43 || !safe(nonce) || dashboard_port == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid dashboard handoff"));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, session: session.into(), nonce: nonce.into(), dashboard_port })
    }

    pub fn url(&self) -> String {
        format!("http://localhost:{}/{}", self.listener.local_addr().unwrap().port(), self.nonce)
    }

    pub fn serve(self, lifetime: Duration) {
        let deadline = Instant::now() + lifetime;
        let host = format!("localhost:{}", self.listener.local_addr().unwrap().port());
        while Instant::now() < deadline {
            let (mut stream, _) = match self.listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => return,
            };
            // macOS and Windows sockets inherit non-blocking mode from the listener. Wait for the
            // request instead of rejecting a browser whose bytes have not arrived yet.
            if stream.set_nonblocking(false).is_err() { continue; }
            let request = read_request(&mut stream, deadline.min(Instant::now() + Duration::from_secs(2)));
            let valid = request.is_ok_and(|request| valid_request(&request, &host, &self.nonce))
                && Instant::now() < deadline;
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            if valid {
                // Cookies are scoped to the hostname, so this host-only cookie also
                // reaches localhost:8080. Match the runtime's normal login attributes.
                let _ = write!(stream, "HTTP/1.1 303 See Other\r\nLocation: http://localhost:{}/\r\nSet-Cookie: openaidr_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", self.dashboard_port, self.session);
                return;
            }
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    }
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    while bytes.len() < 8192 && Instant::now() < deadline {
        stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))))?;
        let count = stream.read(&mut buffer)?;
        if count == 0 { break; }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into());
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

fn valid_request(request: &str, host: &str, nonce: &str) -> bool {
    let mut lines = request.split("\r\n");
    if lines.next() != Some(format!("GET /{nonce} HTTP/1.1").as_str()) { return false; }
    let mut hosts = 0;
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else { return false; };
        if name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if value.trim() != host { return false; }
        }
        if name.eq_ignore_ascii_case("origin")
            || (name.eq_ignore_ascii_case("sec-fetch-site") && !matches!(value.trim(), "none" | "same-origin")) {
            return false;
        }
    }
    hosts == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // Send the request in two delayed parts, as a slow browser can, so the server
    // must wait for the complete request before it replies and closes.
    fn exchange(address: SocketAddr, request: &str) -> String {
        let mut client = TcpStream::connect(address).unwrap();
        let (start, end) = request.split_at(request.len() / 2);
        client.write_all(start.as_bytes()).unwrap();
        thread::sleep(Duration::from_millis(50));
        client.write_all(end.as_bytes()).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn handoff_rejects_other_requests_then_transfers_once() {
        let session = format!("oass_{}", "a".repeat(43));
        let nonce = "b".repeat(43);
        let handoff = Handoff::new(&session, &nonce, 8080).unwrap();
        let address = handoff.listener.local_addr().unwrap();
        let host = format!("localhost:{}", address.port());
        assert!(!handoff.url().contains(&session));
        let server = thread::spawn(move || handoff.serve(Duration::from_secs(10)));
        for (path, headers, method) in [
            ("wrong", format!("Host: {host}"), "GET"),
            (&nonce, "Host: attacker.example".into(), "GET"),
            (&nonce, format!("Host: {host}\r\nHost: {host}"), "GET"),
            (&nonce, format!("Host: {host}\r\nOrigin: https://attacker.example"), "GET"),
            (&nonce, format!("Host: {host}\r\nSec-Fetch-Site: cross-site"), "GET"),
            (&nonce, format!("Host: {host}"), "POST"),
            (&nonce, format!("Host: {host}"), "HEAD"),
        ] {
            let reply = exchange(address, &format!("{method} /{path} HTTP/1.1\r\n{headers}\r\n\r\n"));
            assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
            assert!(!reply.contains(&session));
        }
        let reply = exchange(address, &format!("GET /{nonce} HTTP/1.1\r\nHost: {host}\r\nSec-Fetch-Site: none\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 303"), "{reply}");
        assert!(reply.contains("Location: http://localhost:8080/\r\n"));
        assert!(reply.contains(&format!("Set-Cookie: openaidr_session={session}; Path=/; HttpOnly; SameSite=Lax")));
        server.join().unwrap();
        assert!(TcpStream::connect(address).is_err());
    }

    #[test]
    fn handoff_expires_and_rejects_header_injection() {
        let session = format!("oass_{}", "a".repeat(43));
        let nonce = "b".repeat(43);
        assert!(Handoff::new(&format!("{session}\r\nInjected: value"), &nonce, 8080).is_err());
        assert!(Handoff::new(&session, "guessable", 8080).is_err());
        let handoff = Handoff::new(&session, &nonce, 8080).unwrap();
        let address = handoff.listener.local_addr().unwrap();
        handoff.serve(Duration::ZERO);
        assert!(TcpStream::connect(address).is_err());
    }
}
