//! Bounded login admission keyed by the socket peer, never forwarded headers.
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};
const WINDOW: Duration = Duration::from_secs(60);
struct Window {
    start: Instant,
    used: u32,
}
impl Window {
    fn reset(&mut self, now: Instant) {
        if now.duration_since(self.start) >= WINDOW {
            self.start = now;
            self.used = 0;
        }
    }
}
pub(super) struct LoginAdmission {
    global: Window,
    peers: HashMap<IpAddr, Window>,
}
impl LoginAdmission {
    pub(super) fn new() -> Self {
        Self {
            global: Window {
                start: Instant::now(),
                used: 0,
            },
            peers: HashMap::new(),
        }
    }
    pub(super) fn admit(&mut self, peer: IpAddr, now: Instant) -> bool {
        self.global.reset(now);
        if self.global.used >= 256 {
            return false;
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= 1024 {
            self.peers
                .retain(|_, window| now.duration_since(window.start) < WINDOW);
            if self.peers.len() >= 1024 {
                return false;
            }
        }
        let window = self.peers.entry(peer).or_insert(Window {
            start: now,
            used: 0,
        });
        window.reset(now);
        if window.used >= 32 {
            return false;
        }
        window.used += 1;
        self.global.used += 1;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn per_peer_and_global_windows_are_independent_and_bounded() {
        let mut admission = LoginAdmission::new();
        let now = Instant::now();
        let peer = "127.0.0.1".parse().unwrap();
        for _ in 0..32 {
            assert!(admission.admit(peer, now));
        }
        assert!(!admission.admit(peer, now));
        for n in 2..9 {
            let peer = IpAddr::from([127, 0, 0, n]);
            for _ in 0..32 {
                assert!(admission.admit(peer, now));
            }
        }
        assert!(!admission.admit("127.0.0.9".parse().unwrap(), now));
        assert!(admission.admit(peer, now + WINDOW));
    }
}
