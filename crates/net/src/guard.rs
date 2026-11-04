//! Cheap pre-authentication guards for the responder. Time is injected (seconds) so it is testable
//! and so no wall-clock is ever sent on the wire.
use blake2::{digest::consts::U32, Blake2b, Digest};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict { Allow, RateLimited, Replay }

pub struct HandshakeGuard {
    // token bucket for unauthenticated msg1 attempts
    tokens: f64,
    last: u64,
    capacity: f64,
    refill_per_sec: f64,
    // replay cache: msg1 hash -> time seen; bounded in size AND age
    seen: HashMap<[u8; 32], u64>,
    order: VecDeque<([u8; 32], u64)>,
    max_entries: usize,
    ttl: u64,
}

impl HandshakeGuard {
    /// Defaults: burst of 5 attempts, 1 per 10 s sustained, remember 4096 msg1s for 1 hour.
    pub fn new(now: u64) -> Self { Self::with(now, 5.0, 0.1, 4096, 3600) }

    pub fn with(now: u64, capacity: f64, refill_per_sec: f64, max_entries: usize, ttl: u64) -> Self {
        Self { tokens: capacity, last: now, capacity, refill_per_sec, seen: HashMap::new(), order: VecDeque::new(), max_entries, ttl }
    }

    fn evict(&mut self, now: u64) {
        while let Some(&(h, t)) = self.order.front() {
            if now.saturating_sub(t) > self.ttl || self.order.len() > self.max_entries {
                self.order.pop_front();
                if self.seen.get(&h) == Some(&t) { self.seen.remove(&h); }
            } else { break; }
        }
    }

    /// Call BEFORE any expensive crypto on an unauthenticated msg1. Consumes a token.
    pub fn check(&mut self, msg1: &[u8], now: u64) -> Verdict {
        self.evict(now);
        let dt = now.saturating_sub(self.last) as f64;
        self.last = self.last.max(now);
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        if self.tokens < 1.0 { return Verdict::RateLimited; }
        self.tokens -= 1.0;
        let h: [u8; 32] = Blake2b::<U32>::digest(msg1).into();
        if self.seen.contains_key(&h) { Verdict::Replay } else { Verdict::Allow }
    }

    /// Call only after the handshake SUCCEEDED, so garbage cannot poison/flush the cache.
    pub fn record_success(&mut self, msg1: &[u8], now: u64) {
        let h: [u8; 32] = Blake2b::<U32>::digest(msg1).into();
        self.seen.insert(h, now);
        self.order.push_back((h, now));
        self.evict(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_burst_then_refill() {
        let mut g = HandshakeGuard::with(0, 3.0, 1.0, 16, 100);
        for i in 0..3u8 { assert_eq!(g.check(&[i], 0), Verdict::Allow); }
        assert_eq!(g.check(&[9], 0), Verdict::RateLimited);
        assert_eq!(g.check(&[9], 1), Verdict::Allow); // 1 token refilled
        assert_eq!(g.check(&[9], 1), Verdict::RateLimited);
    }

    #[test]
    fn replay_detected_only_after_success_and_expires() {
        let mut g = HandshakeGuard::with(0, 100.0, 100.0, 16, 10);
        assert_eq!(g.check(b"m1", 0), Verdict::Allow);
        assert_eq!(g.check(b"m1", 0), Verdict::Allow, "failed attempts are not cached");
        g.record_success(b"m1", 0);
        assert_eq!(g.check(b"m1", 5), Verdict::Replay);
        assert_eq!(g.check(b"m1", 11), Verdict::Allow, "ttl expiry");
    }

    #[test]
    fn cache_is_bounded() {
        let mut g = HandshakeGuard::with(0, 1e9, 1e9, 4, 1_000_000);
        for i in 0..100u8 { g.record_success(&[i], i as u64); }
        assert!(g.seen.len() <= 5 && g.order.len() <= 5);
    }
}
