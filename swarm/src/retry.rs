//! Retry timer with exponential backoff for failed connections

use std::time::{Duration, Instant};

use dht_rpc::IdBytes;

/// Backoff intervals matching JS hyperswarm RetryTimer
pub const BACKOFF_INTERVALS: [Duration; 4] = [
    Duration::from_secs(1),    // S: first retry
    Duration::from_secs(5),    // M: second retry
    Duration::from_secs(15),   // L: third retry
    Duration::from_secs(600),  // X: exhausted (10 minutes)
];

/// A scheduled retry for a peer
#[derive(Debug, Clone)]
pub struct RetryEntry {
    pub public_key: IdBytes,
    pub retry_at: Instant,
    pub attempt: u32,
}

impl RetryEntry {
    /// Create a new retry entry with backoff based on attempt count
    pub fn new(public_key: IdBytes, attempt: u32) -> Self {
        let backoff_index = (attempt as usize).saturating_sub(1).min(BACKOFF_INTERVALS.len() - 1);
        let backoff = BACKOFF_INTERVALS[backoff_index];
        // Add some jitter (up to 10% of backoff)
        let jitter = Duration::from_millis((rand::random::<u64>() % (backoff.as_millis() as u64 / 10)).max(100));
        let retry_at = Instant::now() + backoff + jitter;

        Self {
            public_key,
            retry_at,
            attempt,
        }
    }

    /// Check if this entry is ready for retry
    pub fn is_ready(&self) -> bool {
        Instant::now() >= self.retry_at
    }

    /// Time until ready (returns zero if already ready)
    pub fn time_until_ready(&self) -> Duration {
        self.retry_at.saturating_duration_since(Instant::now())
    }
}

/// Timer for managing peer retry scheduling
#[derive(Debug, Default)]
pub struct RetryTimer {
    entries: Vec<RetryEntry>,
}

impl RetryTimer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Schedule a retry for a peer
    pub fn schedule(&mut self, entry: RetryEntry) {
        // Remove existing entry for this peer if any
        self.entries.retain(|e| e.public_key != entry.public_key);
        self.entries.push(entry);
    }

    /// Get peers ready for retry (removes them from timer)
    pub fn get_ready(&mut self) -> Vec<RetryEntry> {
        let now = Instant::now();
        let (ready, pending): (Vec<_>, Vec<_>) =
            self.entries.drain(..).partition(|e| e.retry_at <= now);
        self.entries = pending;
        ready
    }

    /// Cancel retry for a peer
    pub fn cancel(&mut self, public_key: &IdBytes) {
        self.entries.retain(|e| &e.public_key != public_key);
    }

    /// Get the next retry time (for sleep calculation)
    pub fn next_retry_time(&self) -> Option<Instant> {
        self.entries.iter().map(|e| e.retry_at).min()
    }

    /// Duration until next retry (for tokio::time::sleep)
    pub fn duration_until_next(&self) -> Option<Duration> {
        self.next_retry_time().map(|t| t.saturating_duration_since(Instant::now()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all scheduled retries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Check if a peer has a scheduled retry
    pub fn contains(&self, public_key: &IdBytes) -> bool {
        self.entries.iter().any(|e| &e.public_key == public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_intervals() {
        // First attempt uses BACKOFF_INTERVALS[0] = 1s
        let entry = RetryEntry::new(IdBytes([1; 32]), 1);
        // Allow for jitter - should be roughly 1s
        assert!(entry.time_until_ready() <= Duration::from_millis(1200));
        assert!(entry.time_until_ready() >= Duration::from_millis(900));
    }

    #[test]
    fn test_schedule_and_cancel() {
        let mut timer = RetryTimer::new();
        let pk = IdBytes([1; 32]);

        timer.schedule(RetryEntry::new(pk, 1));
        assert_eq!(timer.len(), 1);
        assert!(timer.contains(&pk));

        timer.cancel(&pk);
        assert_eq!(timer.len(), 0);
        assert!(!timer.contains(&pk));
    }

    #[test]
    fn test_schedule_replaces_existing() {
        let mut timer = RetryTimer::new();
        let pk = IdBytes([1; 32]);

        timer.schedule(RetryEntry::new(pk, 1));
        timer.schedule(RetryEntry::new(pk, 2)); // Should replace

        assert_eq!(timer.len(), 1);
    }

    #[test]
    fn test_get_ready() {
        let mut timer = RetryTimer::new();

        // Schedule one with no delay (ready immediately)
        let mut entry = RetryEntry::new(IdBytes([1; 32]), 1);
        entry.retry_at = Instant::now() - Duration::from_secs(1); // In the past
        timer.entries.push(entry);

        // Schedule one for the future
        timer.schedule(RetryEntry::new(IdBytes([2; 32]), 1));

        let ready = timer.get_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].public_key, IdBytes([1; 32]));
        assert_eq!(timer.len(), 1); // One still pending
    }

    #[test]
    fn test_next_retry_time() {
        let mut timer = RetryTimer::new();
        assert!(timer.next_retry_time().is_none());

        timer.schedule(RetryEntry::new(IdBytes([1; 32]), 1));
        assert!(timer.next_retry_time().is_some());
    }
}
