//! Peer information and priority tracking

use std::{
    collections::HashSet,
    net::SocketAddr,
    time::{Duration, Instant},
};

use dht_rpc::IdBytes;

/// Minimum connection time before resetting attempt counter (15 seconds)
const MIN_CONNECTION_TIME: Duration = Duration::from_secs(15);

/// Priority levels for peer connection attempts
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Priority {
    /// Lowest priority - many failed attempts or stale peer
    VeryLow = 0,
    /// Low priority - several failed attempts
    Low = 1,
    /// Normal priority - default for new peers
    #[default]
    Normal = 2,
    /// High priority - few failed attempts
    High = 3,
    /// Highest priority - proven peer with recent success
    VeryHigh = 4,
}

/// Information about a discovered peer
#[derive(Debug)]
pub struct PeerInfo {
    /// The peer's public key
    pub public_key: IdBytes,

    /// Known relay addresses for this peer
    pub relay_addresses: Vec<SocketAddr>,

    /// Whether to attempt reconnection on disconnect
    pub reconnecting: bool,

    /// Whether the peer has been cryptographically verified (successful connection)
    pub proven: bool,

    /// Whether this peer is banned (firewall blocked or too many failures)
    pub banned: bool,

    /// Number of failed connection attempts
    pub attempts: u32,

    /// Current priority level
    pub priority: Priority,

    /// Whether this peer is currently queued for connection
    pub queued: bool,

    /// Whether we initiated the connection (true) or accepted it (false)
    pub client: bool,

    /// Whether this is an explicit peer (added via join_peer)
    pub explicit: bool,

    /// Whether waiting in retry timer
    pub waiting: bool,

    /// Whether currently attempting to connect
    pub connecting: bool,

    /// Topics this peer is associated with
    pub topics: HashSet<IdBytes>,

    /// When this peer was last connected
    pub connected_time: Option<Instant>,

    /// When the last connection attempt started
    pub last_attempt: Option<Instant>,
}

impl PeerInfo {
    /// Create a new PeerInfo for a peer
    pub fn new(public_key: IdBytes) -> Self {
        Self {
            public_key,
            relay_addresses: Vec::new(),
            reconnecting: true,
            proven: false,
            banned: false,
            attempts: 0,
            priority: Priority::Normal,
            queued: false,
            client: false,
            explicit: false,
            waiting: false,
            connecting: false,
            topics: HashSet::new(),
            connected_time: None,
            last_attempt: None,
        }
    }

    /// Add relay addresses if they are new (merge with existing)
    pub fn add_relay_addresses(&mut self, relay_addresses: Vec<SocketAddr>) {
        for addr in relay_addresses {
            if !self.relay_addresses.contains(&addr) {
                self.relay_addresses.push(addr);
            }
        }
    }

    /// Called when a connection is successfully established
    pub fn connected(&mut self) {
        self.proven = true;
        self.connected_time = Some(Instant::now());
        self.update_priority();
    }

    /// Called when a connection is closed
    pub fn disconnected(&mut self) {
        // Only increment attempts if connection was short-lived
        if let Some(connected_time) = self.connected_time {
            if connected_time.elapsed() < MIN_CONNECTION_TIME {
                self.attempts = self.attempts.saturating_add(1);
            } else {
                // Long-lived connection - reset attempts
                self.attempts = 0;
            }
        } else {
            // Never connected - increment attempts
            self.attempts = self.attempts.saturating_add(1);
        }
        self.connected_time = None;
        self.update_priority();
    }

    /// Add a topic this peer is associated with
    pub fn with_topic(mut self, topic: IdBytes) -> Self {
        self.topics.insert(topic);
        self
    }

    /// Remove a topic association
    pub fn remove_topic(&mut self, topic: &IdBytes) {
        self.topics.remove(topic);
    }

    /// Ban this peer
    pub fn ban(&mut self) {
        self.banned = true;
        self.priority = Priority::VeryLow;
    }

    /// Update the priority based on current state
    pub fn update_priority(&mut self) -> bool {
        if self.banned {
            self.priority = Priority::VeryLow;
            return false;
        }

        let old_priority = self.priority;
        self.priority = self.calculate_priority();

        // Return true if should be queued (priority changed or is high enough)
        self.priority != Priority::VeryLow && (self.priority != old_priority || !self.queued)
    }

    /// Calculate priority based on attempts and proven status
    fn calculate_priority(&self) -> Priority {
        match (self.proven, self.attempts) {
            // Proven peers get higher priority
            (true, 0) => Priority::VeryHigh,
            (true, 1) => Priority::VeryHigh,
            (true, 2) => Priority::High,
            (true, 3) => Priority::Normal,
            (true, _) => Priority::Low,

            // Unproven peers start lower
            (false, 0) => Priority::Normal,
            (false, 1) => Priority::High, // Give one retry at high priority
            (false, 2) => Priority::Normal,
            (false, 3) => Priority::Low,
            (false, _) => Priority::VeryLow,
        }
    }

    /// Reset state for re-discovery
    pub fn reset(&mut self) {
        if !self.proven {
            self.attempts = 0;
        }
        self.update_priority();
    }

    /// Check if this peer should be garbage collected
    pub fn should_gc(&self) -> bool {
        // Don't GC if:
        // - Currently queued
        // - Waiting in retry timer
        // - Is an explicit peer
        // - Has active topics
        if self.queued || self.waiting || self.explicit || !self.topics.is_empty() {
            return false;
        }

        // GC if banned or too many attempts
        self.banned || self.attempts > 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::VeryLow < Priority::Low);
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
        assert!(Priority::High < Priority::VeryHigh);
    }

    #[test]
    fn test_new_peer_priority() {
        let info = PeerInfo::new(IdBytes::random());
        assert_eq!(info.priority, Priority::Normal);
        assert!(!info.proven);
        assert!(!info.banned);
        assert_eq!(info.attempts, 0);
    }

    #[test]
    fn test_connected_sets_proven() {
        let mut info = PeerInfo::new(IdBytes::random());
        assert!(!info.proven);

        info.connected();
        assert!(info.proven);
        assert_eq!(info.priority, Priority::VeryHigh);
    }

    #[test]
    fn test_ban_sets_very_low() {
        let mut info = PeerInfo::new(IdBytes::random());
        info.ban();

        assert!(info.banned);
        assert_eq!(info.priority, Priority::VeryLow);
    }

    #[test]
    fn test_attempts_decrease_priority() {
        let mut info = PeerInfo::new(IdBytes::random());

        // Start at Normal
        assert_eq!(info.calculate_priority(), Priority::Normal);

        // First attempt - High (retry)
        info.attempts = 1;
        assert_eq!(info.calculate_priority(), Priority::High);

        // Second attempt - Normal
        info.attempts = 2;
        assert_eq!(info.calculate_priority(), Priority::Normal);

        // Third attempt - Low
        info.attempts = 3;
        assert_eq!(info.calculate_priority(), Priority::Low);

        // Many attempts - VeryLow
        info.attempts = 5;
        assert_eq!(info.calculate_priority(), Priority::VeryLow);
    }

    #[test]
    fn test_proven_peer_priority() {
        let mut info = PeerInfo::new(IdBytes::random());
        info.proven = true;

        // Proven with no attempts - VeryHigh
        assert_eq!(info.calculate_priority(), Priority::VeryHigh);

        // Proven with attempts still gets better treatment
        info.attempts = 3;
        assert_eq!(info.calculate_priority(), Priority::Normal);

        info.attempts = 5;
        assert_eq!(info.calculate_priority(), Priority::Low);
    }

    #[test]
    fn test_should_gc() {
        let mut info = PeerInfo::new(IdBytes::random());

        // New peer with no topics should not be GC'd immediately
        assert!(!info.should_gc());

        // Banned peer should be GC'd
        info.ban();
        assert!(info.should_gc());

        // Reset and add topic - should not GC
        info.banned = false;
        info.topics.insert(IdBytes::random());
        assert!(!info.should_gc());

        // Explicit peer should not be GC'd
        info.topics.clear();
        info.explicit = true;
        assert!(!info.should_gc());

        // Queued peer should not be GC'd
        info.explicit = false;
        info.queued = true;
        assert!(!info.should_gc());
    }
}
