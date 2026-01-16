//! Priority queue for scheduling peer connections

use std::collections::{BinaryHeap, HashSet};
use std::cmp::Ordering;
use std::time::Instant;

use dht_rpc::IdBytes;

use crate::Priority;

/// Entry in the connection queue
#[derive(Debug, Clone)]
pub struct QueuedPeer {
    /// The peer's public key
    pub public_key: IdBytes,
    /// Priority level (higher = connect sooner)
    pub priority: Priority,
    /// When this entry was added (for tie-breaking)
    pub queued_at: Instant,
    /// Random factor for shuffling peers of same priority
    pub shuffle_key: u64,
}

impl Eq for QueuedPeer {}

impl PartialEq for QueuedPeer {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

/// Ordering: higher priority first, then earlier queued_at, then shuffle_key
impl Ord for QueuedPeer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority)
            .then_with(|| other.queued_at.cmp(&self.queued_at)) // Earlier = higher priority
            .then_with(|| self.shuffle_key.cmp(&other.shuffle_key))
    }
}

impl PartialOrd for QueuedPeer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority queue for scheduling peer connections
#[derive(Debug, Default)]
pub struct PeerQueue {
    heap: BinaryHeap<QueuedPeer>,
    /// Track which peers are in the queue to avoid duplicates
    in_queue: HashSet<IdBytes>,
}

impl PeerQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a peer to the queue (no-op if already queued)
    pub fn push(&mut self, peer: QueuedPeer) {
        if self.in_queue.insert(peer.public_key) {
            self.heap.push(peer);
        }
    }

    /// Pop the highest priority peer
    pub fn pop(&mut self) -> Option<QueuedPeer> {
        while let Some(peer) = self.heap.pop() {
            if self.in_queue.remove(&peer.public_key) {
                return Some(peer);
            }
            // Skip stale entries (removed via remove())
        }
        None
    }

    /// Check if a peer is queued
    pub fn contains(&self, public_key: &IdBytes) -> bool {
        self.in_queue.contains(public_key)
    }

    /// Remove a peer from the queue (lazy removal)
    pub fn remove(&mut self, public_key: &IdBytes) {
        self.in_queue.remove(public_key);
        // Actual removal happens on pop - this is lazy removal
    }

    pub fn len(&self) -> usize {
        self.in_queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.in_queue.is_empty()
    }

    /// Clear the queue
    pub fn clear(&mut self) {
        self.heap.clear();
        self.in_queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_pop_ordering() {
        let mut queue = PeerQueue::new();
        let now = Instant::now();

        // Add peers with different priorities
        queue.push(QueuedPeer {
            public_key: IdBytes([1; 32]),
            priority: Priority::Low,
            queued_at: now,
            shuffle_key: 0,
        });
        queue.push(QueuedPeer {
            public_key: IdBytes([2; 32]),
            priority: Priority::VeryHigh,
            queued_at: now,
            shuffle_key: 0,
        });
        queue.push(QueuedPeer {
            public_key: IdBytes([3; 32]),
            priority: Priority::Normal,
            queued_at: now,
            shuffle_key: 0,
        });

        // Should pop in priority order: VeryHigh, Normal, Low
        assert_eq!(queue.pop().unwrap().public_key, IdBytes([2; 32]));
        assert_eq!(queue.pop().unwrap().public_key, IdBytes([3; 32]));
        assert_eq!(queue.pop().unwrap().public_key, IdBytes([1; 32]));
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_no_duplicates() {
        let mut queue = PeerQueue::new();
        let now = Instant::now();
        let pk = IdBytes([1; 32]);

        queue.push(QueuedPeer {
            public_key: pk,
            priority: Priority::Normal,
            queued_at: now,
            shuffle_key: 0,
        });
        queue.push(QueuedPeer {
            public_key: pk,
            priority: Priority::VeryHigh, // Different priority, same key
            queued_at: now,
            shuffle_key: 0,
        });

        assert_eq!(queue.len(), 1);
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_remove() {
        let mut queue = PeerQueue::new();
        let now = Instant::now();

        queue.push(QueuedPeer {
            public_key: IdBytes([1; 32]),
            priority: Priority::Normal,
            queued_at: now,
            shuffle_key: 0,
        });
        queue.push(QueuedPeer {
            public_key: IdBytes([2; 32]),
            priority: Priority::Normal,
            queued_at: now,
            shuffle_key: 0,
        });

        assert_eq!(queue.len(), 2);
        queue.remove(&IdBytes([1; 32]));
        assert_eq!(queue.len(), 1);
        assert!(!queue.contains(&IdBytes([1; 32])));

        // Pop should skip the removed entry
        let popped = queue.pop().unwrap();
        assert_eq!(popped.public_key, IdBytes([2; 32]));
    }

    #[test]
    fn test_contains() {
        let mut queue = PeerQueue::new();
        let pk = IdBytes([1; 32]);

        assert!(!queue.contains(&pk));
        queue.push(QueuedPeer {
            public_key: pk,
            priority: Priority::Normal,
            queued_at: Instant::now(),
            shuffle_key: 0,
        });
        assert!(queue.contains(&pk));
    }
}
