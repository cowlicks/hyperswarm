//! Persistent storage for DHT peer records
//!
//! This module provides storage for:
//! - **PeerRecordCache**: Stores peer records by topic hash (for LOOKUP)
//! - **PeerRouter**: Stores self-announcing peers where target == hash(pubkey) (for FIND_PEER)

use std::{collections::HashMap, net::SocketAddr};

use dht_rpc::IdBytes;

// TODO I think this number  should come from the # of "closer_nodes" within the rpc query kbuckets
// code.
/// Maximum number of peer records stored per topic
pub const MAX_RECORDS_PER_TOPIC: usize = 20;

/// A stored peer record
#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub public_key: [u8; 32],
    pub encoded: Vec<u8>,
}

/// Cache for peer records by topic (for LOOKUP)
#[derive(Debug, Default)]
pub struct PeerRecordCache {
    records: HashMap<IdBytes, Vec<PeerRecord>>,
}

impl PeerRecordCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a peer record for a topic.
    /// If the peer already exists, the record is updated.
    /// If at capacity (20 records), the oldest is evicted.
    pub fn add(&mut self, topic: IdBytes, public_key: [u8; 32], encoded: Vec<u8>) {
        let records = self.records.entry(topic).or_default();

        if let Some(r) = records.iter_mut().find(|r| r.public_key == public_key) {
            r.encoded = encoded;
            return;
        }

        if records.len() >= MAX_RECORDS_PER_TOPIC {
            records.remove(0);
        }

        records.push(PeerRecord {
            public_key,
            encoded,
        });
    }

    /// Get up to `limit` peer records for a topic
    pub fn get(&self, topic: &IdBytes, limit: usize) -> Vec<&PeerRecord> {
        self.records
            .get(topic)
            .map(|records| records.iter().take(limit).collect())
            .unwrap_or_default()
    }

    /// Remove a peer record from a topic
    pub fn remove(&mut self, topic: &IdBytes, public_key: &[u8; 32]) {
        if let Some(records) = self.records.get_mut(topic) {
            records.retain(|r| &r.public_key != public_key);
            // Clean up empty entries
            if records.is_empty() {
                self.records.remove(topic);
            }
        }
    }
}

/// Entry in the router for self-announcing peers (for FIND_PEER)
#[derive(Debug, Clone)]
pub struct RouterEntry {
    /// The relay address (who sent us this announcement)
    pub relay: SocketAddr,
    /// The encoded peer record
    pub record: Vec<u8>,
}

impl RouterEntry {
    pub fn new(relay: SocketAddr, record: Vec<u8>) -> Self {
        Self { relay, record }
    }
}

/// Router for self-announcing peers (where target == hash(pubkey))
#[derive(Debug, Default)]
pub struct PeerRouter {
    entries: HashMap<IdBytes, RouterEntry>,
}

impl PeerRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a router entry
    pub fn set(&mut self, target: IdBytes, entry: RouterEntry) {
        self.entries.insert(target, entry);
    }

    /// Get a router entry
    pub fn get(&self, target: &IdBytes) -> Option<&RouterEntry> {
        self.entries.get(target)
    }

    /// Delete a router entry
    pub fn delete(&mut self, target: &IdBytes) {
        self.entries.remove(target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_cache_add_and_get() {
        let mut cache = PeerRecordCache::new();
        let topic = IdBytes::random();
        let pubkey = [1u8; 32];
        let encoded = b"test record".to_vec();

        cache.add(topic, pubkey, encoded.clone());

        let records = cache.get(&topic, 20);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].public_key, pubkey);
        assert_eq!(records[0].encoded, encoded);
    }

    #[test]
    fn test_record_cache_update_existing() {
        let mut cache = PeerRecordCache::new();
        let topic = IdBytes::random();
        let pubkey = [1u8; 32];

        cache.add(topic, pubkey, b"first".to_vec());
        cache.add(topic, pubkey, b"second".to_vec());

        let records = cache.get(&topic, 20);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].encoded, b"second");
    }

    #[test]
    fn test_record_cache_limit() {
        let mut cache = PeerRecordCache::new();
        let topic = IdBytes::random();

        // Add MAX_RECORDS_PER_TOPIC + 1 records
        for i in 0..=MAX_RECORDS_PER_TOPIC {
            let mut pubkey = [0u8; 32];
            pubkey[0] = i as u8;
            cache.add(topic, pubkey, vec![i as u8]);
        }

        let records = cache.get(&topic, 100);
        assert_eq!(records.len(), MAX_RECORDS_PER_TOPIC);

        // First record should have been evicted (pubkey[0] == 0)
        assert!(records.iter().all(|r| r.public_key[0] != 0));
    }

    #[test]
    fn test_record_cache_remove() {
        let mut cache = PeerRecordCache::new();
        let topic = IdBytes::random();
        let pubkey = [1u8; 32];

        cache.add(topic, pubkey, b"test".to_vec());
        assert_eq!(cache.get(&topic, 20).len(), 1);

        cache.remove(&topic, &pubkey);
        assert_eq!(cache.get(&topic, 20).len(), 0);
    }

    #[test]
    fn test_router_basic_operations() {
        let mut router = PeerRouter::new();
        let target = IdBytes::random();
        let relay = "127.0.0.1:8080".parse().unwrap();
        let record = b"peer record".to_vec();

        router.set(target, RouterEntry::new(relay, record.clone()));

        assert!(router.get(&target).is_some());
        let entry = router.get(&target).unwrap();
        assert_eq!(entry.record, record);

        router.delete(&target);
        assert!(router.get(&target).is_none());
    }
}
