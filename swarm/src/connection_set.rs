//! Connection set for tracking active connections by public key

use std::{
    collections::HashMap,
    time::Instant,
};

use dht_rpc::IdBytes;

/// Information about an active connection
#[derive(Debug)]
pub struct ConnectionInfo {
    /// Whether we initiated the connection (client) or accepted it (server)
    pub client: bool,

    /// Bytes read from this connection (for duplicate resolution)
    pub bytes_read: u64,

    /// Bytes written to this connection (for duplicate resolution)
    pub bytes_written: u64,

    /// When the connection was established
    pub established: Instant,
}

impl ConnectionInfo {
    /// Create a new ConnectionInfo
    pub fn new(client: bool) -> Self {
        Self {
            client,
            bytes_read: 0,
            bytes_written: 0,
            established: Instant::now(),
        }
    }

    /// Total bytes transferred
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_read.saturating_add(self.bytes_written)
    }
}

/// Result of adding a connection to the set
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddResult {
    /// New connection was added
    Added,
    /// Existing connection was kept (new was rejected as duplicate)
    KeptExisting,
    /// New connection replaced existing
    Replaced,
}

/// A set of connections indexed by public key for deduplication
#[derive(Debug, Default)]
pub struct ConnectionSet {
    /// Connections indexed by public key
    connections: HashMap<IdBytes, ConnectionInfo>,
}

impl ConnectionSet {
    /// Create a new empty ConnectionSet
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Check if we have a connection to this peer
    pub fn has(&self, public_key: &IdBytes) -> bool {
        self.connections.contains_key(public_key)
    }

    /// Get connection info for a peer
    pub fn get(&self, public_key: &IdBytes) -> Option<&ConnectionInfo> {
        self.connections.get(public_key)
    }

    /// Get mutable connection info for a peer
    pub fn get_mut(&mut self, public_key: &IdBytes) -> Option<&mut ConnectionInfo> {
        self.connections.get_mut(public_key)
    }

    /// Add a new connection, handling duplicates
    ///
    /// Duplicate resolution logic:
    /// 1. If existing connection has transferred bytes but new hasn't, keep existing
    /// 2. If new connection has transferred bytes but existing hasn't, replace
    /// 3. If neither has transferred, tie-break by initiator (non-client wins)
    pub fn add(&mut self, public_key: IdBytes, client: bool) -> AddResult {
        if let Some(existing) = self.connections.get(&public_key) {
            let existing_active = existing.bytes_transferred() > 0;

            // New connection has no bytes yet
            let new_active = false;

            let keep_existing = if existing_active || new_active {
                // If either has transferred data, keep the one that has
                existing_active
            } else {
                // Neither has data - tie-break: non-client wins
                !existing.client
            };

            if keep_existing {
                return AddResult::KeptExisting;
            }

            // Replace existing
            self.connections.insert(public_key, ConnectionInfo::new(client));
            AddResult::Replaced
        } else {
            // No existing connection
            self.connections.insert(public_key, ConnectionInfo::new(client));
            AddResult::Added
        }
    }

    /// Remove a connection
    pub fn remove(&mut self, public_key: &IdBytes) -> Option<ConnectionInfo> {
        self.connections.remove(public_key)
    }

    /// Get the total number of connections
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Get the number of client-initiated connections
    pub fn client_count(&self) -> usize {
        self.connections.values().filter(|c| c.client).count()
    }

    /// Get the number of server-accepted connections
    pub fn server_count(&self) -> usize {
        self.connections.values().filter(|c| !c.client).count()
    }

    /// Iterate over all public keys
    pub fn keys(&self) -> impl Iterator<Item = &IdBytes> {
        self.connections.keys()
    }

    /// Iterate over all connections
    pub fn iter(&self) -> impl Iterator<Item = (&IdBytes, &ConnectionInfo)> {
        self.connections.iter()
    }

    /// Iterate mutably over all connections
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&IdBytes, &mut ConnectionInfo)> {
        self.connections.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_new_connection() {
        let mut set = ConnectionSet::new();
        let pk = IdBytes::random();

        let result = set.add(pk, true);
        assert_eq!(result, AddResult::Added);
        assert!(set.has(&pk));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_duplicate_no_bytes_client_loses() {
        let mut set = ConnectionSet::new();
        let pk = IdBytes::random();

        // Add server connection first
        set.add(pk, false);
        assert!(!set.get(&pk).unwrap().client);

        // Try to add client connection - should be rejected
        let result = set.add(pk, true);
        assert_eq!(result, AddResult::KeptExisting);
        assert!(!set.get(&pk).unwrap().client); // Still server
    }

    #[test]
    fn test_duplicate_with_bytes_wins() {
        let mut set = ConnectionSet::new();
        let pk = IdBytes::random();

        // Add connection and simulate data transfer
        set.add(pk, true);
        set.get_mut(&pk).unwrap().bytes_read = 100;

        // Try to add another connection - should be rejected because existing has data
        let result = set.add(pk, false);
        assert_eq!(result, AddResult::KeptExisting);
    }

    #[test]
    fn test_remove() {
        let mut set = ConnectionSet::new();
        let pk = IdBytes::random();

        set.add(pk, true);
        assert!(set.has(&pk));

        let removed = set.remove(&pk);
        assert!(removed.is_some());
        assert!(!set.has(&pk));
    }

    #[test]
    fn test_counts() {
        let mut set = ConnectionSet::new();

        set.add(IdBytes::random(), true);  // client
        set.add(IdBytes::random(), true);  // client
        set.add(IdBytes::random(), false); // server

        assert_eq!(set.len(), 3);
        assert_eq!(set.client_count(), 2);
        assert_eq!(set.server_count(), 1);
    }
}
