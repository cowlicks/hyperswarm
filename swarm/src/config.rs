//! Configuration for Swarm behavior

use dht_rpc::DhtConfig;

/// Default maximum parallel connection attempts
pub const DEFAULT_MAX_PARALLEL: usize = 3;

/// Default maximum total connections
pub const DEFAULT_MAX_PEERS: usize = 64;

/// Configuration for Swarm behavior
#[derive(Debug)]
pub struct SwarmConfig {
    /// Maximum parallel connection attempts (default: 3)
    pub max_parallel: usize,
    /// Maximum total peer connections (default: 64)
    pub max_peers: usize,
    /// Whether to automatically connect to discovered peers (default: true)
    pub auto_connect: bool,
    /// Whether to retry failed connections (default: true)
    pub auto_retry: bool,
    /// DHT configuration
    pub dht_config: DhtConfig,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            max_parallel: DEFAULT_MAX_PARALLEL,
            max_peers: DEFAULT_MAX_PEERS,
            auto_connect: true,
            auto_retry: true,
            dht_config: DhtConfig::default(),
        }
    }
}

impl SwarmConfig {
    /// Create a new config with the given DHT configuration
    pub fn new(dht_config: DhtConfig) -> Self {
        Self {
            dht_config,
            ..Default::default()
        }
    }

    /// Set maximum parallel connection attempts
    pub fn max_parallel(mut self, n: usize) -> Self {
        self.max_parallel = n;
        self
    }

    /// Set maximum total peer connections
    pub fn max_peers(mut self, n: usize) -> Self {
        self.max_peers = n;
        self
    }

    /// Enable or disable auto-connect to discovered peers
    pub fn auto_connect(mut self, enabled: bool) -> Self {
        self.auto_connect = enabled;
        self
    }

    /// Enable or disable auto-retry of failed connections
    pub fn auto_retry(mut self, enabled: bool) -> Self {
        self.auto_retry = enabled;
        self
    }

    /// Add a bootstrap node
    pub fn add_bootstrap_node(mut self, addr: std::net::SocketAddr) -> Self {
        self.dht_config = self.dht_config.add_bootstrap_node(addr);
        self
    }
}

impl From<DhtConfig> for SwarmConfig {
    fn from(dht_config: DhtConfig) -> Self {
        Self::new(dht_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SwarmConfig::default();
        assert_eq!(config.max_parallel, DEFAULT_MAX_PARALLEL);
        assert_eq!(config.max_peers, DEFAULT_MAX_PEERS);
        assert!(config.auto_connect);
        assert!(config.auto_retry);
    }

    #[test]
    fn test_builder_pattern() {
        let config = SwarmConfig::default()
            .max_parallel(5)
            .max_peers(100)
            .auto_connect(false);

        assert_eq!(config.max_parallel, 5);
        assert_eq!(config.max_peers, 100);
        assert!(!config.auto_connect);
    }
}
