//! Hyperswarm - Peer-to-peer networking with topic-based discovery

#![warn(
    redundant_lifetimes,
    non_local_definitions,
    clippy::needless_pass_by_ref_mut,
    clippy::enum_glob_use
)]

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use dht_rpc::{Commit, IdBytes};
use futures::StreamExt;
use hyperdht::adht::Dht;
use tracing::debug;

mod connection_set;
mod error;
mod peer_info;

pub use connection_set::{AddResult, ConnectionInfo, ConnectionSet};
pub use error::{Error, Result};
pub use peer_info::{PeerInfo, Priority};

// Re-export from dependencies
pub use dht_rpc::{DhtConfig, IdBytes as Topic};
pub use hyperdht::Keypair;

/// Options for joining a topic
#[derive(Debug, Clone, Copy, Default)]
pub struct JoinOpts {
    /// Announce self on DHT (server mode)
    pub server: bool,
    /// Lookup peers on DHT (client mode)
    pub client: bool,
}

impl JoinOpts {
    pub fn server() -> Self {
        Self {
            server: true,
            client: false,
        }
    }
    pub fn client() -> Self {
        Self {
            server: false,
            client: true,
        }
    }
    pub fn both() -> Self {
        Self {
            server: true,
            client: true,
        }
    }
}

/// Tracks discovery state for a topic
#[derive(Debug)]
struct Discovery {
    #[allow(dead_code)]
    topic: IdBytes,
    #[allow(dead_code)]
    server: bool,
    #[allow(dead_code)]
    client: bool,
}

/// The main Hyperswarm instance
pub struct Swarm {
    inner: Arc<RwLock<SwarmInner>>,
}

struct SwarmInner {
    dht: Dht,
    keypair: Keypair,
    destroyed: bool,
    listening: bool,
    connections: ConnectionSet,
    peers: HashMap<IdBytes, PeerInfo>,
    discoveries: HashMap<IdBytes, Discovery>,
}

impl Swarm {
    /// Create a new Swarm with the given DHT config
    pub async fn new(dht_config: DhtConfig) -> Result<Self> {
        let keypair = Keypair::default();
        let dht = Dht::with_config(dht_config).await?;

        Ok(Self {
            inner: Arc::new(RwLock::new(SwarmInner {
                dht,
                keypair,
                destroyed: false,
                listening: false,
                connections: ConnectionSet::new(),
                peers: HashMap::new(),
                discoveries: HashMap::new(),
            })),
        })
    }

    /// Create with default config
    pub async fn default_config() -> Result<Self> {
        Self::new(DhtConfig::default()).await
    }

    /// Get the swarm's public key
    pub fn public_key(&self) -> IdBytes {
        let inner = self.inner.read().unwrap();
        IdBytes(*inner.keypair.public)
    }

    /// Get a clone of the keypair
    pub fn keypair(&self) -> Keypair {
        self.inner.read().unwrap().keypair.clone()
    }

    /// Check if destroyed
    pub fn destroyed(&self) -> bool {
        self.inner.read().unwrap().destroyed
    }

    /// Check if listening for connections
    pub fn listening(&self) -> bool {
        self.inner.read().unwrap().listening
    }

    /// Start listening for incoming connections
    /// Returns a Server stream that yields connections
    pub fn listen(&self) -> Result<hyperdht::Server> {
        let mut inner = self.inner.write().unwrap();
        if inner.destroyed {
            return Err(Error::Destroyed);
        }
        inner.listening = true;
        let server = inner.dht.listen(inner.keypair.clone());
        Ok(server)
    }

    /// Number of connections
    pub fn connections_count(&self) -> usize {
        self.inner.read().unwrap().connections.len()
    }

    /// Number of known peers
    pub fn peers_count(&self) -> usize {
        self.inner.read().unwrap().peers.len()
    }

    /// Join a topic for peer discovery
    pub fn join(&self, topic: IdBytes, opts: JoinOpts) -> Result<()> {
        let (lookup, announce) = {
            let mut inner = self.inner.write().unwrap();
            if inner.destroyed {
                return Err(Error::Destroyed);
            }

            let discovery = Discovery {
                topic,
                server: opts.server,
                client: opts.client,
            };
            inner.discoveries.insert(topic, discovery);

            let lookup = if opts.client {
                Some(inner.dht.lookup(topic, Commit::No)?)
            } else {
                None
            };

            let announce = if opts.server {
                Some(inner.dht.announce(topic, inner.keypair.clone(), vec![]))
            } else {
                None
            };

            (lookup, announce)
        };

        // Spawn task to drive the lookup
        if let Some(mut lookup) = lookup {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                while let Some(result) = lookup.next().await {
                    match result {
                        Ok(Some(response)) => {
                            let mut guard = inner.write().unwrap();
                            if !guard.discoveries.contains_key(&topic) {
                                break;
                            }
                            for peer in response.peers {
                                let pk = IdBytes(*peer.public_key);
                                debug!(?pk, "discovered peer");
                                guard.peers.entry(pk).or_insert_with(|| {
                                    let mut info = PeerInfo::new(pk);
                                    info.add_topic(topic);
                                    info
                                });
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            debug!(?e, "lookup error");
                        }
                    }
                }
            });
        }

        // Spawn task to drive the announce
        if let Some(announce) = announce {
            tokio::spawn(async move {
                match announce.await {
                    Ok(()) => debug!(?topic, "announced"),
                    Err(e) => debug!(?topic, ?e, "announce error"),
                }
            });
        }

        Ok(())
    }

    /// Leave a topic
    pub fn leave(&self, topic: &IdBytes) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        if inner.destroyed {
            return Err(Error::Destroyed);
        }

        inner.discoveries.remove(topic);
        // TODO: Unannounce if was server
        Ok(())
    }

    /// Check if joined to a topic
    pub fn has_topic(&self, topic: &IdBytes) -> bool {
        self.inner.read().unwrap().discoveries.contains_key(topic)
    }

    /// Get number of active topic discoveries
    pub fn topics_count(&self) -> usize {
        self.inner.read().unwrap().discoveries.len()
    }

    /// Destroy the swarm
    pub fn destroy(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.destroyed = true;
        inner.discoveries.clear();
    }
}

impl Clone for Swarm {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_swarm() {
        let swarm = Swarm::default_config().await.unwrap();
        assert!(!swarm.destroyed());
        assert_eq!(swarm.connections_count(), 0);
    }

    #[tokio::test]
    async fn test_join_leave() {
        let swarm = Swarm::default_config().await.unwrap();
        let topic = IdBytes::random();

        assert!(!swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 0);

        swarm.join(topic, JoinOpts::both()).unwrap();
        assert!(swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 1);

        swarm.leave(&topic).unwrap();
        assert!(!swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 0);
    }

    #[tokio::test]
    async fn test_join_after_destroy_fails() {
        let swarm = Swarm::default_config().await.unwrap();
        swarm.destroy();

        let topic = IdBytes::random();
        let result = swarm.join(topic, JoinOpts::client());
        assert!(result.is_err());
    }
}
