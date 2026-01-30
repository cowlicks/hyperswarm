//! Pure-Rust tests for DHT query handlers (on_announce, on_lookup, on_find_peer, on_unannounce).
//!
//! These tests use a pure-Rust swarm without JavaScript dependencies.

use std::{net::SocketAddr, time::Duration};

use dht_rpc::{Commit, DhtConfig, IdBytes, generic_hash};
use futures::StreamExt;
use hyperdht::{Keypair, adht::Dht};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A pure-Rust DHT testnet for testing query handlers.
pub struct RustTestnet {
    /// The bootstrap node - other nodes connect through this
    pub bootstrap: Dht,
    pub bootstrap_addr: SocketAddr,
    /// Additional DHT nodes in the swarm
    pub nodes: Vec<Dht>,
}

impl RustTestnet {
    /// Create a new testnet with the specified number of nodes (in addition to the bootstrap node).
    pub async fn new(node_count: usize) -> Result<Self> {
        // Create bootstrap node bound to localhost with no external bootstrap
        let mut bootstrap = Dht::with_config(
            DhtConfig::default()
                .empty_bootstrap_nodes()
                .bind("127.0.0.1:0")?,
        )
        .await?;
        let bootstrap_addr = bootstrap.local_addr()?;
        bootstrap.drive();

        // Create additional nodes that bootstrap from the first
        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let mut node = Dht::with_config(
                DhtConfig::default()
                    .add_bootstrap_node(bootstrap_addr)
                    .bind("127.0.0.1:0")?,
            )
            .await?;
            node.bootstrap().await?;
            node.drive();
            nodes.push(node);
        }

        // Allow routing tables to stabilize
        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(Self {
            bootstrap,
            bootstrap_addr,
            nodes,
        })
    }
}

/// Test on_announce and on_lookup: one node announces, another looks up.
#[tokio::test]
async fn rs_swarm_announce_lookup() -> Result<()> {
    let tn = RustTestnet::new(3).await?;
    let announcer = &tn.nodes[0];
    let looker = &tn.nodes[1];

    let topic = IdBytes(generic_hash(b"test-topic"));
    let keypair = Keypair::default();

    // Announcer announces to the swarm
    announcer.announce(topic, keypair.clone(), vec![]).await?;

    // Looker does lookup
    let mut lookup = looker.lookup(topic, Commit::No)?;
    let mut found_keys = vec![];
    while let Some(result) = lookup.next().await {
        if let Ok(Some(resp)) = result {
            found_keys.extend(resp.peers.iter().map(|p| p.public_key.clone()));
        }
    }

    assert!(
        found_keys.contains(&keypair.public),
        "Expected to find announced public key in lookup results"
    );

    Ok(())
}

/// Test on_find_peer: server listens (self-announce), client finds.
#[tokio::test]
async fn rs_swarm_find_peer() -> Result<()> {
    let tn = RustTestnet::new(3).await?;
    let server = &tn.nodes[0];
    let client = &tn.nodes[1];

    let keypair = Keypair::default();
    let _listener = server.listen(keypair.clone()).await?;

    // Wait for announce to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client does find_peer
    let mut query = client.find_peer(&keypair.public, None)?;
    let mut found = false;
    while let Some(Ok(Some(resp))) = query.next().await {
        if resp.peer.public_key == keypair.public {
            found = true;
            break;
        }
    }

    assert!(found, "Expected to find server's public key via find_peer");

    Ok(())
}

/// Test on_unannounce: announce, verify found, unannounce, verify gone.
#[tokio::test]
async fn rs_swarm_unannounce() -> Result<()> {
    let tn = RustTestnet::new(3).await?;
    let announcer = &tn.nodes[0];
    let looker = &tn.nodes[1];

    let topic = IdBytes(generic_hash(b"unannounce-topic"));
    let keypair = Keypair::default();

    // Step 1: Announce
    announcer.announce(topic, keypair.clone(), vec![]).await?;

    // Step 2: Verify found via lookup
    let mut lookup = looker.lookup(topic, Commit::No)?;
    let mut found_before = false;
    while let Some(Ok(Some(resp))) = lookup.next().await {
        if resp.peers.iter().any(|p| p.public_key == keypair.public) {
            found_before = true;
            break;
        }
    }
    assert!(found_before, "Expected to find key after announce");

    // Step 3: Unannounce
    announcer.unannounce(topic, keypair.clone()).await?;

    // Step 4: Verify gone via lookup
    let mut lookup = looker.lookup(topic, Commit::No)?;
    let mut found_after = false;
    while let Some(Ok(Some(resp))) = lookup.next().await {
        if resp.peers.iter().any(|p| p.public_key == keypair.public) {
            found_after = true;
            break;
        }
    }
    assert!(!found_after, "Expected key to be gone after unannounce");

    Ok(())
}
