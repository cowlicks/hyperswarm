//! Integration tests for hyperswarm

mod common;

use common::{Result, Testnet};
use dht_rpc::IdBytes;
use futures::{SinkExt, StreamExt, join};
use hypercore_handshake::CipherEvent;
use hyperswarm::{DhtConfig, JoinOpts, Swarm};

/// Server announces and client discovers via lookup
#[tokio::test]
async fn server_announces_client_discovers_foo() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server = swarm_a.listen()?;
    swarm_a.join(topic, JoinOpts::server())?;

    // Wait for announce to propagate
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Swarm B: client - discovers peers on topic
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.join(topic, JoinOpts::client())?;

    // Wait for lookup to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // B should have discovered A
    assert!(
        swarm_b.peers_count() > 0,
        "swarm_b should have discovered peers"
    );

    Ok(())
}

/// Multiple servers announce, client discovers all
#[tokio::test]
async fn multiple_servers_discovered() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Create two servers announcing on same topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_a = swarm_a.listen()?;
    swarm_a.join(topic, JoinOpts::server())?;

    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_b = swarm_b.listen()?;
    swarm_b.join(topic, JoinOpts::server())?;

    // Wait for announces
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Client discovers
    let swarm_c = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_c.join(topic, JoinOpts::client())?;

    // Wait for lookup
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // C should have found both A and B
    let peers = swarm_c.peers_count();
    assert!(
        peers >= 2,
        "should discover multiple peers, found {}",
        peers
    );

    Ok(())
}

/// Two peers connect and exchange messages
#[tokio::test]
async fn peers_connect_and_exchange_messages() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_a.bootstrap().await?;
    let mut server_a = swarm_a.listen()?;
    let server_addr = swarm_a.local_addr()?;
    swarm_a.join(topic, JoinOpts::server())?;

    // Swarm B: client - connects to A directly using known address and public key
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.bootstrap().await?;
    let server_pub_key = swarm_a.keypair().public;

    // Run connect and accept in parallel
    let (mut client_conn, mut server_conn) = join!(
        async {
            swarm_b
                .peer_handshake(server_pub_key.clone(), server_addr)
                .unwrap()
                .await
                .unwrap()
        },
        async { server_a.next().await.unwrap().unwrap() }
    );

    // Server sends first
    server_conn.send(b"hello from server".into()).await?;
    let CipherEvent::Message(msg) = client_conn.next().await.unwrap() else {
        panic!("Expected message from server");
    };
    assert_eq!(msg.as_slice(), b"hello from server");

    // Client sends back
    client_conn.send(b"hello from client".into()).await?;
    let CipherEvent::Message(msg) = server_conn.next().await.unwrap() else {
        panic!("Expected message from client");
    };
    assert_eq!(msg.as_slice(), b"hello from client");

    Ok(())
}
