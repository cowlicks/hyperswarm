//! Integration tests for hyperswarm

use dht_rpc::IdBytes;
use futures::{SinkExt, StreamExt, join};
use hypercore_handshake::CipherEvent;
use hyperswarm::{DhtConfig, JoinOpts, Swarm, SwarmConfig};
use test_utils::{Result, Testnet};

macro_rules! timeout {
    ($fut:expr, $ms:expr) => {{
        let connection_result =
            tokio::time::timeout(std::time::Duration::from_millis($ms), $fut).await;
        connection_result
    }};
    ($fut:expr) => {{
        let out = timeout!($fut, 300);
        out
    }};
}
/// Server announces and client discovers via lookup
#[tokio::test]
async fn server_announces_client_discovers_foo() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server = swarm_a.listen()?;
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Swarm B: client - discovers peers on topic
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

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
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_b = swarm_b.listen()?;
    swarm_b.join(topic, JoinOpts::Server)?;
    swarm_b.flush().await?;

    // Client discovers
    let swarm_c = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_c.join(topic, JoinOpts::Client)?;
    swarm_c.flush().await?;

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
    let mut server_a = swarm_a.listen()?.await?;
    let server_addr = swarm_a.local_addr()?;
    swarm_a.join(topic, JoinOpts::Server)?;

    // Swarm B: client - connects to A directly using known address and public key
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.bootstrap().await?;
    let server_pub_key = swarm_a.keypair().public;

    // Run connect and accept in parallel
    let (mut client_conn, mut server_conn) = join!(
        async {
            swarm_b
                .peer_handshake(server_pub_key.clone(), server_addr)
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

/// Test that discovery finds peers and enqueues them for connection
#[tokio::test]
async fn discovery_enqueues_peers_for_connection() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let config_a = SwarmConfig::new(DhtConfig::default().add_bootstrap_node(bs_addr));
    let swarm_a = Swarm::with_config(config_a).await?;
    swarm_a.bootstrap().await?;
    let _server_a = swarm_a.listen()?;
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Swarm B: client with auto-connect enabled (default)
    let config_b = SwarmConfig::new(DhtConfig::default().add_bootstrap_node(bs_addr));
    let swarm_b = Swarm::with_config(config_b).await?;
    swarm_b.bootstrap().await?;

    // Join as client - should auto-discover peers
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

    // Should have discovered the server peer
    assert!(
        swarm_b.peers_count() > 0,
        "client should have discovered at least one peer"
    );

    Ok(())
}

/// Test that auto-connect actually establishes connections to discovered peers
#[tokio::test]
async fn auto_connect_establishes_connection() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    swarm_a.bootstrap().await?;
    swarm_b.bootstrap().await?;

    let mut server = swarm_a.listen()?.await?;
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Get connection stream to receive auto-connect events
    let mut connections = swarm_b.connections();

    // Join as client - should auto-discover and auto-connect
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

    let Some(Ok(mut server_conn)) = timeout!(server.next())? else {
        todo!()
    };
    let Some(Ok(client_event)) = timeout!(connections.next())? else {
        todo!()
    };

    let mut client_conn = client_event.connection;

    // Test bidirectional communication
    server_conn.send(b"from server".into()).await?;
    let Some(CipherEvent::Message(msg)) = client_conn.next().await else {
        todo!()
    };
    assert_eq!(msg, b"from server");
    client_conn.send(b"from client".into()).await?;

    let Some(CipherEvent::Message(msg)) = server_conn.next().await else {
        todo!()
    };
    assert_eq!(msg, b"from client");
    Ok(())
}
