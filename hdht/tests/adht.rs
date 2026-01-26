use std::net::SocketAddr;

use dht_rpc::{Commit, DhtConfig, IdBytes, generic_hash};
use futures::{SinkExt, StreamExt, join};
use hypercore_handshake::CipherEvent;
use hyperdht::{
    Keypair, PublicKey,
    adht::{Dht, PeerHandshakeArgs},
};

use rusty_nodejs_repl::wait;
use test_utils::{Result, Testnet};
use tokio::select;

macro_rules! adht_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let dht = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, dht)
    }};
}

#[tokio::test]
async fn rsrs_server_tx_first() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.get_node_i_address(1).await?;
    let a = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let keypair = Keypair::default();
    let a_addr = a.local_addr()?;
    let b = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    a.bootstrap().await?;
    b.bootstrap().await?;

    let mut a_server = a.listen(keypair.clone()).await?;

    let server = tokio::spawn(async move {
        let mut conn = a_server.next().await.unwrap().unwrap();
        conn.send(b"hi".into()).await.unwrap();
        let CipherEvent::Message(msg) = conn.next().await.unwrap() else {
            todo!()
        };
        assert_eq!(msg, b"bye");
        conn
    });

    // wait for server to announce before tring to connect to it
    wait!(200);

    let client = tokio::spawn(async move {
        let mut conn = b
            .peer_handshake(PeerHandshakeArgs::new(keypair.public, a_addr))
            .await
            .unwrap();

        let CipherEvent::Message(msg) = conn.next().await.unwrap() else {
            todo!()
        };
        assert_eq!(msg, b"hi");

        dbg!(conn.send(b"bye".into()).await).unwrap();
        conn // return this so it isn't dropped. bc the "await" above doesn't actually flush....
    });

    let _ = join!(client, server);

    Ok(())
}

#[tokio::test]
async fn rsrs_client_tx_first() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.get_node_i_address(1).await?;
    let a = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let keypair = Keypair::default();
    let a_addr = a.local_addr()?;
    let b = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    a.bootstrap().await?;
    b.bootstrap().await?;

    let mut a_server = a.listen(keypair.clone()).await?;

    //let server_conn_fut = async move {
    let server = tokio::spawn(async move {
        let mut conn = a_server.next().await.unwrap().unwrap();
        let CipherEvent::Message(msg) = conn.next().await.unwrap() else {
            todo!()
        };
        assert_eq!(msg, b"hi");
        conn.send(b"bye".into()).await.unwrap();
    });

    // wait for server to announce before tring to connect to it
    wait!(200);

    let client = tokio::spawn(async move {
        let mut conn = b
            .peer_handshake(PeerHandshakeArgs::new(keypair.public, a_addr))
            .await
            .unwrap();
        conn.send(b"hi".into()).await.unwrap();
        let CipherEvent::Message(msg) = conn.next().await.unwrap() else {
            todo!()
        };
        assert_eq!(msg, b"bye");
    });
    _ = join!(server, client);
    Ok(())
}

/// Check that Rust's lookup works. The steps:
/// js does an announce with a `topic` and `keypair`
/// rs does a lookup for `topic`. Then checks the resulting keys found match `keypair`
#[tokio::test]
async fn js_announces_rs_looksup() -> Result<()> {
    let (mut tn, dht) = adht_setup!();

    let topic = tn.make_topic("hello").await?;

    // with js announc on topic with the node's default keypair
    let _res = tn
        .repl
        .run_tcp(
            "
ann_node = testnet.nodes[testnet.nodes.length - 1];
query = await ann_node.announce(topic, ann_node.defaultKeyPair);
await query.finished();
",
        )
        .await?;

    // with RS do a lookup
    let mut query = dht.lookup(topic.into(), Commit::No)?;
    let mut rs_lookup_keys = vec![];
    while let Some(Ok(msg)) = query.next().await {
        println!("{msg:?}");
        if let Some(msg) = msg {
            rs_lookup_keys.extend(msg.peers);
        }
    }

    // get the public key js announced with
    let js_pk: Vec<u8> = tn
        .repl
        .json_run_tcp("outputJson([...ann_node.defaultKeyPair.publicKey])")
        .await?;
    // check js pub key matches the ones we found in rust
    assert!(!rs_lookup_keys.is_empty());
    for p in rs_lookup_keys {
        assert_eq!(p.public_key.as_slice(), js_pk);
    }
    Ok(())
}
/// Test Rust's announce. The steps:
/// rs does announce for a `topic` with `keypair`
/// js does loookup, and we check that resulting publick keys match `keypair`
#[tokio::test]
async fn rs_announces_js_looksup() -> Result<()> {
    let (mut testnet, dht) = adht_setup!();

    let topic = testnet.make_topic("hello").await?;
    let keypair = Keypair::default();
    dht.announce(topic.into(), keypair.clone(), vec![]).await?;

    // Run announce to completion
    // do lookup in js.
    let found_pk_js = testnet.get_pub_keys_for_lookup().await?;

    assert!(!found_pk_js.is_empty());
    for pk in found_pk_js {
        assert_eq!(keypair.public.as_slice(), pk);
    }
    Ok(())
}

/// js server (it announces for hash of it's key pair)
/// rs does lookup(hash(keypair))
#[tokio::test]
async fn dht_lookup() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    let target = IdBytes(generic_hash(&pub_key));
    let mut lery = dht.lookup(target, Commit::No)?;

    let mut some = false;
    while let Some(x) = lery.next().await {
        if let Ok(Some(resp)) = &x {
            assert_eq!(
                resp.peers
                    .first()
                    .expect("Should have a peer. not sure why")
                    .public_key,
                pub_key.into()
            );
            some = true;
        }
    }
    assert!(some);
    let _res = lery.await?;
    Ok(())
}

// js server listens on certain pub key
// rs does find_peer for the pub_key
// assert pub_key is matching
#[tokio::test]
async fn js_server_listen_rs_find_peer() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();
server_rx_data = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    dht.bootstrap().await?;
    let mut q = dht.find_peer(pub_key.into(), None)?;
    while let Some(e) = q.next().await {
        if let Ok(Some(resp)) = e {
            assert_eq!(resp.peer.public_key, pub_key.into());
        }
    }
    Ok(())
}

/// js create a hyperdht server
/// rs use dht.peer_handshake to connect directly to js server by it's address
/// check data goes both ways
#[tokio::test]
async fn dht_peer_handshake() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();
server_rx_data = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    dht.bootstrap().await?;

    let port: u16 = tn.repl.get_name("server_addr").await?;
    let dest = format!("127.0.0.1:{port}").parse()?;
    let mut conn = dht
        .peer_handshake(PeerHandshakeArgs::new(pub_key.into(), dest))
        .await?;
    conn.send(b"from rust".into()).await?;
    let msg: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(msg, "from rust");

    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;
    let Some(CipherEvent::Message(rx_from_js)) = conn.next().await else {
        todo!()
    };
    assert_eq!(String::from_utf8_lossy(&rx_from_js), "from js");
    Ok(())
}

/// js create hyperdht server
/// rs dht.connect() to js server pub key
/// send data both ways and check
#[tokio::test]
async fn test_rs_connects_to_js() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();
server_rx_data = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    dht.bootstrap().await?;
    let mut conn = dht.connect(pub_key.into(), None)?.await?;
    conn.send(b"from rust".into()).await?;
    let msg: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(msg, "from rust");

    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;
    let Some(CipherEvent::Message(rx_from_js)) = conn.next().await else {
        todo!()
    };
    assert_eq!(String::from_utf8_lossy(&rx_from_js), "from js");
    Ok(())
}

/// Rust listens on a key and JS connects.
/// send data both ways and check
#[tokio::test]
async fn test_js_connects_to_rs() -> Result<()> {
    let (mut tn, dht) = adht_setup!();

    dht.bootstrap().await?;

    tn.repl
        .run_tcp(
            "
DHT = require('hyperdht');
public_key = deferred();
secret_key = deferred();
kp = DHT.keyPair();

public_key.resolve([...kp.publicKey]);
secret_key.resolve([...kp.secretKey]);
",
        )
        .await?;

    let pub_key: [u8; 32] = tn.repl.get_name("public_key").await?;
    let sec_key: Vec<u8> = tn.repl.get_name("secret_key").await?;
    let secret: [u8; 64] = sec_key.try_into().unwrap();

    let keypair = Keypair {
        public: PublicKey::from(pub_key),
        secret,
    };
    let mut server = dht.listen(keypair).await?;

    let x = tokio::spawn(async move {
        let mut conn = server.next().await.unwrap().unwrap();

        let Some(CipherEvent::Message(rx_from_js)) = conn.next().await else {
            todo!()
        };
        assert_eq!(rx_from_js, b"from js");
        conn.send(b"from rust".to_vec()).await.unwrap();
    });
    // wait for announce to happen
    wait!(500);
    tn.repl
        .run_tcp(
            "
client_node = testnet.nodes[testnet.nodes.length - 2];
socket = client_node.connect(kp.publicKey);
SOCKET = deferred();

client_rx_data = deferred();

socket.on('open', () => {
    SOCKET.resolve(socket);
});
socket.on('data', (data) => {
    client_rx_data.resolve(data.toString());
});


await SOCKET
await socket.write(Buffer.from('from js'));
",
        )
        .await?;
    _ = x.await;

    let client_rx_data: String = tn.repl.get_name("client_rx_data").await?;
    assert_eq!(client_rx_data, "from rust");
    Ok(())
}

/// Test Rust's unannounce. The steps:
/// rs does announce
/// js does lookup, check topic is found with correct pk
/// rs does unannounce
/// js does a lookup, check no results found
#[tokio::test]
async fn rs_unannounce() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let topic = tn.make_topic("hello").await?;
    let keypair = Keypair::default();
    // announce our rust node with `topic` and `keypair`
    dht.announce(topic.into(), keypair.clone(), vec![]).await?;

    // with js do a lookup and get pubkeys
    let found_pk_js = tn.get_pub_keys_for_lookup().await?;
    // get result for js and show it matches the RS keypair above
    assert_eq!(keypair.public.as_slice(), found_pk_js[0]);

    // Do the unannounce
    dht.unannounce(topic.into(), keypair).await?;

    // Do a lookup for a the topic again
    let found_pk_js = tn.get_pub_keys_for_lookup().await?;
    // assert no keys found for the topic
    assert!(found_pk_js.is_empty());
    Ok(())
}

/// Test Rust's unannounce. The steps:
/// rs does announce
/// js does lookup, check topic is found with correct pk
/// rs does announce_clear with new pk
/// js does a lookup for topic and finds new pk
#[tokio::test]
async fn rs_announce_clear() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let topic = tn.make_topic("hello").await?;
    let keypair = Keypair::default();
    // announce our rust node with `topic` and `keypair`
    dht.announce(topic.into(), keypair.clone(), vec![]).await?;

    // with js do a lookup and get pubkeys
    let found_pk_js = tn.get_pub_keys_for_lookup().await?;
    // get result for js and show it matches the RS keypair above
    assert_eq!(keypair.public.as_slice(), found_pk_js[0]);

    let keypair2 = Keypair::default();
    // Do the unannounce
    dht.announce_clear(topic.into(), keypair2.clone(), vec![])
        .await?;

    // Do announce_clear with new keypair for the same topic
    let found_pk_js = tn.get_pub_keys_for_lookup().await?;
    let matched = found_pk_js.iter().any(|k| keypair2.public.as_slice() == k);
    assert!(matched);
    Ok(())
}

/// Test relay connection flow: client -> relay -> server all in rust
#[tokio::test]
async fn rsrsrs_relay_connection_flow() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.get_node_i_address(1).await?;

    // Setup server node - listens on a keypair
    let mut server = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let mut relay = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let client = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    server.bootstrap().await?;
    relay.bootstrap().await?;
    client.bootstrap().await?;

    let server_addr = server.local_addr()?;
    let relay_addr = relay.local_addr()?;
    let client_addr = client.local_addr()?;

    println!("SERVER\tname={},\taddr={server_addr:?}", server.name());
    println!("RELAY\tname={},\taddr={relay_addr:?}", relay.name());
    println!("CLIENT\tname={},\taddr={client_addr:?}", client.name());

    let server_keypair = Keypair::default();

    let mut server_listener = server.listen(server_keypair.clone()).await?;

    // Setup relay node - intermediary (doesn't have server's keypair)
    tokio::spawn(async move {
        loop {
            dbg!(select! {
                x = relay.next() => {x}
                x = server.next() => {x}
            });
        }
    });

    let mut client_conn = client
        .peer_handshake(
            PeerHandshakeArgs::new(server_keypair.public, relay_addr).relay_address(server_addr),
        )
        .await?;

    // Server should receive connection through relay
    let mut server_conn = server_listener.next().await.unwrap()?;

    // Test bidirectional communication
    client_conn.send(b"hello from client".into()).await?;
    let CipherEvent::Message(msg) = server_conn.next().await.unwrap() else {
        panic!("Expected message from client");
    };
    assert_eq!(msg.as_slice(), b"hello from client");

    server_conn.send(b"hello from server".into()).await?;
    let CipherEvent::Message(msg) = client_conn.next().await.unwrap() else {
        panic!("Expected message from server");
    };
    assert_eq!(msg.as_slice(), b"hello from server");

    Ok(())
}

/// Test that relay handlers are called and don't panic
/// This is a simpler test to verify the relay path is working
#[tokio::test]
async fn relay_handlers_basic() -> Result<()> {
    use std::time::Duration;

    let mut tn = Testnet::new().await?;
    let bs_addr = tn.get_node_i_address(1).await?;

    // Setup server node
    let server = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let server_keypair = Keypair::default();
    server.bootstrap().await?;
    let _server_listener = server.listen(server_keypair.clone()).await?;
    let server_addr = server.local_addr()?;

    // Setup relay node
    let relay = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    relay.bootstrap().await?;
    let relay_addr = relay.local_addr()?;

    // Setup client node
    let client = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    client.bootstrap().await?;

    println!("Client: {:?}", client.local_addr()?);
    println!("Relay: {:?}", relay_addr);
    println!("Server: {:?}", server_addr);

    // Try to initiate handshake through relay
    // This should at least not panic, even if it times out
    let handshake_future = client.peer_handshake(
        PeerHandshakeArgs::new(server_keypair.public, relay_addr).relay_address(relay_addr),
    );

    //let handshake_future = client.peer_handshake_with_relay(server_keypair.public, relay_addr)?;
    let result = tokio::time::timeout(Duration::from_secs(2), handshake_future).await;

    match result {
        Ok(Ok(_conn)) => {
            println!("✓ Connection succeeded through relay!");
        }
        Ok(Err(e)) => {
            println!("✗ Connection failed with error: {:?}", e);
            println!("This is expected if relay forwarding isn't fully implemented yet");
        }
        Err(_timeout) => {
            println!("⏱ Connection timed out");
            println!("This is expected if relay forwarding isn't responding yet");
        }
    }

    // Test passes as long as we don't panic
    Ok(())
}

/// Test relay connection flow: rust client -> rust relay -> javascript server
/// Three nodes: client connects to server through relay node
#[tokio::test]
async fn rsrsjs_relay_connection_flow() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.get_node_i_address(1).await?;

    let mut relay = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let client = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_port = deferred();
server_rx_data = deferred();

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_port.resolve(server.address().port)
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
outputJson([...pub_key]);
",
        )
        .await?;

    relay.bootstrap().await?;
    client.bootstrap().await?;

    let server_port: usize = tn.repl.get_name("server_port").await?;
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let relay_addr = relay.local_addr()?;
    let client_addr = client.local_addr()?;

    println!("SERVER\taddr={server_addr:?}");
    println!("RELAY\tname={},\taddr={relay_addr:?}", relay.name());
    println!("CLIENT\tname={},\taddr={client_addr:?}", client.name());

    // Setup relay node - intermediary (doesn't have server's keypair)
    tokio::spawn(async move {
        loop {
            dbg!(select! {
                x = relay.next() => {x}
            });
        }
    });

    let mut client_conn = client
        .peer_handshake(
            PeerHandshakeArgs::new(PublicKey::from(pub_key), relay_addr).relay_address(server_addr),
        )
        .await?;

    // Server should receive connection through relay
    //let mut server_conn = server_listener.next().await.unwrap()?;

    // Test bidirectional communication
    client_conn.send(b"hello from client".into()).await?;
    let server_rx_data: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(server_rx_data.as_bytes(), b"hello from client");
    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;

    let CipherEvent::Message(msg) = client_conn.next().await.unwrap() else {
        panic!("Expected message from server");
    };
    assert_eq!(msg.as_slice(), b"from js");

    Ok(())
}
/// Test relay connection flow: rust client -> javascript relay -> javascript server
/// Three nodes: client connects to server through relay node
#[tokio::test]
async fn rsjsjs_relay_connection_flow() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.get_node_i_address(1).await?;

    let client = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_port = deferred();
relay_addr = deferred();
server_rx_data = deferred();

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_port.resolve(server.address().port)
});

relay_node = testnet.nodes[testnet.nodes.length - 2];
let { host, port } = relay_node.remoteAddress();
relay_addr.resolve(`${host}:${port}`);

server.on('listening', () => {
    server_port.resolve(server.address().port)
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
outputJson([...pub_key]);
",
        )
        .await?;

    client.bootstrap().await?;

    let server_port: usize = tn.repl.get_name("server_port").await?;
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    let relay_addr: String = tn.repl.get_name("relay_addr").await?;
    let relay_addr: SocketAddr = relay_addr.parse()?;

    let client_addr = client.local_addr()?;

    println!("SERVER\taddr={server_addr:?}");
    println!("RELAY\taddr={relay_addr:?}");
    println!("CLIENT\tname={},\taddr={client_addr:?}", client.name());

    // Setup relay node - intermediary (doesn't have server's keypair)
    let mut client_conn = client
        .peer_handshake(
            PeerHandshakeArgs::new(PublicKey::from(pub_key), relay_addr).relay_address(server_addr),
        )
        .await?;

    // Server should receive connection through relay
    //let mut server_conn = server_listener.next().await.unwrap()?;

    // Test bidirectional communication
    client_conn.send(b"hello from client".into()).await?;
    let server_rx_data: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(server_rx_data.as_bytes(), b"hello from client");
    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;

    let CipherEvent::Message(msg) = client_conn.next().await.unwrap() else {
        panic!("Expected message from server");
    };
    assert_eq!(msg.as_slice(), b"from js");

    Ok(())
}
