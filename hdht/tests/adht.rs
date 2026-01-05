mod common;

use dht_rpc::{Commit, DhtConfig, IdBytes, generic_hash};
use futures::{SinkExt, StreamExt};
use hypercore_handshake::CipherEvent;
use hyperdht::{Error, Keypair, adht::Dht};

use common::{Result, log, setup::Testnet};

macro_rules! adht_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let rpc = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, rpc)
    }};
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
    log();
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
    let mut q = dht.find_peer(pub_key.into())?;
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
    let mut conn = dht.peer_handshake(pub_key.into(), dest)?.await?;
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
async fn test_dht_connect() -> Result<()> {
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
    let mut conn = dht.connect(pub_key.into()).await?;
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

/// Test Rust's unannounce. The steps:
/// rs does announce
/// js does lookup, check topic is found with correct pk
/// rs does unannounce
/// js does a lookup, check no results found
#[tokio::test]
async fn rs_unannounce() -> Result<()> {
    let (mut tn, mut dht) = adht_setup!();
    let topic = tn.make_topic("hello").await?;
    let keypair = Keypair::default();
    log();
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
    log();
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

/// js do service listen
/// rs do find_peer
/// choose a peer that isn't server that can relay
/// do handshake to that peer
#[ignore]
#[tokio::test]
async fn relay_test() -> Result<()> {
    todo!()
}
