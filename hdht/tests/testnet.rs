#![allow(unreachable_code)]
mod common;
use compact_encoding::CompactEncoding;
use std::net::SocketAddr;

use common::{js::make_repl, Result};
use dht_rpc::DhtConfig;
use futures::StreamExt;
use hypercore_protocol::{handshake_constants::DHT_PATTERN, HandshakeConfig};
use hyperdht::{
    cenc::{NoisePayload, UdxInfo},
    namespace::PEER_HANDSHAKE,
    HyperDht, HyperDhtEvent, Keypair,
};
use rusty_nodejs_repl::Repl;

#[allow(unused)]
fn show_bytes<T: AsRef<[u8]>>(x: T) {
    println!("{}", String::from_utf8(x.as_ref().to_vec()).unwrap())
}

macro_rules! get_pub_keys_for_lookup {
    ($testnet:tt) => {{
        get_pub_keys_for_lookup!($testnet, "testnet.nodes.length - 1")
    }};
    ($testnet:tt, $node_index:tt) => {{
        let node_index = $node_index;
        let found_pk_js: Vec<Vec<u8>> = $testnet
            .repl
            .json_run(format!(
                "
lookup_node = testnet.nodes[{node_index}];
query = await lookup_node.lookup(topic);
let out = [];
for await (const x of query) {{
    out.push([...x.peers[0].publicKey])
}}
writeJson(out)
",
            ))
            .await?;
        found_pk_js
    }};
}

macro_rules! poll_until {
    ($hdht:tt, $variant:path) => {{
        let res = loop {
            match $hdht.next().await {
                Some($variant(x)) => break x,
                _other => {
                    //tracing::info!("{other:?}");
                }
            }
        };
        res
    }};
}

struct Testnet {
    pub repl: Repl,
}

impl Testnet {
    async fn new() -> Result<Self> {
        let mut repl = make_repl().await;
        repl.run(
            "
createTestnet = require('hyperdht/testnet.js');
testnet = await createTestnet();
",
        )
        .await?;
        Ok(Self { repl })
    }

    /// Get the address of a node from an existing testnet in js
    /// NB: `testnet` must exist in the js context already
    async fn get_node_i_address(&mut self, node_index: usize) -> Result<SocketAddr> {
        Ok(self
            .repl
            .json_run::<String, _>(format!(
                "
bs_node = testnet.nodes[{node_index}]
write(stringify(`${{bs_node.host}}:${{bs_node.port}}`))
"
            ))
            .await?
            .parse()?)
    }
    /// Create a target/topic. whith the argument `topic` written to to the beggining of the buffer,
    /// and padded with zeros. The variable in js is named "topic"
    async fn make_topic(&mut self, topic: &str) -> Result<[u8; 32]> {
        Ok(self
            .repl
            .json_run(format!(
                "
    const b4a = require('b4a')
    topic = b4a.alloc(32);
    topic.write('{topic}', 0);
    write(stringify([...topic]))
    "
            ))
            .await?)
    }
}
macro_rules! setup_rs_node_and_js_testnet {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let hdht = HyperDht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, hdht)
    }};
}

/// Check that Rust's lookup works. The steps:
/// js does an announce with a `topic` and `keypair`
/// rs does a lookup for `topic`. Then checks the resulting keys found match `keypair`
#[tokio::test]
async fn js_announces_rs_looksup() -> Result<()> {
    let (mut tn, mut hdht) = setup_rs_node_and_js_testnet!();

    let topic = tn.make_topic("hello").await?;

    // with js announc on topic with the node's default keypair
    let _res = tn
        .repl
        .run(
            "
ann_node = testnet.nodes[testnet.nodes.length - 1];
query = await ann_node.announce(topic, ann_node.defaultKeyPair);
await query.finished();
    ",
        )
        .await?;

    // with RS do a lookup
    let query_id = hdht.lookup(topic.into(), hyperdht::Commit::No);

    // wait for rs lookup to complete
    // and record the public keys in responses
    let mut rs_lookup_keys = vec![];
    loop {
        match hdht.next().await {
            Some(HyperDhtEvent::LookupResult(res)) => {
                if res.query_id == query_id {
                    break;
                }
            }
            Some(HyperDhtEvent::LookupResponse(resp)) => {
                if let Some(_token) = resp.response.response.token {
                    rs_lookup_keys.extend(resp.peers);
                }
            }
            Some(_) => {}
            None => panic!("when would this end?"),
        }
    }

    // get the public key js announced with
    let js_pk: Vec<u8> = tn
        .repl
        .json_run("writeJson([...ann_node.defaultKeyPair.publicKey])")
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
    let (mut testnet, mut hdht) = setup_rs_node_and_js_testnet!();

    let topic = testnet.make_topic("hello").await?;
    let keypair = Keypair::default();
    let _qid = hdht.announce(topic.into(), &keypair, &[]);

    // Run announce to completion
    let _res = poll_until!(hdht, HyperDhtEvent::AnnounceResult);
    // do lookup in js.
    let found_pk_js = get_pub_keys_for_lookup!(testnet);

    assert!(!found_pk_js.is_empty());
    for pk in found_pk_js {
        assert_eq!(keypair.public.as_slice(), pk);
    }
    Ok(())
}

/// Test Rust's unannounce. The steps:
/// rs does announce
/// js does lookup, check topic is found with correct pk
/// rs does unannounce
/// ss does a lookup, check no results found
#[tokio::test]
async fn test_rs_unannounce() -> Result<()> {
    let (mut testnet, mut hdht) = setup_rs_node_and_js_testnet!();
    let topic = testnet.make_topic("hello").await?;
    let keypair = Keypair::default();

    // announce our rust node with `topic` and `keypair`
    let _qid = hdht.announce(topic.into(), &keypair, &[]);

    // finish announce
    let _ = poll_until!(hdht, HyperDhtEvent::AnnounceResult);
    // show_bytes(&test_net.repl.drain_stdout().await?);

    // with js do a lookup and get pubkeys
    let found_pk_js = get_pub_keys_for_lookup!(testnet);

    // get result for js and show it matches the RS keypair above
    assert_eq!(keypair.public.as_slice(), found_pk_js[0]);

    // Do the unannounce
    let _qid = hdht.unannounce(topic.into(), &keypair);
    // Wait for unannounce to complete
    let _ = poll_until!(hdht, HyperDhtEvent::UnAnnounceResult);

    // Do a lookup for a the topic again
    let found_pk_js = get_pub_keys_for_lookup!(testnet);
    // assert no keys found for the topic
    assert_eq!(found_pk_js.len(), 0);
    Ok(())
}

/// Check that Rust's find_peer can find JavaScript server
/// The steps:
/// js does a 'listen' on it's own public key
/// rs does a 'find_peer' on the public key, records the responses.
#[tokio::test]
async fn js_server_listen_rs_find_peer() -> Result<()> {
    let (mut tn, mut hdht) = setup_rs_node_and_js_testnet!();

    // with js announc on topic with the node's default keypair
    let pub_key: [u8; 32] = tn
        .repl
        .json_run(
            "
server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();

writeJson([...server_node.defaultKeyPair.publicKey]);
await server.listen(server_node.defaultKeyPair);
    ",
        )
        .await?;
    // with RS do a find peer
    let _query_id = hdht.find_peer(pub_key.into());

    let mut resps = vec![];
    loop {
        match hdht.next().await {
            Some(HyperDhtEvent::Bootstrapped { .. }) => {}
            Some(HyperDhtEvent::FindPeerResult(_)) => break,
            Some(HyperDhtEvent::FindPeerResponse(r)) => resps.push(r),
            Some(_) => todo!(),
            None => todo!(),
        }
    }
    assert!(!resps.is_empty());
    for r in resps {
        assert_eq!(r.peer.public_key.as_slice(), pub_key);
    }

    Ok(())
}

#[tokio::test]
async fn check_noise() -> Result<()> {
    let (mut tn, hdht) = setup_rs_node_and_js_testnet!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run(
            "
server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
writeJson([...server_node.defaultKeyPair.publicKey]);
await server.listen(server_node.defaultKeyPair);
    ",
        )
        .await?;
    let SocketAddr::V4(rs_client_socket) = hdht.local_addr()? else {
        panic!();
    };

    let np = NoisePayload {
        version: 1,
        error: 0,
        firewall: 0,
        holepunch: None,
        addresses4: Some(vec![rs_client_socket]),
        addresses6: None,
        udx: Some(UdxInfo {
            version: 1,
            reusable_socket: true,
            id: 1,
            seq: 0,
        }),
        secret_stream: None,
        relay_through: None,
    };
    let np_bytes = np.to_encoded_bytes()?;
    let hc = HandshakeConfig {
        pattern: DHT_PATTERN,
        prologue: Some(PEER_HANDSHAKE.to_vec()),
        remote_public_key: Some(pub_key),
    };

    let mut hphs = hypercore_protocol::Handshake::new_with_config(true, &hc)?;
    hphs.set_payload(np_bytes.to_vec());
    let noise_payload = hphs.start_raw()?.unwrap();
    let js_payload = serde_json::to_string(&noise_payload)?;
    let res = tn
        .repl
        .str_run(format!(
            "
noise = {js_payload};
handshake = server.createHandshake(server._keyPair, null);
// this will error if it can't be verified
res = handshake.recv(Buffer.from(noise));
writeJson(res);
"
        ))
        .await?;
    assert!(res.matches("\"version\":1").next().is_some());
    assert!(res.matches("\"relayThrough\":null").next().is_some());
    Ok(())
}
/*
/// In Rust create a "Server" and do a "listen" on `public_key`
/// Then in JavaScript do a `dht.findPeer(public_key)`.
/// And verify it finds the rust Server
#[tokio::test]
async fn js_server_rs_connects() -> Result<()> {
    let (mut tn, mut hdht) = setup_rs_node_and_js_testnet!();

    // with js announc on topic with the node's default keypair
    let pub_key: [u8; 32] = tn
        .repl
        .json_run(
            "
connected = false;
server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('connection', socket => {
    connected = true;
});

writeJson([...server_node.defaultKeyPair.publicKey]);
await server.listen(server_node.defaultKeyPair);
    ",
        )
        .await?;
    // with RS do a find peer
    let _query_id = hdht.find_peer(pub_key.into());

    let mut resps = vec![];
    loop {
        match hdht.next().await {
            Some(HyperDhtEvent::Bootstrapped { .. }) => {}
            Some(HyperDhtEvent::FindPeerResult(_)) => break,
            Some(HyperDhtEvent::FindPeerResponse(r)) => resps.push(r),
            Some(_) => todo!(),
            None => todo!(),
        }
    }
    assert!(!resps.is_empty());
    for r in resps.iter() {
        assert_eq!(r.peer.public_key.as_slice(), pub_key);
    }

    // with js announc on topic with the node's default keypair
    let addr: String = tn
        .repl
        .json_run(
            "
const { host, port } = server_node.address();
        writeJson(`${host}:${port}`);",
        )
        .await?;
    let server_addr: SocketAddr = addr.parse()?;

    todo!("start connecting to the  peer");
    Ok(())
}
