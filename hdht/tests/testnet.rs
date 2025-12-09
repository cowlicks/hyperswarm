mod common;
use compact_encoding::CompactEncoding;
use std::{
    net::{SocketAddr, SocketAddrV4},
    time::Duration,
};

use common::{js::make_repl, Result};
use dht_rpc::{cenc::generic_hash, commands, commit::Commit, DhtConfig, IdBytes, Peer};
use futures::{SinkExt, StreamExt};
use hypercore_protocol::{handshake_constants::DHT_PATTERN, sstream::sm2::Event, HandshakeConfig};
use hyperdht::{
    adht::Dht,
    cenc::{NoisePayload, UdxInfo},
    commands::FIND_PEER,
    namespace::PEER_HANDSHAKE,
    HyperDht, HyperDhtEvent, HyperDhtInner, Keypair,
};
use rusty_nodejs_repl::{wait, Repl};

use crate::common::log;

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
            .json_run_tcp(format!(
                "
lookup_node = testnet.nodes[{node_index}];
query = await lookup_node.lookup(topic);
let out = [];
for await (const x of query) {{
    out.push([...x.peers[0].publicKey])
}}
outputJson(out)
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
        let r = repl
            .run_tcp(
                "
createTestnet = require('hyperdht/testnet.js');
testnet = await createTestnet();
",
            )
            .await;
        repl.print().await?;

        r?;
        Ok(Self { repl })
    }

    /// Get the address of a node from an existing testnet in js
    /// NB: `testnet` must exist in the js context already
    async fn get_node_i_address(&mut self, node_index: usize) -> Result<SocketAddr> {
        Ok(self
            .repl
            .json_run_tcp::<String, _>(format!(
                "
bs_node = testnet.nodes[{node_index}]
outputJson(`${{bs_node.host}}:${{bs_node.port}}`)
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
            .json_run_tcp(format!(
                "
    const b4a = require('b4a')
    topic = b4a.alloc(32);
    topic.write('{topic}', 0);
    outputJson([...topic])
    "
            ))
            .await?)
    }
}
macro_rules! setup_rs_node_and_js_testnet {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let hdht =
            HyperDhtInner::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, hdht)
    }};
}
macro_rules! new_setup_rs_node_and_js_testnet {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let hdht = HyperDht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, hdht)
    }};
}

macro_rules! rpc_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let rpc =
            dht_rpc::AsyncRpcDht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr))
                .await?;
        (tn, rpc)
    }};
}

macro_rules! adht_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let rpc = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, rpc)
    }};
}

#[tokio::test]
async fn adht_lookup() -> Result<()> {
    let (mut tn, mut dht) = adht_setup!();
    let pub_key: Vec<u8> = tn
        .repl
        .run_tcp(
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
    let target = IdBytes(generic_hash(&*pub_key));

    let mut lery = dht.lookup(target, Commit::No)?;
    while let Some(x) = lery.next().await {
        println!("{x:?}");
    }
    let res = lery.await?;
    dbg!(&res);
    Ok(())
}

#[tokio::test]
async fn adht_find_peer() -> Result<()> {
    log();
    let (mut tn, mut dht) = adht_setup!();
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

    dht.boostrap().await?;
    let mut q = dht.find_peer(pub_key.into())?;
    while let Some(e) = q.next().await {
        dbg!(&e);
    }
    Ok(())
}

#[tokio::test]
async fn adht_peer_handshake() -> Result<()> {
    log();
    let (mut tn, mut dht) = adht_setup!();
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

    dht.boostrap().await?;

    let port: u16 = tn.repl.get_name("server_addr").await?;
    tn.repl.print_until_settled().await?;
    let dest = format!("127.0.0.1:{port}").parse()?;
    let mut conn = dht.peer_handshake(pub_key.into(), dest)?.await?;
    conn.send(b"from rust".into()).await?;
    let msg: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(msg, "from rust");

    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;
    let Some(Event::Message(rx_from_js)) = conn.next().await else {
        todo!()
    };
    assert_eq!(String::from_utf8_lossy(&rx_from_js), "from js");
    Ok(())
}

#[tokio::test]
async fn adht_connect() -> Result<()> {
    let (mut tn, mut dht) = adht_setup!();
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

    dht.boostrap().await?;
    let mut conn = dht.connect(pub_key.into()).await?;
    conn.send(b"from rust".into()).await?;
    let msg: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(msg, "from rust");

    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;
    let Some(Event::Message(rx_from_js)) = conn.next().await else {
        todo!()
    };
    assert_eq!(String::from_utf8_lossy(&rx_from_js), "from js");
    Ok(())
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
        .run_tcp(
            "
ann_node = testnet.nodes[testnet.nodes.length - 1];
query = await ann_node.announce(topic, ann_node.defaultKeyPair);
await query.finished();
",
        )
        .await?;

    // with RS do a lookup
    let query_id = hdht.lookup(topic.into(), Commit::No);

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
        .json_run_tcp(
            "
server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();

outputJson([...server_node.defaultKeyPair.publicKey]);
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
        .json_run_tcp(
            "
server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
outputJson([...server_node.defaultKeyPair.publicKey]);
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

    let mut hphs = hypercore_protocol::Handshake::new(true, &hc)?;
    hphs.set_payload(np_bytes.to_vec());
    let noise_payload = hphs.start_raw()?.unwrap();
    let js_payload = serde_json::to_string(&noise_payload)?;
    let res = tn
        .repl
        .run_tcp(format!(
            "
noise = {js_payload};
handshake = server.createHandshake(server._keyPair, null);
// this will error if it can't be verified
res = handshake.recv(Buffer.from(noise));
outputJson(res);
"
        ))
        .await?;
    let res = String::from_utf8(res).unwrap();
    assert!(res.matches("\"version\":1").next().is_some());
    assert!(res.matches("\"relayThrough\":null").next().is_some());
    Ok(())
}

#[tokio::test]
async fn rs_client_js_server_qua() -> Result<()> {
    let (mut tn, mut hdht) = setup_rs_node_and_js_testnet!();
    tn.repl
        .run_tcp(
            "
server_connected = deferred();
server_rx_data = deferred();
server_listening = deferred();

socket_open = deferred();
socket_connect = deferred();

server_rx_message = deferred();

SOCKET = null;

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_listening.resolve(true);
});

server.on('connection', socket => {
    server_connected.resolve(true);
    // NB: socket connect is b4 open (open means fully open)
    socket.on('connect', () => {
        socket_connect.resolve(true);
    });
    socket.on('open', () => {
        socket_open.resolve(true);
    });
    socket.on('data', (data) => {
        console.log('GOTDATA', data.toString());
        server_rx_data.resolve(true);
        SOCKET = socket;
    });
    socket.on('message', (message) => {
        console.log('GOTMESSAGE', message.toString());
        server_rx_message.resolve(true);
    });
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
a = await server.address();
",
        )
        .await?;

    log();
    //tn.repl.print_until_settled().await?;
    let pub_key: [u8; 32] = tn.repl.json_run_tcp("outputJson([...pub_key]);").await?;

    // With RS do a find peer.
    let _query_id = hdht.find_peer(pub_key.into());

    let mut resps = vec![];
    // wait for find_peer to complete
    let qr = loop {
        match hdht.next().await {
            Some(HyperDhtEvent::Bootstrapped { .. }) => {}
            Some(HyperDhtEvent::FindPeerResult(qr)) => break qr,
            Some(HyperDhtEvent::FindPeerResponse(r)) => resps.push(r),
            Some(_) => todo!(),
            None => todo!(),
        }
    };

    //tn.repl.print_until_settled().await?;
    assert!(!resps.is_empty());
    // ensure we found the key we want
    for r in resps.iter() {
        assert_eq!(r.peer.public_key.as_slice(), pub_key);
    }

    wait!(100);
    //tn.repl.print_until_settled().await?;
    // Get the address of the server want to connect to
    // should we just skip the "find_peer" above?
    let addr: String = tn
        .repl
        .json_run_tcp(
            "
const { host, port } = server_node.address();
outputJson(`${host}:${port}`);",
        )
        .await?;

    let SocketAddr::V4(server_addr) = addr.parse()? else {
        todo!()
    };
    let server_connected: bool = tn
        .repl
        .json_run_tcp("outputJson(server_connected.ready)")
        .await?;
    assert!(!server_connected);

    wait!(100);
    //tn.repl.print_until_settled().await?;
    // send the handshake request to the server);
    let tid_tx = hdht.request_peer_handshake(pub_key.into(), server_addr)?;
    //
    let (tid_rx, mut conn) = loop {
        let mut timeout_count = 0;
        let res = loop {
            let result = hdht.next().await;
            if result.is_some() {
                break result;
            } else {
                timeout_count += 1;
            }
            if timeout_count > 2 {
                panic!("should've got Connected Event by now");
            }
        };

        if let Some(evt) = res {
            let HyperDhtEvent::Connected((tid, conn)) = evt else {
                continue;
            };
            break (tid, conn);
        }
    };

    assert_eq!(tid_tx, tid_rx);

    //tn.repl.print_until_settled().await?;
    dbg!();
    let server_listening: bool = tn.repl.get_name("server_listening").await?;
    assert!(server_listening);
    dbg!();
    let server_connected: bool = tn.repl.get_name("server_connected").await?;
    assert!(server_connected);
    dbg!();
    let _socket_connect: bool = tn.repl.get_name("socket_connect").await?;
    assert!(_socket_connect);
    dbg!();
    let _socket_open: bool = tn.repl.get_name("socket_open").await?;
    dbg!();
    assert!(_socket_open);
    //tn.repl.print_until_settled().await?;

    // assert gen_name data rx false
    let server_rx_data: bool = tn
        .repl
        .json_run_tcp("outputJson(server_rx_data.ready)")
        .await?;
    assert!(!server_rx_data);

    conn.send(b"from rust".into()).await?;
    let server_rx_data: bool = tn.repl.get_name("server_rx_data").await?;
    assert!(server_rx_data);

    assert!(String::from_utf8_lossy(&tn.repl.drain_stdout().await?).contains("from rust"));

    tn.repl
        .run_tcp("console.log(await SOCKET.write(Buffer.from('from js')))")
        .await?;

    let Some(Event::Message(m)) = conn.next().await else {
        panic!()
    };
    assert_eq!(m, b"from js");

    Ok(())
}

// TODO move this to rpc crate. (Which requiress giving it it's own js-repl tests
#[tokio::test]
async fn test_async_rpc_request_ping() -> Result<()> {
    let (mut tn, mut rpc) = rpc_setup!();
    let _pub_key: Vec<u8> = tn
        .repl
        .run_tcp(
            "
server_addr = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

pub_key  = server_node.defaultKeyPair.publicKey;;
outputJson([...pub_key]);
",
        )
        .await?;
    let sport: usize = tn
        .repl
        .json_run_tcp("outputJson(server.dht.io.serverSocket._port)")
        .await?;
    // For FIND_NODE test
    //let idbytes: Vec<u8> = tn
    //    .repl
    //    .json_run_tcp("outputJson([...server.dht.id])")
    //    .await?;
    //let idbytes: [u8; 32] = idbytes.try_into().unwrap();
    //let command = commands::PING_NAT;
    //let command = commands::FIND_NODE;
    //let x = rpc.request(command, Some(idbytes), None, destination, None).await?;
    //let command = commands::DOWN_HINT;
    let command = commands::PING;
    let addr = format!("127.0.0.1:{sport}");
    let destination: Peer = addr.parse()?;
    let x = rpc.request(command, None, None, destination, None).await?;
    assert_eq!(x.request.command, command);
    Ok(())
}
#[tokio::test]
async fn test_async_rpc_query_find_node() -> Result<()> {
    let (mut tn, mut rpc) = rpc_setup!();
    let _pub_key: Vec<u8> = tn
        .repl
        .run_tcp(
            "
server_addr = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

pub_key  = server_node.defaultKeyPair.publicKey;;
outputJson([...pub_key]);
",
        )
        .await?;
    let sport: usize = tn
        .repl
        .json_run_tcp("outputJson(server.dht.io.serverSocket._port)")
        .await?;
    println!("SPORT {sport}");
    // For FIND_NODE test
    let idbytes: Vec<u8> = tn
        .repl
        .json_run_tcp("outputJson([...server.dht.id])")
        .await?;
    let idbytes: [u8; 32] = idbytes.try_into().unwrap();
    //let command = commands::PING_NAT;
    let command = commands::FIND_NODE;
    let command = FIND_PEER;
    //let x = rpc.request(command, Some(idbytes), None, destination, None).await?;
    log();
    let x = rpc.query(command, idbytes.into(), None, Commit::No).await?;
    dbg!(&x);
    //assert_eq!(x.request.command, command);
    Ok(())
}

#[tokio::test]
async fn js_js() -> Result<()> {
    let (mut tn, mut hdht) = setup_rs_node_and_js_testnet!();
    tn.repl
        .run_tcp(
            "
server_connected = deferred();
server_rx_data = deferred();
server_listening = deferred();

socket_open = deferred();
socket_connect = deferred();

server_rx_message = deferred();

SERVER_SOCKET = null;

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_listening.resolve(true);
});

server_msgs = []
server.on('connection', socket => {
    server_connected.resolve(true);
    // NB: socket connect is b4 open (open means fully open)
    socket.on('connect', () => {
    console.log('CONNECT')
        socket_connect.resolve(true);
    });
    socket.on('open', () => {
    console.log('OPEN')
        socket_open.resolve(true);
    });
    socket.on('data', (data) => {
    console.log('SERVER_RX_DATA')
        server_msgs.push(data);
        SERVER_SOCKET = socket;
    });
    socket.on('message', (message) => {
        console.log('GOTMESSAGE', message.toString());
        server_rx_message.resolve(true);
    });
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
SERVER_PORT = await server.address();
",
        )
        .await?;

    tn.repl.print_until_settled().await?;
    tn.repl
        .run_tcp(
            "
n = testnet.nodes[0];
client_msgs =[];
console.log('SERVER_PORT', SERVER_PORT.port);
CLIENT_SOCK =  await n.connect(pub_key);
CLIENT_SOCK.on('data', (data) => {
    client_msgs.push(data);
    console.log('CLIENT_RX_DATA');
});
await CLIENT_SOCK.write(Buffer.from('hello'));
await sleep();
console.log(server_msgs);
",
        )
        .await?;
    dbg!();
    tn.repl.print_until_settled().await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    tn.repl
        .run_tcp(
            "
await SERVER_SOCKET.write(Buffer.from('from_server'));
await sleep();
console.log(client_msgs)

    ",
        )
        .await?;
    tn.repl.print_until_settled().await?;
    dbg!();
    Ok(())
}

#[tokio::test]
async fn test_async_peer_handshake_to_connect() -> Result<()> {
    let (mut tn, mut hdht) = new_setup_rs_node_and_js_testnet!();
    tn.repl
        .run_tcp(
            "
server_rx_data = deferred();
SOCKET = null;

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(true)
        SOCKET = socket;
    });
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
",
        )
        .await?;

    let pub_key: [u8; 32] = tn.repl.json_run_tcp("outputJson([...pub_key]);").await?;

    // With RS do a find peer.
    log();
    let resp = hdht.find_peer(pub_key.into()).await?;
    dbg!(&resp);

    let known_good_addr: String = tn
        .repl
        .json_run_tcp(
            "
const { host, port } = server_node.address();
outputJson(`${host}:${port}`);",
        )
        .await?;
    let SocketAddr::V4(known_good_addr) = known_good_addr.parse()? else {
        todo!()
    };
    let mut conn = hdht.peer_handshake(pub_key.into(), known_good_addr).await?;
    conn.send(b"HELLO".to_vec()).await;

    let rx_msg: bool = tn.repl.get_name("server_rx_data").await?;
    tn.repl.print_until_settled().await?;
    tn.repl
        .run_tcp("console.log(await SOCKET.write(Buffer.from('from js')))")
        .await?;
    tn.repl.print_until_settled().await?;
    let Some(Event::Message(m)) = conn.next().await else {
        panic!()
    };
    assert_eq!(m, b"from js");

    Ok(())
}

#[tokio::test]
async fn peer_handshake_with_relay() -> Result<()> {
    let (mut tn, mut hdht) = new_setup_rs_node_and_js_testnet!();
    tn.repl
        .run_tcp(
            "
server_rx_data = deferred();
SOCKET = null;

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(true)
        SOCKET = socket;
    });
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
",
        )
        .await?;

    let pub_key: [u8; 32] = tn.repl.json_run_tcp("outputJson([...pub_key]);").await?;

    // With RS do a find peer.
    log();
    let resp = hdht.find_peer(pub_key.into()).await?;

    let known_good_addr: String = tn
        .repl
        .json_run_tcp(
            "
const { host, port } = server_node.address();
outputJson(`${host}:${port}`);",
        )
        .await?;
    let known_good_addr: SocketAddrV4 = known_good_addr.parse()?;
    let mut conn = None;
    for r in &resp.responses {
        let addr = r.peer.ipv4_addr()?;
        if addr == known_good_addr {
            panic!()
        }

        match hdht.peer_handshake(pub_key.into(), addr).await {
            Ok(c) => {
                conn.insert(c);
                break;
            }
            Err(e) => eprintln!("BADBAD {e}"),
        }
    }

    let Some(mut conn) = conn else {
        return Ok(());
    };

    let mut conn = hdht.peer_handshake(pub_key.into(), known_good_addr).await?;
    conn.send(b"HELLO".to_vec()).await;

    let rx_msg: bool = tn.repl.get_name("server_rx_data").await?;
    tn.repl.print_until_settled().await?;
    tn.repl
        .run_tcp("console.log(await SOCKET.write(Buffer.from('from js')))")
        .await?;
    tn.repl.print_until_settled().await?;
    let Some(Event::Message(m)) = conn.next().await else {
        panic!()
    };
    assert_eq!(m, b"from js");
    tn.repl.print_until_settled().await?;

    Ok(())
}
