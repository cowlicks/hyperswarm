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
        .run_tcp(
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
    dbg!();
    let (mut tn, hdht) = setup_rs_node_and_js_testnet!();
    dbg!();
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
    dbg!(&res);
    println!("{res}");
    assert!(res.matches("\"version\":1").next().is_some());
    assert!(res.matches("\"relayThrough\":null").next().is_some());
    Ok(())
}

#[tokio::test]
async fn udx() -> Result<()> {
    let mut repl = make_repl().await;
    _ = repl
        .run_tcp(
            "
UDX = require('udx-native')
u = new UDX()
a = u.createSocket()
",
        )
        .await;
    let b = UdxSocket::bind_rnd()?;
    let port = b.local_addr()?.port();
    repl.run_tcp(format!("a.send(Buffer.from('hello'), {port})"))
        .await?;

    let _ = b.recv().await?;

    Ok(())
}

#[tokio::test]
async fn hs() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use snow::{params::NoiseParams, Builder};
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2b".parse()?;

    let initiator_kp = Builder::new(params.clone()).generate_keypair()?;
    let responder_kp = Builder::new(params.clone()).generate_keypair()?;

    let mut initiator = Builder::new(params.clone())
        .local_private_key(&initiator_kp.private)?
        .remote_public_key(&responder_kp.public)?
        .build_initiator()?;

    let mut responder = Builder::new(params.clone())
        .local_private_key(&responder_kp.private)?
        .build_responder()?;
    let (mut read_buf, mut first_msg, mut second_msg, mut enc_buf) =
        ([0u8; 1024], [0u8; 1024], [0u8; 1024], [0u8; 1024]);

    // -> e, es, s, ss
    let first_len = initiator.write_message(&[], &mut first_msg)?;
    // responder processes the first message...
    let read_len = responder.read_message(&first_msg[..first_len], &mut read_buf)?;
    println!("{:?}", &first_len);
    println!("{:?}", &read_buf[..read_len]);

    // <- e, ee, se
    let second_len = responder.write_message(&[], &mut second_msg)?;
    let _read_len = initiator.read_message(&second_msg[..second_len], &mut read_buf)?;

    let mut resp_transport = responder.into_transport_mode()?;
    let mut init_transport = initiator.into_transport_mode()?;

    let msg = b"my message";
    let elen = resp_transport.write_message(msg, &mut enc_buf)?;
    println!("{:?}", &enc_buf[..elen]);
    let rlen = init_transport.read_message(&enc_buf[..elen], &mut read_buf)?;
    println!("{}", String::from_utf8_lossy(&read_buf[..rlen]));

    Ok(())
}

/// In JavaScript create a "Server" and do a "listen" on a `public_key`
/// Then in Rust  do a `dht.find_peer(public_key)` to get the address of the servec.
/// Then in Rust should initiate a connection to JavaScript, completing the handshake.
/// Verify data can be sent through the connection
#[tokio::test]
async fn js_server_rs_connects() -> Result<()> {
    let (mut tn, mut hdht) = setup_rs_node_and_js_testnet!();

    log();
    // with js announc on topic with the node's default keypair
    let x = tn
        .repl
        .run_tcp(
            "
server_connected = deferred();
socket_open = deferred();
socket_connect = deferred();
server_rx_msg = deferred();

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('connection', socket => {
    server_connected.resolve(true);
    socket.on('open', () => {
        socket_open.resolve(true);
    });
    socket.on('connect', () => {
        socket_connect.resolve(true);
        //socket.send(Buffer.from('from server'))
    });
    socket.on('message', (message) => {
        console.log('GOTMESSAGE');
        server_rx_msg.resolve(message);
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
    ",
        )
        .await?;

    while !tn.repl.drain_stdout().await?.is_empty() {}
    let pub_key: [u8; 32] = tn.repl.json_run_tcp("outputJson([...pub_key]);").await?;

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

    // with js announce on topic with the node's default keypair
    while !tn.repl.drain_stdout().await?.is_empty() {}
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

    // nothing up my sleave; ensure connect is false
    while !tn.repl.drain_stdout().await?.is_empty() {}
    let server_connected: bool = tn
        .repl
        .json_run_tcp("outputJson(server_connected.ready)")
        .await?;
    assert!(!server_connected);
    // Use the router to initiate peer handshake and establish UdxStream
    log();
    let _tid = hdht.request_peer_handshake(pub_key.into(), server_addr)?;
    let (_tid_2, mut stream, _sock) = loop {
        print_js(&mut tn).await;
        let mut timeout_count = 0;
        let res = loop {
            let result = tokio::time::timeout(Duration::from_secs(1), hdht.next()).await;
            if matches!(result, Ok(Some(_))) {
                break result;
            } else {
                timeout_count += 1;
            }
            if timeout_count > 2 {
                panic!("should've got Connected Event by now");
            }
            print_js(&mut tn).await;
        };

        if let Some(evt) = res? {
            print_js(&mut tn).await;
            let HyperDhtEvent::Connected((tid, stream, sock, _ec)) = evt else {
                continue;
            };
            break (tid, stream, sock);
        }
    };
    while !tn.repl.drain_stdout().await?.is_empty() {}
    let server_connected: bool = tn
        .repl
        .json_run_tcp("outputJson(await server_connected)")
        .await?;
    dbg!(server_connected);
    assert!(server_connected);

    tn.repl.print().await?;
    let mut buf = [0u8; 1];
    // V-----------------------------------------HERE WERE STUCK
    // We never read anything
    // Instead try to send and check if js receives
    //dbg!(stream.read(&mut buf).await?);
    loop {
        let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
        match result {
            Ok(_) => break,
            Err(_) => {
                println!("try send rs to js");
                stream.write_all(b"from rust").await?;
                println!("sent");
                let server_rx_msg = tn.repl.run_tcp("output(server_rx_msg.toString())").await?;
                println!("the promise {:?}", String::from_utf8_lossy(&server_rx_msg));

                match tn
                    .repl
                    .run_tcp("output((await server_rx_msg).toString())")
                    .await
                {
                    Ok(_x) => todo!(),
                    Err(_e) => {
                        println!("err getting server_rx_msg, {_e:?}");
                        tn.repl.print().await?;
                        panic!();
                    }
                }
            }
        }
    }
    let data_len: usize = tn
        .repl
        .json_run_tcp("outputJson(socket_data.length)")
        .await?;
    dbg!(data_len);
    let socket_connect: bool = tn.repl.json_run_tcp("outputJson(!!socket_connect)").await?;
    dbg!(socket_connect);
    Ok(())
}
async fn print_js(tn: &mut Testnet) {
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let stdout = tn.repl.drain_stdout().await.unwrap();
    let stderr = tn.repl.drain_stderr().await.unwrap();
    println!(
        "stdout:
    {}
stderr:
    {}
",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
}

/// js talking to js
#[tokio::test]
async fn js_server_js_connects() -> Result<()> {
    let mut tn = Testnet::new().await?;
    log();
    dbg!();

    let r = tn
        .repl
        .run_tcp(
            "
server_connected = deferred();
socket_open = deferred();
socket_connect = deferred();

client_open = deferred();
client_rx_msg = deferred();
server_rx_msg = deferred();

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('connection', socket => {
    server_connected.resolve(true);
    socket.on('open', () => {
        socket_open.resolve(true);
    });
    socket.on('connect', () => {
        socket_connect.resolve(socket);
    });
    socket.on('message', (m) => {
        server_rx_msg.resolve(m)
    });
});

pub_key = server_node.defaultKeyPair.publicKey;
await server.listen(server_node.defaultKeyPair);
    ",
        )
        .await;
    dbg!();
    println!("{r:?}");
    dbg!();
    tn.repl.print().await?;
    r?;
    dbg!();
    let _s = tn
        .repl
        .run_tcp(
            "
node = testnet.nodes[testnet.nodes.length - 2];

client_socket = node.connect(pub_key);
client_socket.on('open', () => {
    client_open.resolve(true);
});
await client_open;
client_socket.on('message', (m) => {
    client_rx_msg.resolve(m);
});
",
        )
        .await;
    tn.repl.print().await?;
    dbg!(_s)?;

    dbg!();
    assert!(
        tn.repl
            .json_run("writeJson(await server_connected)")
            .await?
    );
    assert!(tn.repl.json_run("writeJson(await socket_open)").await?);
    tn.repl
        .run_tcp("server_socket = await socket_connect")
        .await?;
    assert!(tn.repl.json_run("writeJson(await client_open)").await?);
    tn.repl
        .run_tcp("await server_socket.send(Buffer.from('from server'))")
        .await?;
    let s = tn
        .repl
        .run_tcp(
            "
rx = await client_rx_msg;
output(rx.toString());
",
        )
        .await?;

    assert_eq!(s, b"from server");

    tn.repl
        .run_tcp("await client_socket.send(Buffer.from('from client'))")
        .await?;
    let s = tn
        .repl
        .run_tcp(
            "
rx = await server_rx_msg;
output(rx.toString());
",
        )
        .await?;
    assert_eq!(s, b"from client");
    Ok(())
}
