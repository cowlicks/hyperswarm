mod common;
use compact_encoding::CompactEncoding;

use common::Result;
use hypercore_protocol::{handshake_constants::DHT_PATTERN, HandshakeConfig};
use hyperdht::{
    cenc::{NoisePayload, UdxInfo},
    namespace::PEER_HANDSHAKE,
};

use crate::common::setup::Testnet;

/// this was just checking internals of noise come out the way we would expect
/// could probably be removed
#[tokio::test]
async fn check_noise() -> Result<()> {
    let mut tn = Testnet::new().await?;
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
    let rs_client_socket: std::net::SocketAddrV4 = "127.0.0.1:1245".parse()?;

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
