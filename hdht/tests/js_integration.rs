mod common;
use std::net::SocketAddr;

use compact_encoding::types::CompactEncodable;
use dht_rpc::IdBytes;
use hyperdht::{
    cenc::Announce, namespace, request_announce_or_unannounce_value, sign_announce_or_unannounce,
    Keypair2,
};

use common::{
    js::{make_repl, KEYPAIR_JS},
    Result,
};
use rusty_nodejs_repl::Repl;

const DEFAULT_SEED: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn sign_announce(
    keypair: &Keypair2,
    target: IdBytes,
    token: &[u8; 32],
    from_id: &[u8; 32],
    relay_addresses: &[SocketAddr],
) -> crate::Result<Announce> {
    Ok(sign_announce_or_unannounce(
        keypair,
        target,
        token,
        from_id,
        relay_addresses,
        &namespace::ANNOUNCE,
    ))
}

async fn cmp_buf(repl: &mut Repl, rs_buf: &[u8], js_name: &str) -> Result<bool> {
    let res_vec = repl
        .run(format!("write([...{js_name}].toString())"))
        .await?;
    let resjs_buf_str = String::from_utf8_lossy(&res_vec);
    let rs_buf_str = buf_to_js_comparable_str(rs_buf);
    Ok(rs_buf_str == resjs_buf_str)
}
fn buf_to_js_comparable_str(x: &[u8]) -> String {
    x.iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

#[tokio::test]
async fn compare_rs_namespace_values_to_js() -> crate::Result<()> {
    let mut repl = make_repl().await;
    let result = repl
        .run(
            "
const { NS } = require('hyperdht/lib/constants');
namespace = NS
process.stdout.write([...namespace.ANNOUNCE].toString());
",
        )
        .await?;
    assert_eq!(
        buf_to_js_comparable_str(&namespace::ANNOUNCE),
        String::from_utf8_lossy(&result)
    );
    let result = repl
        .run("process.stdout.write([...namespace.UNANNOUNCE].toString())")
        .await?;
    assert_eq!(
        buf_to_js_comparable_str(&namespace::UNANNOUNCE),
        String::from_utf8_lossy(&result)
    );

    Ok(())
}

#[tokio::test]
async fn same_seed_generates_same_keypair_values() -> Result<()> {
    let mut repl = make_repl().await;
    let result: Vec<Vec<u8>> = repl
        .json_run(
            "
createKeyPair = require('hyperdht/lib/crypto.js').createKeyPair;
let seed = new Uint8Array(32);
seed[0] = 1;
keyPair = createKeyPair(seed)
write(stringify([[...keyPair.publicKey], [...keyPair.secretKey]]))
",
        )
        .await?;

    let k2 = Keypair2::from_seed(DEFAULT_SEED);
    assert_eq!(k2.public.as_slice(), &result[0]);
    assert_eq!(k2.secret.as_slice(), &result[1]);
    Ok(())
}

async fn make_array<const C: usize>(repl: &mut Repl, name: &str, def: &str) -> Result<[u8; C]> {
    let js_str = format!(
        "
{name} = {def};
writeJson([...{name}])"
    );
    let vec: Vec<u8> = repl.json_run(js_str).await?;
    Ok(vec
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}")))?)
}
/// Test creating a signature for an Announce is correct.
/// JS code taken from:
/// https://github.com/holepunchto/hyperdht/blob/0d4f4b65bf1c252487f7fd52ef9e21ac76a3ceba/index.js#L424-L434
#[tokio::test]
async fn announce_signature_is_same() -> Result<()> {
    let mut repl = make_repl().await;
    repl.run(KEYPAIR_JS).await?;
    let target: [u8; 32] = make_array(&mut repl, "target", "Buffer.alloc(32).fill(1)").await?;
    let token: [u8; 32] = make_array(&mut repl, "token", "Buffer.alloc(32).fill(2)").await?;
    let from_id: [u8; 32] = make_array(&mut repl, "from_id", "Buffer.alloc(32).fill(3)").await?;
    let expected: Vec<u8> = repl
        .json_run(
            "
Persistent = require('hyperdht/lib/persistent')
c = require('compact-encoding')
m = require('hyperdht/lib/messages')

relayAddresses = [];

ann = {
  peer: {
    publicKey: keyPair.publicKey,
    relayAddresses: relayAddresses || []
  },
  refresh: null,
  signature: null
}

signature = await Persistent.signAnnounce(target, token, from_id, ann, keyPair)
write(stringify([...signature]))
",
        )
        .await?;

    let kp = Keypair2::from_seed(DEFAULT_SEED);
    let announce = sign_announce(&kp, target.into(), &token, &from_id, &[])?;
    assert_eq!(announce.signature.0.as_slice(), &expected);
    Ok(())
}
// TOOD DRY these tests, deduplicate signing part, relay part, etc
#[tokio::test]
async fn announce_signature_with_relays_is_same() -> Result<()> {
    let one: SocketAddr = "192.168.1.2:1234".parse().unwrap();
    let two: SocketAddr = "10.11.12.13:6547".parse().unwrap();
    let three: SocketAddr = "127.0.0.1:80".parse().unwrap();
    let relay_addresses = vec![one, two, three];

    let mut repl = make_repl().await;
    repl.run(KEYPAIR_JS).await?;
    let target: [u8; 32] = make_array(&mut repl, "target", "Buffer.alloc(32).fill(1)").await?;
    let token: [u8; 32] = make_array(&mut repl, "token", "Buffer.alloc(32).fill(2)").await?;
    let from_id: [u8; 32] = make_array(&mut repl, "from_id", "Buffer.alloc(32).fill(3)").await?;
    let expected: Vec<u8> = repl
        .json_run(
            "
Persistent = require('hyperdht/lib/persistent')
c = require('compact-encoding')
m = require('hyperdht/lib/messages')

relayAddresses = [
    {host: '192.168.1.2', port: 1234},
    {host: '10.11.12.13', port: 6547},
    {host: '127.0.0.1', port: 80},
];

ann = {
  peer: {
    publicKey: keyPair.publicKey,
    relayAddresses: relayAddresses || []
  },
  refresh: null,
  signature: null
}

signature = await Persistent.signAnnounce(target, token, from_id, ann, keyPair)
write(stringify([...signature]))
",
        )
        .await?;

    let kp = Keypair2::from_seed(DEFAULT_SEED);
    let announce = sign_announce(&kp, target.into(), &token, &from_id, &relay_addresses)?;
    assert_eq!(announce.signature.0.as_slice(), &expected);
    Ok(())
}

/// Test encoding a signed Announce is correct.
/// JS code taken from:
/// https://github.com/holepunchto/hyperdht/blob/0d4f4b65bf1c252487f7fd52ef9e21ac76a3ceba/index.js#L424-L436
#[tokio::test]
async fn test_sign_and_encode_announce() -> Result<()> {
    let mut repl = make_repl().await;
    repl.run(KEYPAIR_JS).await?;
    let target: [u8; 32] = make_array(&mut repl, "target", "Buffer.alloc(32).fill(1)").await?;
    let token: [u8; 32] = make_array(&mut repl, "token", "Buffer.alloc(32).fill(2)").await?;
    let from_id: [u8; 32] = make_array(&mut repl, "from_id", "Buffer.alloc(32).fill(3)").await?;
    let expected: Vec<u8> = repl
        .json_run(
            "
Persistent = require('hyperdht/lib/persistent')
c = require('compact-encoding')
m = require('hyperdht/lib/messages')

relayAddresses = [];

ann = {
  peer: {
    publicKey: keyPair.publicKey,
    relayAddresses: relayAddresses || []
  },
  refresh: null,
  signature: null
}

ann.signature = await Persistent.signAnnounce(target, token, from_id, ann, keyPair)
write(stringify([...c.encode(m.announce, ann)]))
",
        )
        .await?;

    let kp = Keypair2::from_seed(DEFAULT_SEED);
    let buff = request_announce_or_unannounce_value(
        &kp,
        target.into(),
        &token,
        from_id.into(),
        &[],
        &namespace::ANNOUNCE,
    );
    assert_eq!(buff, expected);
    Ok(())
}
#[tokio::test]
async fn test_sign_and_encode_announce_with_relays() -> Result<()> {
    let one: SocketAddr = "192.168.1.2:1234".parse().unwrap();
    let two: SocketAddr = "10.11.12.13:6547".parse().unwrap();
    let three: SocketAddr = "127.0.0.1:80".parse().unwrap();
    let relay_addresses = vec![one, two, three];

    let mut repl = make_repl().await;
    repl.run(KEYPAIR_JS).await?;
    let target: [u8; 32] = make_array(&mut repl, "target", "Buffer.alloc(32).fill(1)").await?;
    let token: [u8; 32] = make_array(&mut repl, "token", "Buffer.alloc(32).fill(2)").await?;
    let from_id: [u8; 32] = make_array(&mut repl, "from_id", "Buffer.alloc(32).fill(3)").await?;
    let expected: Vec<u8> = repl
        .json_run(
            "
Persistent = require('hyperdht/lib/persistent')
c = require('compact-encoding')
m = require('hyperdht/lib/messages')

relayAddresses = [
    {host: '192.168.1.2', port: 1234},
    {host: '10.11.12.13', port: 6547},
    {host: '127.0.0.1', port: 80},
];

ann = {
  peer: {
    publicKey: keyPair.publicKey,
    relayAddresses: relayAddresses || []
  },
  refresh: null,
  signature: null
}

ann.signature = await Persistent.signAnnounce(target, token, from_id, ann, keyPair)
write(stringify([...c.encode(m.announce, ann)]))
",
        )
        .await?;

    let kp = Keypair2::from_seed(DEFAULT_SEED);
    let buff = request_announce_or_unannounce_value(
        &kp,
        target.into(),
        &token,
        from_id.into(),
        &relay_addresses,
        &namespace::ANNOUNCE,
    );
    assert_eq!(buff, expected);
    Ok(())
}

#[tokio::test]
async fn announce_decod_is_same() -> Result<()> {
    let mut repl = make_repl().await;
    repl.run(KEYPAIR_JS).await?;
    let target: [u8; 32] = make_array(&mut repl, "target", "Buffer.alloc(32).fill(1)").await?;
    let token: [u8; 32] = make_array(&mut repl, "token", "Buffer.alloc(32).fill(2)").await?;
    let from_id: [u8; 32] = make_array(&mut repl, "from_id", "Buffer.alloc(32).fill(3)").await?;
    let _js_ann: Vec<u8> = repl
        .json_run(
            "
Persistent = require('hyperdht/lib/persistent')
c = require('compact-encoding')
m = require('hyperdht/lib/messages')

relayAddresses = [];

ann = {
  peer: {
    publicKey: keyPair.publicKey,
    relayAddresses: relayAddresses || []
  },
  refresh: null,
  signature: null
}

ann.signature = await Persistent.signAnnounce(target, token, from_id, ann, keyPair)
encoded_announce = c.encode(m.announce, ann);
write(stringify([...encoded_announce]))
",
        )
        .await?;

    let kp = Keypair2::from_seed(DEFAULT_SEED);
    let rs_ann_enc = request_announce_or_unannounce_value(
        &kp,
        target.into(),
        &token,
        from_id.into(),
        &[],
        &namespace::ANNOUNCE,
    );

    let (ann, rest): (Announce, _) = CompactEncodable::decode(&rs_ann_enc)?;
    assert!(rest.is_empty());

    repl.run(
        "
    decoded_announce = c.decode(m.announce, encoded_announce);
    ",
    )
    .await?;

    let _x = repl
        .run("write([...decoded_announce.signature].toString())")
        .await?;

    assert!(cmp_buf(&mut repl, &*ann.signature, "decoded_announce.signature").await?);
    assert!(
        cmp_buf(
            &mut repl,
            &*ann.peer.public_key,
            "decoded_announce.peer.publicKey"
        )
        .await?
    );

    let verified: bool = repl
        .json_run(
            "
verified = Persistent.prototype.verifyAnnounce({ value: encoded_announce, target, token }, from_id);
writeJson(verified);
",
        )
        .await?;
    assert!(verified);

    Ok(())
}
