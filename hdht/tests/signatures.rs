//! Given some known good values (they came from adding `console.log(...)` in JS hyperdht)
//! Check that the signature RS creates from values is verified by JS
//! And likewise JS signature is verified by RS
use common::{js::make_repl, Result};
use compact_encoding::CompactEncoding;
use dht_rpc::IdBytes;
use hyperdht::{cenc::Announce, make_signable_announce_or_unannounce, namespace};
use rusty_nodejs_repl::Repl;

mod common;

const VALUE: &[u8] = &[
    5, 206, 205, 109, 15, 42, 98, 66, 107, 27, 31, 54, 201, 136, 155, 42, 245, 234, 210, 154, 31,
    11, 151, 222, 135, 63, 208, 92, 4, 74, 24, 20, 109, 0, 49, 107, 254, 99, 36, 124, 108, 65, 174,
    60, 38, 12, 182, 110, 6, 215, 255, 19, 177, 141, 34, 177, 44, 213, 226, 206, 148, 246, 168,
    179, 176, 33, 117, 139, 191, 54, 19, 232, 12, 218, 55, 26, 107, 78, 178, 76, 252, 175, 89, 204,
    117, 165, 89, 32, 234, 143, 60, 157, 40, 233, 236, 239, 41, 8,
];
const TOKEN: [u8; 32] = [
    36, 6, 6, 155, 30, 71, 106, 67, 42, 98, 245, 4, 186, 36, 240, 5, 122, 103, 150, 70, 158, 158,
    55, 38, 154, 45, 194, 191, 37, 14, 50, 21,
];
const ID: [u8; 32] = [
    144, 142, 182, 97, 170, 104, 69, 6, 221, 242, 249, 208, 96, 76, 57, 128, 126, 140, 89, 26, 115,
    131, 139, 110, 211, 183, 214, 39, 134, 156, 128, 165,
];

const TARGET: &[u8] = &[
    104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];
/// This demonstrates that known good values fails in Rust's verify
#[tokio::test]
async fn check_in_rs_known_good_sig_created_in_js() -> Result<()> {
    let target: IdBytes = TryInto::<[u8; 32]>::try_into(TARGET).unwrap().into();

    let (announce, _) = <Announce as CompactEncoding>::decode(VALUE)?;

    let mut peer_buff = vec![0u8; CompactEncoding::encoded_size(&announce.peer).unwrap()];
    announce.peer.encode(&mut peer_buff).unwrap();

    println!("rsep = {:?}", &peer_buff);
    let signable =
        make_signable_announce_or_unannounce(target, &TOKEN, &ID, &peer_buff, &namespace::ANNOUNCE);
    announce
        .peer
        .public_key
        .verify(announce.signature, &signable)
        .unwrap();
    Ok(())
}

#[tokio::test]
async fn check_in_js_known_good_sig_created_in_js() -> Result<()> {
    let target: IdBytes = TryInto::<[u8; 32]>::try_into(TARGET).unwrap().into();

    let mut repl = make_repl().await;
    let _res = repl
        .run_tcp(
            "
Persistent = require('hyperdht/lib/persistent.js');
output(Persistent.prototype.verifyAnnounce.toString())
",
        )
        .await?;

    js_list_from_rs_vec(&mut repl, VALUE, "value").await?;
    js_list_from_rs_vec(&mut repl, target.0.as_slice(), "target").await?;
    js_list_from_rs_vec(&mut repl, &TOKEN, "token").await?;
    js_list_from_rs_vec(&mut repl, &ID, "id").await?;

    let res = repl
        .run_tcp(
            "
res = Persistent.prototype.verifyAnnounce({ value, target, token }, id);
output(res.toString());
",
        )
        .await?;

    assert_eq!(res, b"true");

    //println!("{}", String::from_utf8_lossy(&res));
    println!("{}", String::from_utf8_lossy(&res));
    Ok(())
}
async fn js_list_from_rs_vec(repl: &mut Repl, arr: &[u8], name: &str) -> Result<()> {
    let elments_str = arr
        .iter()
        .map(|e| format!("{e}"))
        .collect::<Vec<String>>()
        .join(",");
    let code = format!("{name} = Buffer.from([{elments_str}]);");
    repl.run_tcp(code).await?;
    Ok(())
}
