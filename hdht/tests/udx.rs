//! these really belong in async_udx's integration tests
mod common;

use async_udx::{UdxSocket, UdxStream};
use common::Result;
use rusty_nodejs_repl::Repl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::js::make_repl;

struct UdxStuff {
    socket: UdxSocket,
    rs_port: u16,
    _js_port: u16,
    stream: UdxStream,
}

/// create connected js and rs socket and stream.
/// js socket named 'a' and socket named 'jstream'
async fn udx_setup(repl: &mut Repl) -> Result<UdxStuff> {
    let js_port = repl
        .run_tcp(
            "
UDX = require('udx-native')
u = new UDX()
a = u.createSocket()
a.bind()
output(a.address().port.toString());
",
        )
        .await?;
    let js_port: u16 = String::from_utf8(js_port).unwrap().parse().unwrap();
    let socket = UdxSocket::bind_rnd()?;
    let rs_port = socket.local_addr()?.port();

    // this would hang forever, messages are not broadcasted or cloned
    // let (_, msg) = b.recv().await?;

    let js_id = 42;
    let rs_id = 66;

    let stream = socket
        .connect(
            format!("127.0.0.1:{js_port}").parse().unwrap(),
            rs_id,
            js_id,
        )
        .unwrap();
    repl.run_tcp(format!(
        "
jstream = u.createStream({js_id})
jstream.connect(a, {rs_id}, {rs_port}, '127.0.0.1')
"
    ))
    .await?;
    Ok(UdxStuff {
        socket,
        rs_port,
        _js_port: js_port,
        stream,
    })
}

#[tokio::test]
async fn udx_does_stream_get_consumed_by_socket() -> Result<()> {
    let mut repl = make_repl().await;
    let o = repl
        .run_tcp(
            "
UDX = require('udx-native')
u = new UDX()
a = u.createSocket()
b = u.createSocket()
a.bind()
b.bind()

let aid = 42;
let bid = 66;

astream = u.createStream(aid);
astream.connect(a, bid, b.address().port, '127.0.0.1')

await astream.write(Buffer.from('AAAAAAAAA'));

// uncomment to block recv to verify that creating stream, without connecting it, blocks recv for
// that i.d
//bstream = u.createStream(bid);

let b_sock_res = await new Promise(res => {
    b.on('message', (m) => {
        console.log('B-SOCK-MSG', [...m])
        res(m)
    })
})
bstream = u.createStream(bid);

bprom = new Promise(res => {
    bstream.on('data', (m) => {
        console.log('B-STREAM-MSG', [...m])
        res(m)
    })
})
await astream.write(Buffer.from('BBBBBBB'));
await new Promise(res => setTimeout(res, 500))
bstream.connect(b, aid, a.address().port, '127.0.0.1')
await astream.write(Buffer.from('CCCCCCC'));
await bprom;
await new Promise(res => setTimeout(res, 500))
",
        )
        .await?;
    println!("{}", String::from_utf8_lossy(&o));
    repl.print_until_settled().await?;
    Ok(())
}

#[tokio::test]
async fn udx_js_rs_socket() -> Result<()> {
    let mut repl = make_repl().await;
    let UdxStuff {
        socket, rs_port, ..
    } = udx_setup(&mut repl).await?;
    repl.run_tcp(format!("a.send(Buffer.from('hello'), {rs_port})"))
        .await?;
    let (_, msg) = socket.recv().await?;
    assert_eq!(msg, b"hello");

    let c = socket.clone();
    assert_eq!(socket.local_addr()?.port(), c.local_addr()?.port());

    repl.run_tcp(format!("a.send(Buffer.from('yo'), {rs_port})"))
        .await?;
    let (_, msg) = c.recv().await?;
    assert_eq!(msg, b"yo");
    Ok(())
}

#[tokio::test]
async fn udx_js_stream_to_rs_stream() -> Result<()> {
    let mut repl = make_repl().await;
    let UdxStuff { mut stream, .. } = udx_setup(&mut repl).await?;

    repl.run_tcp(
        "
jstream.write(Buffer.from('hello'))
jstream.end()
",
    )
    .await?;

    let mut buf = [0u8; 5];
    stream.read_exact(buf.as_mut_slice()).await?;
    assert_eq!(&buf, b"hello");
    Ok(())
}

#[tokio::test]
async fn udx_rs_stream_to_js_stream() -> Result<()> {
    let mut repl = make_repl().await;
    let UdxStuff { mut stream, .. } = udx_setup(&mut repl).await?;

    stream.write_all(b"hello").await?;

    let res = repl
        .run_tcp(
            "
got_msg = deferred();
jstream.on('data', function (data) {
    got_msg.resolve(data.toString())
})
output(await got_msg);
",
        )
        .await?;

    assert_eq!(String::from_utf8_lossy(&res), "hello");
    Ok(())
}

/// this will hang because rs sock can't recieve from a rs stream
#[ignore]
#[tokio::test]
async fn udx_js_stream_rs_socket_ustrrsock() -> Result<()> {
    let mut repl = make_repl().await;
    let UdxStuff { socket, .. } = udx_setup(&mut repl).await?;

    repl.run_tcp(
        "
jstream.write(Buffer.from('hello'))
jstream.end()
",
    )
    .await?;

    let (_, x) = socket.recv().await?;
    assert_eq!(x, b"hello");
    Ok(())
}
