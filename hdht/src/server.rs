use dht_rpc::IdBytes;
use udx::UdxSocket;
pub struct Server {
    socket: UdxSocket,
}

impl Server {
    fn new(socket: UdxSocket) -> Self {
        Self { socket }
    }
}
