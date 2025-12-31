pub mod connection;
use std::{
    collections::BTreeMap,
    net::SocketAddrV4,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use compact_encoding::CompactEncoding;
use dht_rpc::{InResponse, Tid};
use udx::UdxSocket;

use hypercore_handshake::{Cipher, CipherEvent};
use tracing::instrument;

use crate::{
    Error, PeerHandshakeResponse,
    cenc::{
        NoisePayload, NoisePayloadBuilder, PeerHandshakePayloadBuilder, UdxInfoBuilder, firewall,
    },
    next_router::connection::Connection,
};

// TODO: swap this with rng thing later. We increment now bc we're debugging stuff.
// TODO: even better make udx stream api like (half_stream, local_id) = socket.new_stream()
#[derive(Debug)]
pub struct StreamIdMaker {
    counter: AtomicU32,
}

impl StreamIdMaker {
    // TODO use RNG to pick id
    pub fn new() -> Self {
        Self {
            counter: AtomicU32::new(1u32),
        }
    }
    pub fn new_id(&self) -> u32 {
        self.counter.fetch_add(1u32, Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct Router {
    id_maker: StreamIdMaker,
    connections: BTreeMap<Tid, Connection>,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            id_maker: StreamIdMaker::new(),
            connections: Default::default(),
        }
    }
}

#[expect(unused, reason = "will be used when we have multiple connections")]
impl Router {
    #[instrument(skip_all, err)]
    pub fn inject_response(
        &mut self,
        resp: &Arc<InResponse>,
        ph: Arc<PeerHandshakeResponse>,
        _socket: UdxSocket,
    ) -> crate::Result<Connection> {
        let conn = self.connections.remove(&resp.request.tid).unwrap();
        let res = conn.receive_next(ph.noise.clone())?;
        let msg: Vec<u8> = match res {
            CipherEvent::HandshakePayload(payload) => payload,
            CipherEvent::Message(_items) => todo!(),
            CipherEvent::ErrStuff(_error) => todo!(),
        };
        let (np, rest) = NoisePayload::decode(&msg)?;
        debug_assert!(rest.is_empty());
        if !ph.relayed {
            if !conn.handshake_ready() {
                // We are not "ready" here but we can encrypt stuff.
                // And the next message we would receive would contain our decryptor.
                // So we can basically be "ready"
                //panic!("curr handshake pattern with this side being initializer should complete with first response")
                // TODO
            }
            let udx_remote_id = np
                .udx
                .as_ref()
                .expect("TODO response SHOULD have udx_info")
                .id as u32;

            conn.connect(resp.request.to.addr, udx_remote_id, np)?;
            Ok(conn)
        } else {
            Err(Error::PeerHandshakeFailed(
                "relay not implemented yet".into(),
            ))
        }
    }

    /// Create the first payload for the handshake protocol. Create and store an object for
    /// tracking the handshake state.
    pub fn first_step(
        &mut self,
        tid: Tid,
        remote_public_key: [u8; 32],
        local_addrs4: Option<Vec<SocketAddrV4>>,
        socket: UdxSocket,
    ) -> Result<Vec<u8>, Error> {
        let mut hs =
            Cipher::new_dht_init(None, &remote_public_key, &crate::namespace::PEER_HANDSHAKE)?;
        let udx_local_id = self.id_maker.new_id();
        let np = NoisePayloadBuilder::default()
            .firewall(firewall::OPEN)
            .addresses4(local_addrs4)
            .udx(Some(
                UdxInfoBuilder::default()
                    .reusable_socket(false)
                    .id(udx_local_id as usize)
                    .build()?,
            ))
            .build()?
            .to_encoded_bytes()?;
        hs.handshake_start(&np)?;
        let noise = hs
            .get_next_sendable_message()?
            .expect("should be present we just set payload above");
        let peer_handshake_payload = PeerHandshakePayloadBuilder::default()
            .noise(noise)
            .mode(crate::cenc::HandshakeSteps::FromClient)
            .build()?
            .to_encoded_bytes()?;
        let half_stream = socket.create_stream(udx_local_id)?;
        let conn = Connection::new(hs, udx_local_id, half_stream);
        self.connections.insert(tid, conn);
        Ok(peer_handshake_payload.into())
    }
}
