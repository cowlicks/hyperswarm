#![allow(unused)]
pub mod connection;
use std::{
    any::Any,
    collections::BTreeMap,
    net::SocketAddrV4,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use async_compat::Compat;
use async_udx::{UdxSocket, UdxStream};
use compact_encoding::CompactEncoding;
use dht_rpc::{io::InResponse, Tid};
use futures::{Sink, Stream, StreamExt};

use hypercore_protocol::{
    sstream::sm2::{Event, Machine, MachineIo},
    EncryptCipher, Handshake, HandshakeConfig, Uint24LELengthPrefixedFraming,
};
use rand::{rngs::StdRng, SeedableRng};
use tracing::instrument;

use crate::{
    cenc::{
        firewall, NoisePayload, NoisePayloadBuilder, PeerHandshakePayload,
        PeerHandshakePayloadBuilder, UdxInfoBuilder,
    },
    namespace,
    next_router::connection::{ConnStep, Connection, ConnectionInner, ReadyData},
    Error, HyperDhtEvent,
};

// swap this with rng thing later. We increment now bc we're debugging stuff.
#[derive(Debug)]
struct StreamIdMaker {
    counter: u32,
}

impl StreamIdMaker {
    fn new() -> Self {
        Self { counter: 1 }
    }
    fn new_id(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }
}

#[derive(Debug)]
pub struct Router {
    rng: StdRng,
    id_maker: StreamIdMaker,
    connections: BTreeMap<Tid, Connection>,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            id_maker: StreamIdMaker::new(),
            connections: Default::default(),
        }
    }
}

impl Router {
    #[instrument(skip_all, err)]
    pub fn inject_response(
        &mut self,
        resp: &Arc<InResponse>,
        ph: PeerHandshakePayload,
        event_queue: &mut dyn FnMut(HyperDhtEvent),
        socket: UdxSocket,
    ) -> Result<(), Error> {
        let mut conn = self.connections.remove(&resp.request.tid).unwrap();
        let res = conn.receive_next(ph.noise)?;

        let msg: Vec<u8> = match res {
            Event::HandshakePayload(payload) => payload,
            Event::Message(items) => todo!(),
            Event::ErrStuff(error) => todo!(),
        };
        let (np, rest) = NoisePayload::decode(&msg)?;
        assert!(rest.is_empty());

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
        event_queue(HyperDhtEvent::Connected((resp.request.tid, conn)));
        Ok(())
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
            Machine::new_dht_init(None, &remote_public_key, &crate::namespace::PEER_HANDSHAKE)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use hypercore_protocol::sstream::hc_specific::generate_keypair;

    #[tokio::test]
    #[ignore]
    async fn qqstep_next_router() -> Result<(), Box<dyn std::error::Error>> {
        let kp = generate_keypair()?;
        let mut router = Router::default();
        let tid = 1u16;
        router.first_step(
            tid,
            kp.public.try_into().unwrap(),
            None,
            UdxSocket::bind("127.0.0.1:0")?,
        )?;
        //let remote_public_key
        todo!()
    }
}
