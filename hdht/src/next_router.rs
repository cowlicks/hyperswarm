#![allow(unused)]
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
    namespace, Error, HyperDhtEvent,
};

#[derive(Debug)]
pub struct Router {
    rng: StdRng,
    connections: BTreeMap<Tid, Connection>,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            connections: Default::default(),
        }
    }
}

#[derive(Debug)]
struct ReadyData {
    noise_payload: NoisePayload,
    stream: UdxStream,
}

impl ReadyData {
    fn new(noise_payload: NoisePayload, stream: UdxStream) -> Self {
        Self {
            noise_payload,
            stream,
        }
    }
}

#[derive(Debug)]
enum ConnStep {
    /// Initial State
    Start,
    /// Initial hanshake message sent
    RequestSent, // is this specific initializerl
    /// Handshake Ready
    Ready(ReadyData),
    // Handshake failed
    Failed,
}

#[derive(Debug, Clone)]
struct Connection {
    inner: Arc<RwLock<ConnectionInner>>,
}

macro_rules! w {
    ($self:expr) => {
        $self.inner.write().unwrap()
    };
}
macro_rules! r {
    ($self:expr) => {
        $self.inner.read().unwrap()
    };
}

impl Connection {
    fn new(handshake: Machine, udx_local_id: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionInner {
                handshake,
                udx_local_id,
                step: ConnStep::Start,
            })),
        }
    }
    fn receive_next(&self, noise: Vec<u8>) -> Result<Event, Error> {
        w!(self).handshake.receive_next(noise);
        Ok(w!(self)
            .handshake
            .next_decrypted_message()?
            .expect("recieved msg above"))
    }
    fn handshake_ready(&self) -> bool {
        r!(self).handshake.ready()
    }
    fn udx_local_id(&self) -> u32 {
        r!(self).udx_local_id
    }
    fn handshake_set_io(&self, io: Box<dyn MachineIo<Error = std::io::Error>>) {
        w!(self).handshake.set_io(io)
    }
    fn set_step(&self, step: ConnStep) {
        w!(self).step = step;
    }
    fn get_constep(&self) -> &ConnStep {
        //&r!(self).step
        todo!()
    }
}

#[derive(Debug)]
struct ConnectionInner {
    handshake: Machine,
    udx_local_id: u32,
    step: ConnStep,
}

impl Router {
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        for (tid, conn) in self.connections.iter_mut() {
            if matches!(conn.inner.read().unwrap().step, ConnStep::Ready(_)) {
                let x =
                    Machine::poll_next(Pin::new(&mut conn.inner.write().unwrap().handshake), cx);
            }
        }
        Poll::Pending
    }

    #[instrument(skip_all, err)]
    pub fn inject_response(
        &mut self,
        resp: &Arc<InResponse>,
        ph: PeerHandshakePayload,
        event_queue: &mut dyn FnMut(HyperDhtEvent),
        socket: UdxSocket,
    ) -> Result<(), Error> {
        println!("FOO RESPONSE");
        let conn = self.connections.get_mut(&resp.request.tid).unwrap();
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
        }

        let udx_remote_id = np
            .udx
            .as_ref()
            .expect("TODO response SHOULD have udx_info")
            .id as u32;
        let udx_stream = socket
            .connect(resp.request.to.addr, conn.udx_local_id(), udx_remote_id)
            .expect("TODO why would this happen");

        let framed_udx_stream = Uint24LELengthPrefixedFraming::new(Compat::new(udx_stream.clone()));
        conn.handshake_set_io(Box::new(framed_udx_stream));

        conn.set_step(ConnStep::Ready(ReadyData::new(np, udx_stream.clone())));
        event_queue(HyperDhtEvent::Connected((
            resp.request.tid,
            udx_stream,
            socket.clone(),
            None,
        )));
        Ok(())
    }

    /// Create the first payload for the handshake protocol. Create and store an object for
    /// tracking the handshake state.
    pub fn first_step(
        &mut self,
        tid: Tid,
        remote_public_key: [u8; 32],
        local_addrs4: Option<Vec<SocketAddrV4>>,
    ) -> Result<Vec<u8>, Error> {
        let mut hs =
            Machine::new_dht_init(None, &remote_public_key, &crate::namespace::PEER_HANDSHAKE)?;
        // TODO store this
        //let udx_local_id = self.rng.next_u32();
        let udx_local_id = 43;
        let np = NoisePayloadBuilder::default()
            .firewall(firewall::UNKNOWN)
            .addresses4(local_addrs4)
            .udx(Some(
                UdxInfoBuilder::default()
                    .reusable_socket(true)
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
        let conn = Connection::new(hs, udx_local_id);
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
        router.first_step(tid, kp.public.try_into().unwrap(), None)?;
        //let remote_public_key
        todo!()
    }
}
