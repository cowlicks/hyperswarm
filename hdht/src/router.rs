#![allow(unused)]
use std::{any::Any, collections::BTreeMap, net::SocketAddrV4, sync::Arc};

use async_udx::{UdxSocket, UdxStream};
use compact_encoding::CompactEncoding;
use dht_rpc::{io::InResponse, Tid};
use hypercore_protocol::{
    handshake_constants::DHT_PATTERN, DecryptCipher, EncryptCipher, Handshake, HandshakeConfig,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
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
    udx_socket: UdxSocket,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            connections: Default::default(),
            udx_socket: UdxSocket::bind("127.0.0.1:0").unwrap(),
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

#[derive(Debug)]
struct Connection {
    handshake: Handshake,
    udx_local_id: u32,
    step: ConnStep,
    //noise_payload: Option<NoisePayload>,
}

impl Connection {
    fn new(handshake: Handshake, udx_local_id: u32) -> Self {
        Self {
            handshake,
            udx_local_id,
            step: ConnStep::Start,
        }
    }
}

fn dht_handshake_config(remote_public_key: [u8; 32]) -> HandshakeConfig {
    HandshakeConfig {
        pattern: DHT_PATTERN,
        prologue: Some(namespace::PEER_HANDSHAKE.to_vec()),
        remote_public_key: Some(remote_public_key),
    }
}

impl Router {
    #[instrument(skip_all, err)]
    pub fn inject_response(
        &mut self,
        resp: &Arc<InResponse>,
        ph: PeerHandshakePayload,
        event_queue: &mut dyn FnMut(HyperDhtEvent),
    ) -> Result<(), Error> {
        let conn = self.connections.get_mut(&resp.request.tid).unwrap();
        let Some(res) = conn.handshake.read_raw(&ph.noise)? else {
            todo!()
        };

        let (np, rest) = NoisePayload::decode(&res)?;

        if !conn.handshake.complete() {
            panic!("curr handshake pattern with this side being initializer should complete with first response")
        }
        let hs_res = conn.handshake.get_result()?;
        let (ec, init_msg) = EncryptCipher::from_handshake_tx(hs_res)?;

        let udx_remote_id = np
            .udx
            .as_ref()
            .expect("TODO response SHOULD have udx_info")
            .id as u32;
        let stream = self
            .udx_socket
            .connect(resp.request.to.addr, conn.udx_local_id, udx_remote_id)
            .expect("TODO why would this happen");

        conn.step = ConnStep::Ready(ReadyData::new(np, stream.clone()));
        event_queue(HyperDhtEvent::Connected((
            resp.request.tid,
            stream,
            self.udx_socket.clone(),
            Some(ec),
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
        let conf = dht_handshake_config(remote_public_key);
        let mut hs = Handshake::new(true, &conf).expect(
            "This would only fail for bad config values. These are know good. The only runtime input is remote_public_key which should work for any value"
        );
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

        hs.set_payload(np.into());
        let noise = hs
            .start_raw()?
            .expect("We are initiator here so this should be some");

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
    use crate::Keypair;
    use hypercore_protocol::sstream::hc_specific::generate_keypair;

    #[tokio::test]
    #[ignore]
    async fn qqstep_router() -> Result<(), Box<dyn std::error::Error>> {
        let kp = generate_keypair()?;
        let mut router = Router::default();
        let tid = 1u16;
        router.first_step(tid, kp.public.try_into().unwrap(), None)?;
        //let remote_public_key
        todo!()
    }
    #[tokio::test]
    async fn first() -> Result<(), Error> {
        let mut r = Router::default();
        let kp = Keypair::default();
        let remote_public_key = [0u8; 32];
        let local_addrs4 = Some(vec!["127.0.0.1:1234".parse()?]);
        let buf = r.first_step(16, *kp.public, local_addrs4)?;

        Ok(())
    }
}
