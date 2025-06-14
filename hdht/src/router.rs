// TODO handshake should take a keyPair
#![allow(unused)]
use std::{collections::BTreeMap, net::SocketAddrV4, sync::Arc};

use async_udx::{UdxSocket, UdxStream};
use compact_encoding::CompactEncoding;
use dht_rpc::{io::InResponse, Tid};
use hypercore_protocol::{handshake_constants::DHT_PATTERN, Handshake, HandshakeConfig};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    cenc::{firewall, NoisePayloadBuilder, PeerHandshakePayloadBuilder, UdxInfoBuilder},
    namespace, Error,
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
struct Connection {
    handshake: Handshake,
    udx_local_id: u32,
}

impl Connection {
    fn new(handshake: Handshake, udx_local_id: u32) -> Self {
        Self {
            handshake,
            udx_local_id,
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
    fn inject_response(&mut self, _resp: Arc<InResponse>) {
        todo!()
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

    use crate::Keypair;

    use super::*;
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
