use compact_encoding::CompactEncoding;
use std::net::SocketAddrV4;

use crate::cenc::{HandshakeSteps, NoisePayload, PeerHandshakePayloadBuilder};

use super::cenc::PeerHandshakePayload;

// TODO: consider adding constructors/new functions and make fields private
// TODO: consider more sophisticated "version" handling for UdxInfo.version,
// SecretStreamInfo.version, RelayThroughInfo.version, NoisePayload.version
impl PeerHandshakePayload {
    /// Create a handshake payload with noise-processed payload
    /// This encodes the NoisePayload and processes it through the DHT noise handshake
    fn create_with_noise_payload(
        mode: HandshakeSteps,
        payload: &NoisePayload,
        peer_address: Option<SocketAddrV4>,
        relay_address: Option<SocketAddrV4>,
        is_initiator: bool,
        remote_public_key: Option<[u8; 32]>,
    ) -> Result<Self, crate::Error> {
        let noise_buffer = Self::create_noise_buffer(payload, is_initiator, remote_public_key)?;
        Ok(PeerHandshakePayloadBuilder::default()
            .mode(mode)
            .noise(noise_buffer)
            .peer_address(peer_address)
            .relay_address(relay_address)
            .build()?)
        //Ok(Self::new(mode, noise_buffer, peer_address, relay_address))
    }

    // this noise_handshake thing should be stored in hdht to handle the handshaking
    /// Create noise buffer by encoding payload and processing through DHT noise handshake
    fn create_noise_buffer(
        payload: &NoisePayload,
        is_initiator: bool,
        remote_public_key: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, crate::Error> {
        // 1. Encode the NoisePayload using CompactEncoding
        let encoded_payload = payload
            .to_encoded_bytes()
            .map_err(crate::Error::from)?
            .to_vec();

        // 2. Create DHT noise handshake using protocol crate
        let mut noise_handshake = hypercore_protocol::Handshake::new_dht(
            is_initiator,
            remote_public_key,
            &crate::crypto::namespace::PEER_HANDSHAKE,
        )
        .map_err(|e| crate::Error::IoError(e))?;

        // 3. Set the payload to be sent through noise handshake
        noise_handshake.set_payload(encoded_payload);

        // 4. Generate the noise message
        let result = if is_initiator {
            noise_handshake
                .start_raw()
                .map_err(|e| crate::Error::IoError(e))?
                .ok_or_else(|| {
                    crate::Error::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Expected noise message from initiator",
                    ))
                })?
        } else {
            // For responder, we would need the initiator's message first
            // This is a simplified implementation - in practice, the responder
            // would receive the initiator's message and respond accordingly
            return Err(crate::Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Responder noise handling not yet implemented",
            )));
        };

        Ok(result)
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn handshake_parts_discriminant() {
        assert_eq!(HandshakeSteps::FromClient as isize, 0);
    }
}
