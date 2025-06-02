use compact_encoding::{decode_usize, encode_usize_var, CompactEncoding, EncodingError};

use crate::cenc::SocketAddr2;

#[derive(Debug, Clone, Copy, PartialEq)]
enum HandshakeParts {
    FromClient = 0,
    FromServer = 1,
    FromRelay = 2,
    FromSecondRelay = 3,
    Repl = 4,
}

impl CompactEncoding for HandshakeParts {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(1)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        encode_usize_var(&(*self as usize), buffer)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (discriminant, rest) = decode_usize(buffer)?;
        let mode = match discriminant {
            0 => HandshakeParts::FromClient,
            1 => HandshakeParts::FromServer,
            2 => HandshakeParts::FromRelay,
            3 => HandshakeParts::FromSecondRelay,
            4 => HandshakeParts::Repl,
            x => {
                return Err(EncodingError::invalid_data(&format!(
                    "Invalid value [{x}] for decoding HandshakeParts"
                )));
            }
        };
        Ok((mode, rest))
    }
}

struct Handshake {
    peer_address: Option<SocketAddr2>,
    relay_address: Option<SocketAddr2>,
    mode: HandshakeParts, // TODO
    noise: Vec<u8>,
}

impl CompactEncoding for Handshake {
    fn encoded_size(&self) -> Result<usize, compact_encoding::EncodingError> {
        Ok(1 /* flags */ + self.mode.encoded_size()?
            + (if self.peer_address.is_some() { SocketAddr2::ENCODED_SIZE } else { 0 })
            + (if self.relay_address.is_some() { SocketAddr2::ENCODED_SIZE } else {0})
            + self.noise.encoded_size()?)
    }

    fn encode<'a>(
        &self,
        buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], compact_encoding::EncodingError> {
        let mut flags = self.peer_address.as_ref().map(|_| 1).unwrap_or_default();
        flags |= self.relay_address.as_ref().map(|_| 2).unwrap_or_default();
        let mut rest = encode_usize_var(&flags, buffer)?;
        rest = self.mode.encode(rest)?;
        rest = self.noise.encode(rest)?;
        if let Some(addr) = &self.peer_address {
            rest = addr.encode(rest)?;
        }
        if let Some(addr) = &self.relay_address {
            rest = addr.encode(rest)?;
        }
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), compact_encoding::EncodingError>
    where
        Self: Sized,
    {
        let (flags, rest) = decode_usize(buffer)?;
        let (mode, rest) = HandshakeParts::decode(rest)?;
        let (noise, rest) = <Vec<u8> as CompactEncoding>::decode(rest)?;
        let (peer_address, rest) = if flags & 1 != 0 {
            let (addr, rest) = SocketAddr2::decode(rest)?;
            (Some(addr), rest)
        } else {
            (None, rest)
        };
        let (relay_address, rest) = if flags & 2 != 0 {
            let (addr, rest) = SocketAddr2::decode(rest)?;
            (Some(addr), rest)
        } else {
            (None, rest)
        };
        Ok((
            Self {
                mode,
                noise,
                peer_address,
                relay_address,
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn handshake_parts_discriminant() {
        assert_eq!(HandshakeParts::FromClient as isize, 0);
    }
}
