// TODO remove magic numbers
// - 4 = number of bytes in an ipv4 addresses
// - 2 = number of bytes in a port
use compact_encoding::{
    decode_usize, encoded_size_usize, map_decode, take_array, write_array, CompactEncoding,
    EncodingError, VecEncodable,
};
use std::net::SocketAddrV4;

use crate::crypto::{PublicKey, Signature2};

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub public_key: PublicKey,
    pub relay_addresses: Vec<SocketAddrV4>,
}

impl CompactEncoding for Peer {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        let n_addrs = self.relay_addresses.len();
        let x = /* pub_key size */ 32 + encoded_size_usize(n_addrs) + (/* socket size */6 * n_addrs);
        Ok(x)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let rest = write_array(&*self.public_key, buffer)?;
        self.relay_addresses.encode(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((public_key, relay_addresses), rest) =
            map_decode!(buffer, [[u8; 32], Vec<SocketAddrV4>]);
        Ok((
            Peer {
                public_key: public_key.into(),
                relay_addresses,
            },
            rest,
        ))
    }
}

impl VecEncodable for Peer {
    fn vec_encoded_size(vec: &[Self]) -> Result<usize, EncodingError>
    where
        Self: Sized,
    {
        let mut out = encoded_size_usize(vec.len());
        for x in vec {
            out += x.encoded_size()?;
        }
        Ok(out)
    }
}

#[derive(Debug)]
/// Struct representing Announce OR Unannounce request value
pub struct Announce {
    pub peer: Peer,
    pub refresh: Option<[u8; 32]>,
    pub signature: Signature2,
}

impl CompactEncoding for Announce {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(
            1 /* flags */ + self.peer.encoded_size()? + self.refresh.map(|_| 32).unwrap_or(0) + 64, /*signature*/
        )
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let flags: u8 = (1 << 0) | self.refresh.map(|_| (1 << 1)).unwrap_or(0) | (1 << 2);
        let rest = write_array(&[flags], buffer)?;
        let rest = self.peer.encode(rest)?;
        let rest = match self.refresh {
            Some(x) => write_array(&x, rest)?,
            None => rest,
        };
        write_array(&self.signature.0, rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (flags, rest) = decode_usize(buffer)?;
        let (peer, rest) = if flags & (1 << 0) > 0 {
            Peer::decode(rest)?
        } else {
            return Err(EncodingError::new(
                compact_encoding::EncodingErrorKind::InvalidData,
                "Announce peer is required",
            ));
        };
        let (refresh, rest) = if flags & (1 << 1) > 0 {
            let (refresh, rest) = take_array::<32>(rest)?;
            (Some(refresh), rest)
        } else {
            (None, rest)
        };
        let (signature, rest) = if flags & (1 << 2) > 0 {
            take_array::<64>(rest)?
        } else {
            return Err(EncodingError::new(
                compact_encoding::EncodingErrorKind::InvalidData,
                "Announce signature required",
            ));
        };
        Ok((
            Announce {
                peer,
                refresh,
                signature: Signature2(signature),
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use compact_encoding::EncodingError;

    #[test]
    fn socket_addr_enc_dec() -> Result<(), EncodingError> {
        let sa: SocketAddr = "192.168.1.2:1234".parse().unwrap();
        println!("{sa:?}");
        let x = SocketAddrV4::from(sa);
        let mut buf: [u8; 6] = [0; 6];
        x.encode(&mut buf).unwrap();

        assert_eq!(buf, [192, 168, 1, 2, 210, 4]);

        let (val, _rest) = SocketAddrV4::decode(&buf).unwrap();
        assert_eq!(val.0, x.0);
        Ok(())
    }

    #[test]
    fn peer_encoding() -> Result<(), EncodingError> {
        let one: SocketAddrV4 = "192.168.1.2:1234".parse().unwrap();
        let two: SocketAddrV4 = "10.11.12.13:6547".parse().unwrap();
        let three: SocketAddrV4 = "127.0.0.1:80".parse().unwrap();
        let pub_key_bytes = [
            114, 200, 78, 248, 86, 217, 108, 95, 186, 140, 62, 30, 146, 198, 167, 188, 187, 151,
            86, 70, 50, 238, 193, 187, 208, 113, 48, 47, 217, 126, 252, 251,
        ];
        //let public_key = PublicKey::from_bytes(&pub_key_bytes).unwrap();

        let peer = Peer {
            public_key: pub_key_bytes.into(),
            relay_addresses: vec![one, two, three],
        };

        let enc_sized = <Peer as CompactEncoding>::encoded_size(&peer)?;
        let mut buf: Vec<u8> = vec![0; enc_sized];
        let remaining_enc = peer.encode(&mut buf)?;
        assert_eq!(remaining_enc.len(), 0);
        assert_eq!(buf.len(), enc_sized);
        let (peer2, remaining_dec) = <Peer as CompactEncoding>::decode(&buf)?;
        assert_eq!(peer, peer2);
        assert!(remaining_dec.is_empty());
        Ok(())
    }
}
