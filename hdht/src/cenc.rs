use compact_encoding::{
    types::{
        take_array, usize_decode, usize_encoded_bytes, usize_encoded_size, write_array,
        CompactEncodable,
    },
    EncodingError,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::crypto::{PublicKey, Signature2};

#[derive(Debug)]
struct SocketAddr2(pub SocketAddr);
impl From<SocketAddr> for SocketAddr2 {
    fn from(value: SocketAddr) -> Self {
        Self(value)
    }
}
impl From<SocketAddr2> for SocketAddr {
    fn from(value: SocketAddr2) -> Self {
        value.0
    }
}
impl CompactEncodable for SocketAddr2 {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(4 + 2) // ipv4 addr + port
    }
    fn encoded_bytes<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let IpAddr::V4(ip) = self.0.ip() else { todo!() };
        let rest = CompactEncodable::encoded_bytes(&ip, buffer)?;
        let Some((dest, rest)) = rest.split_first_chunk_mut::<2>() else {
            todo!()
        };
        dest.copy_from_slice(&self.0.port().to_le_bytes());
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let Some((src, rest)) = buffer.split_first_chunk::<4>() else {
            todo!()
        };
        let ip = Ipv4Addr::from(*src);
        let Some((src, rest)) = rest.split_first_chunk::<2>() else {
            todo!()
        };
        let port = u16::from_le_bytes(*src);
        Ok((SocketAddr2(SocketAddr::new(IpAddr::V4(ip), port)), rest))
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub public_key: PublicKey,
    pub relay_addresses: Vec<SocketAddr>,
}

impl CompactEncodable for Peer {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        let n_addrs = self.relay_addresses.len();
        let x = /* pub_key size */ 32 + usize_encoded_size(n_addrs) + (/* socket size */6 * n_addrs);
        Ok(x)
    }

    fn encoded_bytes<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let Some((dest, mut rest)) = buffer.split_first_chunk_mut::<32>() else {
            todo!()
        };
        dest.copy_from_slice(&*self.public_key);
        rest = self
            .relay_addresses
            .iter()
            .map(|x| SocketAddr2(*x))
            .collect::<Vec<SocketAddr2>>()
            .encoded_bytes(rest)?;
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let Some((public_key, rest)) = buffer.split_first_chunk::<32>() else {
            todo!()
        };
        let res: (Vec<SocketAddr2>, &[u8]) = <Vec<SocketAddr2> as CompactEncodable>::decode(rest)?;
        //todo!()
        let relay_addresses = res.0.into_iter().map(SocketAddr::from).collect();
        Ok((
            Peer {
                public_key: (*public_key).into(),
                relay_addresses,
            },
            res.1,
        ))
    }
}

#[derive(Debug)]
/// Struct representing Announce OR Unannounce request value
pub struct Announce {
    pub peer: Peer,
    pub refresh: Option<[u8; 32]>,
    pub signature: Signature2,
}

impl CompactEncodable for Announce {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(
            1 /* flags */ + self.peer.encoded_size()? + self.refresh.map(|_| 32).unwrap_or(0) + 64, /*signature*/
        )
    }

    fn encoded_bytes<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let flags = (1 << 0) | self.refresh.map(|_| (1 << 1)).unwrap_or(0) | (1 << 2);
        let rest = usize_encoded_bytes(flags, buffer)?;
        let rest = self.peer.encoded_bytes(rest)?;
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
        let (flags, rest) = usize_decode(buffer)?;
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
        let x = SocketAddr2::from(sa);
        let mut buf: [u8; 6] = [0; 6];
        x.encoded_bytes(&mut buf).unwrap();

        assert_eq!(buf, [192, 168, 1, 2, 210, 4]);

        let (val, _rest) = SocketAddr2::decode(&buf).unwrap();
        assert_eq!(val.0, x.0);
        Ok(())
    }

    #[test]
    fn peer_encoding() -> Result<(), EncodingError> {
        let one: SocketAddr = "192.168.1.2:1234".parse().unwrap();
        let two: SocketAddr = "10.11.12.13:6547".parse().unwrap();
        let three: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let pub_key_bytes = [
            114, 200, 78, 248, 86, 217, 108, 95, 186, 140, 62, 30, 146, 198, 167, 188, 187, 151,
            86, 70, 50, 238, 193, 187, 208, 113, 48, 47, 217, 126, 252, 251,
        ];
        //let public_key = PublicKey::from_bytes(&pub_key_bytes).unwrap();

        let peer = Peer {
            public_key: pub_key_bytes.into(),
            relay_addresses: vec![one, two, three],
        };

        let enc_sized = <Peer as CompactEncodable>::encoded_size(&peer)?;
        let mut buf: Vec<u8> = vec![0; enc_sized];
        let remaining_enc = peer.encoded_bytes(&mut buf)?;
        assert_eq!(remaining_enc.len(), 0);
        assert_eq!(buf.len(), enc_sized);
        let (peer2, remaining_dec) = <Peer as CompactEncodable>::decode(&buf)?;
        assert_eq!(peer, peer2);
        assert!(remaining_dec.is_empty());
        Ok(())
    }
}
