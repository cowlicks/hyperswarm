use std::net::{SocketAddrV4, SocketAddrV6};

use compact_encoding::{
    decode_usize, encode_usize_var, encoded_size_usize, map_decode, map_encode, map_first,
    sum_encoded_size, vec_encoded_size_for_fixed_sized_elements, CompactEncoding, EncodingError,
    VecEncodable, SOCKET_ADDR_V4_ENCODED_SIZE,
};

const UDX_INFO_VERSION: usize = 1;
const SECRET_STREAM_INFO_VERSION: usize = 1;
const RELAY_THROUGH_INFO_VERSION: usize = 1;
const NOISE_PAYLOAD_VERSION: usize = 1;
const NO_ERROR_NOISE_PAYLOAD_VALUE: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeSteps {
    FromClient = 0,
    FromServer = 1,
    FromRelay = 2,
    FromSecondRelay = 3,
    Repl = 4,
}

impl CompactEncoding for HandshakeSteps {
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
            0 => HandshakeSteps::FromClient,
            1 => HandshakeSteps::FromServer,
            2 => HandshakeSteps::FromRelay,
            3 => HandshakeSteps::FromSecondRelay,
            4 => HandshakeSteps::Repl,
            x => {
                return Err(EncodingError::invalid_data(&format!(
                    "Invalid value [{x}] for decoding HandshakeParts"
                )));
            }
        };
        Ok((mode, rest))
    }
}

#[derive(Debug)]
pub struct PeerHandshakePayload {
    peer_address: Option<SocketAddrV4>,
    relay_address: Option<SocketAddrV4>,
    mode: HandshakeSteps,
    noise: Vec<u8>,
}

impl PeerHandshakePayload {
    pub fn new(
        mode: HandshakeSteps,
        noise: Vec<u8>,
        peer_address: Option<SocketAddrV4>,
        relay_address: Option<SocketAddrV4>,
    ) -> Self {
        Self {
            mode,
            noise,
            peer_address,
            relay_address,
        }
    }
}

impl CompactEncoding for PeerHandshakePayload {
    fn encoded_size(&self) -> Result<usize, compact_encoding::EncodingError> {
        Ok(1 /* flags */ + self.mode.encoded_size()?
            + (if self.peer_address.is_some() { SOCKET_ADDR_V4_ENCODED_SIZE } else { 0 })
            + (if self.relay_address.is_some() { SOCKET_ADDR_V4_ENCODED_SIZE } else {0})
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
        let (mode, rest) = HandshakeSteps::decode(rest)?;
        let (noise, rest) = <Vec<u8> as CompactEncoding>::decode(rest)?;
        let (peer_address, rest) = if flags & 1 != 0 {
            let (addr, rest) = SocketAddrV4::decode(rest)?;
            (Some(addr), rest)
        } else {
            (None, rest)
        };
        let (relay_address, rest) = if flags & 2 != 0 {
            let (addr, rest) = SocketAddrV4::decode(rest)?;
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

#[derive(Debug)]
pub struct Holepunch {
    mode: HandshakeSteps,
    id: usize,
    payload: Vec<u8>,
    peer_address: Option<SocketAddrV4>,
}

impl CompactEncoding for Holepunch {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(
            1 /* flags */ + self.mode.encoded_size()? + encoded_size_usize(self.id)
             + (if self.peer_address.is_some() { SOCKET_ADDR_V4_ENCODED_SIZE } else { 0 }),
        )
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let flags = self.peer_address.as_ref().map(|_| 1).unwrap_or_default();
        let mut rest = encode_usize_var(&flags, buffer)?;
        rest = self.mode.encode(rest)?;
        rest = encode_usize_var(&self.id, rest)?;
        rest = self.payload.encode(rest)?;
        if let Some(addr) = &self.peer_address {
            rest = addr.encode(rest)?;
        }
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (flags, rest) = decode_usize(buffer)?;
        let (mode, rest) = HandshakeSteps::decode(rest)?;
        let (id, rest) = decode_usize(rest)?;
        let (payload, rest) = <Vec<u8> as CompactEncoding>::decode(rest)?;
        let (peer_address, rest) = if flags & 1 != 0 {
            let (addr, rest) = SocketAddrV4::decode(rest)?;
            (Some(addr), rest)
        } else {
            (None, rest)
        };
        Ok((
            Self {
                mode,
                id,
                payload,
                peer_address,
            },
            rest,
        ))
    }
}

#[derive(Debug)]
pub struct HolepunchInfo {
    id: usize,
    relays: Vec<RelayInfo>,
}
impl CompactEncoding for HolepunchInfo {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.id, self.relays))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.id, self.relays))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((id, relays), rest) = map_decode!(buffer, [usize, Vec<RelayInfo>]);
        Ok((Self { id, relays }, rest))
    }
}

#[derive(Debug, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct UdxInfo {
    #[builder(default = UDX_INFO_VERSION)]
    pub version: usize,
    pub reusable_socket: bool,
    pub id: usize,
    pub seq: usize,
}

impl CompactEncoding for UdxInfo {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(1 + 1 /* version + features */ + sum_encoded_size!(self.id, self.seq))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let rest = self.version.encode(buffer)?;
        let rest = if self.reusable_socket { 1usize } else { 0usize }.encode(rest)?;
        Ok(map_encode!(rest, self.id, self.seq))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((version, features, id, seq), rest) =
            map_decode!(buffer, [usize, usize, usize, usize]);
        Ok((
            Self {
                version,
                reusable_socket: features & 1 != 0,
                id,
                seq,
            },
            rest,
        ))
    }
}

#[derive(Debug)]
pub struct SecretStreamInfo {
    version: usize,
}

impl Default for SecretStreamInfo {
    fn default() -> Self {
        Self {
            version: SECRET_STREAM_INFO_VERSION,
        }
    }
}

impl CompactEncoding for SecretStreamInfo {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.version))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.version))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((version,), rest) = map_decode!(buffer, [usize]);
        Ok((Self { version }, rest))
    }
}

#[derive(Debug)]
pub struct RelayInfo {
    relay_address: SocketAddrV4,
    peer_address: SocketAddrV4,
}
impl RelayInfo {
    const ENCODED_SIZE: usize = SOCKET_ADDR_V4_ENCODED_SIZE * 2;
}
impl CompactEncoding for RelayInfo {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(SOCKET_ADDR_V4_ENCODED_SIZE * 2)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let rest = SocketAddrV4::encode(&self.relay_address, buffer)?;
        SocketAddrV4::encode(&self.peer_address, rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((relay_address, peer_address), rest) =
            map_decode!(buffer, [SocketAddrV4, SocketAddrV4]);
        Ok((
            Self {
                relay_address,
                peer_address,
            },
            rest,
        ))
    }
}

impl VecEncodable for RelayInfo {
    fn vec_encoded_size(vec: &[Self]) -> Result<usize, EncodingError>
    where
        Self: Sized,
    {
        Ok(vec_encoded_size_for_fixed_sized_elements(
            vec,
            RelayInfo::ENCODED_SIZE,
        ))
    }
}

#[derive(Debug, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct RelayThroughInfo {
    #[builder(default = RELAY_THROUGH_INFO_VERSION)]
    version: usize,
    public_key: [u8; 32],
    token: [u8; 32],
}

impl CompactEncoding for RelayThroughInfo {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(1 + 1 /* version + flags */ + sum_encoded_size!(self.public_key, self.token))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let flags = 0usize;
        Ok(map_encode!(
            buffer,
            self.version,
            flags,
            self.public_key,
            self.token
        ))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((version, _flags, public_key, token), rest) =
            map_decode!(buffer, [usize, usize, [u8; 32], [u8; 32]]);
        Ok((
            Self {
                version,
                public_key,
                token,
            },
            rest,
        ))
    }
}

macro_rules! ternary {
    ($cond:expr,  $if_true:expr, $if_false:expr) => {
        if $cond {
            $if_true
        } else {
            $if_false
        }
    };
    (let Some($name:ident) = $opt:expr, $if_true:expr, $if_false:expr) => {
        if let Some($name) = $opt {
            $if_true
        } else {
            $if_false
        }
    };
}

macro_rules! else_zero {
    ($cond:expr,  $if_true:expr) => {
        ternary!($cond, $if_true, 0)
    };
    (let Some($name:ident) = $opt:expr, $if_true:expr) => {
        ternary!(let Some($name) = $opt, $if_true, 0)
    };
}

// NB: in JS version, error & firewall are ncedoded as variable sized uints. But they add a
// constant "1" byte for each. Which could possibly break if these valuse get too big.
// Here and elsewhere I choose to copy this behavior.
#[derive(Debug, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct NoisePayload {
    #[builder(default = NOISE_PAYLOAD_VERSION)]
    pub version: usize,
    #[builder(default = NO_ERROR_NOISE_PAYLOAD_VALUE)]
    pub error: usize,
    pub firewall: usize,
    pub holepunch: Option<HolepunchInfo>,
    pub addresses4: Option<Vec<SocketAddrV4>>,
    pub addresses6: Option<Vec<SocketAddrV6>>,
    pub udx: Option<UdxInfo>,
    pub secret_stream: Option<SecretStreamInfo>,
    pub relay_through: Option<RelayThroughInfo>,
}

impl CompactEncoding for NoisePayload {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(1 + 1 + 1 + 1 /* version + flags + error + firewall */
             + else_zero!(let Some(x) = &self.holepunch, x.encoded_size()?)
             + else_zero!(let Some(x) = &self.addresses4, else_zero!(!x.is_empty(), x.encoded_size()?))
             + else_zero!(let Some(x) = &self.addresses6, else_zero!(!x.is_empty(), x.encoded_size()?))
             + else_zero!(let Some(x) = &self.udx, x.encoded_size()?)
             + else_zero!(let Some(x) = &self.secret_stream, x.encoded_size()?)
             + else_zero!(let Some(x) = &self.relay_through, x.encoded_size()?))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let mut flags = 0_usize;
        flags |= else_zero!(self.holepunch.is_some(), 1 << 0);
        flags |= else_zero!(let Some(x) = &self.addresses4, else_zero!(!x.is_empty(), 1 << 1));
        flags |= else_zero!(let Some(x) = &self.addresses6, else_zero!(!x.is_empty(), 1 << 2));
        flags |= else_zero!(self.udx.is_some(), 1 << 3);
        flags |= else_zero!(self.secret_stream.is_some(), 1 << 4);
        flags |= else_zero!(self.relay_through.is_some(), 1 << 5);

        let mut rest = map_encode!(buffer, self.version, flags, self.error, self.firewall);

        if let Some(hp) = &self.holepunch {
            rest = hp.encode(rest)?;
        }
        if let Some(addrs) = &self.addresses4 {
            if !addrs.is_empty() {
                rest = addrs.encode(rest)?;
            }
        }
        if let Some(addrs) = &self.addresses6 {
            if !addrs.is_empty() {
                rest = addrs.encode(rest)?;
            }
        }
        if let Some(udx) = &self.udx {
            rest = udx.encode(rest)?;
        }
        if let Some(secret_stream) = &self.secret_stream {
            rest = secret_stream.encode(rest)?;
        }
        if let Some(relay_through) = &self.relay_through {
            rest = relay_through.encode(rest)?;
        }
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (version, rest) = usize::decode(buffer)?;
        // NB: in JS there is a comment here:
        // // Do not attempt to decode but return this back to the user so they can
        // // actually handle it
        // It then returns with this almost empty self (just version populated).
        // And in JS that leaves the `State` (the thing that holds buffer and where we have decoded to)
        // in an invalid/undefined state. The caller does not know an error happened, and, cannot
        // begin to decode anything else becaue next bytes to decode within `State` belong to this
        // NoisePaylod. So... this seems wrong. Currently this panics. I think ti should be an
        // error. But maybe not a kind we currently have in compact_encoding. Maybe a new:
        // IncompatibleVersion error should be added.
        if version != NOISE_PAYLOAD_VERSION {
            return Ok((
                Self {
                    version,
                    error: Default::default(),
                    firewall: Default::default(),
                    holepunch: Default::default(),
                    addresses4: Default::default(),
                    addresses6: Default::default(),
                    udx: Default::default(),
                    secret_stream: Default::default(),
                    relay_through: Default::default(),
                },
                rest,
            ));
        }
        let ((flags, error, firewall), rest) = map_decode!(rest, [usize, usize, usize]);

        let (holepunch, rest) = if flags & 1 << 0 != 0 {
            map_first!(HolepunchInfo::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (addresses4, rest) = if flags & 1 << 1 != 0 {
            map_first!(Vec::<SocketAddrV4>::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (addresses6, rest) = if flags & 1 << 2 != 0 {
            map_first!(Vec::<SocketAddrV6>::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (udx, rest) = if flags & 1 << 3 != 0 {
            map_first!(UdxInfo::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (secret_stream, rest) = if flags & 1 << 4 != 0 {
            map_first!(SecretStreamInfo::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (relay_through, rest) = if flags & 1 << 5 != 0 {
            map_first!(RelayThroughInfo::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        Ok((
            Self {
                version,
                error,
                firewall,
                holepunch,
                addresses4,
                addresses6,
                udx,
                secret_stream,
                relay_through,
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
        assert_eq!(HandshakeSteps::FromClient as isize, 0);
    }
}
