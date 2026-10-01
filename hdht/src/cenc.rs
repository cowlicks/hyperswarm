// TODO remove magic numbers
// - 4 = number of bytes in an ipv4 addresses
// - 2 = number of bytes in a port
use compact_encoding::{
    CompactEncoding, EncodingError, SOCKET_ADDR_V4_ENCODED_SIZE, VecEncodable, decode_usize,
    encode_usize_var, encoded_size_usize, map_decode, map_encode, map_first, sum_encoded_size,
    take_array, vec_encoded_size_for_fixed_sized_elements, write_array,
};
use std::net::{SocketAddrV4, SocketAddrV6};
use tracing::error;

const UDX_INFO_VERSION: usize = 1;
const UDX_INFO_DEFAULT_SEQ: usize = 0;
const SECRET_STREAM_INFO_VERSION: usize = 1;
const RELAY_THROUGH_INFO_VERSION: usize = 1;
const NOISE_PAYLOAD_VERSION: usize = 1;
const NO_ERROR_NOISE_PAYLOAD_VALUE: usize = 0;

use crate::crypto::{PublicKey, Signature2};

macro_rules! ternary {
    ($cond:expr,  $if_true:expr, $if_false:expr) => {
        if $cond { $if_true } else { $if_false }
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
        let rest = write_array(&self.public_key, buffer)?;
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
pub struct AnnounceRequestValue {
    pub peer: Peer,
    pub refresh: Option<[u8; 32]>,
    pub signature: Signature2,
}

impl CompactEncoding for AnnounceRequestValue {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(
            1 /* flags */ + self.peer.encoded_size()? + self.refresh.map(|_| 32).unwrap_or(0) + 64, /*signature*/
        )
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let flags: u8 = (1 << 0) | self.refresh.map(|_| 1 << 1).unwrap_or(0) | (1 << 2);
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
            AnnounceRequestValue {
                peer,
                refresh,
                signature: Signature2(signature),
            },
            rest,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeSteps {
    FromClient = 0,
    FromServer = 1,
    FromRelay = 2,
    FromSecondRelay = 3,
    Reply = 4,
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
            4 => HandshakeSteps::Reply,
            x => {
                return Err(EncodingError::invalid_data(&format!(
                    "Invalid value [{x}] for decoding HandshakeParts"
                )));
            }
        };
        Ok((mode, rest))
    }
}

#[derive(Debug, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct PeerHandshakePayload {
    #[builder(default = None)]
    pub peer_address: Option<SocketAddrV4>,
    #[builder(default = None)]
    pub relay_address: Option<SocketAddrV4>,
    pub mode: HandshakeSteps,
    pub noise: Vec<u8>,
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
// Nothing constructs one until the relay path lands. `allow` rather than `expect` for the
// same reason as `HolepunchPayload` below: the round-trip test makes these live under
// `--all-targets` but not under a plain lib build, so an expectation would be unfulfilled in
// one of the two configurations.
#[expect(dead_code)]
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
             + self.payload.encoded_size()?
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

/// The negotiation that rides inside [`Holepunch::payload`], encrypted end to end.
///
/// [`Holepunch`] itself is the envelope, and relays read it to know where to forward. This is
/// the part only the two peers can read, which is why the firewall verdict and the addresses
/// to aim at live here: a relay has no business learning either, and a peer must not be able
/// to talk a third party into punching somewhere on its behalf.
///
/// Port of `holepunchPayload` in `js/hyperdht/lib/messages.js:253`.
// Nothing constructs one until the relay path and the puncher land. `allow` rather than
// `expect` for the same reason as `nat.rs`: the round-trip tests below make these live under
// `--all-targets` but not under a plain lib build, so an expectation would be unfulfilled in
// one of the two configurations.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct HolepunchPayload {
    /// Nonzero means the sender is abandoning the punch, and says why.
    #[builder(default = 0)]
    pub error: usize,
    /// What the sender worked out about its own NAT. This is the value the strategy table in
    /// `js/hyperdht/lib/holepuncher.js:188` dispatches on, one half from each peer.
    #[builder(default = Firewall::Unknown)]
    pub firewall: Firewall,
    /// Which round of the punch this is. Rounds let both sides stay in step, since a punch
    /// only works if the two bursts overlap in time.
    #[builder(default = 0)]
    pub round: usize,
    /// The sender already has a working connection, so everyone can stop.
    #[builder(default = false)]
    pub connected: bool,
    /// The sender is punching now, which is the cue for the receiver to punch back.
    #[builder(default = false)]
    pub punching: bool,
    /// Where the sender believes it can be reached.
    ///
    /// For a [`Firewall::Random`] peer these carry a host and a zero port, because there is no
    /// port worth naming. Note the flag is set even for an empty list, matching JS, which
    /// tests only `m.addresses` and not its length.
    #[builder(default = None)]
    pub addresses: Option<Vec<SocketAddrV4>>,
    /// Where the sender is seeing the *receiver*, which is how a peer behind a NAT learns the
    /// address it has to tell everyone else about.
    #[builder(default = None)]
    pub remote_address: Option<SocketAddrV4>,
    #[builder(default = None)]
    pub token: Option<[u8; 32]>,
    #[builder(default = None)]
    pub remote_token: Option<[u8; 32]>,
}

impl CompactEncoding for HolepunchPayload {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        // JS reserves one byte each for these four rather than sizing the varints, and
        // over-reserving would desync `encode`, so copy it exactly. Same choice as
        // `NoisePayload`, and it breaks identically if any of them ever exceeds 127.
        Ok(1 + 1 + 1 + 1 /* flags + error + firewall + round */
            + else_zero!(let Some(x) = &self.addresses, x.encoded_size()?)
            + else_zero!(self.remote_address.is_some(), SOCKET_ADDR_V4_ENCODED_SIZE)
            + else_zero!(self.token.is_some(), 32)
            + else_zero!(self.remote_token.is_some(), 32))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let mut flags = 0_usize;
        flags |= else_zero!(self.connected, 1 << 0);
        flags |= else_zero!(self.punching, 1 << 1);
        flags |= else_zero!(self.addresses.is_some(), 1 << 2);
        flags |= else_zero!(self.remote_address.is_some(), 1 << 3);
        flags |= else_zero!(self.token.is_some(), 1 << 4);
        flags |= else_zero!(self.remote_token.is_some(), 1 << 5);

        let mut rest = map_encode!(buffer, flags, self.error, self.firewall, self.round);

        if let Some(addrs) = &self.addresses {
            rest = addrs.encode(rest)?;
        }
        if let Some(addr) = &self.remote_address {
            rest = addr.encode(rest)?;
        }
        if let Some(token) = &self.token {
            rest = write_array(token, rest)?;
        }
        if let Some(token) = &self.remote_token {
            rest = write_array(token, rest)?;
        }
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((flags, error, firewall, round), rest) =
            map_decode!(buffer, [usize, usize, Firewall, usize]);

        let (addresses, rest) = if flags & (1 << 2) != 0 {
            map_first!(<Vec<SocketAddrV4> as CompactEncoding>::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (remote_address, rest) = if flags & (1 << 3) != 0 {
            map_first!(SocketAddrV4::decode(rest)?, Some)
        } else {
            (None, rest)
        };
        let (token, rest) = if flags & (1 << 4) != 0 {
            map_first!(take_array::<32>(rest)?, Some)
        } else {
            (None, rest)
        };
        let (remote_token, rest) = if flags & (1 << 5) != 0 {
            map_first!(take_array::<32>(rest)?, Some)
        } else {
            (None, rest)
        };

        Ok((
            Self {
                error,
                firewall,
                round,
                connected: flags & (1 << 0) != 0,
                punching: flags & (1 << 1) != 0,
                addresses,
                remote_address,
                token,
                remote_token,
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
    // TODO this comes from udx socket id which is a u32. So shoul it be u32?
    pub id: usize,
    #[builder(default = UDX_INFO_DEFAULT_SEQ)]
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

/// What a peer has worked out about its own NAT, and the value that decides which
/// holepunching strategy a pair of peers can use.
///
/// The discriminants are wire values, but they are deliberately not ordered, so ask the
/// predicates rather than comparing. JS writes `firewall >= FIREWALL.RANDOM`
/// (`js/hyperdht/lib/holepuncher.js:99`), which reads as a ranking but only works because
/// `RANDOM` happens to be the largest value: it means `== Random`. There is no axis along
/// which these four actually sort. `Unknown` is the worst case, since a peer that has not
/// classified itself cannot punch at all, yet it holds the lowest value; and
/// [`Firewall::is_predictable`] groups `Open` with `Consistent`, which numeric order splits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Firewall {
    /// Not enough samples yet. Such a peer cannot punch, because neither side can tell
    /// which strategy would work.
    #[default]
    Unknown = 0,
    /// Reachable without punching at all.
    Open = 1,
    /// Behind a NAT that gives out the same external port whoever it is talking to, so a
    /// third party's report of that port is worth aiming at.
    Consistent = 2,
    /// Behind a NAT that picks a fresh external port per destination, so the port a third
    /// party reports is not the port this peer's counterpart will see.
    Random = 3,
}

impl Firewall {
    /// Whether a third party's report of this peer's address can be aimed at directly.
    ///
    /// The strategy table never distinguishes `Open` from `Consistent`: an unfirewalled peer
    /// is just the easiest kind of predictable one. `coerceFirewall`
    /// (`js/hyperdht/lib/holepuncher.js:333`) collapses the two the same way.
    pub fn is_predictable(self) -> bool {
        matches!(self, Firewall::Open | Firewall::Consistent)
    }
}

impl CompactEncoding for Firewall {
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
        let firewall = match discriminant {
            0 => Firewall::Unknown,
            1 => Firewall::Open,
            2 => Firewall::Consistent,
            3 => Firewall::Random,
            x => {
                return Err(EncodingError::invalid_data(&format!(
                    "Invalid value [{x}] for decoding Firewall"
                )));
            }
        };
        Ok((firewall, rest))
    }
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
    pub firewall: Firewall,
    #[builder(default = None)]
    pub holepunch: Option<HolepunchInfo>,
    pub addresses4: Option<Vec<SocketAddrV4>>,
    #[builder(default = None)]
    pub addresses6: Option<Vec<SocketAddrV6>>,
    pub udx: Option<UdxInfo>,
    #[builder(default = None)]
    pub secret_stream: Option<SecretStreamInfo>,
    #[builder(default = None)]
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
        if let Some(addrs) = &self.addresses4
            && !addrs.is_empty()
        {
            rest = addrs.encode(rest)?;
        }
        if let Some(addrs) = &self.addresses6
            && !addrs.is_empty()
        {
            rest = addrs.encode(rest)?;
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
            error!(
                "Received unexpected NOISE_PAYLOAD_VERSION = [{version}]. We expected [{NOISE_PAYLOAD_VERSION}]"
            );
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
        let ((flags, error, firewall), rest) = map_decode!(rest, [usize, usize, Firewall]);

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
    use crate::make_signable_announce_or_unannounce;

    use super::*;
    use compact_encoding::EncodingError;
    use dht_rpc::IdBytes;

    /// Encode, compare against bytes the real JS encoder produced, then decode back.
    ///
    /// The golden bytes are what make this worth more than a round trip: a Rust-only round
    /// trip passes just as happily when both directions are wrong in the same way.
    /// Regenerate with `node -e` against `test_utils/js/hyperdht`, using
    /// `c.encode(messages.holepunchPayload, ..)`.
    fn matches_js(value: &HolepunchPayload, expected: &[u8]) -> Result<(), EncodingError> {
        let mut buf = vec![0u8; value.encoded_size()?];
        let rest = value.encode(&mut buf)?;
        assert!(
            rest.is_empty(),
            "encoded_size over-reserved by {} bytes",
            rest.len()
        );
        assert_eq!(buf, expected, "encoded bytes differ from the JS encoder");

        let (decoded, rest) = HolepunchPayload::decode(&buf)?;
        assert!(rest.is_empty(), "decode left {} bytes unread", rest.len());
        assert_eq!(&decoded, value, "did not survive a round trip");
        Ok(())
    }

    fn v4(s: &str) -> SocketAddrV4 {
        s.parse().expect("test address should parse")
    }

    #[test]
    fn holepunch_payload_with_every_field_set() -> Result<(), EncodingError> {
        matches_js(
            &HolepunchPayload {
                error: 3,
                firewall: Firewall::Consistent,
                round: 7,
                connected: true,
                punching: true,
                addresses: Some(vec![v4("192.168.1.2:1234"), v4("10.11.12.13:6547")]),
                remote_address: Some(v4("127.0.0.1:80")),
                token: Some([1u8; 32]),
                remote_token: Some([2u8; 32]),
            },
            &[
                63, 3, 2, 7, 2, 192, 168, 1, 2, 210, 4, 10, 11, 12, 13, 147, 25, 127, 0, 0, 1, 80,
                0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2,
            ],
        )
    }

    /// Every optional field absent. Four bytes, one each for flags, error, firewall and round.
    #[test]
    fn holepunch_payload_with_nothing_set() -> Result<(), EncodingError> {
        matches_js(
            &HolepunchPayloadBuilder::default().build().unwrap(),
            &[0, 0, 0, 0],
        )
    }

    /// An empty address list is not the same as no address list, and JS agrees: it sets the
    /// flag on `m.addresses` alone, without testing its length, unlike `noisePayload` right
    /// above it. So the flag byte is 4 and a zero-length array follows.
    #[test]
    fn holepunch_payload_keeps_an_empty_address_list() -> Result<(), EncodingError> {
        matches_js(
            &HolepunchPayloadBuilder::default()
                .addresses(Some(vec![]))
                .build()
                .unwrap(),
            &[4, 0, 0, 0, 0],
        )
    }

    /// What a peer behind a random NAT actually sends: its host with a zero port, because it
    /// has no port worth naming.
    #[test]
    fn holepunch_payload_from_a_random_nat() -> Result<(), EncodingError> {
        matches_js(
            &HolepunchPayloadBuilder::default()
                .firewall(Firewall::Random)
                .round(1)
                .punching(true)
                .addresses(Some(vec![v4("203.0.113.1:0")]))
                .build()
                .unwrap(),
            &[6, 0, 3, 1, 1, 203, 0, 113, 1, 0, 0],
        )
    }

    /// `encoded_size` has to account for the payload, which is the only variable-length field
    /// in the envelope. It did not, so `encode` ran off the end of the buffer it was handed.
    /// The empty-payload case still passes without the fix, because the one byte JS reserves
    /// for the flags happens to cover the payload's length varint, so both are exercised here.
    #[test]
    fn holepunch_envelope_round_trip() -> Result<(), EncodingError> {
        for (name, value) in [
            (
                "every field set",
                Holepunch {
                    mode: HandshakeSteps::FromRelay,
                    id: 42,
                    payload: vec![1, 2, 3],
                    peer_address: Some(v4("192.168.1.2:1234")),
                },
            ),
            (
                "no peer address",
                Holepunch {
                    mode: HandshakeSteps::Reply,
                    id: 300,
                    payload: vec![9; 200],
                    peer_address: None,
                },
            ),
            (
                "nothing set",
                Holepunch {
                    mode: HandshakeSteps::FromClient,
                    id: 0,
                    payload: vec![],
                    peer_address: None,
                },
            ),
        ] {
            let mut buf = vec![0u8; value.encoded_size()?];
            let rest = value.encode(&mut buf)?;
            assert!(
                rest.is_empty(),
                "{name}: encoded_size over-reserved by {} bytes",
                rest.len()
            );

            let (decoded, rest) = Holepunch::decode(&buf)?;
            assert!(rest.is_empty(), "{name}: decode left {} bytes", rest.len());
            assert_eq!(decoded.mode, value.mode, "{name}: mode");
            assert_eq!(decoded.id, value.id, "{name}: id");
            assert_eq!(decoded.payload, value.payload, "{name}: payload");
            assert_eq!(
                decoded.peer_address, value.peer_address,
                "{name}: peer_address"
            );
        }
        Ok(())
    }

    #[test]
    fn socket_addr_enc_dec() -> Result<(), EncodingError> {
        let sa: SocketAddrV4 = "192.168.1.2:1234".parse().unwrap();
        let x = sa;
        let mut buf: [u8; 6] = [0; 6];
        x.encode(&mut buf).unwrap();

        assert_eq!(buf, [192, 168, 1, 2, 210, 4]);

        let (val, _rest) = SocketAddrV4::decode(&buf).unwrap();
        assert_eq!(val, x);
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
    /// This demonstrates that known good values fails in Rust's verify
    #[test]
    fn check_in_rs_known_good_sig_created_in_js() -> Result<(), Box<dyn std::error::Error>> {
        const VALUE: &[u8] = &[
            5, 206, 205, 109, 15, 42, 98, 66, 107, 27, 31, 54, 201, 136, 155, 42, 245, 234, 210,
            154, 31, 11, 151, 222, 135, 63, 208, 92, 4, 74, 24, 20, 109, 0, 49, 107, 254, 99, 36,
            124, 108, 65, 174, 60, 38, 12, 182, 110, 6, 215, 255, 19, 177, 141, 34, 177, 44, 213,
            226, 206, 148, 246, 168, 179, 176, 33, 117, 139, 191, 54, 19, 232, 12, 218, 55, 26,
            107, 78, 178, 76, 252, 175, 89, 204, 117, 165, 89, 32, 234, 143, 60, 157, 40, 233, 236,
            239, 41, 8,
        ];
        const TOKEN: [u8; 32] = [
            36, 6, 6, 155, 30, 71, 106, 67, 42, 98, 245, 4, 186, 36, 240, 5, 122, 103, 150, 70,
            158, 158, 55, 38, 154, 45, 194, 191, 37, 14, 50, 21,
        ];
        const ID: [u8; 32] = [
            144, 142, 182, 97, 170, 104, 69, 6, 221, 242, 249, 208, 96, 76, 57, 128, 126, 140, 89,
            26, 115, 131, 139, 110, 211, 183, 214, 39, 134, 156, 128, 165,
        ];

        const TARGET: &[u8] = &[
            104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        use crate::namespace;
        let target: IdBytes = TryInto::<[u8; 32]>::try_into(TARGET).unwrap().into();

        let (announce, _) = <AnnounceRequestValue as CompactEncoding>::decode(VALUE)?;

        let mut peer_buff = vec![0u8; CompactEncoding::encoded_size(&announce.peer).unwrap()];
        announce.peer.encode(&mut peer_buff).unwrap();

        println!("rsep = {:?}", peer_buff);
        let signable = make_signable_announce_or_unannounce(
            target,
            &TOKEN,
            &ID,
            &peer_buff,
            &namespace::ANNOUNCE,
        );
        announce
            .peer
            .public_key
            .verify(&announce.signature, &signable)
            .unwrap();
        Ok(())
    }
}
