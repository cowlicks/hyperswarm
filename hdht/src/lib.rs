//! Rust Implementation of the hyperswarm DHT
#![warn(
    //unreachable_pub, // TODO
    //missing_debug_implementations, // TODO
    //missing_docs, // TODO
    redundant_lifetimes,
    unsafe_code,
    non_local_definitions,
    //clippy::needless_pass_by_value, // TODO
    clippy::needless_pass_by_ref_mut,
    clippy::enum_glob_use
)]

use std::{
    array::TryFromSliceError,
    fmt,
    net::{AddrParseError, SocketAddr, SocketAddrV4},
    sync::Arc,
};

pub use cenc::AnnounceRequestValue;
use cenc::{
    NoisePayloadBuilderError, PeerHandshakePayload, PeerHandshakePayloadBuilderError,
    RelayThroughInfoBuilderError, UdxInfoBuilderError,
};
use compact_encoding::{CompactEncoding, EncodingError};
use dht_rpc::{IdBytes, InResponse, RequestFutureError, RpcInnerBuilderError};
use tokio::sync::oneshot::error::RecvError;

use crate::cenc::HandshakeSteps;

mod dht_proto {
    include!(concat!(env!("OUT_DIR"), "/dht_pb.rs"));
}
mod cenc;
mod crypto;
mod next_router;
mod server;
mod store;

pub mod adht;

pub use crypto::{
    Keypair, make_signable_announce_or_unannounce, namespace, sign_announce_or_unannounce,
};

/// The publicly available hyperswarm DHT addresses
pub const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "node1.hyperdht.org:49737",
    "node2.hyperdht.org:49737",
    "node3.hyperdht.org:49737",
];

pub(crate) const ERR_INVALID_INPUT: usize = 7;
pub(crate) const ERR_INVALID_SEQ: usize = 11;
pub(crate) const ERR_SEQ_MUST_EXCEED_CURRENT: usize = 13;

pub mod commands {
    use dht_rpc::{Command, ExternalCommand};

    pub const PEER_HANDSHAKE: Command = Command::External(ExternalCommand(values::PEER_HANDSHAKE));
    pub const PEER_HOLEPUNCH: Command = Command::External(ExternalCommand(values::PEER_HOLEPUNCH));
    pub const FIND_PEER: Command = Command::External(ExternalCommand(values::FIND_PEER));
    pub const LOOKUP: Command = Command::External(ExternalCommand(values::LOOKUP));
    pub const ANNOUNCE: Command = Command::External(ExternalCommand(values::ANNOUNCE));
    pub const UNANNOUNCE: Command = Command::External(ExternalCommand(values::UNANNOUNCE));

    pub mod values {
        pub const PEER_HANDSHAKE: usize = 0;
        pub const PEER_HOLEPUNCH: usize = 1;
        pub const FIND_PEER: usize = 2;
        pub const LOOKUP: usize = 3;
        pub const ANNOUNCE: usize = 4;
        pub const UNANNOUNCE: usize = 5;
    }
}
/// The command identifier for `Mutable` storage
pub const MUTABLE_STORE_CMD: usize = 1;
/// The command identifier for immutable storage
pub const IMMUTABLE_STORE_CMD: usize = 2;
/// The command identifier to (un)announce/lookup peers
pub const PEERS_CMD: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error from dht_rpc: {0}")]
    RpcError(#[from] ::dht_rpc::Error),
    #[error("Error from compact_encoding: {0}")]
    CompactEncodingError(EncodingError),
    #[error("IO Eror")]
    IoError(#[from] std::io::Error),
    #[error("Invalid RPC command in message: {0}")]
    InvalidRpcCommand(u8),
    #[error("Incorrect message ID size. Expected 32. Error: {0}")]
    IncorrectMessageIdSize(TryFromSliceError),
    #[error("Error in libsodium's genric_hash function. Return value: {0}")]
    LibSodiumGenericHashError(i32),
    #[error("RpcDhtBuilderError: {0}")]
    RpcDhtBuilderError(#[from] RpcInnerBuilderError),
    #[error("RecvError: {0}")]
    RecvError(#[from] RecvError),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("Requests must have a 'to' field")]
    RequestRequiresToField,
    #[error("Ipv6 not supported")]
    Ipv6NotSupported,
    #[error("Invalid Signature")]
    InvalidSignature(i32),
    #[error("Future Request error")]
    FutureRequestFailed(#[from] RequestFutureError),
    #[error("Error building PeerHandshakePayload: {0}")]
    PeerHandshakePayloadBuilder(#[from] PeerHandshakePayloadBuilderError),
    #[error("Error building UdxInfo: {0}")]
    UdxInfoBuilder(#[from] UdxInfoBuilderError),
    #[error("Error building NoisePaylod: {0}")]
    NoisePayloadBuilder(#[from] NoisePayloadBuilderError),
    #[error("Error building RelayThroughInfo: {0}")]
    RelayThroughInfoBuilder(#[from] RelayThroughInfoBuilderError),
    #[error("Hypercore Protocol Error: {0}")]
    HypercoreProtocolError(#[from] hypercore_handshake::Error),
    // TODO make err  more useful here
    #[error("Peer handshake failed: {0}")]
    PeerHandshakeFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// TODO make EncodingError impl Error trait
impl From<EncodingError> for Error {
    fn from(value: EncodingError) -> Self {
        Error::CompactEncodingError(value)
    }
}

#[derive(Debug)]
pub struct PeerHandshakeResponse {
    noise: Vec<u8>,
    relayed: bool,
    #[expect(unused)]
    server_address: SocketAddrV4,
    #[expect(unused)]
    client_address: SocketAddrV4,
}
impl PeerHandshakeResponse {
    fn new(
        noise: Vec<u8>,
        relayed: bool,
        server_address: SocketAddrV4,
        client_address: SocketAddrV4,
    ) -> Self {
        Self {
            noise,
            relayed,
            server_address,
            client_address,
        }
    }
}

/// Represents the response received from a peer
#[derive(Debug)]
pub struct PeerResponseItem<T: fmt::Debug> {
    /// Address of the peer this response came from
    pub peer: SocketAddr,
    /// The identifier of the `peer` if included in the response
    pub peer_id: Option<IdBytes>,
    /// The value the `peer` provided
    pub value: T,
}

/// Result of a [`HyperDht::lookup`] query.
#[derive(Debug, Clone)]
pub struct Lookup {
    /// The hash to lookup
    pub topic: IdBytes,
    /// The gathered responses
    pub peers: Vec<Peers>,
}

/// A Response to a query request from a peer
#[derive(Debug, Clone)]
pub struct Peers {
    /// The DHT node that is returning this data
    pub node: SocketAddr,
    /// The id of the `peer` if available
    pub peer_id: Option<IdBytes>,
    /// List of peers that announced the topic hash
    pub peers: Vec<SocketAddr>,
    /// List of LAN peers that announced the topic hash
    pub local_peers: Vec<SocketAddr>,
}

pub fn request_announce_or_unannounce_value(
    keypair: &Keypair,
    target: IdBytes,
    token: &[u8; 32],
    from: IdBytes,
    relay_addresses: &[SocketAddr],
    namespace: &[u8; 32],
) -> Vec<u8> {
    let announce =
        sign_announce_or_unannounce(keypair, target, token, &from.0, relay_addresses, namespace);
    announce
        .to_encoded_bytes()
        .expect("known to succeed for all `Announce` values")
        .to_vec()
}

fn decode_peer_handshake_response(resp: &Arc<InResponse>) -> Result<Arc<PeerHandshakeResponse>> {
    let hs: PeerHandshakePayload = resp
        .response
        .value
        .as_ref()
        .ok_or_else(|| Error::PeerHandshakeFailed("missing value".into()))
        .and_then(|value| {
            let (hs, _rest) = PeerHandshakePayload::decode(value)?;
            debug_assert!(_rest.is_empty());
            Ok(hs)
        })?;

    if !matches!(hs.mode, HandshakeSteps::Reply) || resp.request.to != resp.peer {
        // "BAD_HANDSHAKE_REPLY()" is the name of the js error
        return Err(Error::PeerHandshakeFailed("BAD_HANDSHAKE_REPLY".into()));
    }

    let server_address = if let Some(x) = hs.peer_address {
        x
    } else {
        resp.request.to.ipv4_addr()?
    };

    Ok(Arc::new(PeerHandshakeResponse::new(
        hs.noise,
        hs.peer_address.is_some(),
        server_address,
        resp.response.to.ipv4_addr()?,
    )))
}
