//! Error types for the hyperswarm crate

use std::io;

/// Error type for hyperswarm operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error from the underlying HyperDHT
    #[error("DHT error: {0}")]
    Dht(#[from] hyperdht::Error),

    /// Error from dht-rpc
    #[error("RPC error: {0}")]
    Rpc(#[from] dht_rpc::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Swarm has been destroyed
    #[error("Swarm has been destroyed")]
    Destroyed,

    /// Topic is required and must be a 32-byte buffer
    #[error("Topic is required and must be a 32-byte buffer")]
    InvalidTopic,

    /// Peer is banned
    #[error("Peer is banned")]
    PeerBanned,

    /// Connection failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Channel receive error
    #[error("Channel error: {0}")]
    ChannelRecv(#[from] tokio::sync::oneshot::error::RecvError),
}

/// Result type alias for hyperswarm operations
pub type Result<T> = std::result::Result<T, Error>;
