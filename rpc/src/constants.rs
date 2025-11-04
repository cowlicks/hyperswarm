pub(crate) const HASH_SIZE: usize = 32;
pub(crate) const ID_SIZE: usize = 32;
// constants from dht-rpc/lib/io.js
// https://github.com/holepunchto/dht-rpc/blob/93b1124d2fe8646d5b6630d0eccf67a8e06635ec/lib/io.js#L13-L15
pub(crate) const VERSION: u8 = 0b11;
pub(crate) const RESPONSE_ID: u8 = (0b0001 << 4) | VERSION;
#[expect(clippy::identity_op)]
pub(crate) const REQUEST_ID: u8 = 0b0000 << 4 | VERSION;
// From dht-rpc/index.js tick interval for the rpc client
pub(crate) const TICK_INTERVAL_MS: u64 = 5000;
/// we normally send [`K_VALUE`] = 20 request message, and ?? book keeping messages. Add a good
/// fudge factor.
pub const DEFAULT_COMMIT_CHANNEL_SIZE: usize = 20 * 5;
/// Size of an ID
pub const ID_BYTES_LENGTH: usize = 32;
