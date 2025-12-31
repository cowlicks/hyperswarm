#![expect(unused)]
use std::hash::Hash;

use ::dht_rpc::{CommandQuery, CommandQueryResponse, IdBytes};
use ed25519_dalek::{PublicKey, Signature, SignatureError, Verifier};
use lru::LruCache;
use prost::Message;

use crate::{
    ERR_INVALID_INPUT, ERR_INVALID_SEQ, ERR_SEQ_MUST_EXCEED_CURRENT, IMMUTABLE_STORE_CMD,
    MUTABLE_STORE_CMD,
    crypto::{self, VALUE_MAX_SIZE},
    dht_proto::Mutable,
};

/// PUT_VALUE_MAX_SIZE (1000B) + packet overhead (i.e. the key etc.) should be
/// less than the network MTU, normally 1400 bytes
pub const PUT_VALUE_MAX_SIZE: usize = VALUE_MAX_SIZE;

#[derive(Debug, Clone)]
pub enum StorageEntry {
    Mutable(Mutable),
    Immutable(Vec<u8>),
}

impl StorageEntry {
    pub fn as_mutable(&self) -> Option<&Mutable> {
        if let StorageEntry::Mutable(m) = self {
            Some(m)
        } else {
            None
        }
    }

    pub fn as_immutable(&self) -> Option<&Vec<u8>> {
        if let StorageEntry::Immutable(i) = self {
            Some(i)
        } else {
            None
        }
    }

    pub fn into_mutable(self) -> Option<Mutable> {
        if let StorageEntry::Mutable(m) = self {
            Some(m)
        } else {
            None
        }
    }

    pub fn into_immutable(self) -> Option<Vec<u8>> {
        if let StorageEntry::Immutable(i) = self {
            Some(i)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum StorageKey {
    Mutable(Vec<u8>),
    Immutable(IdBytes),
}

#[derive(Debug)]
pub struct Store {
    /// Value cache
    inner: LruCache<StorageKey, StorageEntry>,
}

impl Store {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: LruCache::new(cap),
            // streams: Default::default(),
        }
    }

    /// Callback for immutable command.
    pub fn on_command(&mut self, query: CommandQuery) -> CommandQueryResponse {
        assert_eq!(query.command, IMMUTABLE_STORE_CMD);
        self.query(query)
    }

    /// Callback for mutable command
    pub fn on_command_mut(&mut self, mut query: CommandQuery) -> CommandQueryResponse {
        assert_eq!(query.command, MUTABLE_STORE_CMD);
        if let Some(mutable) = query
            .value
            .take()
            .and_then(|buf| Mutable::decode(buf.as_slice()).ok())
        {
            return self.query_mut(query, mutable);
        }
        query.into_response_with_error(ERR_INVALID_INPUT)
    }

    pub fn get(&mut self, key: &StorageKey) -> Option<&StorageEntry> {
        self.inner.get(key)
    }

    pub fn put_immutable(&mut self, key: IdBytes, value: Vec<u8>) -> Option<Vec<u8>> {
        self.inner
            .put(StorageKey::Immutable(key), StorageEntry::Immutable(value))
            .and_then(StorageEntry::into_immutable)
    }

    pub fn put_mutable(&mut self, key: Vec<u8>, value: Mutable) -> Option<Mutable> {
        self.inner
            .put(StorageKey::Mutable(key), StorageEntry::Mutable(value))
            .and_then(StorageEntry::into_mutable)
    }

    pub fn get_mut_key(mutable: &Mutable, id: &IdBytes) -> Vec<u8> {
        if let Some(ref salt) = mutable.salt {
            id.as_ref().iter().chain(salt.iter()).cloned().collect()
        } else {
            id.to_vec()
        }
    }

    pub fn query_mut(&mut self, mut query: CommandQuery, mutable: Mutable) -> CommandQueryResponse {
        let key = StorageKey::Mutable(Self::get_mut_key(&mutable, &query.target));
        if let Some(val) = self.inner.get(&key).and_then(StorageEntry::as_mutable)
            && val.seq.unwrap_or_default() >= mutable.seq.unwrap_or_default()
        {
            let mut buf = Vec::with_capacity(val.encoded_len());
            val.encode(&mut buf).unwrap();
            query.value = Some(buf);
        }
        query.into()
    }

    pub fn update_mut(&mut self, query: CommandQuery, mutable: Mutable) -> CommandQueryResponse {
        if mutable.value.is_none() || mutable.signature.is_none() {
            return query.into();
        }

        let key = StorageKey::Mutable(Self::get_mut_key(&mutable, &query.target));
        if let Err(err) = verify(&query.target, &mutable) {
            return query.into_response_with_error(err);
        }

        if let Some(local) = self.inner.get(&key).and_then(StorageEntry::as_mutable)
            && let Err(err) = maybe_seq_error(&mutable, local)
        {
            let mut resp = query.into_response_with_error(err);
            let mut buf = Vec::with_capacity(local.encoded_len());
            local.encode(&mut buf).unwrap();
            resp.msg.value = Some(buf);
            return resp;
        }

        self.inner.put(key, StorageEntry::Mutable(mutable));
        query.into()
    }

    /// Callback for a [`IMMUTABLE_STORE_CMD`] request of type [`Type::Query`].
    pub fn query(&mut self, mut query: CommandQuery) -> CommandQueryResponse {
        let val = self
            .inner
            .get(&StorageKey::Immutable(query.target))
            .and_then(StorageEntry::as_immutable)
            .cloned();
        query.value = val;
        query.into()
    }

    /// Callback for a [`IMMUTABLE_STORE_CMD`] request of type [`Type::Update`].
    pub fn update(&mut self, mut query: CommandQuery) -> CommandQueryResponse {
        if let Some(value) = query.value.take() {
            let key = crypto::hash_id(value.as_slice());
            if key != query.target {
                return query.into_response_with_error(ERR_INVALID_INPUT);
            }
            self.inner
                .put(StorageKey::Immutable(key), StorageEntry::Immutable(value));
        }
        query.into()
    }
}

#[inline]
pub fn verify(pk: &IdBytes, mutable: &Mutable) -> Result<(), usize> {
    let public_key = PublicKey::from_bytes(pk.as_ref()).map_err(|_| ERR_INVALID_INPUT)?;
    let sig = signature(mutable).ok_or(ERR_INVALID_INPUT)?;
    let msg = crypto::signable_mutable(mutable).map_err(|_| ERR_INVALID_INPUT)?;
    crypto_verify(&public_key, &msg, &sig).map_err(|_| ERR_INVALID_INPUT)
}

/// Sign the value as [`signable`] using the keypair.
/// Verify a signature on a message with a keypair's public key.
#[inline]
pub fn crypto_verify(
    public: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> Result<(), SignatureError> {
    public.verify(msg, sig)
}

#[inline]
pub fn maybe_seq_error(a: &Mutable, b: &Mutable) -> Result<(), usize> {
    let seq_a = a.seq.unwrap_or_default();
    let seq_b = b.seq.unwrap_or_default();
    if a.value.is_some() && seq_a == seq_b && a.value != b.value {
        return Err(ERR_INVALID_SEQ);
    }
    if seq_a <= seq_b {
        Err(ERR_SEQ_MUST_EXCEED_CURRENT)
    } else {
        Ok(())
    }
}

#[inline]
pub fn signature(mutable: &Mutable) -> Option<Signature> {
    if let Some(ref sig) = mutable.signature {
        Signature::from_bytes(sig).ok()
    } else {
        None
    }
}
