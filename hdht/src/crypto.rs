use std::{
    net::{SocketAddr, SocketAddrV4},
    ops::Deref,
};

use compact_encoding::{CompactEncoding, write_array};
use libsodium_sys::{
    crypto_sign_BYTES, crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES, crypto_sign_keypair, crypto_sign_seed_keypair,
};

use crate::cenc::AnnounceRequestValue;
use ::dht_rpc::IdBytes;

type PublicKey2Bytes = [u8; crypto_sign_PUBLICKEYBYTES as usize];

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(PublicKey2Bytes);

impl From<PublicKey2Bytes> for PublicKey {
    fn from(value: PublicKey2Bytes) -> Self {
        Self(value)
    }
}

impl Deref for PublicKey {
    type Target = PublicKey2Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PublicKey {
    pub fn verify(&self, signature: &Signature2, message: &[u8]) -> crate::Result<()> {
        #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
        let res = unsafe {
            libsodium_sys::crypto_sign_verify_detached(
                signature.0.as_ptr(),
                message.as_ptr(),
                message.len() as _,
                self.0.as_ptr(),
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(crate::Error::InvalidSignature(res))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Keypair {
    /// The public key
    pub public: PublicKey,
    /// The secret key. Note: The secret key contains secret & public. First 32 bytes is secret, next 32 bytes is public.
    pub secret: [u8; crypto_sign_SECRETKEYBYTES as usize],
}

impl Default for Keypair {
    fn default() -> Self {
        let mut public = [0; crypto_sign_PUBLICKEYBYTES as usize];
        let mut secret = [0; crypto_sign_SECRETKEYBYTES as usize];
        #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
        let err = unsafe { crypto_sign_keypair(public.as_mut_ptr(), secret.as_mut_ptr()) };
        if err != 0 {
            todo!()
        }
        Self {
            public: public.into(),
            secret,
        }
    }
}

impl Keypair {
    // Returns (secret_key, public_key)
    pub fn to_snow_secret_and_public_parts(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.secret[..32].try_into().expect("[..32].len() == 32"),
            self.public.0,
        )
    }
    pub fn from_seed(seed: [u8; crypto_sign_SEEDBYTES as usize]) -> Self {
        let mut public = [0; crypto_sign_PUBLICKEYBYTES as usize];
        let mut secret = [0; crypto_sign_SECRETKEYBYTES as usize];
        #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
        let err = unsafe {
            crypto_sign_seed_keypair(public.as_mut_ptr(), secret.as_mut_ptr(), seed.as_ptr())
        };
        if err != 0 {
            todo!()
        }
        Self {
            public: public.into(),
            secret,
        }
    }
    pub fn sign(&self, value: &[u8]) -> Signature2 {
        let mut signature: [u8; 64] = [0u8; crypto_sign_BYTES as usize];
        #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
        let err = unsafe {
            libsodium_sys::crypto_sign_detached(
                signature.as_mut_ptr(),
                std::ptr::null_mut(),
                value.as_ptr(),
                value.len() as _,
                self.secret.as_ptr(),
            )
        };
        if err != 0 {
            todo!()
        }
        Signature2(signature)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Signature2(pub [u8; crypto_sign_BYTES as usize]);
impl Deref for Signature2 {
    type Target = [u8; crypto_sign_BYTES as usize];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Generated from the [original JavaScript code]( https://github.com/cowlicks/hyperdht/blob/eecdf3669744e88ec2fceb851cedf5274a106c94/test/print_ns.js#L2)
pub mod namespace {
    macro_rules! const_hex_decode {
        ($arg:expr) => {{
            match const_hex::const_decode_to_array($arg) {
                Ok(x) => x,
                Err(_) => panic!("Failed to decode"),
            }
        }};
    }

    pub const ANNOUNCE: [u8; 32] =
        const_hex_decode!(b"36386adddf9f6fd60db83a6f42fc159d1146aa8644037664230aaa1f0179d497");
    pub const UNANNOUNCE: [u8; 32] =
        const_hex_decode!(b"ded293cd93fb395e756ecf5fff426529e72c36eacc22e5ed944d9099a2561e32");
    pub const MUTABLE_PUT: [u8; 32] =
        const_hex_decode!(b"668e823edd5ce7f5338d68bf1161f4a3c28ce437ee2ab49efd30d99366039b1e");
    pub const PEER_HANDSHAKE: [u8; 32] =
        const_hex_decode!(b"14d6d4b49214ab1033ed204976caa258bae9e1e8543b9ad1fd996a910b0c4e3a");
    pub const PEER_HOLEPUNCH: [u8; 32] =
        const_hex_decode!(b"f1191cd5e67b10b54a507033280ed1ff0e12278268d5679c8f93d417210d168b");
}

pub fn generic_hash_batch(inputs: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; libsodium_sys::crypto_generichash_BYTES as usize];
    #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
    let mut st = vec![0u8; unsafe { libsodium_sys::crypto_generichash_statebytes() }];
    #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
    let pst = unsafe {
        std::mem::transmute::<*mut u8, *mut libsodium_sys::crypto_generichash_state>(
            st.as_mut_ptr(),
        )
    };

    #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
    if 0 != unsafe {
        libsodium_sys::crypto_generichash_init(pst, std::ptr::null_mut(), 0, out.len())
    } {
        panic!(
            "Should only error when out-of-memory OR when the input is invalid. Inputs here or checked"
        );
    }

    for chunk in inputs {
        #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
        if 0 != unsafe {
            libsodium_sys::crypto_generichash_update(pst, chunk.as_ptr(), chunk.len() as u64)
        } {
            panic!(
                "Should only error when out-of-memory OR when the input is invalid. Inputs here or checked"
            );
        }
    }
    #[expect(unsafe_code, reason = "needed to use libsodium bindings")]
    if 0 != unsafe { libsodium_sys::crypto_generichash_final(pst, out.as_mut_ptr(), out.len()) } {
        panic!(
            "Should only error when out-of-memory OR when the input is invalid. Inputs here or checked"
        );
    }
    out
}

const NAMESPACE_SIZE: usize = 32;
const ANN_OR_UNANN_SIGNABLE_SIZE: usize = 64;
/// NB: the constraint NAMESPACE_SIZE < ANN_OR_UNANN_SIGNABLE_SIZE ensures this will not panic
pub fn make_signable_announce_or_unannounce(
    target: IdBytes,
    token: &[u8; 32],
    id: &[u8; 32],
    encoded_peer: &[u8],
    namespace: &[u8; NAMESPACE_SIZE],
) -> [u8; ANN_OR_UNANN_SIGNABLE_SIZE] {
    let mut signable = [0; ANN_OR_UNANN_SIGNABLE_SIZE];
    let rest = write_array::<32>(namespace, &mut signable)
        .expect("NAMESPACE_SIZE < ANN_OR_UNANN_SIGNABLE_SIZE so this does not fail");
    rest.copy_from_slice(&generic_hash_batch(&[
        &target.0,
        id,
        token,
        encoded_peer,
        &[],
    ]));
    signable
}

// TODO RMME
fn sa4_from_sa_todo_remove_use_of_socketaddr(s: SocketAddr) -> SocketAddrV4 {
    match s {
        SocketAddr::V4(x) => x,
        SocketAddr::V6(_) => todo!(),
    }
}
pub fn sign_announce_or_unannounce(
    keypair: &Keypair,
    target: IdBytes,
    token: &[u8; 32],
    from_id: &[u8; 32],
    relay_addresses: &[SocketAddr],
    namespace: &[u8; 32],
) -> AnnounceRequestValue {
    use crate::cenc::Peer;
    let peer = Peer {
        public_key: keypair.public.clone(),
        relay_addresses: relay_addresses
            .iter()
            .map(|s| sa4_from_sa_todo_remove_use_of_socketaddr(*s))
            .collect(),
    };
    let encoded = peer
        .to_encoded_bytes()
        .expect("Known to succeed for all values of `Peer`");

    let signable =
        make_signable_announce_or_unannounce(target, token, from_id, &encoded, namespace);

    AnnounceRequestValue {
        peer,
        refresh: None,
        signature: keypair.sign(&signable),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn compare_batch_hash_with_javascript_result() {
        // value calculated from
        // https://gist.github.com/cowlicks/901ee94ace3b881e0ef057f472d16a71
        let expected: [u8; 32] = [
            96, 83, 105, 30, 76, 247, 143, 215, 26, 251, 250, 184, 48, 122, 222, 187, 105, 4, 254,
            251, 46, 29, 249, 66, 167, 216, 198, 209, 204, 167, 180, 62,
        ];

        let x: &[&[u8]] = &[b"yolo", b"wassup", b"howdy"];
        let res = generic_hash_batch(x);
        assert_eq!(res, expected);
    }
}
