use std::net::SocketAddr;

use fnv::FnvHashMap;

use crate::{IdBytes, PeerId};

#[derive(Debug)]
pub struct QueryTable {
    id: IdBytes,
    target: IdBytes,
    /// The closest peers to the target.
    peers: FnvHashMap<PeerId, PeerState>,
}

impl QueryTable {
    pub fn new<T>(id: IdBytes, target: IdBytes, known_closest_peers: T) -> Self
    where
        T: IntoIterator<Item = PeerId>,
    {
        // Initialise the closest peers to start the iterator with.
        let peers: FnvHashMap<PeerId, PeerState> = known_closest_peers
            .into_iter()
            .map(|key| (key, PeerState::NotContacted))
            .collect();

        Self { id, target, peers }
    }

    pub fn peers(&self) -> &FnvHashMap<PeerId, PeerState> {
        &self.peers
    }

    pub(crate) fn peers_mut(&mut self) -> &mut FnvHashMap<PeerId, PeerState> {
        &mut self.peers
    }

    pub fn target(&self) -> &IdBytes {
        &self.target
    }

    pub fn get_peer(&self, peer: &crate::Peer) -> Option<crate::Peer> {
        self.peers
            .keys()
            .filter(|p| p.addr == peer.addr)
            .map(|p| crate::Peer::from(p.addr))
            .next()
    }

    pub fn get_token(&self, peer: &crate::Peer) -> Option<&Vec<u8>> {
        self.peers
            .iter()
            .filter(|(p, _)| p.addr == peer.addr)
            .map(|(_, s)| s.get_token())
            .next()
            .flatten()
    }

    pub(crate) fn _add_unverified(&mut self, peer: PeerId) {
        if peer.id == self.id {
            return;
        }
        self.peers.insert(peer, PeerState::NotContacted);
    }

    pub(crate) fn add_verified(
        &mut self,
        key: PeerId,
        roundtrip_token: Vec<u8>,
        to: Option<SocketAddr>,
    ) {
        if key.id == self.id {
            return;
        }
        if let Some(prev) = self.peers.get_mut(&key) {
            *prev = PeerState::Succeeded {
                roundtrip_token,
                to,
            };
        } else {
            self.peers.insert(
                key,
                PeerState::Succeeded {
                    roundtrip_token,
                    to,
                },
            );
        }
    }

    /// Set the state of every `Peer` to `PeerState::NotContacted`
    pub fn set_all_not_contacted(&mut self) {
        for state in self.peers.values_mut() {
            *state = PeerState::NotContacted;
        }
    }

    pub(crate) fn peers_iter(&self) -> Vec<(PeerId, PeerState)> {
        self.peers
            .clone()
            .into_iter()
            .map(|(k, v)| (k.clone(), v))
            .collect()
    }
}

/// Representation of a peer in the context of a iterator.
#[allow(unused)] // FIXME bg: why is this not used?
#[derive(Debug, Clone)]
pub(crate) struct Peer {
    key: PeerId,
    state: PeerState,
}

/// The state of a single `Peer`.
#[derive(Debug, Clone)]
pub enum PeerState {
    /// The peer has not yet been contacted.
    ///
    /// This is the starting state for every peer.
    NotContacted,

    /// Obtaining a result from the peer has failed.
    ///
    /// This is a final state, reached as a result of a call to `on_failure`.
    Failed,

    /// A successful result from the peer has been delivered.
    ///
    /// This is a final state, reached as a result of a call to `on_success`.
    Succeeded {
        roundtrip_token: Vec<u8>,
        to: Option<SocketAddr>,
    },
}

impl PeerState {
    pub fn is_verified(&self) -> bool {
        matches!(self, PeerState::Succeeded { .. })
    }

    pub fn is_not_contacted(&self) -> bool {
        matches!(self, PeerState::NotContacted)
    }

    pub fn get_token(&self) -> Option<&Vec<u8>> {
        match self {
            PeerState::Succeeded {
                roundtrip_token, ..
            } => Some(roundtrip_token),
            _ => None,
        }
    }
}
