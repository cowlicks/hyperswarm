use std::{
    collections::HashMap,
    future::Future,
    net::{SocketAddr, SocketAddrV4, ToSocketAddrs},
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    task::{Context, Poll},
};

use tokio::sync::{
    mpsc,
    oneshot::{self},
};

use compact_encoding::CompactEncoding;
use dht_rpc::{
    BootstrapFuture, Commit, CustomCommandRequest, DhtConfig, ExternalCommand, IdBytes, InResponse,
    OutRequestBuilder, Peer, QueryArgs, QueryId, QueryNext, RequestMsgData, Rpc,
    RpcDhtRequestFuture, generic_hash,
};
use futures::{Stream, stream::FuturesUnordered};
use hypercore_handshake::Cipher;
use tracing::{error, info, instrument, trace, warn};

use crate::{
    DEFAULT_BOOTSTRAP, Error, Keypair, Result,
    cenc::{
        AnnounceRequestValue, HandshakeSteps, NoisePayload, NoisePayloadBuilder,
        PeerHandshakePayload, PeerHandshakePayloadBuilder, UdxInfoBuilder, firewall,
    },
    commands,
    crypto::PublicKey,
    decode_peer_handshake_response, namespace,
    next_router::{StreamIdMaker, connection::Connection},
    persistent::{MAX_RECORDS_PER_TOPIC, PeerRecordCache, PeerRouter, RouterEntry},
    request_announce_or_unannounce_value,
    server::ServerFuture,
};

#[derive(Debug)]
pub struct QueryResult {
    pub topic: IdBytes,
    pub responses: Vec<Arc<InResponse>>,
    pub query_id: QueryId,
}

enum TakableResult<T, E> {
    Ok(T),
    Err(Option<E>),
}

impl<T, E> TakableResult<T, E> {
    fn from_result(result: std::result::Result<T, E>) -> Self {
        match result {
            Ok(x) => TakableResult::Ok(x),
            Err(e) => TakableResult::Err(Some(e)),
        }
    }
}

pub struct ConnectFuture {
    dht: Arc<RwLock<DhtInner>>,
    query: TakableResult<FindPeer, Error>,
    pub_key: PublicKey,
    pending_handshake: Option<PeerHandshake>,
}

impl Future for ConnectFuture {
    type Output = Result<Connection>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // If we have a pending handshake, poll it first
            if let Some(ref mut handshake) = self.pending_handshake {
                match Pin::new(handshake).poll(cx) {
                    Poll::Ready(Ok(conn)) => return Poll::Ready(Ok(conn)),
                    Poll::Ready(Err(_)) => {
                        self.pending_handshake = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            let mut query = match &mut self.query {
                TakableResult::Ok(x) => x,
                TakableResult::Err(e) => match e.take() {
                    Some(e) => return Poll::Ready(Err(e)),
                    None => todo!(),
                },
            };

            // Poll the query for more peers
            match Pin::new(&mut query).poll_next(cx) {
                Poll::Ready(Some(Ok(Some(FindPeerResponse { response, .. })))) => {
                    // Try to start a handshake with this peer
                    let dht = self.dht.read().unwrap();
                    if let Ok(handshake) = dht.peer_handshake(PeerHandshakeArgs::new(
                        self.pub_key.clone(),
                        response.request.to.addr,
                    )) {
                        drop(dht); // Release lock before storing
                        self.pending_handshake = Some(handshake);
                        // Continue loop to poll the new handshake
                    }
                }
                Poll::Ready(Some(Ok(None))) | Poll::Ready(Some(Err(_))) => {
                    // No peer info or error, continue to next
                }
                Poll::Ready(None) => {
                    // Query exhausted, no connection made
                    return Poll::Ready(Err(Error::ConnectionFailed));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub struct Dht {
    inner: Arc<RwLock<DhtInner>>,
    driver: Option<tokio::task::JoinHandle<()>>,
}

impl Dht {
    pub async fn with_config(config: DhtConfig) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(RwLock::new(DhtInner::with_config(config).await?)),
            driver: None,
        })
    }
    pub fn name(&self) -> String {
        self.inner.read().unwrap().name()
    }
    pub fn bootstrap(&self) -> BootstrapFuture {
        self.inner.read().unwrap().bootstrap()
    }
    /// Connect to a peer by their public key.
    ///
    /// The `closest_nodes` parameter provides starting hints for peer discovery, similar to
    /// `relayAddresses` in JavaScript hyperswarm. These are typically DHT nodes that previously
    /// told us about this peer (from a lookup). The query starts from these nodes rather than
    /// DHT bootstrap nodes, making discovery faster.
    ///
    /// ## Differences from JavaScript implementation
    ///
    /// JS hyperswarm calls `dht.connect(publicKey, { relayAddresses })` which passes them as
    /// `closestNodes` to `findPeer` with `onlyClosestNodes: true`. This means JS:
    /// 1. Only queries the provided relay nodes (doesn't fall back to routing table)
    /// 2. Does up to 2 query attempts before giving up
    /// 3. For each responding node, calls `connectThroughNode` to do the handshake
    ///
    /// Rust implementation:
    /// 1. Uses `closest_nodes` as starting nodes for the `find_peer` query
    /// 2. May still fall back to routing table nodes if closest_nodes don't respond
    /// 3. For each responding node, starts a `peer_handshake`
    ///
    /// The JS `onlyClosestNodes` behavior could be added to Rust's `QueryArgs` if needed.
    pub fn connect(&self, pub_key: PublicKey, closest_nodes: Option<Vec<Peer>>) -> ConnectFuture {
        self.inner
            .read()
            .unwrap()
            .connect(pub_key, closest_nodes, self.inner.clone())
    }
    pub fn lookup(&self, target: IdBytes, commit: Commit) -> Result<Lookup> {
        self.inner.read().unwrap().lookup(target, commit)
    }
    pub fn find_peer(
        &self,
        pub_key: PublicKey,
        closest_nodes: Option<Vec<Peer>>,
    ) -> Result<FindPeer> {
        self.inner.read().unwrap().find_peer(pub_key, closest_nodes)
    }
    pub fn announce(
        &self,
        target: IdBytes,
        keypair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> Announce {
        self.inner
            .read()
            .unwrap()
            .announce(target, keypair, relay_addresses)
    }
    pub fn unannounce(&self, target: IdBytes, keypair: Keypair) -> Unannounce {
        self.inner.read().unwrap().unannounce(target, keypair)
    }
    pub fn request(&self, o: OutRequestBuilder) -> RpcDhtRequestFuture {
        self.inner.read().unwrap().request(o)
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.read().unwrap().local_addr()
    }
    pub fn peer_handshake(
        &self,
        args: PeerHandshakeArgs,
    ) -> impl Future<Output = Result<Connection>> + use<> {
        let fut = { self.inner.read().unwrap().peer_handshake(args) };
        async move { fut?.await }
    }
    pub fn announce_clear(
        &self,
        target: IdBytes,
        keypair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> AnnounceClear {
        self.inner
            .read()
            .unwrap()
            .announce_clear(target, keypair, relay_addresses)
    }

    pub fn listen(&self, keypair: Keypair) -> ServerFuture {
        let (tx, rx) = mpsc::channel(32);
        let target = IdBytes(generic_hash(&*keypair.public));
        let announcer = self.announce(target, keypair.clone(), vec![]);
        self.inner.write().unwrap().add_listening_key(keypair, tx);

        ServerFuture::new(rx, self.inner.clone(), announcer)
    }

    /// Spawn a background task that drives this DHT's event loop.
    /// The task is automatically aborted when `Dht` is dropped.
    pub fn drive(&mut self) {
        let inner = self.inner.clone();

        let handle = tokio::spawn(async move {
            use futures::StreamExt;

            // A wrapper to drive  DhtInner
            struct Driver(Arc<RwLock<DhtInner>>);

            impl Stream for Driver {
                type Item = Result<CustomCommandRequest>;

                fn poll_next(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<Option<Self::Item>> {
                    let mut inner = self.0.write().unwrap();
                    Pin::new(&mut *inner).poll_next(cx)
                }
            }

            let mut driver = Driver(inner);
            while driver.next().await.is_some() {}
        });

        self.driver = Some(handle);
    }
}

impl Drop for Dht {
    fn drop(&mut self) {
        if let Some(handle) = self.driver.take() {
            handle.abort();
        }
    }
}

impl Stream for Dht {
    type Item = Result<CustomCommandRequest>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = self.inner.write().unwrap();
        Pin::new(&mut *inner).poll_next(cx)
    }
}

/// A connection waiting for its response to be flushed before being emitted
struct PendingConnection {
    /// Resolves when the response has been flushed
    flushed: oneshot::Receiver<()>,
    /// The connection to be emitted
    connection: Connection,
    /// Channel to send the connection on
    tx: mpsc::Sender<Result<Connection>>,
}

pub struct DhtInner {
    rpc: Rpc,
    id_maker: StreamIdMaker,
    #[expect(unused)]
    default_keypair: Keypair,
    listening_keypairs: HashMap<IdBytes, (Keypair, mpsc::Sender<Result<Connection>>)>,
    /// Connections waiting for their response to be flushed
    pending_connections: Vec<PendingConnection>,
    /// Peer record cache for LOOKUP queries (stores peers by topic)
    peer_records: PeerRecordCache,
    /// Router for self-announcing peers (FIND_PEER queries)
    peer_router: PeerRouter,
}

impl DhtInner {
    pub async fn with_config(mut config: DhtConfig) -> Result<Self> {
        if config.bootstrap_nodes.is_empty() {
            for addr_str in DEFAULT_BOOTSTRAP.iter() {
                if let Some(addr) = addr_str.to_socket_addrs()?.last() {
                    config.bootstrap_nodes.push(addr)
                }
            }
        }

        Ok(Self {
            rpc: Rpc::with_config(config).await?,
            id_maker: StreamIdMaker::new(),
            default_keypair: Default::default(),
            listening_keypairs: Default::default(),
            pending_connections: Default::default(),
            peer_records: PeerRecordCache::new(),
            peer_router: PeerRouter::new(),
        })
    }
    pub fn name(&self) -> String {
        self.rpc.name()
    }

    fn add_listening_key(&mut self, keypair: Keypair, tx: mpsc::Sender<Result<Connection>>) {
        let target = IdBytes(generic_hash(&*keypair.public));
        self.listening_keypairs.insert(target, (keypair, tx));
    }

    #[instrument(skip_all, err)]
    // TODO add a new error enum: FromPeerError and use them here
    pub fn on_request(
        &mut self,
        CustomCommandRequest {
            request,
            peer,
            command: ExternalCommand(command),
        }: CustomCommandRequest,
    ) -> Result<()> {
        use crate::commands::values;
        match command {
            values::PEER_HANDSHAKE => self.on_peer_handshake(*request, peer)?,
            values::PEER_HOLEPUNCH => todo!(),
            values::FIND_PEER => self.on_find_peer(*request, peer)?,
            values::LOOKUP => self.on_lookup(*request, peer)?,
            values::ANNOUNCE => self.on_announce(*request, peer)?,
            values::UNANNOUNCE => self.on_unannounce(*request, peer)?,
            x => todo!("{x}"),
        }
        Ok(())
    }

    /// Handle ANNOUNCE query - verify signature and store peer record.
    // TODO maybe propogate an error here about bad user data instead of returning Ok(()).
    // Note that using ? in poll_next is valid but it propagates the error.
    #[instrument(skip_all, err)]
    fn on_announce(&mut self, request: RequestMsgData, from_peer: Peer) -> Result<()> {
        let RequestMsgData {
            token,
            target,
            value,
            ..
        } = &request;
        let (Some(target), Some(token), Some(value)) = (target, token, value) else {
            return Err(Error::BadMsgFromPeer(format!(
                "Received Announce message with missing field:
target = [{target:?}], token = [{token:?}], value = [{value:?}]",
            )));
        };

        let (ann, _) = AnnounceRequestValue::decode(value).map_err(Error::EncodingErrorFromPeer)?;

        let encoded_peer = ann
            .peer
            .to_encoded_bytes()
            .map_err(Error::EncodingErrorFromPeer)?;

        let our_id = self.rpc.id();
        let signable = crate::crypto::make_signable_announce_or_unannounce(
            IdBytes(*target),
            token,
            &our_id.0,
            &encoded_peer,
            &namespace::ANNOUNCE,
        );
        ann.peer.public_key.verify(ann.signature, &signable)?;

        let pubkey_hash = generic_hash(&*ann.peer.public_key);
        let is_self_announce = pubkey_hash == *target;
        let target = IdBytes(*target);

        if is_self_announce {
            self.peer_router.set(
                target,
                RouterEntry::new(from_peer.addr, encoded_peer.into()),
            );
            self.peer_records.remove(&target, &ann.peer.public_key);
        } else {
            self.peer_records
                .add(target, *ann.peer.public_key, encoded_peer.into());
        }

        self.rpc.respond(&request, None, Some(vec![]), &from_peer)?;
        Ok(())
    }

    /// Handle FIND_PEER query - return a single peer record from the router.
    /// Used when target == hash(publicKey) - for direct peer lookups.
    fn on_find_peer(&self, request: RequestMsgData, from_peer: Peer) -> Result<()> {
        let Some(target) = request.target else {
            return Err(Error::BadMsgFromPeer(
                "Received FindPeer message without a 'target' field".into(),
            ));
        };
        let target = IdBytes(target);

        let value = self.peer_router.get(&target).map(|e| e.record.clone());

        self.rpc.respond(&request, value, None, &from_peer)?;
        Ok(())
    }

    /// Handle LOOKUP query - return up to 20 (MAX_RECORDS_PER_TOPIC) peer records for a topic.
    fn on_lookup(&self, request: RequestMsgData, from_peer: Peer) -> Result<()> {
        let Some(target) = request.target else {
            return Err(Error::BadMsgFromPeer(
                "Received Lookup message without a 'target' field".into(),
            ));
        };
        let target = IdBytes(target);

        let mut encoded_records: Vec<&[u8]> = self
            .peer_records
            .get(&target, MAX_RECORDS_PER_TOPIC)
            .into_iter()
            .map(|r| r.encoded.as_slice())
            .collect();

        if let Some(entry) = self.peer_router.get(&target)
            && encoded_records.len() < MAX_RECORDS_PER_TOPIC
        {
            encoded_records.push(&entry.record);
        }

        let value = if encoded_records.is_empty() {
            None
        } else {
            // TODO: There's something I don't understand here. We should be able to do:
            // let value = PeerRecords.get(..).to_encoded_bytes()?;
            // self.rpc.respond(.., value, ..);
            // But that isn't working. But this does
            let mut peers = Vec::with_capacity(encoded_records.len());
            for encoded in encoded_records {
                let (peer, _) = crate::cenc::Peer::decode(encoded)?;
                peers.push(peer);
            }
            Some(peers.to_encoded_bytes()?.to_vec())
        };

        self.rpc.respond(&request, value, None, &from_peer)?;
        Ok(())
    }

    /// Handle UNANNOUNCE query - verify signature and remove peer record.
    fn on_unannounce(&mut self, request: RequestMsgData, from_peer: Peer) -> Result<()> {
        let RequestMsgData {
            token,
            target,
            value,
            ..
        } = &request;
        let (Some(target), Some(token), Some(value)) = (target, token, value) else {
            return Err(Error::BadMsgFromPeer(format!(
                "Received UnAnnounce message with missing field:
target = [{target:?}], token = [{token:?}], value = [{value:?}]",
            )));
        };

        let (ann, _) = AnnounceRequestValue::decode(value).map_err(Error::EncodingErrorFromPeer)?;
        let encoded_peer = ann
            .peer
            .to_encoded_bytes()
            .map_err(Error::EncodingErrorFromPeer)?;

        let our_id = self.rpc.id();
        let signable = crate::crypto::make_signable_announce_or_unannounce(
            IdBytes(*target),
            token,
            &our_id.0,
            &encoded_peer,
            &namespace::UNANNOUNCE,
        );
        ann.peer.public_key.verify(ann.signature, &signable)?;

        let pubkey_hash = generic_hash(&*ann.peer.public_key);
        let is_self_announce = pubkey_hash == *target;
        let target = IdBytes(*target);

        if is_self_announce {
            self.peer_router.delete(&target);
        }
        self.peer_records.remove(&target, &ann.peer.public_key);

        self.rpc.respond(&request, None, Some(vec![]), &from_peer)?;
        Ok(())
    }

    /// Handle PeerHandshake when we are a relay.
    /// Relay doesn't create a UDX connection. Just pass message around to the server.
    pub fn on_peer_handshake_as_relay(
        &mut self,
        request: RequestMsgData,
        from_peer: Peer,
        php: PeerHandshakePayload,
    ) -> Result<()> {
        match php.mode {
            HandshakeSteps::FromClient => {
                // TODO: Forward as FROM_RELAY to relay address
                // (Implement later - not in this PR)
                self.on_peer_handshake_as_relay_from_client(request, from_peer, php)
            }
            HandshakeSteps::FromRelay => {
                // TODO: Forward as FROM_SECOND_RELAY
                // (Implement later - not in this PR)
                todo!("relay FROM_RELAY")
            }
            HandshakeSteps::FromServer => {
                self.on_peer_handshake_as_relay_from_server(request, from_peer, php)
            }
            HandshakeSteps::FromSecondRelay => {
                // (Implement later - not in this PR)
                todo!("relay FROM_SECOND_RELAY")
            }
            HandshakeSteps::Reply => {
                // Relay should never receive Reply mode
                Err(Error::PeerHandshakeFailed(
                    "TODO relay received unexpected Reply".into(),
                ))
            }
        }
    }

    /// Handle PeerHandshake with mode = FromClient when we are a relay.
    fn on_peer_handshake_as_relay_from_client(
        &self,
        request: RequestMsgData,
        from_peer: Peer,
        php: PeerHandshakePayload,
    ) -> Result<()> {
        // If no relay address is known, respond with closer nodes to help routing
        // TODO expose getting closer nodes later
        let Some(relay_address) = php.relay_address else {
            /*
            // TODO: Check if we have a relay registered in state for this target
            // For now, return closer nodes to help DHT routing
            let target = request
                .target
                .ok_or_else(|| Error::PeerHandshakeFailed("FROM_CLIENT missing target".into()))?;

            let closer_nodes = self
                .rpc
                .inner
                .lock()
                .unwrap()
                .closer_nodes(IdBytes::from(target), K_VALUE as usize);

            // Respond with no value but with closer nodes
            self.rpc.respond(
                request,
                None,               // No value
                Some(closer_nodes), // Help client route
                from_peer,
            )?;

            return Ok(());
            */
            todo!()
        };

        // TODO this should be cleaned up  when SocketAddr/SocketAddrV4 is handled
        let SocketAddr::V4(client_addr) = from_peer.addr else {
            return Err(Error::Ipv6NotSupported);
        };

        let relay_payload = PeerHandshakePayloadBuilder::default()
            .mode(HandshakeSteps::FromRelay)
            .noise(php.noise)
            .peer_address(Some(client_addr)) // Client's address for server
            .relay_address(None) // Clear relay_address after first hop
            .build()?
            .to_encoded_bytes()?;

        let o = OutRequestBuilder::from_request(request.clone())
            .value(relay_payload.to_vec())
            .peer(Peer::from(SocketAddr::from(relay_address)));
        self.rpc.request2(o)?;
        Ok(())
    }
    fn on_peer_handshake_as_relay_from_server(
        &self,
        request: RequestMsgData,
        from_peer: Peer,
        php: PeerHandshakePayload,
    ) -> Result<()> {
        let peer_address = php
            .peer_address
            .ok_or_else(|| Error::PeerHandshakeFailed("FROM_SERVER missing peer_address".into()))?;

        let SocketAddr::V4(server_addr) = from_peer.addr else {
            return Err(Error::Ipv6NotSupported);
        };

        let reply_payload = PeerHandshakePayloadBuilder::default()
            .mode(HandshakeSteps::Reply)
            .noise(php.noise)
            .peer_address(Some(server_addr)) // Server's address for client
            .build()?
            .to_encoded_bytes()?;

        self.rpc.respond(
            &request,
            Some(reply_payload.into()),
            Some(vec![]),                    // No closer nodes
            &Peer::new(peer_address.into()), // Client's address
        )?;

        Ok(())
    }

    pub fn on_peer_handshake(&mut self, request: RequestMsgData, from_peer: Peer) -> Result<()> {
        let Some(target) = request.target else {
            return Err(Error::PeerHandshakeFailed("missing target".into()));
        };
        let Some(value) = &request.value else {
            return Err(Error::PeerHandshakeFailed("missing value".into()));
        };

        let (php, rest) = PeerHandshakePayload::decode(value)?;
        debug_assert!(rest.is_empty());

        let Some((keypair, tx)) = self.listening_keypairs.get(&IdBytes(target)) else {
            info!("Relay RX PEER_HANDSHAKE mode = {:?}", php.mode);
            return self.on_peer_handshake_as_relay(request, from_peer, php);
        };
        info!("Server RX PEER_HANDSHAKE mode = {:?}", php.mode);
        let tx = tx.clone();

        // Create our UDX stream
        let udx_local_id = self.id_maker.new_id();

        // Build our NoisePayload with our UDX info for the response
        let SocketAddr::V4(local_addr) = self.rpc.local_addr()? else {
            return Err(Error::Ipv6NotSupported);
        };
        let server_np = NoisePayloadBuilder::default()
            .firewall(firewall::OPEN)
            .addresses4(Some(vec![local_addr]))
            .udx(Some(
                UdxInfoBuilder::default()
                    .reusable_socket(false)
                    .id(udx_local_id as usize)
                    .build()?,
            ))
            .build()?
            .to_encoded_bytes()?;

        // Create responder cipher with same prologue as initiator
        let mut hs = Cipher::resp_from_private_with_prologue(
            None,
            &keypair.secret[..32],
            &namespace::PEER_HANDSHAKE,
        )?;

        hs.queue_msg(server_np.to_vec());

        // Receive client's noise message
        hs.receive_next(php.noise);

        // Decrypt the client's payload to get their UDX info
        let Some(hypercore_handshake::CipherEvent::HandshakePayload(payload_bytes)) =
            hs.next_decrypted_message()?
        else {
            return Err(Error::PeerHandshakeFailed(
                "expected handshake payload".into(),
            ));
        };
        let (remote_payload, _rest) = NoisePayload::decode(&payload_bytes)?;
        debug_assert!(_rest.is_empty());

        // Set our payload and get the response noise
        let Some(noise) = hs.get_next_sendable_message()? else {
            return Err(Error::PeerHandshakeFailed(
                "failed to generate response noise".into(),
            ));
        };

        let udx_remote_id = remote_payload
            .udx
            .as_ref()
            .ok_or_else(|| Error::PeerHandshakeFailed("client missing udx info".into()))?
            .id as u32;

        // Build and send the response
        match php.mode {
            crate::cenc::HandshakeSteps::FromClient => {
                let connection =
                    self.new_connection(from_peer.addr, hs, udx_local_id, udx_remote_id)?;
                self.on_peer_handshake_from_client(request, noise, from_peer, connection, tx)
            }
            crate::cenc::HandshakeSteps::FromServer => todo!(),
            crate::cenc::HandshakeSteps::FromRelay => {
                let Some(peer_address) = php.peer_address else {
                    todo!()
                };

                let connection =
                    self.new_connection(peer_address.into(), hs, udx_local_id, udx_remote_id)?;

                self.on_peer_handshake_as_server_from_relay(
                    &request,
                    &from_peer,
                    noise,
                    php.peer_address,
                    connection,
                    tx,
                )?;
                Ok(())
            }
            crate::cenc::HandshakeSteps::FromSecondRelay => todo!(),
            crate::cenc::HandshakeSteps::Reply => todo!(),
        }
    }

    fn new_connection(
        &self,
        destination: SocketAddr,
        cipher: Cipher,
        udx_local_id: u32,
        udx_remote_id: u32,
    ) -> Result<Connection> {
        let half_stream = self.rpc.socket().create_stream(udx_local_id)?;
        let connection =
            Connection::new_with_rpc(cipher, udx_local_id, half_stream, self.rpc.clone());
        connection.connect(destination, udx_remote_id)?;
        Ok(connection)
    }
    fn on_peer_handshake_from_client(
        &mut self,
        request: RequestMsgData,
        noise: Vec<u8>,
        from_peer: Peer,
        connection: Connection,
        tx: mpsc::Sender<Result<Connection>>,
    ) -> Result<()> {
        let peer_handshake_payload = PeerHandshakePayloadBuilder::default()
            .mode(crate::cenc::HandshakeSteps::Reply)
            .noise(noise)
            .build()?;

        let response_flushed = self.rpc.respond(
            &request,
            Some(peer_handshake_payload.to_encoded_bytes()?.into()),
            Some(vec![]),
            &Peer::new(from_peer.addr),
        )?;
        // Queue the connection to be sent after the response is flushed
        self.pending_connections.push(PendingConnection {
            flushed: response_flushed,
            connection,
            tx,
        });

        Ok(())
    }

    fn on_peer_handshake_as_server_from_relay(
        &mut self,
        request: &RequestMsgData,
        peer: &Peer,
        noise: Vec<u8>,
        peer_address: Option<SocketAddrV4>,
        connection: Connection,
        tx: mpsc::Sender<Result<Connection>>,
    ) -> Result<()> {
        let value = PeerHandshakePayloadBuilder::default()
            .mode(HandshakeSteps::FromServer)
            .peer_address(peer_address)
            .noise(noise)
            .build()?
            .to_encoded_bytes()?;

        let o = OutRequestBuilder::from_request(request.clone())
            .value(value.to_vec())
            .peer(peer.clone());
        let flush = self.rpc.request2(o)?;
        self.pending_connections.push(PendingConnection {
            connection,
            tx,
            flushed: flush,
        });
        Ok(())
    }

    pub fn bootstrap(&self) -> BootstrapFuture {
        self.rpc.bootstrap()
    }

    pub fn connect(
        &self,
        pub_key: PublicKey,
        closest_nodes: Option<Vec<Peer>>,
        dht: Arc<RwLock<DhtInner>>,
    ) -> ConnectFuture {
        ConnectFuture {
            dht,
            query: TakableResult::from_result(self.find_peer(pub_key.clone(), closest_nodes)),
            pub_key,
            pending_handshake: None,
        }
    }

    pub fn lookup(&self, target: IdBytes, commit: Commit) -> Result<Lookup> {
        let query = self
            .rpc
            .query(QueryArgs::new(commands::LOOKUP, target).commit(commit));
        Ok(Lookup {
            query,
            topic: target,
            collected_responses: Vec::new(),
        })
    }

    pub fn find_peer(
        &self,
        pub_key: PublicKey,
        closest_nodes: Option<Vec<Peer>>,
    ) -> Result<FindPeer> {
        let target = IdBytes(generic_hash(&*pub_key));
        let mut args = QueryArgs::new(commands::FIND_PEER, target);
        if let Some(nodes) = closest_nodes {
            args = args.closest_nodes(nodes);
        }
        let query = self.rpc.query(args);
        Ok(FindPeer {
            query,
            topic: target,
            collected_responses: Vec::new(),
        })
    }

    // TODO  return something more useful, maybe indicate if commits failed, etc
    pub fn announce(
        &self,
        target: IdBytes,
        keypair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> Announce {
        let query = self.rpc.query(QueryArgs::new(commands::LOOKUP, target));
        Announce {
            rpc: self.rpc.clone(),
            query,
            target,
            keypair,
            relay_addresses,
            pending_requests: Default::default(),
            query_done: false.into(),
        }
    }
    pub fn unannounce(&self, target: IdBytes, keypair: Keypair) -> Unannounce {
        let query = self.rpc.query(QueryArgs::new(commands::LOOKUP, target));
        Unannounce {
            rpc: self.rpc.clone(),
            query,
            target,
            keypair: keypair.clone(),
            done: false.into(),
            pending_requests: Default::default(),
        }
    }

    pub fn request(&self, o: OutRequestBuilder) -> RpcDhtRequestFuture {
        self.rpc.request_from_builder(o)
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.rpc.local_addr()?)
    }

    pub fn peer_handshake(
        &self,
        PeerHandshakeArgs {
            remote_public_key,
            relay_address,
            destination,
        }: PeerHandshakeArgs,
    ) -> Result<PeerHandshake> {
        let SocketAddr::V4(addr) = self.rpc.local_addr()? else {
            todo!()
        };

        let relay_address = relay_address
            .map(|x| match x {
                SocketAddr::V4(o) => Ok(o),
                SocketAddr::V6(_) => Err(Error::Ipv6NotSupported),
            })
            .transpose()?;

        let mut hs =
            Cipher::new_dht_init(None, &remote_public_key, &crate::namespace::PEER_HANDSHAKE)?;
        let udx_local_id = self.id_maker.new_id();
        let np = NoisePayloadBuilder::default()
            .firewall(firewall::OPEN)
            .addresses4(Some(vec![addr]))
            .udx(Some(
                UdxInfoBuilder::default()
                    .reusable_socket(false)
                    .id(udx_local_id as usize)
                    .build()?,
            ))
            .build()?
            .to_encoded_bytes()?;
        hs.handshake_start(&np)?;
        let noise = hs
            .get_next_sendable_message()?
            .expect("we just set payload above. See `.handshake_start(np)`");

        let peer_handshake_payload = PeerHandshakePayloadBuilder::default()
            .noise(noise)
            .mode(crate::cenc::HandshakeSteps::FromClient)
            .relay_address(relay_address)
            .build()?
            .to_encoded_bytes()?;

        let half_stream = self.rpc.socket().create_stream(udx_local_id)?;
        let connection = Connection::new(hs, udx_local_id, half_stream);

        let o = OutRequestBuilder::new(Peer::new(destination), commands::PEER_HANDSHAKE)
            .value(peer_handshake_payload.into())
            .target(generic_hash(&*remote_public_key).into());

        Ok(PeerHandshake {
            request: self.request(o),
            connection,
        })
    }

    pub fn announce_clear(
        &self,
        target: IdBytes,
        keypair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> AnnounceClear {
        let query = self.rpc.query(QueryArgs::new(commands::LOOKUP, target));
        AnnounceClear {
            rpc: self.rpc.clone(),
            query,
            target,
            keypair,
            pending_requests: Default::default(),
            relay_addresses,
            query_done: false.into(),
            commits_done: false.into(),
        }
    }
}

impl Stream for DhtInner {
    type Item = Result<CustomCommandRequest>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll pending connections - send them once their response is flushed
        self.pending_connections.retain_mut(|pending| {
            match Pin::new(&mut pending.flushed).poll(cx) {
                Poll::Ready(_) => {
                    let _ = pending.tx.try_send(Ok(pending.connection.clone()));
                    false
                }
                Poll::Pending => true,
            }
        });

        match Stream::poll_next(Pin::new(&mut self.rpc), cx) {
            Poll::Ready(x) => match x {
                Some(y) => match y {
                    dht_rpc::RpcEvent::CustomRequest(request) => {
                        self.on_request(request)?;
                    }
                    dht_rpc::RpcEvent::ResponseResult(_response_ok) => {
                        return Poll::Pending;
                    }
                    dht_rpc::RpcEvent::RoutingUpdated { .. } => {}
                    dht_rpc::RpcEvent::Bootstrapped(_bootstrapped) => {}
                    dht_rpc::RpcEvent::ReadyToCommit { .. } => todo!(),
                    dht_rpc::RpcEvent::QueryResult(_query_result) => {
                        return Poll::Pending;
                    }
                    dht_rpc::RpcEvent::QueryResponse(_in_response) => {
                        return Poll::Pending;
                    }
                },
                None => return Poll::Ready(None),
            },
            Poll::Pending => return Poll::Pending,
        }
        Poll::Pending
    }
}

#[derive(Debug)]
pub struct PeerHandshakeArgs {
    remote_public_key: PublicKey,
    relay_address: Option<SocketAddr>,
    destination: SocketAddr,
}

impl PeerHandshakeArgs {
    pub fn new(remote_public_key: PublicKey, destination: SocketAddr) -> Self {
        Self {
            remote_public_key,
            relay_address: None,
            destination,
        }
    }

    pub fn relay_address(mut self, relay_address: SocketAddr) -> Self {
        self.relay_address = Some(relay_address);
        self
    }
}

#[derive(Debug)]
pub struct PeerHandshake {
    request: RpcDhtRequestFuture,
    connection: Connection,
}

impl Future for PeerHandshake {
    type Output = Result<Connection>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let resp = match Pin::new(&mut self.request).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(resp)) => resp,
        };

        let phs = decode_peer_handshake_response(&resp)?;
        let hypercore_handshake::CipherEvent::HandshakePayload(payload) =
            self.connection.receive_next(phs.noise.clone())?
        else {
            todo!()
        };
        let (np, rest) = NoisePayload::decode(&payload)?;
        debug_assert!(rest.is_empty());
        self.connection.connect(
            phs.server_address.into(),
            np.udx
                .as_ref()
                .expect("TODO response SHOULD have udx_info")
                .id as u32,
        )?;
        Poll::Ready(Ok(self.connection.clone()))
    }
}

#[derive(Debug)]
pub struct LookupResponse {
    pub response: Arc<InResponse>,
    pub peers: Vec<crate::cenc::Peer>,
}

impl LookupResponse {
    #[instrument(skip_all, err)]
    fn decode_response(response: Arc<InResponse>) -> Result<Option<LookupResponse>> {
        let Some(value) = &response.response.value else {
            return Ok(None);
        };
        let (peers, _rest): (Vec<crate::cenc::Peer>, &[u8]) =
            <Vec<crate::cenc::Peer> as CompactEncoding>::decode(value)?;
        debug_assert!(_rest.is_empty());
        Ok(Some(LookupResponse { response, peers }))
    }
}

#[derive(Debug)]
pub struct Lookup {
    query: QueryNext,
    topic: IdBytes,
    collected_responses: Vec<Arc<InResponse>>,
}

impl Stream for Lookup {
    type Item = Result<Option<LookupResponse>>;

    #[instrument(skip_all)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.query).poll_next(cx).map(|x| {
            x.map(|response| {
                self.collected_responses.push(response.clone());
                LookupResponse::decode_response(response)
            })
        })
    }
}

impl Future for Lookup {
    type Output = Result<QueryResult>;

    #[instrument(skip_all)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(response)) => self.collected_responses.push(response),
                Poll::Ready(None) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: std::mem::take(&mut self.collected_responses),
                query_id: query_result.query_id,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
pub struct FindPeerResponse {
    pub response: Arc<InResponse>,
    pub peer: crate::cenc::Peer,
}

impl FindPeerResponse {
    #[instrument(skip_all, err)]
    fn decode_response(response: Arc<InResponse>) -> Result<Option<FindPeerResponse>> {
        let Some(value) = &response.response.value else {
            return Ok(None);
        };
        let (peer, _rest): (crate::cenc::Peer, &[u8]) =
            <crate::cenc::Peer as CompactEncoding>::decode(value)?;
        debug_assert!(_rest.is_empty());
        Ok(Some(FindPeerResponse { response, peer }))
    }
}

pub struct FindPeer {
    query: QueryNext,
    topic: IdBytes,
    collected_responses: Vec<Arc<InResponse>>,
}

impl Stream for FindPeer {
    type Item = Result<Option<FindPeerResponse>>;

    #[instrument(skip_all)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.query).poll_next(cx).map(|x| {
            x.map(|response| {
                self.collected_responses.push(response.clone());
                FindPeerResponse::decode_response(response)
            })
        })
    }
}

impl Future for FindPeer {
    type Output = Result<QueryResult>;

    #[instrument(skip_all)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(response)) => self.collected_responses.push(response),
                Poll::Ready(None) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: std::mem::take(&mut self.collected_responses),
                query_id: query_result.query_id,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct Announce {
    rpc: Rpc,
    query: QueryNext,
    target: IdBytes,
    keypair: Keypair,
    relay_addresses: Vec<SocketAddr>,
    pending_requests: FuturesUnordered<RpcDhtRequestFuture>,
    query_done: AtomicBool,
}

impl Future for Announce {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Phase 1: Complete the query and queue commit requests
        if !self.query_done.load(Relaxed) {
            match Pin::new(&mut self.query).poll(cx) {
                Poll::Ready(Ok(query_result)) => {
                    for reply in query_result.closest_replies.iter() {
                        let (Some(token), Some(responder_id)) =
                            (reply.response.token, reply.response.id)
                        else {
                            warn!(
                                tid = reply.tid(),
                                "In Announce result.closest_replies a reply is missing:
    token = [{:?}] or id = [{:?}]",
                                reply.response.token,
                                reply.response.id
                            );
                            continue;
                        };
                        let value = request_announce_or_unannounce_value(
                            &self.keypair,
                            self.target,
                            &token,
                            IdBytes(responder_id),
                            &self.relay_addresses,
                            &crate::crypto::namespace::ANNOUNCE,
                        );
                        let from_peer = Peer {
                            id: Some(responder_id),
                            addr: reply.peer.addr,
                            referrer: None,
                        };
                        let o = OutRequestBuilder::new(from_peer, crate::commands::ANNOUNCE)
                            .target(self.target)
                            .value(value)
                            .token(token);
                        self.pending_requests.push(self.rpc.request_from_builder(o));
                    }
                    self.query_done.store(true, Relaxed);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Phase 2: Wait for all commit requests to complete
        match Pin::new(&mut self.pending_requests).poll_next(cx) {
            Poll::Ready(Some(Ok(res))) => {
                trace!(tid = res.request.tid, "RX announce commit");
                cx.waker().wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => error!(error =? e, "Announce commit request error"),
            Poll::Ready(None) => {
                // All commits done
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }
        Poll::Pending
    }
}

pub struct Unannounce {
    rpc: Rpc,
    query: QueryNext,
    target: IdBytes,
    keypair: Keypair,
    pending_requests: FuturesUnordered<RpcDhtRequestFuture>,
    done: AtomicBool,
}

impl Future for Unannounce {
    type Output = Result<()>;

    // Send a request for each response, push into FuturesUnordered.
    // poll FuturesUnordered for each poll call.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !&self.done.load(Relaxed) {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(resp)) => {
                    let (Some(token), Some(responder_id), commands::LOOKUP) =
                        (&resp.response.token, resp.response.id, resp.cmd())
                    else {
                        warn!("Unannounce: missing token or id in response, skipping");
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    };
                    let destination = Peer {
                        addr: resp.peer.addr,
                        id: Some(responder_id),
                        referrer: None,
                    };
                    let value = request_announce_or_unannounce_value(
                        &self.keypair,
                        self.target,
                        token,
                        IdBytes(responder_id),
                        &[],
                        &namespace::UNANNOUNCE,
                    );

                    let o = OutRequestBuilder::new(destination, crate::commands::UNANNOUNCE)
                        .target(self.target)
                        .value(value)
                        .token(*token);
                    let req = self.rpc.request_from_builder(o);
                    trace!(tid = req.tid(), "TX unannounce commit");
                    self.pending_requests.push(req);
                }
                Poll::Ready(None) => {
                    self.done.store(true, Relaxed);
                }
                Poll::Pending => {}
            }
        }
        match Pin::new(&mut self.pending_requests).poll_next(cx) {
            Poll::Ready(Some(Ok(res))) => {
                trace!(tid = res.request.tid, "RX unannounce commit");
                cx.waker().wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => error!(error =? e, "Unannounce commit request error"),
            Poll::Ready(None) => {
                if self.done.load(Relaxed) {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Pending => {}
        }
        Poll::Pending
    }
}

pub struct AnnounceClear {
    rpc: Rpc,
    query: QueryNext,
    target: IdBytes,
    keypair: Keypair,
    pending_requests: FuturesUnordered<RpcDhtRequestFuture>,
    relay_addresses: Vec<SocketAddr>,
    query_done: AtomicBool,
    commits_done: AtomicBool,
}

impl AnnounceClear {
    fn do_query(&mut self, cx: &mut Context<'_>) -> Option<Poll<Result<()>>> {
        if self.query_done.load(Relaxed) {
            return None;
        }
        match Pin::new(&mut self.query).poll_next(cx) {
            Poll::Ready(Some(resp)) => {
                let (Some(token), Some(responder_id), commands::LOOKUP) =
                    (&resp.response.token, resp.response.id, resp.cmd())
                else {
                    warn!("AnnounceClear: missing token or id in response, skipping");
                    cx.waker().wake_by_ref();
                    return Some(Poll::Pending);
                };
                let destination = Peer {
                    addr: resp.peer.addr,
                    id: Some(responder_id),
                    referrer: None,
                };
                let value = request_announce_or_unannounce_value(
                    &self.keypair,
                    self.target,
                    token,
                    IdBytes(responder_id),
                    &[],
                    &namespace::UNANNOUNCE,
                );

                let o = OutRequestBuilder::new(destination, crate::commands::UNANNOUNCE)
                    .target(self.target)
                    .value(value)
                    .token(*token);
                let req = self.rpc.request_from_builder(o);
                trace!(tid = req.tid(), "TX unannounce commit");
                self.pending_requests.push(req);
            }
            Poll::Ready(None) => {
                self.query_done.store(true, Relaxed);
            }
            Poll::Pending => {}
        }
        Some(Poll::Pending)
    }
    fn do_commit(&mut self, cx: &mut Context<'_>) -> Option<Poll<Result<()>>> {
        if self.commits_done.load(Relaxed) {
            return None;
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => {
                for reply in query_result.closest_replies.iter() {
                    let (Some(token), Some(responder_id)) =
                        (reply.response.token, reply.response.id)
                    else {
                        warn!(
                            tid = reply.tid(),
                            "In AnnounceClear result.closest_replies a reply is missing:
    token = [{:?}] or id = [{:?}]",
                            reply.response.token,
                            reply.response.id
                        );
                        continue;
                    };
                    let value = request_announce_or_unannounce_value(
                        &self.keypair,
                        self.target,
                        &token,
                        IdBytes(responder_id),
                        &self.relay_addresses,
                        &crate::crypto::namespace::ANNOUNCE,
                    );
                    let from_peer = Peer {
                        id: Some(responder_id),
                        addr: reply.peer.addr,
                        referrer: None,
                    };
                    let o = OutRequestBuilder::new(from_peer, crate::commands::ANNOUNCE)
                        .target(self.target)
                        .value(value)
                        .token(token);
                    self.pending_requests.push(self.rpc.request_from_builder(o));
                }
                self.commits_done.store(true, Relaxed);
            }
            Poll::Ready(Err(e)) => return Some(Poll::Ready(Err(e.into()))),
            Poll::Pending => return Some(Poll::Pending),
        }
        None
    }

    fn poll_pending_requests(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match Pin::new(&mut self.pending_requests).poll_next(cx) {
            Poll::Ready(Some(Ok(res))) => {
                trace!(tid = res.request.tid, "RX AnnounceClear commit");
                cx.waker().wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(error =? e, "AnnounceClear commit request error")
            }
            Poll::Ready(None) => {
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }
        Poll::Pending
    }
}

impl Future for AnnounceClear {
    type Output = Result<()>;

    // Send a request for each response, push into FuturesUnordered.
    // poll FuturesUnordered for each poll call.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(x) = self.do_query(cx) {
            _ = self.poll_pending_requests(cx);
            return x;
        }
        if let Some(x) = self.do_commit(cx) {
            _ = self.poll_pending_requests(cx);
            return x;
        }
        self.poll_pending_requests(cx)
    }
}
