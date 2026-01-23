use std::{net::SocketAddr, sync::Arc, task::Waker};

use crate::{IdBytes, Result, cenc::validate_id};
use fnv::FnvHashMap;
use futures::{
    Sink, Stream,
    task::{Context, Poll},
};
use rand::Rng;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio::sync::oneshot::{self, Receiver, Sender};
use tracing::{error, trace};
use wasm_timer::Instant;

use super::{
    Command, Peer, QueryAndTid,
    cenc::{generic_hash, generic_hash_with_key, ipv4},
    message::{MsgData, ReplyMsgData, RequestMsgData},
    query::QueryId,
    stateobserver::Observer,
    stream::MessageDataStream,
    thirty_two_random_bytes,
};

const ROTATE_INTERVAL: u64 = 300_000;

pub type Tid = u16;

/// TODO hide secrets in fmt::Debug
#[derive(Debug)]
pub struct Secrets {
    _rotate_counter: usize,
    // NB starts null in js. Not initialized until token call.
    // so my behavior diverges when drain called until token
    // bc drain checks if secrets initialized
    secrets: [[u8; 32]; 2],
    _rotation: Duration,
    _last_rotation: Instant,
}

impl Default for Secrets {
    fn default() -> Self {
        Self {
            _rotate_counter: 10,
            _rotation: Duration::from_millis(ROTATE_INTERVAL),
            _last_rotation: Instant::now(),
            secrets: [thirty_two_random_bytes(), thirty_two_random_bytes()],
        }
    }
}

impl Secrets {
    fn _rotate_secrets(&mut self) -> Result<()> {
        let tmp = self.secrets[0];
        self.secrets[0] = self.secrets[1];
        self.secrets[1] = generic_hash(&tmp);
        Ok(())
    }

    fn _drain(&mut self) -> Result<()> {
        self._rotate_counter -= 1;
        if self._rotate_counter == 0 {
            self._rotate_counter = 10;
            self._rotate_secrets()?;
        }
        Ok(())
    }

    pub fn token(&self, peer: &Peer, secret_index: usize) -> Result<[u8; 32]> {
        generic_hash_with_key(&ipv4(&peer.addr)?.octets()[..], &self.secrets[secret_index])
    }
}

/// Recied response data along with metadata
#[derive(Debug, Clone)]
pub struct InResponse {
    pub request: Box<RequestMsgData>,
    pub response: ReplyMsgData,
    /// [`Peer`] who sent the response
    pub peer: Peer,
    pub query_id: Option<QueryId>,
}

impl InResponse {
    pub fn tid(&self) -> Tid {
        self.request.tid
    }
    pub fn cmd(&self) -> Command {
        self.request.command
    }

    pub fn valid_peer_id(&self) -> Option<IdBytes> {
        validate_id(&self.response.id, &self.peer)
    }

    fn new(
        request: Box<RequestMsgData>,
        response: ReplyMsgData,
        peer: Peer,
        query_id: Option<QueryId>,
    ) -> Self {
        Self {
            request,
            response,
            peer,
            query_id,
        }
    }
}

#[derive(Debug)]
pub struct OutRequestBuilder {
    peer: Peer,
    command: Command,
    tid: Option<u16>,
    id: Option<[u8; 32]>,
    query_id: Option<QueryId>,
    token: Option<[u8; 32]>,
    target: Option<IdBytes>,
    value: Option<Vec<u8>>,
}

macro_rules! setter {
    ($name:ident, $type:ty) => {
        pub fn $name(mut self, $name: $type) -> Self {
            self.$name = Some($name);
            self
        }
    };
}
impl OutRequestBuilder {
    pub fn from_request(req: RequestMsgData) -> Self {
        Self {
            peer: req.to.clone(),
            command: req.command,
            tid: Some(req.tid),
            id: req.id,
            query_id: None,
            token: req.token,
            target: req.target.map(IdBytes::from),
            value: req.value,
        }
    }
    pub fn new(peer: Peer, command: Command) -> Self {
        Self {
            peer,
            command,
            tid: None,
            query_id: None,
            token: None,
            target: None,
            value: None,
            id: None,
        }
    }
    pub fn peer(mut self, peer: Peer) -> Self {
        self.peer = peer;
        self
    }
    setter!(tid, u16);
    setter!(query_id, QueryId);
    setter!(token, [u8; 32]);
    setter!(target, IdBytes);
    setter!(value, Vec<u8>);
}

/// OutMessage contains outgoing messages data, including local metadata for managing messages
#[derive(Debug)]
pub enum OutMessage {
    Request((Option<QueryId>, RequestMsgData, Option<Sender<()>>)),
    Reply((Option<Sender<()>>, ReplyMsgData)),
}

impl OutMessage {
    fn to_sendable(self) -> (MsgData, SocketAddr, Option<Sender<()>>) {
        match self {
            OutMessage::Request((_query_id, msg, tx)) => {
                let dest = SocketAddr::from(&msg.to);
                (MsgData::Request(msg), dest, tx)
            }
            OutMessage::Reply((tx, msg)) => {
                let dest = SocketAddr::from(&msg.to);
                (MsgData::Reply(msg), dest, tx)
            }
        }
    }
}

#[derive(Debug)]
struct InflightRequest {
    /// The message send
    message: RequestMsgData,
    /// Timestamp when the request was sent
    #[expect(unused)] // TODO FIXME not read. Why not?
    timestamp: Instant,
    // Identifier for the query this request is used with
    query_id: Option<QueryId>,
}

#[derive(Debug)]
pub struct IoHandler {
    id: Observer<IdBytes>,
    ephemeral: bool,
    message_stream: MessageDataStream,
    /// Messages to send
    pending_send: VecDeque<OutMessage>,
    /// Current message
    pending_flush: Option<OutMessage>,
    /// Sent requests we currently wait for a response
    pending_recv: FnvHashMap<Tid, InflightRequest>,
    secrets: Secrets,
    tid: AtomicU16,
    stream_waker: Option<Waker>,
    name: String,
}

impl IoHandler {
    pub fn new(
        id: Observer<IdBytes>,
        message_stream: MessageDataStream,
        _config: IoConfig,
    ) -> Self {
        Self {
            id,
            ephemeral: true,
            message_stream,
            pending_send: Default::default(),
            pending_flush: None,
            pending_recv: Default::default(),
            secrets: Default::default(),
            tid: AtomicU16::new(rand::thread_rng().r#gen()),
            stream_waker: Default::default(),
            name: random_name(),
        }
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    pub fn id(&self) -> IdBytes {
        *self.id.get()
    }

    pub fn local_addr(&self) -> crate::Result<SocketAddr> {
        self.message_stream.local_addr()
    }
    pub fn socket(&self) -> udx::UdxSocket {
        self.message_stream.socket()
    }
    /// TODO check this is correct.
    pub fn token(&self, peer: &Peer, secret_index: usize) -> crate::Result<[u8; 32]> {
        self.secrets.token(peer, secret_index)
    }

    pub fn new_tid(&self) -> Tid {
        self.tid.fetch_add(1, Ordering::Relaxed)
    }

    pub fn enqueue_reply(&mut self, msg: ReplyMsgData, tx: Option<Sender<()>>) {
        self.pending_send.push_back(OutMessage::Reply((tx, msg)));
        self.maybe_wake();
    }

    pub fn request_from_builder(
        &mut self,
        OutRequestBuilder {
            tid,
            query_id,
            peer,
            command,
            token,
            target,
            value,
            id,
        }: OutRequestBuilder,
    ) -> QueryAndTid {
        let id = id.or_else(|| (!self.ephemeral).then(|| self.id().0));
        let tid = tid.unwrap_or_else(|| self.new_tid());
        self.enqueue_request((
            query_id,
            RequestMsgData {
                tid,
                to: peer,
                id,
                token,
                command,
                target: target.map(|x| x.into()),
                value,
            },
            None,
        ));
        (query_id, tid)
    }

    pub fn request(
        &mut self,
        command: Command,
        target: Option<IdBytes>,
        value: Option<Vec<u8>>,
        peer: Peer,
        query_id: Option<QueryId>,
        token: Option<[u8; 32]>,
    ) -> QueryAndTid {
        let id = (!self.ephemeral).then(|| self.id().0);
        let tid = self.new_tid();
        self.enqueue_request((
            query_id,
            RequestMsgData {
                tid,
                to: peer,
                id,
                token,
                command,
                target: target.map(|x| x.0),
                value,
            },
            None,
        ));
        (query_id, tid)
    }

    pub fn enqueue_request(&mut self, msg: (Option<QueryId>, RequestMsgData, Option<Sender<()>>)) {
        self.pending_send.push_back(OutMessage::Request(msg));
        self.maybe_wake();
    }
    pub fn error(
        &mut self,
        request: RequestMsgData,
        error: usize,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<Peer>>,
        peer: &Peer,
    ) -> crate::Result<()> {
        let id = (!self.ephemeral).then(|| self.id().0);
        let token = Some(self.token(peer, 1)?);

        self.enqueue_reply(
            ReplyMsgData {
                tid: request.tid,
                to: peer.clone(),
                id,
                token,
                closer_nodes: closer_nodes.unwrap_or_default(),
                error,
                value,
            },
            None,
        );
        Ok(())
    }

    pub fn reply(&mut self, mut msg: ReplyMsgData) {
        if msg.token.is_none() {
            msg.token = self.token(&msg.to, 1).ok();
        }
        self.enqueue_reply(msg, None)
    }

    pub fn request2(
        &mut self,
        OutRequestBuilder {
            query_id,
            tid,
            peer,
            command,
            token,
            target,
            value,
            id,
        }: OutRequestBuilder,
    ) -> crate::Result<Receiver<()>> {
        let (tx, rx) = oneshot::channel();
        let id = id.or_else(|| (!self.ephemeral).then(|| self.id().0));
        let tid = tid.unwrap_or_else(|| self.new_tid());
        self.enqueue_request((
            query_id,
            RequestMsgData {
                tid,
                command,
                id,
                token,
                target: target.map(|t| t.into()),
                value,
                to: peer,
            },
            Some(tx),
        ));
        Ok(rx)
    }

    pub fn response(
        &mut self,
        request: RequestMsgData,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<Peer>>,
        peer: Peer,
    ) -> crate::Result<Receiver<()>> {
        let id = (!self.ephemeral).then(|| self.id().0);
        let token = Some(self.token(&peer, 1)?);
        let (tx, rx) = oneshot::channel();
        self.enqueue_reply(
            ReplyMsgData {
                tid: request.tid,
                to: peer.clone(),
                id,
                token,
                closer_nodes: closer_nodes.unwrap_or_default(),
                error: 0,
                value,
            },
            Some(tx),
        );
        Ok(rx)
    }

    fn on_response(&mut self, recv: ReplyMsgData, peer: Peer) -> IoHandlerEvent {
        if let Some(req) = self.pending_recv.remove(&recv.tid) {
            return IoHandlerEvent::InResponse(Arc::new(InResponse::new(
                Box::new(req.message),
                recv,
                peer,
                req.query_id,
            )));
        }
        IoHandlerEvent::InResponseBadRequestId {
            peer,
            message: recv,
        }
    }
    /// A new `Message` was read from the socket.
    fn on_message(&mut self, msg: MsgData, rinfo: SocketAddr) -> IoHandlerEvent {
        let peer = Peer::from(&rinfo);
        match msg {
            MsgData::Request(req) => {
                trace!(name=self.name(), tid = req.tid, command =% req.command, "RX:Request");
                IoHandlerEvent::InRequest { message: req, peer }
            }
            MsgData::Reply(rep) => {
                trace!(name = self.name(), tid = rep.tid, "RX:Reply");
                self.on_response(rep, peer)
            }
        }
    }

    fn poll_send(&mut self, cx: &mut Context<'_>) -> Option<IoHandlerEvent> {
        let msg = match self.pending_flush.take() {
            Some(m) => m,
            None => match self.pending_send.pop_front() {
                Some(m) => m,
                None => {
                    return match Sink::poll_flush(Pin::new(&mut self.message_stream), cx) {
                        Poll::Ready(_e) => None,
                        Poll::Pending => {
                            cx.waker().wake_by_ref();
                            None
                        }
                    };
                }
            },
        };
        if !Sink::poll_ready(Pin::new(&mut self.message_stream), cx).is_ready() {
            self.pending_flush = Some(msg);
            return None;
        }
        let out = match &msg {
            OutMessage::Request((query_id, message, _tx)) => {
                let tid = message.tid;
                self.pending_recv.insert(
                    message.tid,
                    InflightRequest {
                        message: message.clone(),
                        timestamp: Instant::now(),
                        query_id: *query_id,
                    },
                );
                IoHandlerEvent::OutRequest { tid }
            }
            OutMessage::Reply((_tx, message)) => {
                let peer = message.to.clone();
                IoHandlerEvent::OutResponse {
                    message: message.clone(),
                    peer,
                }
            }
        };

        let (msg, socket, tx) = msg.to_sendable();
        match &msg {
            MsgData::Request(m) => {
                trace!(name=self.name(), tid = m.tid, cmd =% m.command, "TX:Request")
            }
            MsgData::Reply(m) => trace!(name = self.name(), tid = m.tid, "TX:Reply"),
        }
        if let Err(e) = Sink::start_send(Pin::new(&mut self.message_stream), (msg, socket)) {
            error!(error =? e, "start_send error");
            todo!()
        }
        _ = Sink::poll_flush(Pin::new(&mut self.message_stream), cx);
        if let Some(tx) = tx {
            _ = tx.send(());
        }

        if !self.pending_send.is_empty() {
            cx.waker().wake_by_ref();
        }
        Some(out)
    }

    fn maybe_wake(&mut self) {
        if let Some(w) = self.stream_waker.take() {
            w.wake()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IoConfig {
    pub rotation: Option<Duration>,
    pub secrets: Option<([u8; 32], [u8; 32])>,
}

impl Stream for IoHandler {
    type Item = IoHandlerEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        _ = pin.stream_waker.insert(cx.waker().clone());

        if let Some(out) = pin.poll_send(cx) {
            return Poll::Ready(Some(out));
        }

        // read from socket
        match Stream::poll_next(Pin::new(&mut pin.message_stream), cx) {
            Poll::Ready(Some(Ok((msg, rinfo)))) => {
                let out = pin.on_message(msg, rinfo);
                cx.waker().wake_by_ref();
                return Poll::Ready(Some(out));
            }
            Poll::Ready(Some(Err(err))) => {
                let out = IoHandlerEvent::InSocketErr { err };
                error!("{out:#?}");
                return Poll::Ready(Some(out));
            }
            _ => {}
        }

        //if pin.last_rotation + pin.rotation > Instant::now() {
        //    pin.rotate_secrets();
        //}

        Poll::Pending
    }
}

/// Event generated by the IO handler
#[derive(Debug)]
pub enum IoHandlerEvent {
    ///  A response was sent
    OutResponse { message: ReplyMsgData, peer: Peer },
    /// A request was sent
    OutRequest { tid: Tid },
    /// A Response to a Query Message was recieved
    InResponse(Arc<InResponse>),
    /// A Request was receieved
    InRequest { message: RequestMsgData, peer: Peer },
    /// Error while sending a message
    OutSocketErr { err: crate::Error },
    /// A request did not recieve a response within the given timeout
    RequestTimeout {
        message: MsgData,
        peer: Peer,
        sent: Instant,
        query_id: QueryId,
    },
    /// Error while decoding a message from socket
    /// TODO unused
    InMessageErr { err: io::Error, peer: Peer },
    /// Error while reading from socket
    InSocketErr { err: crate::Error },
    /// Received a response with a request id that was doesn't match any pending
    /// responses.
    InResponseBadRequestId { message: ReplyMsgData, peer: Peer },
    /// A Response to message handled by a request future
    ChanneledResponse(Tid),
}

impl IoHandlerEvent {
    fn kind(&self) -> String {
        use IoHandlerEvent as Ihe;
        match self {
            Ihe::OutResponse { .. } => "OutResponse",
            Ihe::OutRequest { .. } => "OutRequest",
            Ihe::InResponse(_) => "InResponse",
            Ihe::InRequest { .. } => "InRequest",
            Ihe::OutSocketErr { .. } => "OutSocketErr",
            Ihe::RequestTimeout { .. } => "RequestTimeout",
            Ihe::InMessageErr { .. } => "InMessageErr",
            Ihe::InSocketErr { .. } => "InSocketErr",
            Ihe::InResponseBadRequestId { .. } => "InResponseBadRequestId",
            Ihe::ChanneledResponse(_) => "ChanneledResponse",
        }
        .to_string()
    }
}

impl std::fmt::Display for IoHandlerEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IoHandlerEvent as Ihe;
        match self {
            Ihe::InResponse(x) => write!(
                f,
                "InRespInResponse(tid={}, cmd={})",
                x.request.tid, x.request.command
            ),
            _ => write!(f, "{}()", self.kind()),
        }
    }
}

/// return a Random String, 5 letters long containing only the letters a-zA-Z.
pub fn random_name() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    (0..5)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod test {
    use crate::{InternalCommand, stateobserver::State, thirty_two_random_bytes};
    use futures::StreamExt;

    use super::*;

    fn new_io() -> IoHandler {
        let view = State::new(IdBytes::from(thirty_two_random_bytes())).view();
        let message_stream = MessageDataStream::defualt_bind().unwrap();
        IoHandler::new(view, message_stream, Default::default())
    }
    #[tokio::test]
    async fn test_iohandler_to_iohandler_messaging() -> crate::Result<()> {
        let mut a = new_io();
        let mut b = new_io();

        let to = Peer::from(&b.local_addr()?);
        let id = Some(thirty_two_random_bytes());
        let msg = RequestMsgData {
            tid: 42,
            to,
            id,
            token: None,
            command: InternalCommand::Ping.into(),
            target: None,
            value: None,
        };
        let query_id = Some(QueryId(42));
        a.enqueue_request((query_id, msg.clone(), None));
        a.next().await;
        let IoHandlerEvent::InRequest { message: res, .. } = b.next().await.unwrap() else {
            panic!()
        };
        assert_eq!(res, msg);
        Ok(())
    }
}
