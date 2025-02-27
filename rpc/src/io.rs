use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use crate::{
    cenc::validate_id,
    futreqs::{new_request_channel, RequestFuture, RequestSender},
    IdBytes, RequestMsgDataInner, Result,
};
use fnv::FnvHashMap;
use futures::{
    channel::mpsc,
    task::{Context, Poll},
    Sink, Stream,
};
use rand::Rng;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tracing::{error, trace};
use wasm_timer::Instant;

use super::{
    cenc::{generic_hash, generic_hash_with_key, ipv4},
    message::{MsgData, ReplyMsgData, RequestMsgData},
    query::QueryId,
    stateobserver::Observer,
    stream::MessageDataStream,
    thirty_two_random_bytes, Command, Peer, QueryAndTid,
};

pub const VERSION: u64 = 1;

const ROTATE_INTERVAL: u64 = 300_000;

const IO_TX_RX_CHANNEL_DEFAULT_SIZE: usize = 1024;

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

/// OutMessage contains outgoing messages data, including local metadata for managing messages
#[derive(Debug, Clone)]
pub enum OutMessage {
    Request((Option<QueryId>, RequestMsgData)),
    Reply(ReplyMsgData),
}

impl OutMessage {
    fn to(&self) -> Peer {
        match self {
            OutMessage::Request((_, x)) => x.to.clone(),
            OutMessage::Reply(x) => x.to.clone(),
        }
    }
    fn inner(self) -> MsgData {
        match self {
            OutMessage::Request((_, x)) => MsgData::Request(x),
            OutMessage::Reply(x) => MsgData::Reply(x),
        }
    }
}

#[derive(Debug)]
struct InflightRequest {
    /// The message send
    message: RequestMsgData,
    /// Timestamp when the request was sent
    #[allow(unused)] // TODO FIXME not read. Why not?
    timestamp: Instant,
    // Identifier for the query this request is used with
    query_id: Option<QueryId>,
}

#[derive(Debug)]
struct InflightRequestFuture {
    /// The message send
    message: RequestMsgData,
    sender: RequestSender<Arc<InResponse>>,
    // Identifier for the query this request is used with
    query_id: Option<QueryId>,
}

type MessageChannelItem = (
    RequestSender<Arc<InResponse>>,
    (Option<QueryId>, RequestMsgDataInner),
);

/// A channel that can be used to send messages.
pub struct MessageSender {
    tx: mpsc::Sender<MessageChannelItem>,
}

impl MessageSender {
    fn new(tx: mpsc::Sender<MessageChannelItem>) -> Self {
        Self { tx }
    }
    /// Sends a message to IoHandler. Get a future back witch will resolve with the result
    pub fn send(
        &mut self,
        msg: (Option<QueryId>, RequestMsgDataInner),
    ) -> Result<RequestFuture<Arc<InResponse>>> {
        let (result_tx, result_rx) = new_request_channel();
        self.tx
            .try_send((result_tx, msg))
            .map(|_| result_rx)
            .map_err(|e| {
                error!("Got an eror sending into MessageSender channel: {e:?}");
                crate::Error::RequestChannelSendError()
            })
    }
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
    // inflight futures
    inflight: BTreeMap<Tid, InflightRequestFuture>,
    secrets: Secrets,
    tid: AtomicU16,
    /// sender / reciever handles to recieve messages to send through
    txrx: (
        mpsc::Sender<MessageChannelItem>,
        mpsc::Receiver<MessageChannelItem>,
    ),
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
            inflight: Default::default(),
            secrets: Default::default(),
            tid: AtomicU16::new(rand::thread_rng().gen()),
            txrx: mpsc::channel(IO_TX_RX_CHANNEL_DEFAULT_SIZE),
        }
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
    /// TODO check this is correct.
    pub fn token(&self, peer: &Peer, secret_index: usize) -> crate::Result<[u8; 32]> {
        self.secrets.token(peer, secret_index)
    }

    pub fn new_tid(&self) -> Tid {
        self.tid.fetch_add(1, Ordering::Relaxed)
    }

    pub fn enqueue_request(&mut self, msg: (Option<QueryId>, RequestMsgData)) {
        self.pending_send.push_back(OutMessage::Request(msg));
    }
    pub fn enqueue_reply(&mut self, msg: ReplyMsgData) {
        self.pending_send.push_back(OutMessage::Reply(msg));
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
        let id = if !self.ephemeral {
            Some(self.id().0)
        } else {
            None
        };

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
        ));
        (query_id, tid)
    }
    pub fn error(
        &mut self,
        request: RequestMsgData,
        error: usize,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<Peer>>,
        peer: &Peer,
    ) -> crate::Result<()> {
        let id = if !self.ephemeral {
            Some(self.id().0)
        } else {
            None
        };

        let token = Some(self.token(peer, 1)?);

        self.enqueue_reply(ReplyMsgData {
            tid: request.tid,
            to: peer.clone(),
            id,
            token,
            closer_nodes: closer_nodes.unwrap_or_default(),
            error,
            value,
        });
        Ok(())
    }

    pub fn reply(&mut self, mut msg: ReplyMsgData) {
        if msg.token.is_none() {
            msg.token = self.token(&msg.to, 1).ok();
        }
        self.enqueue_reply(msg)
    }

    pub fn response(
        &mut self,
        request: RequestMsgData,
        value: Option<Vec<u8>>,
        closer_nodes: Option<Vec<Peer>>,
        peer: Peer,
    ) -> crate::Result<()> {
        let id = if !self.ephemeral {
            Some(self.id().0)
        } else {
            None
        };
        let token = Some(self.token(&peer, 1)?);
        self.enqueue_reply(ReplyMsgData {
            tid: request.tid,
            to: peer.clone(),
            id,
            token,
            closer_nodes: closer_nodes.unwrap_or_default(),
            error: 0,
            value,
        });
        Ok(())
    }

    pub fn create_sender(&mut self) -> MessageSender {
        let tx = self.txrx.0.clone();
        MessageSender::new(tx)
    }

    fn on_response(&mut self, recv: ReplyMsgData, peer: Peer) -> IoHandlerEvent {
        if let Some(InflightRequestFuture {
            message: request,
            sender,
            query_id,
        }) = self.inflight.remove(&recv.tid)
        {
            let tid = request.tid;
            let msg = Arc::new(InResponse::new(Box::new(request), recv, peer, query_id));
            let _ = sender.send(msg);
            return IoHandlerEvent::ChanneledResponse(tid);
        }
        if let Some(req) = self.pending_recv.remove(&recv.tid) {
            trace!(
                msg.tid = recv.tid,
                cmd = tracing::field::display(&req.message.command),
                "RX:Response"
            );
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
            MsgData::Request(req) => IoHandlerEvent::InRequest { message: req, peer },
            MsgData::Reply(rep) => self.on_response(rep, peer),
        }
    }

    pub fn start_send_next_fut_no_id(
        &mut self,
        query_id: Option<QueryId>,
        data: RequestMsgDataInner,
    ) -> crate::Result<RequestFuture<Arc<InResponse>>> {
        let tid = self.new_tid();
        let id = self.id().0;
        let msg = RequestMsgData::from_ids_and_inner_data(tid, Some(id), data);
        self.start_send_next_fut((query_id, msg))
    }

    pub fn start_send_next_fut_no_id_with_tx(
        &mut self,
        (sender, (query_id, data)): MessageChannelItem,
    ) -> crate::Result<()> {
        let tid = self.new_tid();
        let id = self.id().0;
        let full_req = RequestMsgData::from_ids_and_inner_data(tid, Some(id), data);
        self.inner_send(OutMessage::Request((query_id, full_req.clone())))?;
        let inflight_req = InflightRequestFuture {
            message: full_req,
            sender,
            query_id,
        };
        self.inflight.insert(tid, inflight_req);
        Ok(())
    }

    pub fn start_send_next_fut(
        &mut self,
        msg: (Option<QueryId>, RequestMsgData),
    ) -> crate::Result<RequestFuture<Arc<InResponse>>> {
        let tid = msg.1.tid;
        self.inner_send(OutMessage::Request(msg.clone()))?;
        let (sender, reciever) = new_request_channel();
        let inflight_req = InflightRequestFuture {
            message: msg.1,
            sender,
            query_id: msg.0,
        };
        self.inflight.insert(tid, inflight_req);
        Ok(reciever)
    }

    fn start_send_next(&mut self) -> crate::Result<()> {
        if self.pending_flush.is_none() {
            if let Some(msg) = self.pending_send.pop_front() {
                self.inner_send(msg.clone())?;
                self.pending_flush = Some(msg);
            }
        }
        Ok(())
    }

    fn inner_send(&mut self, msg: OutMessage) -> crate::Result<()> {
        let addr = SocketAddr::from(&msg.to());
        Sink::start_send(Pin::new(&mut self.message_stream), (msg.inner(), addr))
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

        while let Poll::Ready(Some((tx, msg))) = Stream::poll_next(Pin::new(&mut pin.txrx.1), cx) {
            if let Err(e) = pin.start_send_next_fut_no_id_with_tx((tx, msg)) {
                error!("Error sending message = {e:?}");
            }
        }
        // queue in the next message if not currently flushing
        // moves msg pending_flush = pending_send[0]
        // and sends it
        if let Err(err) = pin.start_send_next() {
            let out = IoHandlerEvent::OutSocketErr { err };
            trace!("{out:#?}");
            return Poll::Ready(Some(out));
        }

        // flush the message
        if let Some(ev) = pin.pending_flush.take() {
            if Sink::poll_ready(Pin::new(&mut pin.message_stream), cx).is_ready() {
                return match ev {
                    OutMessage::Request((query_id, message)) => {
                        let tid = message.tid;
                        pin.pending_recv.insert(
                            message.tid,
                            InflightRequest {
                                message,
                                timestamp: Instant::now(),
                                query_id,
                            },
                        );
                        let out = IoHandlerEvent::OutRequest { tid };
                        return Poll::Ready(Some(out));
                    }
                    OutMessage::Reply(message) => {
                        let peer = message.to.clone();
                        let out = IoHandlerEvent::OutResponse { message, peer };
                        trace!("{out:#?}");
                        return Poll::Ready(Some(out));
                    }
                };
            } else {
                pin.pending_flush = Some(ev);
            }
        }

        // read from socket
        match Stream::poll_next(Pin::new(&mut pin.message_stream), cx) {
            Poll::Ready(Some(Ok((msg, rinfo)))) => {
                let out = pin.on_message(msg, rinfo);
                return Poll::Ready(Some(out));
            }
            Poll::Ready(Some(Err(err))) => {
                let out = IoHandlerEvent::InSocketErr { err };
                trace!("{out:#?}");
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

#[cfg(test)]
mod test {
    use crate::{stateobserver::State, thirty_two_random_bytes, InternalCommand};
    use futures::StreamExt;

    use super::*;

    fn new_io() -> IoHandler {
        let view = State::new(IdBytes::from(thirty_two_random_bytes())).view();
        let message_stream = MessageDataStream::defualt_bind().unwrap();
        IoHandler::new(view, message_stream, Default::default())
    }
    #[tokio::test]
    async fn foo() -> crate::Result<()> {
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
        a.enqueue_request((query_id, msg.clone()));
        a.next().await;
        let IoHandlerEvent::InRequest { message: res, .. } = b.next().await.unwrap() else {
            panic!()
        };
        assert_eq!(res, msg);
        Ok(())
    }
}
