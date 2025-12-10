use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use compact_encoding::CompactEncoding;
use futures::{Future, Sink, Stream};
use tracing::trace;
use udx::{RecvFuture, UdxSocket};

use crate::Result;

use super::message::MsgData;

// Wrapper struct around UdxSocket that handles Messages
pub struct MessageDataStream {
    socket: UdxSocket,
    // Buffer for incoming messages that couldn't be processed immediately
    recv_queue: VecDeque<(MsgData, SocketAddr)>,
    next_message: Option<RecvFuture>,
}

impl MessageDataStream {
    pub fn new(socket: UdxSocket) -> Self {
        Self {
            socket,
            recv_queue: Default::default(),
            next_message: Default::default(),
        }
    }
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self> {
        let socket = UdxSocket::bind(addr)?;
        Ok(MessageDataStream::new(socket))
    }
    pub fn defualt_bind() -> Result<Self> {
        Ok(MessageDataStream::new(UdxSocket::bind("127.0.0.1:0")?))
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn socket(&self) -> UdxSocket {
        self.socket.clone()
    }
}

impl Stream for MessageDataStream {
    type Item = Result<(MsgData, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First check if we have any buffered messages
        if let Some(out) = self.recv_queue.pop_front() {
            // always wake. We want to always be holding a future in self.next_message
            cx.waker().wake_by_ref();
            return Poll::Ready(Some(Ok(out)));
        }

        let mut fut = self
            .next_message
            .take()
            .unwrap_or_else(|| self.socket.recv());
        // Try to receive data from the socket
        match Pin::new(&mut fut).poll(cx) {
            Poll::Ready(Ok((addr, buff))) => {
                // Try to decode the received message
                match MsgData::decode(&buff) {
                    Ok((msg, _rest)) => {
                        trace!(
                            msg.tid = msg.tid(),
                            to =?addr,
                            "RX"
                        );
                        debug_assert!(_rest.is_empty());

                        self.recv_queue.push_back((msg, addr));
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Some(Err(e.into()))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Pending => {
                _ = self.next_message.insert(fut);
                Poll::Pending
            }
        }
    }
}

impl Sink<(MsgData, SocketAddr)> for MessageDataStream {
    type Error = crate::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: (MsgData, SocketAddr)) -> Result<()> {
        let (message, addr) = item;
        trace!(
            msg.tid = message.tid(),
            to =?addr,
            "TX"
        );
        let buff = message.to_encoded_bytes()?;
        self.socket.send(addr, &buff);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        // No buffering in UdxSocket, so no need to flush
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        // No special cleanup needed
        Poll::Ready(Ok(()))
    }
}

impl std::fmt::Debug for MessageDataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageDataStream")
            .field("socket", &self.socket)
            .field("next_message", &self.next_message.is_some())
            .finish()
    }
}
#[cfg(test)]
mod test {
    use crate::{message::ReplyMsgData, Peer};
    use futures::{SinkExt, StreamExt};

    use super::*;
    #[tokio::test]
    async fn bar() -> Result<()> {
        let mut one = MessageDataStream::defualt_bind()?;
        let mut two = MessageDataStream::defualt_bind()?;
        let expected = MsgData::Reply(ReplyMsgData {
            tid: 0,
            to: Peer {
                id: None,
                addr: "0.0.0.0:666".parse()?,
                referrer: None,
            },
            id: None,
            token: None,
            closer_nodes: vec![],
            error: 0,
            value: None,
        });
        one.send((expected.clone(), two.local_addr()?)).await?;
        let (result, _sender) = two.next().await.unwrap()?;
        assert_eq!(result, expected);

        Ok(())
    }
}
