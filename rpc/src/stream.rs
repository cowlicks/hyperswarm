use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use async_udx::UdxSocket;
use futures::{Future, Sink, Stream};
use tracing::trace;

use crate::Result;

use super::message::MsgData;

// Wrapper struct around UdxSocket that handles Messages
#[derive(Debug)]
pub struct MessageDataStream {
    socket: UdxSocket,
    // Buffer for incoming messages that couldn't be processed immediately
    recv_queue: VecDeque<(MsgData, SocketAddr)>,
}

impl MessageDataStream {
    pub fn new(socket: UdxSocket) -> Self {
        Self {
            socket,
            recv_queue: VecDeque::new(),
        }
    }
    pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self> {
        Ok(MessageDataStream {
            socket: UdxSocket::bind(addr)?,
            recv_queue: Default::default(),
        })
    }
    pub fn defualt_bind() -> Result<Self> {
        Ok(MessageDataStream {
            socket: UdxSocket::bind("0.0.0.0:0")?,
            recv_queue: Default::default(),
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

impl Stream for MessageDataStream {
    type Item = Result<(MsgData, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First check if we have any buffered messages
        if let Some((msg, addr)) = self.recv_queue.pop_front() {
            trace!(
                "RX addr:
 addr:\t {addr}
 msg: \t {msg:#?}"
            );
            return Poll::Ready(Some(Ok((msg, addr))));
        }

        // Try to receive data from the socket
        let mut fut = self.socket.recv();
        match Pin::new(&mut fut).poll(cx) {
            Poll::Ready(Ok((addr, buff))) => {
                // Try to decode the received message
                match MsgData::decode(&buff) {
                    Ok(msg) => {
                        trace!(
                            "RX addr:
 addr:\t {addr}
 msg: \t {msg:#?}"
                        );
                        Poll::Ready(Some(Ok((msg, addr))))
                    }
                    Err(e) => Poll::Ready(Some(Err(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Pending => Poll::Pending,
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
            "TX addr:
 addr:\t {addr}
 msg: \t {message:#?}"
        );
        let buff = MsgData::encode(&message)?;
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
        let _ = one.send((expected.clone(), two.local_addr()?)).await?;
        let (result, _sender) = two.next().await.unwrap()?;
        assert_eq!(result, expected);

        Ok(())
    }
}
