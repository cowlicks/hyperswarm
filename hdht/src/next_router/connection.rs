use std::{
    mem::replace,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use async_compat::Compat;
use dht_rpc::Rpc;
use futures::{Sink, Stream};
use hypercore_handshake::{Cipher, CipherEvent, CipherIo};
use udx::HalfOpenStreamHandle;
use uint24le_framing::Uint24LELengthPrefixedFraming;

use crate::Error;

#[derive(Debug)]
pub enum ConnStep {
    /// Initial State
    Start(HalfOpenStreamHandle),
    /// Handshake Ready
    Ready,
    // Handshake failed
    Failed,
}

pub struct ConnectionInner {
    pub handshake: Cipher,
    pub udx_local_id: u32,
    pub step: ConnStep,
    /// Optional RPC to poll for flushing responses (used by server-side connections)
    pub rpc: Option<Rpc>,
}

impl std::fmt::Debug for ConnectionInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionInner")
            .field("handshake", &self.handshake)
            .field("udx_local_id", &self.udx_local_id)
            .field("step", &self.step)
            //.field("rpc", &self.rpc)
            .finish()
    }
}

impl ConnectionInner {
    pub fn new(handshake: Cipher, udx_local_id: u32, half_stream: HalfOpenStreamHandle) -> Self {
        Self {
            handshake,
            udx_local_id,
            step: ConnStep::Start(half_stream),
            rpc: None,
        }
    }

    pub fn new_with_rpc(
        handshake: Cipher,
        udx_local_id: u32,
        half_stream: HalfOpenStreamHandle,
        rpc: Rpc,
    ) -> Self {
        Self {
            handshake,
            udx_local_id,
            step: ConnStep::Start(half_stream),
            rpc: Some(rpc),
        }
    }
    pub fn receive_next(&mut self, noise: Vec<u8>) -> Result<CipherEvent, Error> {
        self.handshake.receive_next(noise);
        Ok(self
            .handshake
            .next_decrypted_message()?
            .expect("recieved msg above"))
    }
    pub fn handshake_ready(&self) -> bool {
        self.handshake.ready()
    }
    pub fn udx_local_id(&self) -> u32 {
        self.udx_local_id
    }
    pub fn handshake_set_io(&mut self, io: Box<dyn CipherIo<Error = std::io::Error>>) {
        self.handshake.set_io(io)
    }
    pub fn set_step(&mut self, step: ConnStep) {
        self.step = step;
    }

    fn connect(&mut self, addr: SocketAddr, remote_id: u32) -> Result<(), Error> {
        let ConnStep::Start(half_stream) = replace(&mut self.step, ConnStep::Failed) else {
            todo!()
        };
        let stream = half_stream.connect(addr, remote_id)?;

        let framed_udx_stream = Uint24LELengthPrefixedFraming::new(Compat::new(stream.clone()));
        self.handshake_set_io(Box::new(framed_udx_stream));
        self.step = ConnStep::Ready;
        Ok(())
    }
}

impl Stream for ConnectionInner {
    type Item = CipherEvent;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(ref mut rpc) = self.rpc {
            while Pin::new(&mut *rpc).poll_next(cx).is_ready() {
                // Keep polling to flush responses
            }
        }
        Pin::new(&mut self.handshake).poll_next(cx)
    }
}
impl Sink<Vec<u8>> for ConnectionInner {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.handshake).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.handshake).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.handshake).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.handshake).poll_close(cx)
    }
}
#[derive(Clone)]
pub struct Connection {
    pub inner: Arc<RwLock<ConnectionInner>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.try_read() {
            Ok(x) => f.debug_struct("Connection").field("inner", &x).finish(),
            Err(_) => f.debug_struct("Connection").field("inner", &()).finish(),
        }
    }
}

macro_rules! w {
    ($self:expr) => {
        $self.inner.write().unwrap()
    };
}
macro_rules! r {
    ($self:expr) => {
        $self.inner.read().unwrap()
    };
}

impl Connection {
    pub fn new(handshake: Cipher, udx_local_id: u32, half_stream: HalfOpenStreamHandle) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionInner {
                handshake,
                udx_local_id,
                step: ConnStep::Start(half_stream),
                rpc: None,
            })),
        }
    }

    pub fn new_with_rpc(
        handshake: Cipher,
        udx_local_id: u32,
        half_stream: HalfOpenStreamHandle,
        rpc: Rpc,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionInner {
                handshake,
                udx_local_id,
                step: ConnStep::Start(half_stream),
                rpc: Some(rpc),
            })),
        }
    }
    pub fn receive_next(&self, noise: Vec<u8>) -> Result<CipherEvent, Error> {
        w!(self).handshake.receive_next(noise);
        Ok(w!(self)
            .handshake
            .next_decrypted_message()?
            .expect("recieved msg above"))
    }
    pub fn step_ready(&self) -> bool {
        matches!(r!(self).step, ConnStep::Ready)
    }
    pub fn handshake_ready(&self) -> bool {
        r!(self).handshake.ready()
    }
    pub fn udx_local_id(&self) -> u32 {
        r!(self).udx_local_id
    }
    pub fn handshake_set_io(&self, io: Box<dyn CipherIo<Error = std::io::Error>>) {
        w!(self).handshake.set_io(io)
    }
    pub fn set_step(&self, step: ConnStep) {
        w!(self).step = step;
    }
    pub fn connect(&self, addr: SocketAddr, remote_id: u32) -> Result<(), Error> {
        w!(self).connect(addr, remote_id)
    }

    /// Get the remote peer's static public key (from Noise handshake).
    ///
    /// For server-side connections (responder), this returns the initiator's public key.
    /// For client-side connections (initiator), returns None (client already knows the server key).
    pub fn get_remote_static(&self) -> Option<[u8; 32]> {
        r!(self).handshake.get_remote_static()
    }

    /// Get the handshake hash.
    ///
    /// This is a unique identifier for this encrypted session, the same on both sides.
    /// Used for capability verification in hypercore replication.
    ///
    /// Returns `None` until the handshake is complete.
    pub fn handshake_hash(&self) -> Option<Vec<u8>> {
        r!(self).handshake.handshake_hash().map(|h| h.to_vec())
    }
}

impl Stream for Connection {
    type Item = CipherEvent;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = self.inner.write().unwrap();
        // Poll the RPC to flush any pending responses
        if let Some(ref mut rpc) = inner.rpc {
            while Pin::new(&mut *rpc).poll_next(cx).is_ready() {
                // Keep polling to flush responses
            }
        }
        Pin::new(&mut inner.handshake).poll_next(cx)
    }
}
impl Sink<Vec<u8>> for Connection {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner.write().unwrap().handshake).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_close(cx)
    }
}
