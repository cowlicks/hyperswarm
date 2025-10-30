use std::{
    mem::replace,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use async_compat::Compat;
use async_udx::{HalfOpenStreamHandle, UdxStream};
use futures::{Sink, Stream};
use hypercore_protocol::{
    sstream::sm2::{Event, Machine, MachineIo},
    Uint24LELengthPrefixedFraming,
};

use crate::{cenc::NoisePayload, Error};

#[derive(Debug)]
pub struct ReadyData {
    noise_payload: NoisePayload,
}

impl ReadyData {
    pub fn new(noise_payload: NoisePayload) -> Self {
        Self { noise_payload }
    }
}

#[derive(Debug)]
pub enum ConnStep {
    /// Initial State
    Start(HalfOpenStreamHandle),
    /// Handshake Ready
    Ready(ReadyData),
    // Handshake failed
    Failed,
}

#[derive(Debug)]
pub struct ConnectionInner {
    pub handshake: Machine,
    pub udx_local_id: u32,
    pub step: ConnStep,
}

impl ConnectionInner {
    pub fn new(handshake: Machine, udx_local_id: u32, half_stream: HalfOpenStreamHandle) -> Self {
        Self {
            handshake,
            udx_local_id,
            step: ConnStep::Start(half_stream),
        }
    }
    pub fn receive_next(&mut self, noise: Vec<u8>) -> Result<Event, Error> {
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
    pub fn handshake_set_io(&mut self, io: Box<dyn MachineIo<Error = std::io::Error>>) {
        self.handshake.set_io(io)
    }
    pub fn set_step(&mut self, step: ConnStep) {
        self.step = step;
    }

    fn connect(
        &mut self,
        addr: SocketAddr,
        remote_id: u32,
        noise_payload: NoisePayload,
    ) -> Result<(), Error> {
        let ConnStep::Start(half_stream) = replace(&mut self.step, ConnStep::Failed) else {
            todo!()
        };
        let stream = half_stream.connect(addr, remote_id)?;

        let framed_udx_stream = Uint24LELengthPrefixedFraming::new(Compat::new(stream.clone()));
        self.handshake_set_io(Box::new(framed_udx_stream));
        self.step = ConnStep::Ready(ReadyData { noise_payload });
        Ok(())
    }
}

impl Stream for ConnectionInner {
    type Item = Event;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
#[derive(Debug)]
pub struct Connection {
    pub inner: Arc<RwLock<ConnectionInner>>,
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
    pub fn new(handshake: Machine, udx_local_id: u32, half_stream: HalfOpenStreamHandle) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionInner {
                handshake,
                udx_local_id,
                step: ConnStep::Start(half_stream),
            })),
        }
    }
    pub fn receive_next(&self, noise: Vec<u8>) -> Result<Event, Error> {
        w!(self).handshake.receive_next(noise);
        Ok(w!(self)
            .handshake
            .next_decrypted_message()?
            .expect("recieved msg above"))
    }
    pub fn step_ready(&self) -> bool {
        matches!(r!(self).step, ConnStep::Ready(_))
    }
    pub fn handshake_ready(&self) -> bool {
        r!(self).handshake.ready()
    }
    pub fn udx_local_id(&self) -> u32 {
        r!(self).udx_local_id
    }
    pub fn handshake_set_io(&self, io: Box<dyn MachineIo<Error = std::io::Error>>) {
        w!(self).handshake.set_io(io)
    }
    pub fn set_step(&self, step: ConnStep) {
        w!(self).step = step;
    }
    pub fn connect(&self, addr: SocketAddr, remote_id: u32, np: NoisePayload) -> Result<(), Error> {
        w!(self).connect(addr, remote_id, np)
    }
}

impl Stream for Connection {
    type Item = Event;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_next(cx)
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
