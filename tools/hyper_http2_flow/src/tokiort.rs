//! Minimal Tokio executor and I/O adapters used by the Hyper reference harness.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use hyper::rt::{Sleep, Timer};
use pin_project_lite::pin_project;

#[derive(Clone)]
/// An Executor that uses the tokio runtime.
pub struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

/// Tokio-backed timer required by Hyper's HTTP/2 keep-alive machinery.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct TokioTimer;

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep_until(deadline.into()),
        })
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into()
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, deadline: Instant) {
        if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<TokioSleep>() {
            sleep.reset(deadline);
        }
    }
}

pin_project! {
    struct TokioSleep {
        #[pin]
        inner: tokio::time::Sleep,
    }
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.project().inner.poll(cx)
    }
}

impl Sleep for TokioSleep {}

impl TokioSleep {
    #[allow(dead_code)]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.as_mut().reset(deadline.into());
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum MaybeTls {
    Clear(tokio::net::TcpStream),
    Client(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Server(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl tokio::io::AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Client(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Server(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::Client(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::Server(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_flush(cx),
            Self::Client(stream) => Pin::new(stream).poll_flush(cx),
            Self::Server(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Client(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Server(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pin_project! {
    #[derive(Debug)]
    pub struct TokioIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> TokioIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> hyper::rt::Read for TokioIo<T>
where
    T: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(self.project().inner, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> hyper::rt::Write for TokioIo<T>
where
    T: tokio::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

// Hyper exposes an upgraded HTTP/2 CONNECT stream through its own runtime I/O
// traits. Adapt that stream back to Tokio so independent interop fixtures can
// exercise the tunnel with AsyncReadExt/AsyncWriteExt.
impl<T> tokio::io::AsyncRead for TokioIo<T>
where
    T: hyper::rt::Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let already_filled = buffer.filled().len();
        let newly_filled = unsafe {
            let mut hyper_buffer = hyper::rt::ReadBuf::uninit(buffer.unfilled_mut());
            match hyper::rt::Read::poll_read(self.project().inner, cx, hyper_buffer.unfilled()) {
                Poll::Ready(Ok(())) => hyper_buffer.filled().len(),
                other => return other,
            }
        };
        unsafe {
            buffer.assume_init(newly_filled);
            buffer.set_filled(already_filled + newly_filled);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> tokio::io::AsyncWrite for TokioIo<T>
where
    T: hyper::rt::Write,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        hyper::rt::Write::poll_write(self.project().inner, cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        hyper::rt::Write::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        hyper::rt::Write::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        hyper::rt::Write::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        hyper::rt::Write::poll_write_vectored(self.project().inner, cx, buffers)
    }
}
