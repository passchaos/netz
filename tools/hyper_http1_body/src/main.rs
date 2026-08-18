use std::convert::Infallible;
use std::env;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::thread;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_CHUNK_BYTES: usize = 16 * 1024;
const DEFAULT_WARMUP: usize = 20;
const DEFAULT_ITERATIONS: usize = 100;
const RESPONSE_DATE: &str = "Mon, 17 Aug 2026 00:00:00 GMT";

type Body = http_body_util::combinators::BoxBody<Bytes, Infallible>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Fixed,
    Chunked,
}

#[derive(Clone, Copy)]
struct Options {
    mode: Mode,
    body_bytes: usize,
    chunk_bytes: usize,
    warmup: usize,
    iterations: usize,
}

fn main() {
    let options = parse_options();
    assert!(options.body_bytes > 0);
    assert!(options.chunk_bytes > 0);
    assert_eq!(options.body_bytes % options.chunk_bytes, 0);
    assert!(options.iterations > 0);

    let payload = Bytes::from(vec![b'x'; options.body_bytes]);
    let (address_tx, address_rx) = mpsc::channel();
    let server_payload = payload.clone();
    let server = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build server runtime");
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            address_tx.send(listener.local_addr().unwrap()).unwrap();
            let (stream, _) = listener.accept().await.expect("accept");
            stream.set_nodelay(true).expect("server TCP_NODELAY");
            let io = TokioIo::new(stream);
            let service_options = options;
            let service = service_fn(move |request: Request<Incoming>| {
                let response_payload = server_payload.clone();
                async move {
                    let received = consume_body(request.into_body()).await;
                    assert_eq!(received, service_options.body_bytes);
                    let body = make_body(
                        service_options.mode,
                        response_payload,
                        service_options.chunk_bytes,
                    );
                    let response = Response::builder()
                        .status(200)
                        .header("date", RESPONSE_DATE)
                        .body(body)
                        .unwrap();
                    Ok::<_, Infallible>(response)
                }
            });
            server_http1::Builder::new()
                .serve_connection(io, service)
                .await
                .expect("serve connection");
        });
    });

    let address = address_rx.recv().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build client runtime");
    let (mut sender, connection) = runtime.block_on(async {
        let stream = TcpStream::connect(address).await.expect("connect");
        stream.set_nodelay(true).expect("client TCP_NODELAY");
        client_http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .expect("handshake")
    });
    runtime.spawn(async move {
        connection.await.expect("client connection");
    });

    let mut checksum = 0u64;
    for _ in 0..options.warmup {
        checksum = checksum.wrapping_add(runtime.block_on(exchange(
            &mut sender,
            options,
            payload.clone(),
        )));
    }

    let started = Instant::now();
    for _ in 0..options.iterations {
        checksum = checksum.wrapping_add(runtime.block_on(exchange(
            &mut sender,
            options,
            payload.clone(),
        )));
    }
    let elapsed = started.elapsed();
    drop(sender);
    runtime.block_on(async { tokio::task::yield_now().await });
    server.join().unwrap();

    let elapsed_ns = elapsed.as_nanos() as u64;
    let wire_body_bytes = (options.body_bytes as u64) * 2 * (options.iterations as u64);
    let mib_per_second = if elapsed_ns == 0 {
        0
    } else {
        wire_body_bytes * 1_000_000_000 / (elapsed_ns * 1024 * 1024)
    };
    println!("Hyper HTTP/1 streaming body benchmark");
    println!("  mode: {:?}", options.mode);
    println!("  body bytes/direction: {}", options.body_bytes);
    println!("  chunk bytes: {}", options.chunk_bytes);
    println!("  warmup iterations: {}", options.warmup);
    println!("  iterations: {}", options.iterations);
    println!(
        "  ns/round-trip: {}",
        elapsed_ns / options.iterations as u64
    );
    println!("  aggregate body MiB/s: {}", mib_per_second);
    println!("  checksum: {}", checksum);
}

async fn exchange(
    sender: &mut client_http1::SendRequest<Body>,
    options: Options,
    payload: Bytes,
) -> u64 {
    let body = make_body(options.mode, payload, options.chunk_bytes);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/body")
        .header("host", "localhost")
        .body(body)
        .unwrap();
    let response = sender.send_request(request).await.expect("response");
    let received = consume_body(response.into_body()).await;
    assert_eq!(received, options.body_bytes);
    received as u64
}

async fn consume_body(mut body: Incoming) -> usize {
    let mut total = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("body frame");
        if let Ok(data) = frame.into_data() {
            total += data.len();
            std::hint::black_box(data.first());
            std::hint::black_box(data.last());
        }
    }
    total
}

fn make_body(mode: Mode, payload: Bytes, chunk_bytes: usize) -> Body {
    match mode {
        Mode::Fixed => Full::new(payload).boxed(),
        Mode::Chunked => {
            // Yield exactly the same 64 x 16-KiB application boundaries as
            // netz's writeChunks harness. Bytes::slice keeps every frame
            // borrowed from one shared payload allocation.
            let stream = ChunkStream {
                payload,
                chunk_bytes,
                offset: 0,
            };
            StreamBody::new(stream).boxed()
        }
    }
}

struct ChunkStream {
    payload: Bytes,
    chunk_bytes: usize,
    offset: usize,
}

impl futures_core::Stream for ChunkStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.offset == self.payload.len() {
            return Poll::Ready(None);
        }
        let end = (self.offset + self.chunk_bytes).min(self.payload.len());
        let chunk = self.payload.slice(self.offset..end);
        self.offset = end;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }
}

fn parse_options() -> Options {
    let mut options = Options {
        mode: Mode::Fixed,
        body_bytes: DEFAULT_BODY_BYTES,
        chunk_bytes: DEFAULT_CHUNK_BYTES,
        warmup: DEFAULT_WARMUP,
        iterations: DEFAULT_ITERATIONS,
    };
    for argument in env::args().skip(1) {
        if argument == "--mode=fixed" {
            options.mode = Mode::Fixed;
        } else if argument == "--mode=chunked" {
            options.mode = Mode::Chunked;
        } else if let Some(value) = argument.strip_prefix("--body-bytes=") {
            options.body_bytes = value.parse().expect("body bytes");
        } else if let Some(value) = argument.strip_prefix("--chunk-bytes=") {
            options.chunk_bytes = value.parse().expect("chunk bytes");
        } else if let Some(value) = argument.strip_prefix("--warmup=") {
            options.warmup = value.parse().expect("warmup");
        } else if let Some(value) = argument.strip_prefix("--iterations=") {
            options.iterations = value.parse().expect("iterations");
        } else {
            panic!("unsupported argument: {argument}");
        }
    }
    options
}

#[derive(Debug)]
struct TokioIo<T> {
    inner: T,
}

impl<T> TokioIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncRead + Unpin> Read for TokioIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buffer: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let count = unsafe {
            let mut tokio_buffer = tokio::io::ReadBuf::uninit(buffer.as_mut());
            match Pin::new(&mut self.get_mut().inner).poll_read(cx, &mut tokio_buffer) {
                Poll::Ready(Ok(())) => tokio_buffer.filled().len(),
                other => return other,
            }
        };
        unsafe {
            buffer.advance(count);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> Write for TokioIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }
}
