use std::cell::Cell;
use std::convert::Infallible;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Response;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

const PIPELINE_DEPTH: usize = 16;
const DEFAULT_WARMUP: usize = 200;
const DEFAULT_ITERATIONS: usize = 2_000;
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
const RESPONSE_BODY: &[u8] = b"Hello, World!";
const RESPONSE_WIRE_BYTES: usize = 89;

#[derive(Clone, Copy)]
struct Options {
    warmup: usize,
    iterations: usize,
}

fn main() {
    let options = parse_options();
    let request_batch = REQUEST.repeat(PIPELINE_DEPTH);
    let (address_tx, address_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let server_requests = Rc::new(Cell::new(0usize));
        let service_requests = server_requests.clone();
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
            http1::Builder::new()
                .pipeline_flush(true)
                .serve_connection(
                    io,
                    service_fn(move |_| {
                        let requests = service_requests.clone();
                        async move {
                            requests.set(requests.get() + 1);
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from_static(RESPONSE_BODY)))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .expect("serve connection");
        });
        server_requests.get()
    });

    let address = address_rx.recv().unwrap();
    let mut client = TcpStream::connect(address).expect("connect");
    client.set_nodelay(true).expect("client TCP_NODELAY");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let expected_batch_bytes = RESPONSE_WIRE_BYTES * PIPELINE_DEPTH;
    let mut receive_buffer = [0u8; 8192];

    for _ in 0..options.warmup {
        exchange(
            &mut client,
            &request_batch,
            expected_batch_bytes,
            &mut receive_buffer,
        );
    }
    let started = Instant::now();
    let mut received_bytes = 0usize;
    for _ in 0..options.iterations {
        received_bytes += exchange(
            &mut client,
            &request_batch,
            expected_batch_bytes,
            &mut receive_buffer,
        );
    }
    let elapsed_ns = started.elapsed().as_nanos() as u64;
    drop(client);
    let served_requests = server.join().unwrap();

    let requests = options.iterations * PIPELINE_DEPTH;
    let expected_server_requests = (options.warmup + options.iterations) * PIPELINE_DEPTH;
    assert_eq!(served_requests, expected_server_requests);
    assert_eq!(received_bytes, requests * RESPONSE_WIRE_BYTES);
    let ns_per_request = elapsed_ns / requests as u64;
    let requests_per_s = requests as u64 * 1_000_000_000 / elapsed_ns;

    println!("Hyper HTTP/1 pipeline runtime benchmark");
    println!("  io backend: hyper-tokio");
    println!("  pipeline depth: {PIPELINE_DEPTH}");
    println!("  warmup iterations: {}", options.warmup);
    println!("  iterations: {}", options.iterations);
    println!("  requests: {requests}");
    println!("  ns/request: {ns_per_request}");
    println!("  requests/s: {requests_per_s}");
    println!(
        "record=config implementation=hyper protocol=http1 transport=tcp \
         workload=pipeline benchmark_scope=same-application-shape \
         client_io=rust-std-sync server_io=hyper-tokio connection_scope=persistent \
         pipeline_depth={PIPELINE_DEPTH} warmup={} iterations={} \
         request_wire_bytes={} response_wire_bytes={RESPONSE_WIRE_BYTES} \
         pipeline_flush=true write_strategy=hyper-pipeline-flush",
        options.warmup,
        options.iterations,
        REQUEST.len(),
    );
    println!(
        "record=result implementation=hyper protocol=http1 transport=tcp \
         workload=pipeline benchmark_scope=same-application-shape \
         client_io=rust-std-sync server_io=hyper-tokio connection_scope=persistent \
         pipeline_depth={PIPELINE_DEPTH} warmup={} iterations={} requests={requests} \
         received_bytes={received_bytes} server_requests={expected_server_requests} \
         elapsed_ns={elapsed_ns} ns_per_request={ns_per_request} \
         requests_per_s={requests_per_s} complete=true",
        options.warmup, options.iterations,
    );
}

fn exchange(
    stream: &mut TcpStream,
    request_batch: &[u8],
    expected_response_bytes: usize,
    buffer: &mut [u8],
) -> usize {
    stream
        .write_all(request_batch)
        .expect("write request batch");
    let mut received = 0usize;
    while received < expected_response_bytes {
        let count = stream.read(buffer).expect("read response batch");
        assert_ne!(count, 0, "server closed during response batch");
        received += count;
    }
    assert_eq!(received, expected_response_bytes);
    received
}

fn parse_options() -> Options {
    let mut options = Options {
        warmup: DEFAULT_WARMUP,
        iterations: DEFAULT_ITERATIONS,
    };
    for argument in env::args().skip(1) {
        if let Some(value) = argument.strip_prefix("--warmup=") {
            options.warmup = value.parse().expect("warmup");
        } else if let Some(value) = argument.strip_prefix("--iterations=") {
            options.iterations = value.parse().expect("iterations");
        } else {
            panic!("unsupported argument: {argument}");
        }
    }
    assert!(options.iterations > 0);
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

impl<T: AsyncRead + Unpin> HyperRead for TokioIo<T> {
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

impl<T: AsyncWrite + Unpin> HyperWrite for TokioIo<T> {
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
