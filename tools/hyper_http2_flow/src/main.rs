use std::convert::Infallible;
use std::env;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Instant;

use bytes::Bytes;
use futures_util::future::join_all;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

mod tokiort;
use tokiort::{TokioExecutor, TokioIo};

const DEFAULT_PARALLEL: usize = 10;
const DEFAULT_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_STREAM_WINDOW: u32 = 8 * 1024;
const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;
const DEFAULT_WARMUP: usize = 5;
const DEFAULT_ITERATIONS: usize = 20;
const RESPONSE_DATE: &str = "Mon, 17 Aug 2026 00:00:00 GMT";

type RequestBody = Empty<Bytes>;

#[derive(Clone, Copy)]
struct Options {
    parallel: usize,
    body_bytes: usize,
    stream_window: u32,
    connection_window: u32,
    warmup: usize,
    iterations: usize,
}

fn main() {
    let options = parse_options();
    assert!(options.parallel > 0);
    assert!(options.body_bytes > 0);
    assert!(options.stream_window > 0);
    assert!(options.connection_window >= 65_535);
    assert!(options.iterations > 0);

    let body = Bytes::from(vec![b'x'; options.body_bytes]);
    let (address_tx, address_rx) = mpsc::channel();
    let server_body = body.clone();
    let response_barrier = Arc::new(Barrier::new(options.parallel));
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
            server_http2::Builder::new(TokioExecutor)
                .initial_stream_window_size(options.stream_window)
                .initial_connection_window_size(options.connection_window)
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: Request<Incoming>| {
                        let response_body = server_body.clone();
                        let response_barrier = response_barrier.clone();
                        async move {
                            let mut incoming = request.into_body();
                            while incoming.frame().await.is_some() {}
                            response_barrier.wait().await;
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("date", RESPONSE_DATE)
                                    .body(Full::new(response_body))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .expect("serve HTTP/2 connection");
        });
    });

    let address = address_rx.recv().unwrap();
    let uri: hyper::Uri = format!("http://{address}/flow").parse().unwrap();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build client runtime"),
    );
    let executor = runtime.clone();
    let mut sender = runtime.block_on(async move {
        let stream = TcpStream::connect(address).await.expect("connect");
        stream.set_nodelay(true).expect("client TCP_NODELAY");
        let (sender, connection) = client_http2::Builder::new(TokioExecutor)
            .initial_stream_window_size(options.stream_window)
            .initial_connection_window_size(options.connection_window)
            .handshake(TokioIo::new(stream))
            .await
            .expect("HTTP/2 handshake");
        executor.spawn(async move {
            connection.await.expect("client HTTP/2 connection");
        });
        sender
    });

    let mut checksum = 0usize;
    for _ in 0..options.warmup {
        checksum = checksum.wrapping_add(runtime.block_on(exchange(&mut sender, options, &uri)));
    }
    let started = Instant::now();
    for _ in 0..options.iterations {
        checksum = checksum.wrapping_add(runtime.block_on(exchange(&mut sender, options, &uri)));
    }
    let elapsed = started.elapsed();
    drop(sender);
    runtime.block_on(async { tokio::task::yield_now().await });
    server.join().unwrap();

    let elapsed_ns = elapsed.as_nanos() as u64;
    let wire_body_bytes =
        options.body_bytes as u64 * options.parallel as u64 * options.iterations as u64;
    let mib_per_second = wire_body_bytes * 1_000_000_000 / (elapsed_ns * 1024 * 1024);
    println!("Hyper HTTP/2 flow-controlled response benchmark");
    println!("  parallel streams: {}", options.parallel);
    println!("  response bytes/stream: {}", options.body_bytes);
    println!("  initial stream window: {}", options.stream_window);
    println!("  initial connection window: {}", options.connection_window);
    println!("  warmup iterations: {}", options.warmup);
    println!("  iterations: {}", options.iterations);
    println!("  ns/batch: {}", elapsed_ns / options.iterations as u64);
    println!("  body MiB/s: {}", mib_per_second);
    println!("  checksum: {}", checksum);
}

async fn exchange(
    sender: &mut client_http2::SendRequest<RequestBody>,
    options: Options,
    uri: &hyper::Uri,
) -> usize {
    let responses = (0..options.parallel).map(|_| {
        let request = Request::builder()
            .uri(uri.clone())
            .body(Empty::new())
            .unwrap();
        let response = sender.send_request(request);
        async move {
            let mut total = 0usize;
            let mut body = response.await.expect("response").into_body();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.expect("response body").into_data() {
                    total += data.len();
                }
            }
            total
        }
    });
    let total = join_all(responses).await.into_iter().sum();
    assert_eq!(total, options.body_bytes * options.parallel);
    total
}

fn parse_options() -> Options {
    let mut options = Options {
        parallel: DEFAULT_PARALLEL,
        body_bytes: DEFAULT_BODY_BYTES,
        stream_window: DEFAULT_STREAM_WINDOW,
        connection_window: DEFAULT_CONNECTION_WINDOW,
        warmup: DEFAULT_WARMUP,
        iterations: DEFAULT_ITERATIONS,
    };
    for argument in env::args().skip(1) {
        if let Some(value) = argument.strip_prefix("--parallel=") {
            options.parallel = value.parse().expect("parallel");
        } else if let Some(value) = argument.strip_prefix("--body-bytes=") {
            options.body_bytes = value.parse().expect("body bytes");
        } else if let Some(value) = argument.strip_prefix("--stream-window=") {
            options.stream_window = value.parse().expect("stream window");
        } else if let Some(value) = argument.strip_prefix("--connection-window=") {
            options.connection_window = value.parse().expect("connection window");
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
