//! Hyper client for the HTTP/2 cancellation-race benchmark.

use std::env;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::future;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2;
use hyper::{Request, StatusCode};
use tokio::net::TcpStream;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{TokioExecutor, TokioIo};

#[cfg(feature = "allocation-stats")]
#[path = "../counting_allocator.rs"]
mod counting_allocator;
#[cfg(feature = "allocation-stats")]
#[global_allocator]
static COUNTING_ALLOCATOR: counting_allocator::CountingAllocator =
    counting_allocator::CountingAllocator::new();

const STREAM_WINDOW: u32 = 8 * 1024;
const CONNECTION_WINDOW: u32 = 65_535;
const OFFERED_BYTES: usize = 128 * 1024;
const SIBLING_BYTES: usize = 16 * 1024;

type RequestBody = Empty<Bytes>;

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().expect("port").parse().expect("valid port");
    let warmup: usize = args.next().expect("warmup").parse().expect("valid warmup");
    let iterations: usize = args
        .next()
        .expect("iterations")
        .parse()
        .expect("valid iterations");
    assert!(port != 0 && iterations != 0 && args.next().is_none());

    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build client runtime"),
    );
    let executor = runtime.clone();
    let (mut sender, connection_task) = runtime.block_on(async move {
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect benchmark server");
        stream.set_nodelay(true).expect("client TCP_NODELAY");
        let mut builder = http2::Builder::new(TokioExecutor);
        builder
            .initial_stream_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW);
        let (sender, connection) = builder
            .handshake(TokioIo::new(stream))
            .await
            .expect("HTTP/2 handshake");
        let task = executor.spawn(async move {
            let _ = connection.await;
        });
        (sender, task)
    });

    for _ in 0..warmup {
        runtime.block_on(exchange(&mut sender));
    }
    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        checksum = checksum.wrapping_add(runtime.block_on(exchange(&mut sender)));
    }
    let elapsed_ns = started.elapsed().as_nanos() as u64;
    runtime.block_on(verify_reuse(&mut sender));
    let ns_per_batch = elapsed_ns / iterations as u64;
    let batches_per_second = iterations as u128 * 1_000_000_000 / elapsed_ns as u128;

    println!(
        "record=result implementation=hyper protocol=http2 transport=h2c mode=cancellation-race server_implementation=hyper client_io=hyper-tokio server_io=hyper-tokio connection_scope=persistent benchmark_scope=same-server-behavior warmup={warmup} iterations={iterations} stream_window=8192 connection_window=65535 offered_bytes=131072 canceled_bytes=8192 sibling_bytes=16384 completed_batches={iterations} reuse_requests=1 cancellation_observation=server-body-drop-gated-sibling sibling_concurrent=true elapsed_ns={elapsed_ns} ns_per_batch={ns_per_batch} batches_per_s={batches_per_second} checksum={checksum} complete=true"
    );
    #[cfg(feature = "allocation-stats")]
    {
        let snapshot = COUNTING_ALLOCATOR.snapshot();
        snapshot.print();
        println!(
            "record=memory implementation=hyper protocol=http2 transport=h2c mode=cancellation-race server_implementation=hyper client_io=hyper-tokio server_io=hyper-tokio memory_scope=client-process-through-reuse allocator_scope=rust-system-requested alloc_count={} free_count={} realloc_count={} total_allocated_bytes={} total_freed_bytes={} live_bytes={} peak_live_bytes={} complete=true",
            snapshot.alloc_count, snapshot.free_count, snapshot.realloc_count,
            snapshot.total_allocated, snapshot.total_freed, snapshot.current_bytes,
            snapshot.peak_bytes
        );
    }
    drop(sender);
    runtime.block_on(async { tokio::task::yield_now().await });
    runtime
        .block_on(connection_task)
        .expect("join connection driver");
}

async fn exchange(sender: &mut http2::SendRequest<RequestBody>) -> usize {
    let cancel_request = Request::builder()
        .uri("http://localhost/cancel")
        .body(Empty::new())
        .expect("cancel request");
    let sibling_request = Request::builder()
        .uri("http://localhost/sibling")
        .body(Empty::new())
        .expect("sibling request");
    let mut cancel_sender = sender.clone();
    let mut sibling_sender = sender.clone();
    let cancel = async move {
        let response = cancel_sender
            .send_request(cancel_request)
            .await
            .expect("cancel response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-length").unwrap(), "131072");
        let mut body = response.into_body();
        let data = body
            .frame()
            .await
            .expect("cancellation DATA")
            .expect("valid cancellation DATA")
            .into_data()
            .expect("DATA frame");
        assert_eq!(data.len(), STREAM_WINDOW as usize);
        assert!(data.iter().all(|byte| *byte == b'c'));
        drop(body);
        data.len()
    };
    let sibling = async move {
        let response = sibling_sender
            .send_request(sibling_request)
            .await
            .expect("sibling response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("sibling body")
            .to_bytes();
        assert_eq!(body.len(), SIBLING_BYTES);
        assert!(body.iter().all(|byte| *byte == b's'));
        body.len()
    };
    let (canceled, sibling) = future::join(cancel, sibling).await;
    assert_eq!(OFFERED_BYTES, 128 * 1024);
    canceled + sibling
}

async fn verify_reuse(sender: &mut http2::SendRequest<RequestBody>) {
    let response = sender
        .send_request(
            Request::builder()
                .uri("http://localhost/reuse")
                .body(Empty::new())
                .expect("reuse request"),
        )
        .await
        .expect("reuse response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("reuse body")
        .to_bytes();
    assert_eq!(body, b"reuse-ok".as_slice());
}
