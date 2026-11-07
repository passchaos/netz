//! Independent Hyper/rustls server for netz's unified ALPN client gate.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{TokioExecutor, TokioIo};

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().expect("port").parse().expect("valid port");
    let cert = args.next().expect("certificate");
    let key = args.next().expect("private key");
    let protocol = args.next().expect("h1 or h2");
    assert!(protocol == "h1" || protocol == "h2" || protocol == "h2-shared");
    assert!(args.next().is_none());

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(run(port, &cert, &key, &protocol));
}

async fn run(port: u16, cert: &str, key: &str, protocol: &str) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    println!("Hyper unified server listening protocol={protocol} port={port}");
    io::stdout().flush().expect("flush readiness");
    let (stream, _) = listener.accept().await.expect("accept");
    stream.set_nodelay(true).expect("TCP_NODELAY");
    let tls = TlsAcceptor::from(tls_config(cert, key, protocol))
        .accept(stream)
        .await
        .expect("TLS handshake");
    let expected_alpn = if protocol.starts_with("h2") {
        b"h2".as_slice()
    } else {
        b"http/1.1".as_slice()
    };
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(expected_alpn));
    let requests = Arc::new(AtomicUsize::new(0));
    let service_requests = requests.clone();
    let service_protocol = protocol.to_owned();
    let shared = Arc::new(Shared::new(port));
    let service_shared = shared.clone();
    let service = service_fn(move |request| {
        handle(
            request,
            service_requests.clone(),
            service_protocol.clone(),
            service_shared.clone(),
        )
    });
    if protocol.starts_with("h2") {
        let mut builder = http2::Builder::new(TokioExecutor);
        if protocol == "h2-shared" {
            builder.max_concurrent_streams(3);
        }
        builder
            .serve_connection(TokioIo::new(tls), service)
            .await
            .expect("serve h2");
    } else {
        http1::Builder::new()
            .serve_connection(TokioIo::new(tls), service)
            .await
            .expect("serve h1");
    }
    if protocol == "h2-shared" {
        assert_eq!(requests.load(Ordering::SeqCst), 7);
        assert_eq!(shared.cancellations.load(Ordering::Acquire), 1);
        assert!(shared.first_finished.load(Ordering::Acquire));
        assert!(shared.survivor_finished.load(Ordering::Acquire));
        assert_eq!(shared.paths.lock().unwrap().len(), 7);
        println!("Hyper unified shared server completed protocol=h2 alpn=h2 requests=7 connections=1 late_sibling=true cancellations=1 surviving_second=true later_reuse=true tls=pinned client_io=zio-std-io server_io=hyper-tokio");
        return;
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    println!("Hyper unified server completed protocol={protocol} alpn={expected} requests=2 connections=1 client_io=zio-std-io server_io=hyper-tokio", expected = String::from_utf8_lossy(expected_alpn));
}

async fn handle(
    request: Request<Incoming>,
    requests: Arc<AtomicUsize>,
    protocol: String,
    shared: Arc<Shared>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    if protocol == "h2-shared" {
        requests.fetch_add(1, Ordering::SeqCst);
        return handle_shared(request, shared).await;
    }
    let index = requests.fetch_add(1, Ordering::SeqCst);
    let expected_path = if index == 0 { "/one" } else { "/two" };
    assert!(index < 2);
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().path(), expected_path);
    assert_eq!(
        request.headers().get("x-netz-unified").unwrap(),
        protocol.as_str()
    );
    Ok(Response::new(
        Full::new(Bytes::from(format!("{protocol}-{}", index + 1))).boxed(),
    ))
}

struct Shared {
    authority: String,
    paths: Mutex<BTreeSet<String>>,
    first_waiting: AtomicBool,
    second_arrived: AtomicBool,
    first_finished: AtomicBool,
    cancel_waiting: AtomicBool,
    survivor_waiting: AtomicBool,
    survivor_finished: AtomicBool,
    cancellations: AtomicUsize,
    changed: Notify,
}

impl Shared {
    fn new(port: u16) -> Self {
        Self {
            authority: format!("localhost:{port}"),
            paths: Mutex::new(BTreeSet::new()),
            first_waiting: AtomicBool::new(false),
            second_arrived: AtomicBool::new(false),
            first_finished: AtomicBool::new(false),
            cancel_waiting: AtomicBool::new(false),
            survivor_waiting: AtomicBool::new(false),
            survivor_finished: AtomicBool::new(false),
            cancellations: AtomicUsize::new(0),
            changed: Notify::new(),
        }
    }

    async fn wait(&self, ready: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                if ready() {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("shared request barrier deadline");
    }
}

struct HeldBody(Arc<Shared>);

impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }
}

impl Drop for HeldBody {
    fn drop(&mut self) {
        assert!(self.0.survivor_waiting.load(Ordering::Acquire));
        assert_eq!(self.0.cancellations.fetch_add(1, Ordering::AcqRel), 0);
        self.0.changed.notify_waiters();
    }
}

async fn handle_shared(
    request: Request<Incoming>,
    shared: Arc<Shared>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    assert_eq!(request.method(), Method::GET);
    assert_eq!(
        request.headers().get("x-netz-unified").unwrap(),
        "h2-shared"
    );
    assert_eq!(
        request.uri().authority().unwrap().as_str(),
        shared.authority
    );
    let path = request.uri().path().to_owned();
    assert!(
        shared.paths.lock().unwrap().insert(path.clone()),
        "duplicate shared request"
    );
    let body = match path.as_str() {
        "/shared-first" => {
            assert!(!shared.first_waiting.swap(true, Ordering::AcqRel));
            shared.changed.notify_waiters();
            shared
                .wait(|| shared.second_arrived.load(Ordering::Acquire))
                .await;
            shared.first_finished.store(true, Ordering::Release);
            "first"
        }
        "/shared-entered" => {
            shared
                .wait(|| shared.first_waiting.load(Ordering::Acquire))
                .await;
            assert!(!shared.second_arrived.load(Ordering::Acquire));
            assert!(!shared.first_finished.load(Ordering::Acquire));
            "first-entered"
        }
        "/shared-second" => {
            assert!(shared.first_waiting.load(Ordering::Acquire));
            assert!(!shared.first_finished.load(Ordering::Acquire));
            assert!(!shared.second_arrived.swap(true, Ordering::AcqRel));
            shared.changed.notify_waiters();
            "second"
        }
        "/shared-cancel" => {
            assert!(!shared.cancel_waiting.swap(true, Ordering::AcqRel));
            shared.changed.notify_waiters();
            return Ok(Response::new(HeldBody(shared).boxed()));
        }
        "/shared-survivor" => {
            assert!(!shared.survivor_waiting.swap(true, Ordering::AcqRel));
            shared.changed.notify_waiters();
            shared
                .wait(|| shared.cancellations.load(Ordering::Acquire) == 1)
                .await;
            shared.survivor_finished.store(true, Ordering::Release);
            "survivor"
        }
        "/shared-pending" => {
            shared
                .wait(|| {
                    shared.cancel_waiting.load(Ordering::Acquire)
                        && shared.survivor_waiting.load(Ordering::Acquire)
                })
                .await;
            assert_eq!(shared.cancellations.load(Ordering::Acquire), 0);
            "both-pending"
        }
        "/shared-later" => {
            assert!(shared.survivor_finished.load(Ordering::Acquire));
            assert_eq!(shared.cancellations.load(Ordering::Acquire), 1);
            "later"
        }
        _ => panic!("unexpected shared path: {path}"),
    };
    Ok(Response::new(
        Full::new(Bytes::from_static(body.as_bytes())).boxed(),
    ))
}

fn tls_config(cert_path: &str, key_path: &str, protocol: &str) -> Arc<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open(cert_path).expect("open cert"),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("parse cert");
    let key =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(key_path).expect("open key")))
            .expect("parse key")
            .expect("private key");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("identity");
    config.alpn_protocols = vec![if protocol.starts_with("h2") {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Arc::new(config)
}
