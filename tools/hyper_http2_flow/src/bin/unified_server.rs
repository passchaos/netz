//! Independent Hyper/rustls server for netz's unified ALPN client gate.

use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use tokio::net::TcpListener;
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
    assert!(protocol == "h1" || protocol == "h2");
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
    let expected_alpn = if protocol == "h2" {
        b"h2".as_slice()
    } else {
        b"http/1.1".as_slice()
    };
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(expected_alpn));
    let requests = Arc::new(AtomicUsize::new(0));
    let service_requests = requests.clone();
    let service_protocol = protocol.to_owned();
    let service = service_fn(move |request| {
        handle(request, service_requests.clone(), service_protocol.clone())
    });
    if protocol == "h2" {
        http2::Builder::new(TokioExecutor)
            .serve_connection(TokioIo::new(tls), service)
            .await
            .expect("serve h2");
    } else {
        http1::Builder::new()
            .serve_connection(TokioIo::new(tls), service)
            .await
            .expect("serve h1");
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    println!("Hyper unified server completed protocol={protocol} alpn={expected} requests=2 connections=1 client_io=zio-std-io server_io=hyper-tokio", expected = String::from_utf8_lossy(expected_alpn));
}

async fn handle(
    request: Request<Incoming>,
    requests: Arc<AtomicUsize>,
    protocol: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let index = requests.fetch_add(1, Ordering::SeqCst);
    let expected_path = if index == 0 { "/one" } else { "/two" };
    assert!(index < 2);
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().path(), expected_path);
    assert_eq!(
        request.headers().get("x-netz-unified").unwrap(),
        protocol.as_str()
    );
    Ok(Response::new(Full::new(Bytes::from(format!(
        "{protocol}-{}",
        index + 1
    )))))
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
    config.alpn_protocols = vec![if protocol == "h2" {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Arc::new(config)
}
