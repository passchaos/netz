//! Low-level h2 peer for HTTP/2 server-push interoperability with netz.
//!
//! Hyper intentionally disables push in its high-level HTTP/2 client, while
//! its audited h2 dependency exposes the complete push API. This fixture uses
//! that dependency directly so push success and Hyper's opt-out behavior are
//! both observable across a process boundary.

use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use h2::{client, server};
use http::{Method, Request, Response, StatusCode, Uri};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[allow(dead_code)]
#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::MaybeTls;

const PUSH_BODY: &[u8] = b"hyper-pushed-css";
const PARENT_BODY: &[u8] = b"hyper-parent";

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("client or server mode");
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    let tls_paths = args.next().map(|first| {
        if mode.ends_with("server") {
            (first, args.next().expect("TLS private key argument"))
        } else {
            (first, String::new())
        }
    });
    assert!(args.next().is_none(), "unexpected extra argument");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    match mode.as_str() {
        "server" => runtime.block_on(run_push_server(port, tls_paths)),
        "client" => runtime.block_on(run_push_disabled_client(port, tls_paths)),
        "informational-server" => runtime.block_on(run_informational_server(port, tls_paths)),
        "informational-client" => runtime.block_on(run_informational_client(port, tls_paths)),
        _ => panic!("unknown mode: {mode}"),
    }
}

async fn run_informational_server(port: u16, tls_paths: Option<(String, String)>) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind h2 informational server");
    println!("h2 informational interop server listening on 127.0.0.1:{port}");
    io::stdout().flush().expect("flush readiness line");
    let (stream, _) = listener.accept().await.expect("accept netz client");
    stream.set_nodelay(true).expect("server TCP_NODELAY");
    let io = match tls_paths {
        Some((cert, key)) => {
            let tls = TlsAcceptor::from(tls_server_config(&cert, &key))
                .accept(stream)
                .await
                .expect("accept TLS with h2 ALPN");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            MaybeTls::Server(tls)
        }
        None => MaybeTls::Clear(stream),
    };
    let mut connection = server::handshake::<_>(io)
        .await
        .expect("h2 server handshake");
    let (request, mut respond) = connection
        .accept()
        .await
        .expect("connection closed before request")
        .expect("valid request");
    assert_eq!(request.uri().path(), "/informational");
    respond
        .send_informational(
            Response::builder()
                .status(StatusCode::EARLY_HINTS)
                .header("link", "</style.css>; rel=preload")
                .body(())
                .expect("103 response"),
        )
        .expect("send 103");
    respond
        .send_informational(
            Response::builder()
                .status(StatusCode::PROCESSING)
                .header("x-progress", "half")
                .body(())
                .expect("102 response"),
        )
        .expect("send 102");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("x-h2-final", "yes")
        .body(())
        .expect("final response");
    let mut body = respond
        .send_response(response, false)
        .expect("send final response");
    body.send_data(Bytes::from_static(b"final"), true)
        .expect("send final body");
    while connection.accept().await.is_some() {}
    println!("h2 server sent informational responses to netz: statuses=103,102 final=200 body=5");
}

async fn run_informational_client(port: u16, ca_path: Option<(String, String)>) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz informational server");
    stream.set_nodelay(true).expect("client TCP_NODELAY");
    let io = match ca_path {
        Some((ca, _)) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                rustls_pemfile::certs(&mut BufReader::new(
                    File::open(Path::new(&ca)).expect("open CA certificate"),
                ))
                .map(|result| result.expect("parse CA certificate")),
            );
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let tls = TlsConnector::from(Arc::new(config))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect TLS with h2 ALPN");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            MaybeTls::Client(tls)
        }
        None => MaybeTls::Clear(stream),
    };
    let (mut sender, connection) = client::handshake(io).await.expect("h2 client handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/informational")
        .body(())
        .expect("informational request");
    let (mut response, _) = sender
        .send_request(request, true)
        .expect("send informational request");
    let first = futures_util::future::poll_fn(|cx| response.poll_informational(cx))
        .await
        .expect("first informational response")
        .expect("valid first informational response");
    let second = futures_util::future::poll_fn(|cx| response.poll_informational(cx))
        .await
        .expect("second informational response")
        .expect("valid second informational response");
    let statuses = [first.status().as_u16(), second.status().as_u16()];
    assert_eq!(statuses, [103, 102]);
    let response = response.await.expect("receive final response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-netz-final"),
        Some(&http::HeaderValue::from_static("yes")),
    );
    let mut body = response.into_body();
    let payload = body
        .data()
        .await
        .expect("final response body")
        .expect("valid final response body");
    assert_eq!(payload, b"final".as_slice());
    assert!(
        body.data().await.is_none(),
        "unexpected extra response DATA"
    );
    println!("h2 client received netz informational responses: statuses=103,102 final=200 body=5");
}

async fn run_push_server(port: u16, tls_paths: Option<(String, String)>) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind h2 push server");
    println!("h2 push interop server listening on 127.0.0.1:{port}");
    io::stdout().flush().expect("flush readiness line");

    let (stream, _) = listener.accept().await.expect("accept netz client");
    stream.set_nodelay(true).expect("server TCP_NODELAY");
    let io = match tls_paths {
        Some((cert, key)) => {
            let tls = TlsAcceptor::from(tls_server_config(&cert, &key))
                .accept(stream)
                .await
                .expect("accept TLS with h2 ALPN");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            MaybeTls::Server(tls)
        }
        None => MaybeTls::Clear(stream),
    };
    let mut connection = server::handshake(io).await.expect("h2 server handshake");
    let (request, mut respond) = connection
        .accept()
        .await
        .expect("connection closed before request")
        .expect("valid request");
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().path(), "/push-parent");

    let push_request = Request::builder()
        .method(Method::GET)
        .uri("https://localhost/style.css")
        .header("accept", "text/css")
        .body(())
        .expect("push request");
    let mut push = respond
        .push_request(push_request)
        .expect("client enabled push");
    let parent_response = Response::builder()
        .status(StatusCode::OK)
        .header("x-hyper-parent", "yes")
        .body(())
        .expect("parent response");
    let mut parent_body = respond
        .send_response(parent_response, false)
        .expect("send parent response headers");
    parent_body
        .send_data(Bytes::from_static(PARENT_BODY), true)
        .expect("send parent response body");

    // Netz intentionally finishes the parent response before the application
    // accepts its queued promise. Preserve that deterministic consumption
    // order while still emitting PUSH_PROMISE before the parent response.
    // `SendResponse` only queues frames; drive the connection until the
    // already queued PUSH_PROMISE and parent response reach the netz client.
    // No second request is expected, so this bounded accept must time out.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), connection.accept(),)
            .await
            .is_err(),
        "unexpected second request while flushing parent response",
    );
    let push_response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/css")
        .header("x-hyper-push", "yes")
        .body(())
        .expect("push response");
    let mut push_body = push
        .send_response(push_response, false)
        .expect("send pushed response headers");
    push_body
        .send_data(Bytes::from_static(PUSH_BODY), true)
        .expect("send pushed response body");

    while connection.accept().await.is_some() {}
    println!("h2 server pushed to netz: parent_stream=1 promised_stream=2 path=/style.css body=16");
}

async fn run_push_disabled_client(port: u16, ca_path: Option<(String, String)>) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz push server");
    stream.set_nodelay(true).expect("client TCP_NODELAY");
    let io = match ca_path {
        Some((ca, _)) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                rustls_pemfile::certs(&mut BufReader::new(
                    File::open(Path::new(&ca)).expect("open CA certificate"),
                ))
                .map(|result| result.expect("parse CA certificate")),
            );
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let tls = TlsConnector::from(Arc::new(config))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect TLS with h2 ALPN");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            MaybeTls::Client(tls)
        }
        None => MaybeTls::Clear(stream),
    };
    let mut builder = client::Builder::new();
    builder.enable_push(false);
    let (mut sender, connection) = builder
        .handshake::<_, Bytes>(io)
        .await
        .expect("h2 client handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::GET)
        .uri(
            Uri::builder()
                .scheme("http")
                .authority("localhost")
                .path_and_query("/push-disabled")
                .build()
                .expect("request URI"),
        )
        .body(())
        .expect("request");
    let (response, _) = sender
        .send_request(request, true)
        .expect("send push-disabled request");
    let response = response.await.expect("receive normal response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    drop(response);
    drop(sender);
    println!(
        "h2 client disabled netz push: request_stream=1 promise_rejected=true parent_status=204"
    );
}

fn tls_server_config(cert_path: &str, key_path: &str) -> Arc<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open(Path::new(cert_path)).expect("open TLS certificate"),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("parse TLS certificate");
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(Path::new(key_path)).expect("open TLS private key"),
    ))
    .expect("parse TLS private key")
    .expect("TLS private key");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("certificate and private key match");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}
