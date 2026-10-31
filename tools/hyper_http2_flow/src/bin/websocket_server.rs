//! Hyper RFC 8441 server used to verify netz WebSocket-over-HTTP/2 on a real
//! process boundary. WebSocket frames are parsed here independently of netz.

use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{MaybeTls, TokioExecutor, TokioIo};

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    let tls_paths = args
        .next()
        .map(|cert| (cert, args.next().expect("TLS private key argument")));
    assert!(args.next().is_none(), "unexpected extra argument");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    runtime.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind Hyper RFC 8441 server");
        println!("Hyper RFC 8441 server listening on 127.0.0.1:{port}");
        io::stdout().flush().expect("flush readiness line");

        let (stream, _) = listener.accept().await.expect("accept netz client");
        stream.set_nodelay(true).expect("server TCP_NODELAY");
        let mut exporter = None;
        let tls_enabled = tls_paths.is_some();
        let io = match tls_paths {
            Some((cert, key)) => {
                let mut tls = TlsAcceptor::from(tls_server_config(&cert, &key))
                    .accept(stream)
                    .await
                    .expect("accept TLS with h2 ALPN");
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                let mut bytes = [0; 32];
                tls.get_ref()
                    .1
                    .export_keying_material(&mut bytes, b"EXPORTER-netz-rfc8441", Some(b"hyper"))
                    .expect("derive rustls exporter");
                exporter = Some(bytes);
                tls.get_mut()
                    .1
                    .refresh_traffic_keys()
                    .expect("queue rustls KeyUpdate");
                tls.flush().await.expect("flush rustls KeyUpdate");
                println!("rustls RFC 8441 server sent TLS KeyUpdate request");
                MaybeTls::Server(tls)
            }
            None => MaybeTls::Clear(stream),
        };
        let mut builder = server_http2::Builder::new(TokioExecutor);
        builder.enable_connect_protocol();
        let authority = format!("localhost:{port}");
        builder
            .serve_connection(
                TokioIo::new(io),
                service_fn(move |request| {
                    handle(request, exporter, tls_enabled, authority.clone())
                }),
            )
            .await
            .expect("serve netz RFC 8441 client");
    });
}

fn tls_server_config(cert_path: &str, key_path: &str) -> Arc<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut io::BufReader::new(
        File::open(Path::new(cert_path)).expect("open TLS certificate"),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("parse TLS certificate");
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(
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

async fn handle(
    mut request: Request<hyper::body::Incoming>,
    exporter: Option<[u8; 32]>,
    tls_enabled: bool,
    authority: String,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.version(), Version::HTTP_2);
    assert_eq!(
        request.uri().scheme_str(),
        Some(if tls_enabled { "https" } else { "http" })
    );
    assert_eq!(
        request.uri().authority().map(|value| value.as_str()),
        Some(authority.as_str())
    );
    assert!(!request.headers().contains_key("proxy-authorization"));
    assert_eq!(
        request.uri().path_and_query().unwrap().as_str(),
        "/websocket"
    );
    assert_eq!(request.headers()["sec-websocket-version"], "13");
    let protocol = request
        .extensions()
        .get::<hyper::ext::Protocol>()
        .expect("extended CONNECT protocol");
    assert_eq!(protocol.as_str(), "websocket");

    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let upgraded = on_upgrade.await.expect("upgrade RFC 8441 stream");
        let mut stream = TokioIo::new(upgraded);

        let first = read_frame(&mut stream, true).await;
        assert_eq!(first.opcode, 0x1);
        assert!(!first.fin);
        assert_eq!(first.payload, b"netz ");
        let second = read_frame(&mut stream, true).await;
        assert_eq!(second.opcode, 0x0);
        assert!(!second.fin);
        assert_eq!(second.payload, b"websocket ");
        let third = read_frame(&mut stream, true).await;
        assert_eq!(third.opcode, 0x0);
        assert!(third.fin);
        assert_eq!(third.payload, b"h2");
        write_frame(&mut stream, 0x1, b"hyper websocket h2").await;
        if let Some(bytes) = exporter {
            write_frame(&mut stream, 0x2, &bytes).await;
        }

        let ping = read_frame(&mut stream, true).await;
        assert_eq!(ping.opcode, 0x9);
        assert!(ping.fin);
        assert_eq!(ping.payload, b"ping");
        write_frame(&mut stream, 0xA, b"unsolicited").await;
        write_frame(&mut stream, 0x2, b"during probe").await;
        write_frame(&mut stream, 0xA, &ping.payload).await;
        println!(
            "Hyper RFC 8441 Ping fixture sent unsolicited Pong and interleaved application data"
        );

        let close = read_frame(&mut stream, true).await;
        assert_eq!(close.opcode, 0x8);
        assert!(close.fin);
        assert_eq!(close.payload, [0x03, 0xE8, b'd', b'o', b'n', b'e']);
        write_frame(&mut stream, 0x8, &close.payload).await;
        stream.shutdown().await.expect("finish RFC 8441 stream");
        println!("Hyper RFC 8441 server interoperated with netz: fragmented-text ping pong bounded-close client_io=zio-std-io server_io=hyper-tokio");
    });

    let mut response = Response::new(Empty::new());
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

async fn read_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    expect_masked: bool,
) -> Frame {
    let mut fixed = [0; 2];
    stream
        .read_exact(&mut fixed)
        .await
        .expect("read frame head");
    let fin = fixed[0] & 0x80 != 0;
    let opcode = fixed[0] & 0x0F;
    let masked = fixed[1] & 0x80 != 0;
    assert_eq!(masked, expect_masked);
    let mut length = u64::from(fixed[1] & 0x7F);
    if length == 126 {
        let mut encoded = [0; 2];
        stream
            .read_exact(&mut encoded)
            .await
            .expect("read 16-bit frame length");
        length = u64::from(u16::from_be_bytes(encoded));
    } else if length == 127 {
        let mut encoded = [0; 8];
        stream
            .read_exact(&mut encoded)
            .await
            .expect("read 64-bit frame length");
        length = u64::from_be_bytes(encoded);
        assert_eq!(length >> 63, 0);
    }
    let mut mask = [0; 4];
    if masked {
        stream.read_exact(&mut mask).await.expect("read mask key");
    }
    let mut payload = vec![0; usize::try_from(length).expect("bounded frame length")];
    stream
        .read_exact(&mut payload)
        .await
        .expect("read frame payload");
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }
    Frame {
        fin,
        opcode,
        payload,
    }
}

async fn write_frame(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    opcode: u8,
    payload: &[u8],
) {
    assert!(payload.len() <= 125);
    let head = [0x80 | opcode, payload.len() as u8];
    stream.write_all(&head).await.expect("write frame head");
    stream
        .write_all(payload)
        .await
        .expect("write frame payload");
    stream.flush().await.expect("flush frame");
}
