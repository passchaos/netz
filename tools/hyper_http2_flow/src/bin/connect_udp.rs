//! Independent Hyper/Tokio RFC 9298 peer for netz HTTP/1.1 and HTTP/2.
//!
//! Hyper owns HTTP parsing, HPACK, SETTINGS_ENABLE_CONNECT_PROTOCOL, Upgrade,
//! and stream I/O. This fixture owns only the CONNECT-UDP semantics and an
//! independent RFC 9297 Capsule/QUIC-varint codec.

use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::client::conn::{http1 as client_http1, http2 as client_http2};
use hyper::server::conn::{http1 as server_http1, http2 as server_http2};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{MaybeTls, TokioExecutor, TokioIo, TokioTimer};

const TARGET_PATH: &str = "/.well-known/masque/udp/dns.example/53/";
const CLIENT_PAYLOAD_LEN: usize = 513;
const SERVER_PAYLOAD_LEN: usize = 777;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpVersion {
    Http1,
    Http2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Client,
    Server,
}

fn main() {
    let mut args = env::args().skip(1);
    let mode = args
        .next()
        .expect("h1-client, h1-server, h2-client, or h2-server");
    let (version, role) = match mode.as_str() {
        "h1-client" => (HttpVersion::Http1, Role::Client),
        "h1-server" => (HttpVersion::Http1, Role::Server),
        "h2-client" => (HttpVersion::Http2, Role::Client),
        "h2-server" => (HttpVersion::Http2, Role::Server),
        _ => panic!("unsupported mode: {mode}"),
    };
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    let first_path = args.next();
    let second_path = args.next();
    assert!(args.next().is_none(), "unexpected extra argument");
    match role {
        Role::Client => assert!(second_path.is_none(), "client accepts only a CA path"),
        Role::Server => assert_eq!(first_path.is_some(), second_path.is_some()),
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    runtime.block_on(async move {
        match (version, role) {
            (HttpVersion::Http1, Role::Client) => run_h1_client(port, first_path).await,
            (HttpVersion::Http1, Role::Server) => {
                run_h1_server(port, first_path.zip(second_path)).await
            }
            (HttpVersion::Http2, Role::Client) => run_h2_client(port, first_path).await,
            (HttpVersion::Http2, Role::Server) => {
                run_h2_server(port, first_path.zip(second_path)).await
            }
        }
    });
}

async fn run_h1_server(port: u16, tls_paths: Option<(String, String)>) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind Hyper HTTP/1 CONNECT-UDP server");
    println!(
        "Hyper HTTP/1 CONNECT-UDP server listening transport={} on 127.0.0.1:{port}",
        transport_name(tls_paths.is_some()),
    );
    io::stdout().flush().expect("flush readiness marker");
    let (stream, _) = listener.accept().await.expect("accept netz H1 client");
    stream.set_nodelay(true).expect("set H1 TCP_NODELAY");
    let io = server_io(stream, tls_paths.as_ref(), HttpVersion::Http1).await;
    let (completion, mut completed) = mpsc::channel(1);
    server_http1::Builder::new()
        .serve_connection(
            TokioIo::new(io),
            service_fn(move |request| handle_h1(request, completion.clone())),
        )
        .with_upgrades()
        .await
        .expect("serve netz HTTP/1 CONNECT-UDP client");
    completed
        .recv()
        .await
        .expect("H1 exchange completion")
        .expect("H1 capsule exchange");
    println!(
        "Hyper HTTP/1 CONNECT-UDP server interoperated with netz: transport={} received={} sent={} unknown_capsule=true unknown_context=true fragmented=true",
        transport_name(tls_paths.is_some()),
        CLIENT_PAYLOAD_LEN,
        SERVER_PAYLOAD_LEN,
    );
}

async fn handle_h1(
    mut request: Request<hyper::body::Incoming>,
    completion: mpsc::Sender<Result<(), String>>,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.version(), Version::HTTP_11);
    assert_eq!(request.uri().path(), TARGET_PATH);
    assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
    assert_eq!(request.headers()["host"], "localhost");
    assert!(header_contains_token(&request, "connection", "upgrade"));
    assert_eq!(request.headers()["upgrade"], "connect-udp");
    assert_eq!(request.headers()["capsule-protocol"], "?1");
    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let result = async {
            let upgraded = on_upgrade.await.map_err(io::Error::other)?;
            let mut stream = TokioIo::new(upgraded);
            exchange_server(&mut stream).await
        }
        .await
        .map_err(|error| error.to_string());
        let _ = completion.send(result).await;
    });
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "Upgrade")
        .header("upgrade", "connect-udp")
        .header("capsule-protocol", "?1")
        .body(Empty::new())
        .expect("H1 CONNECT-UDP response"))
}

async fn run_h1_client(port: u16, ca_path: Option<String>) {
    let tls_enabled = ca_path.is_some();
    let io = client_io(port, ca_path.as_deref(), HttpVersion::Http1).await;
    let (mut sender, connection) = client_http1::Builder::new()
        .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
        .await
        .expect("Hyper HTTP/1 handshake");
    let driver = tokio::spawn(async move { connection.with_upgrades().await });
    let scheme = if tls_enabled { "https" } else { "http" };
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{scheme}://localhost{TARGET_PATH}"))
        .header("host", "localhost")
        .header("connection", "Upgrade")
        .header("upgrade", "connect-udp")
        .header("capsule-protocol", "?1")
        .body(Empty::new())
        .expect("H1 CONNECT-UDP request");
    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .expect("H1 response timeout")
        .expect("H1 CONNECT-UDP response");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.headers()["upgrade"], "connect-udp");
    assert_eq!(response.headers()["capsule-protocol"], "?1");
    let upgraded = timeout(IO_TIMEOUT, hyper::upgrade::on(response))
        .await
        .expect("H1 upgrade timeout")
        .expect("H1 upgraded stream");
    let mut stream = TokioIo::new(upgraded);
    exchange_client(&mut stream)
        .await
        .expect("H1 capsule exchange");
    drop(sender);
    timeout(IO_TIMEOUT, driver)
        .await
        .expect("H1 driver timeout")
        .expect("H1 driver join")
        .expect("H1 connection driver");
    println!(
        "Hyper HTTP/1 CONNECT-UDP client interoperated with netz: transport={} sent={} received={} unknown_capsule=true unknown_context=true fragmented=true",
        transport_name(tls_enabled),
        CLIENT_PAYLOAD_LEN,
        SERVER_PAYLOAD_LEN,
    );
}

async fn run_h2_server(port: u16, tls_paths: Option<(String, String)>) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind Hyper HTTP/2 CONNECT-UDP server");
    println!(
        "Hyper HTTP/2 CONNECT-UDP server listening transport={} on 127.0.0.1:{port}",
        transport_name(tls_paths.is_some()),
    );
    io::stdout().flush().expect("flush readiness marker");
    let (stream, _) = listener.accept().await.expect("accept netz H2 client");
    stream.set_nodelay(true).expect("set H2 TCP_NODELAY");
    let io = server_io(stream, tls_paths.as_ref(), HttpVersion::Http2).await;
    let (completion, mut completed) = mpsc::channel(1);
    let mut builder = server_http2::Builder::new(TokioExecutor);
    builder.enable_connect_protocol();
    builder
        .serve_connection(
            TokioIo::new(io),
            service_fn(move |request| handle_h2(request, completion.clone())),
        )
        .await
        .expect("serve netz HTTP/2 CONNECT-UDP client");
    completed
        .recv()
        .await
        .expect("H2 exchange completion")
        .expect("H2 capsule exchange");
    println!(
        "Hyper HTTP/2 CONNECT-UDP server interoperated with netz: transport={} received={} sent={} settings_enable_connect_protocol=true unknown_capsule=true unknown_context=true fragmented=true",
        transport_name(tls_paths.is_some()),
        CLIENT_PAYLOAD_LEN,
        SERVER_PAYLOAD_LEN,
    );
}

async fn handle_h2(
    mut request: Request<hyper::body::Incoming>,
    completion: mpsc::Sender<Result<(), String>>,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.version(), Version::HTTP_2);
    assert_eq!(request.uri().scheme_str(), Some("https"));
    assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
    assert_eq!(request.uri().path(), TARGET_PATH);
    assert_eq!(request.headers()["capsule-protocol"], "?1");
    let protocol = request
        .extensions()
        .get::<hyper::ext::Protocol>()
        .expect("H2 Extended CONNECT protocol");
    assert_eq!(protocol.as_str(), "connect-udp");
    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let result = async {
            let upgraded = on_upgrade.await.map_err(io::Error::other)?;
            let mut stream = TokioIo::new(upgraded);
            exchange_server(&mut stream).await
        }
        .await
        .map_err(|error| error.to_string());
        let _ = completion.send(result).await;
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(Empty::new())
        .expect("H2 CONNECT-UDP response"))
}

async fn run_h2_client(port: u16, ca_path: Option<String>) {
    let tls_enabled = ca_path.is_some();
    let io = client_io(port, ca_path.as_deref(), HttpVersion::Http2).await;
    let mut builder = client_http2::Builder::new(TokioExecutor);
    builder.timer(TokioTimer);
    let (mut sender, connection) = builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
        .await
        .expect("Hyper HTTP/2 handshake");
    let driver = tokio::spawn(async move { connection.await });
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(format!("https://localhost{TARGET_PATH}"))
        .header("capsule-protocol", "?1")
        .body(Empty::new())
        .expect("H2 CONNECT-UDP request");
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("connect-udp"));
    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .expect("H2 response timeout")
        .expect("H2 CONNECT-UDP response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["capsule-protocol"], "?1");
    let upgraded = timeout(IO_TIMEOUT, hyper::upgrade::on(response))
        .await
        .expect("H2 upgrade timeout")
        .expect("H2 upgraded stream");
    let mut stream = TokioIo::new(upgraded);
    exchange_client(&mut stream)
        .await
        .expect("H2 capsule exchange");
    drop(sender);
    timeout(IO_TIMEOUT, driver)
        .await
        .expect("H2 driver timeout")
        .expect("H2 driver join")
        .expect("H2 connection driver");
    println!(
        "Hyper HTTP/2 CONNECT-UDP client interoperated with netz: transport={} sent={} received={} settings_enable_connect_protocol=true unknown_capsule=true unknown_context=true fragmented=true",
        transport_name(tls_enabled),
        CLIENT_PAYLOAD_LEN,
        SERVER_PAYLOAD_LEN,
    );
}

async fn exchange_client(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<()> {
    write_sequence(stream, 0x5a, CLIENT_PAYLOAD_LEN).await?;
    let payload = read_udp_payload(stream).await?;
    validate_payload(&payload, 0xa5, SERVER_PAYLOAD_LEN)?;
    stream.shutdown().await
}

async fn exchange_server(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<()> {
    let payload = read_udp_payload(stream).await?;
    validate_payload(&payload, 0x5a, CLIENT_PAYLOAD_LEN)?;
    write_sequence(stream, 0xa5, SERVER_PAYLOAD_LEN).await?;
    stream.shutdown().await
}

async fn write_sequence(
    stream: &mut (impl AsyncWrite + Unpin),
    payload_byte: u8,
    payload_len: usize,
) -> io::Result<()> {
    let mut bytes = Vec::new();
    append_capsule(&mut bytes, 0x21, b"unknown-capsule");
    let mut unknown_context = Vec::new();
    encode_varint(2, &mut unknown_context);
    unknown_context.extend_from_slice(b"unknown-context");
    append_capsule(&mut bytes, 0, &unknown_context);
    let mut datagram = Vec::with_capacity(payload_len + 8);
    encode_varint(0, &mut datagram);
    datagram.extend(std::iter::repeat_n(payload_byte, payload_len));
    append_capsule(&mut bytes, 0, &datagram);

    let mut offset = 0;
    let mut chunk_len = 1;
    while offset < bytes.len() {
        let end = (offset + chunk_len).min(bytes.len());
        timeout(IO_TIMEOUT, stream.write_all(&bytes[offset..end]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "capsule write timeout"))??;
        offset = end;
        chunk_len = (chunk_len * 2 % 17) + 1;
    }
    stream.flush().await
}

async fn read_udp_payload(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut buffered = Vec::new();
    loop {
        let mut consumed = 0;
        while consumed < buffered.len() {
            let Some((capsule_len, capsule_type, value)) = parse_capsule(&buffered[consumed..])?
            else {
                break;
            };
            consumed += capsule_len;
            if capsule_type != 0 {
                continue;
            }
            let Some((context_id, context_len)) = decode_varint(value) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "complete DATAGRAM capsule lacks Context ID",
                ));
            };
            if context_id == 0 {
                return Ok(value[context_len..].to_vec());
            }
        }
        if consumed != 0 {
            buffered.drain(..consumed);
        }
        if buffered.len() > 65_560 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete capsule exceeds bound",
            ));
        }
        let mut chunk = [0; 4096];
        let count = timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "capsule read timeout"))??;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "capsule stream ended before UDP payload",
            ));
        }
        buffered.extend_from_slice(&chunk[..count]);
    }
}

fn append_capsule(out: &mut Vec<u8>, capsule_type: u64, value: &[u8]) {
    encode_varint(capsule_type, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn parse_capsule(bytes: &[u8]) -> io::Result<Option<(usize, u64, &[u8])>> {
    let Some((capsule_type, type_len)) = decode_varint(bytes) else {
        return Ok(None);
    };
    let Some((value_len, length_len)) = decode_varint(&bytes[type_len..]) else {
        return Ok(None);
    };
    let value_len = usize::try_from(value_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "capsule length overflow"))?;
    let header_len = type_len + length_len;
    let total_len = header_len
        .checked_add(value_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "capsule length overflow"))?;
    if bytes.len() < total_len {
        return Ok(None);
    }
    Ok(Some((
        total_len,
        capsule_type,
        &bytes[header_len..total_len],
    )))
}

fn encode_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => panic!("QUIC varint overflow"),
    }
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

fn validate_payload(payload: &[u8], expected: u8, len: usize) -> io::Result<()> {
    if payload.len() != len || payload.iter().any(|byte| *byte != expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected UDP payload len={} expected={len}",
                payload.len()
            ),
        ));
    }
    Ok(())
}

fn header_contains_token(
    request: &Request<hyper::body::Incoming>,
    name: &'static str,
    token: &str,
) -> bool {
    request.headers().get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|text| {
            text.split(',')
                .any(|member| member.trim().eq_ignore_ascii_case(token))
        })
    })
}

async fn client_io(port: u16, ca_path: Option<&str>, version: HttpVersion) -> MaybeTls {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz CONNECT-UDP peer");
    stream.set_nodelay(true).expect("set client TCP_NODELAY");
    let Some(ca_path) = ca_path else {
        return MaybeTls::Clear(stream);
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        rustls_pemfile::certs(&mut BufReader::new(
            File::open(Path::new(ca_path)).expect("open CA certificate"),
        ))
        .map(|result| result.expect("parse CA certificate")),
    );
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn(version).to_vec()];
    let tls = TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").expect("valid server name"),
            stream,
        )
        .await
        .expect("connect TLS CONNECT-UDP peer");
    validate_alpn(tls.get_ref().1.alpn_protocol(), version);
    MaybeTls::Client(tls)
}

async fn server_io(
    stream: TcpStream,
    tls_paths: Option<&(String, String)>,
    version: HttpVersion,
) -> MaybeTls {
    let Some((cert, key)) = tls_paths else {
        return MaybeTls::Clear(stream);
    };
    let tls = TlsAcceptor::from(tls_server_config(cert, key, version))
        .accept(stream)
        .await
        .expect("accept TLS CONNECT-UDP peer");
    validate_alpn(tls.get_ref().1.alpn_protocol(), version);
    MaybeTls::Server(tls)
}

fn tls_server_config(
    cert_path: &str,
    key_path: &str,
    version: HttpVersion,
) -> Arc<rustls::ServerConfig> {
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
    config.alpn_protocols = vec![alpn(version).to_vec()];
    Arc::new(config)
}

fn alpn(version: HttpVersion) -> &'static [u8] {
    match version {
        HttpVersion::Http1 => b"http/1.1",
        HttpVersion::Http2 => b"h2",
    }
}

fn validate_alpn(selected: Option<&[u8]>, version: HttpVersion) {
    match version {
        // RFC 9112 permits HTTP/1.1 TLS without ALPN; netz deliberately keeps
        // that legacy-compatible path while accepting an explicit selection.
        HttpVersion::Http1 => assert!(selected.is_none() || selected == Some(alpn(version))),
        HttpVersion::Http2 => assert_eq!(selected, Some(alpn(version))),
    }
}

fn transport_name(tls: bool) -> &'static str {
    if tls {
        "tls"
    } else {
        "cleartext"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varint_boundaries_round_trip() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ] {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded);
            assert_eq!(decode_varint(&encoded), Some((value, encoded.len())));
            for split in 0..encoded.len() {
                assert_eq!(decode_varint(&encoded[..split]), None);
            }
        }
    }

    #[test]
    fn capsule_parser_waits_for_every_fragment() {
        let value = vec![0x5a; CLIENT_PAYLOAD_LEN + 1];
        let mut encoded = Vec::new();
        append_capsule(&mut encoded, 0, &value);
        for split in 0..encoded.len() {
            assert!(parse_capsule(&encoded[..split]).unwrap().is_none());
        }
        let parsed = parse_capsule(&encoded).unwrap().unwrap();
        assert_eq!(parsed.0, encoded.len());
        assert_eq!(parsed.1, 0);
        assert_eq!(parsed.2, value);
    }
}
