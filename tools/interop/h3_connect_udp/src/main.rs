//! Independent h3/quinn RFC 9298 peer for netz process interoperability.

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::quinn;
use http::{Method, Request, Response, StatusCode, Version};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const TARGET_PATH: &str = "/.well-known/masque/udp/dns.example/53/";
const CLIENT_PAYLOAD_LEN: usize = 513;
const SERVER_PAYLOAD_LEN: usize = 777;
const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/*/*/";
const CLIENT_IP_PACKET: [u8; 20] = [
    0x45, 0, 0, 20, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71,
];
const SERVER_IP_PACKET: [u8; 40] = [
    0x60, 0, 0, 0, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82,
    0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82,
    0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82,
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut args = env::args().skip(1);
    let role = args.next().ok_or("client or server role")?;
    let port: u16 = args.next().ok_or("port")?.parse()?;
    if port == 0 {
        return Err("port must be nonzero".into());
    }
    match role.as_str() {
        "server" => {
            let cert = args.next().ok_or("certificate DER path")?;
            let key = args.next().ok_or("PKCS#8 key DER path")?;
            if args.next().is_some() {
                return Err("unexpected server argument".into());
            }
            run_server(port, &cert, &key).await
        }
        "client" => {
            let ca = args.next().ok_or("CA DER path")?;
            if args.next().is_some() {
                return Err("unexpected client argument".into());
            }
            run_client(port, &ca).await
        }
        "ip-server" => {
            let cert = args.next().ok_or("certificate DER path")?;
            let key = args.next().ok_or("PKCS#8 key DER path")?;
            if args.next().is_some() {
                return Err("unexpected ip-server argument".into());
            }
            run_ip_server(port, &cert, &key).await
        }
        "ip-client" => {
            let ca = args.next().ok_or("CA DER path")?;
            if args.next().is_some() {
                return Err("unexpected ip-client argument".into());
            }
            run_ip_client(port, &ca).await
        }
        _ => Err(format!("unsupported role: {role}").into()),
    }
}

async fn run_ip_server(port: u16, cert_path: &str, key_path: &str) -> Result<(), Box<dyn Error>> {
    let cert = CertificateDer::from(fs::read(cert_path)?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key_path)?));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    server_config.transport = Arc::new(transport);
    let endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    println!("h3/quinn CONNECT-IP server listening on 127.0.0.1:{port}");
    io::stdout().flush()?;

    let incoming = timeout(IO_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| "CONNECT-IP server QUIC accept timeout")?
        .ok_or("CONNECT-IP endpoint closed before connection")?;
    let connection = timeout(IO_TIMEOUT, incoming)
        .await
        .map_err(|_| "CONNECT-IP server QUIC handshake timeout")??;
    let raw_connection = connection.clone();
    let mut h3_connection = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(true)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let resolver = timeout(IO_TIMEOUT, h3_connection.accept())
        .await
        .map_err(|_| "CONNECT-IP server request timeout")??
        .ok_or("client closed before CONNECT-IP")?;
    let (request, mut stream) = timeout(IO_TIMEOUT, resolver.resolve_request())
        .await
        .map_err(|_| "CONNECT-IP request resolution timeout")??;
    validate_ip_request(&request)?;
    let stream_id = stream.id();
    let mut datagram_sender = h3_connection.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_connection.get_datagram_reader();
    let driver = tokio::spawn(async move {
        loop {
            match h3_connection.accept().await {
                Ok(Some(_)) => return Err("unexpected second request".to_string()),
                Ok(None) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            }
        }
    });
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())?;
    timeout(IO_TIMEOUT, stream.send_response(response)).await??;

    let mut request_data = timeout(IO_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| "CONNECT-IP ADDRESS_REQUEST timeout")??
        .ok_or("missing CONNECT-IP ADDRESS_REQUEST")?;
    let request_capsule = request_data.copy_to_bytes(request_data.remaining());
    validate_address_request(&request_capsule, 21)?;
    let packet = read_context_zero(&mut datagram_reader, stream_id).await?;
    if packet != CLIENT_IP_PACKET {
        return Err("invalid CONNECT-IP client packet".into());
    }
    stream
        .send_data(Bytes::from(encode_address_assign(21, [192, 0, 2, 21])))
        .await?;
    send_context_zero(&mut datagram_sender, &SERVER_IP_PACKET)?;
    let ack = read_context_zero(&mut datagram_reader, stream_id).await?;
    if ack != b"netz-ip-ack" {
        return Err("invalid CONNECT-IP delivery acknowledgment".into());
    }
    let request_end = timeout(IO_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| "CONNECT-IP request FIN timeout")??;
    if request_end.is_some() {
        return Err("CONNECT-IP request carried unexpected extra DATA".into());
    }
    timeout(IO_TIMEOUT, stream.finish()).await??;
    timeout(IO_TIMEOUT, raw_connection.closed())
        .await
        .map_err(|_| "CONNECT-IP peer close timeout")?;
    let _ = timeout(IO_TIMEOUT, driver).await;
    endpoint.wait_idle().await;
    println!(
        "h3/quinn CONNECT-IP server interoperated with netz: address_request=true address_assign=true received_ip={} sent_ip={} delivery_ack=true request_fin=true response_fin=true",
        CLIENT_IP_PACKET.len(), SERVER_IP_PACKET.len(),
    );
    Ok(())
}

async fn run_ip_client(port: u16, ca_path: &str) -> Result<(), Box<dyn Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(fs::read(ca_path)?))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    client_config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(client_config);
    let connection = timeout(
        IO_TIMEOUT,
        endpoint.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), "localhost")?,
    )
    .await
    .map_err(|_| "CONNECT-IP client QUIC handshake timeout")??;
    let raw_connection = connection.clone();
    let (mut h3_connection, mut sender) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(true)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_3)
        .uri(format!("https://localhost{CONNECT_IP_PATH}"))
        .header("capsule-protocol", "?1")
        .body(())?;
    request.extensions_mut().insert(Protocol::CONNECT_IP);
    let mut stream = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| "CONNECT-IP request send timeout")??;
    let stream_id = stream.id();
    let mut datagram_sender = h3_connection.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_connection.get_datagram_reader();
    let driver = tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });
    let response = timeout(IO_TIMEOUT, stream.recv_response())
        .await
        .map_err(|_| "CONNECT-IP response timeout")??;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok())
            != Some("?1")
    {
        return Err("invalid CONNECT-IP response".into());
    }
    stream
        .send_data(Bytes::from(encode_address_request(21)))
        .await?;
    send_context_zero(&mut datagram_sender, &CLIENT_IP_PACKET)?;
    let packet = read_context_zero(&mut datagram_reader, stream_id).await?;
    if packet != SERVER_IP_PACKET {
        return Err("invalid CONNECT-IP server packet".into());
    }
    let mut response_data = timeout(IO_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| "CONNECT-IP ADDRESS_ASSIGN timeout")??
        .ok_or("missing CONNECT-IP ADDRESS_ASSIGN")?;
    let assignment = response_data.copy_to_bytes(response_data.remaining());
    validate_address_assign(&assignment, 21, [192, 0, 2, 21])?;
    send_context_zero(&mut datagram_sender, b"h3-ip-ack")?;
    timeout(IO_TIMEOUT, stream.finish()).await??;
    let response_end = timeout(IO_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| "CONNECT-IP response FIN timeout")??;
    if response_end.is_some() {
        return Err("CONNECT-IP response carried unexpected extra DATA".into());
    }
    raw_connection.close(0u32.into(), b"CONNECT-IP complete");
    let _ = timeout(IO_TIMEOUT, driver).await;
    endpoint.wait_idle().await;
    println!(
        "h3/quinn CONNECT-IP client interoperated with netz: address_request=true address_assign=true sent_ip={} received_ip={} delivery_ack=true request_fin=true response_fin=true",
        CLIENT_IP_PACKET.len(), SERVER_IP_PACKET.len(),
    );
    Ok(())
}

async fn run_server(port: u16, cert_path: &str, key_path: &str) -> Result<(), Box<dyn Error>> {
    let cert = CertificateDer::from(fs::read(cert_path)?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key_path)?));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    server_config.transport = Arc::new(transport);
    let endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    println!("h3/quinn CONNECT-UDP server listening on 127.0.0.1:{port}");
    io::stdout().flush()?;

    let incoming = timeout(IO_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| "server QUIC accept timeout")?
        .ok_or("endpoint closed before connection")?;
    let quinn_connection = timeout(IO_TIMEOUT, incoming)
        .await
        .map_err(|_| "server QUIC handshake timeout")??;
    let raw_connection = quinn_connection.clone();
    let mut h3_connection = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(true)
        .build(h3_quinn::Connection::new(quinn_connection))
        .await?;
    let resolver = timeout(IO_TIMEOUT, h3_connection.accept())
        .await
        .map_err(|_| "server H3 request timeout")??
        .ok_or("client closed before CONNECT-UDP")?;
    let (request, mut request_stream) = timeout(IO_TIMEOUT, resolver.resolve_request())
        .await
        .map_err(|_| "server H3 request resolution timeout")??;
    validate_request(&request)?;
    let stream_id = request_stream.id();
    let mut datagram_sender = h3_connection.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_connection.get_datagram_reader();
    let driver = tokio::spawn(async move {
        loop {
            match h3_connection.accept().await {
                Ok(Some(_)) => return Err("unexpected second request".to_string()),
                Ok(None) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            }
        }
    });

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())?;
    timeout(IO_TIMEOUT, request_stream.send_response(response)).await??;

    let received = read_context_sequence(&mut datagram_reader, stream_id).await?;
    validate_payload(&received, 0x5a, CLIENT_PAYLOAD_LEN)?;
    let proxied = udp_round_trip(&received).await?;
    validate_payload(&proxied, 0x5a, CLIENT_PAYLOAD_LEN)?;
    send_context_sequence(&mut datagram_sender, 0xa5, SERVER_PAYLOAD_LEN)?;
    let ack = read_context_zero(&mut datagram_reader, stream_id).await?;
    if ack != b"netz-ack" {
        return Err("invalid netz delivery acknowledgment".into());
    }
    timeout(IO_TIMEOUT, request_stream.finish()).await??;

    raw_connection.close(0u32.into(), b"CONNECT-UDP complete");
    let _ = timeout(IO_TIMEOUT, driver).await;
    endpoint.wait_idle().await;
    println!(
        "h3/quinn CONNECT-UDP server interoperated with netz: received={} proxied_udp=true sent={} settings_datagram=true settings_extended_connect=true unknown_context=true delivery_ack=true response_fin=true",
        CLIENT_PAYLOAD_LEN, SERVER_PAYLOAD_LEN,
    );
    Ok(())
}

async fn run_client(port: u16, ca_path: &str) -> Result<(), Box<dyn Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(fs::read(ca_path)?))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    client_config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(client_config);
    let quinn_connection = timeout(
        IO_TIMEOUT,
        endpoint.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), "localhost")?,
    )
    .await
    .map_err(|_| "client QUIC handshake timeout")??;
    let raw_connection = quinn_connection.clone();
    let (mut h3_connection, mut request_sender) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(true)
        .build(h3_quinn::Connection::new(quinn_connection))
        .await?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_3)
        .uri(format!("https://localhost{TARGET_PATH}"))
        .header("capsule-protocol", "?1")
        .body(())?;
    request.extensions_mut().insert(Protocol::CONNECT_UDP);
    let mut request_stream = timeout(IO_TIMEOUT, request_sender.send_request(request))
        .await
        .map_err(|_| "client H3 request send timeout")??;
    let stream_id = request_stream.id();
    let mut datagram_sender = h3_connection.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_connection.get_datagram_reader();
    let driver = tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });

    let response = timeout(IO_TIMEOUT, request_stream.recv_response())
        .await
        .map_err(|_| "client H3 response timeout")??;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok())
            != Some("?1")
    {
        return Err("invalid CONNECT-UDP response".into());
    }
    eprintln!("h3/quinn client received CONNECT-UDP response");
    send_context_sequence(&mut datagram_sender, 0x5a, CLIENT_PAYLOAD_LEN)?;
    eprintln!("h3/quinn client queued CONNECT-UDP datagrams");
    let received = read_context_sequence(&mut datagram_reader, stream_id).await?;
    eprintln!("h3/quinn client received CONNECT-UDP datagrams");
    validate_payload(&received, 0xa5, SERVER_PAYLOAD_LEN)?;
    timeout(IO_TIMEOUT, request_stream.finish())
        .await
        .map_err(|_| "client request FIN timeout")??;
    let response_end = timeout(IO_TIMEOUT, request_stream.recv_data())
        .await
        .map_err(|_| "client response FIN timeout")??;
    if response_end.is_some() {
        return Err("CONNECT-UDP response carried unexpected DATA".into());
    }

    raw_connection.close(0u32.into(), b"CONNECT-UDP complete");
    let _ = timeout(IO_TIMEOUT, driver).await;
    endpoint.wait_idle().await;
    println!(
        "h3/quinn CONNECT-UDP client interoperated with netz: sent={} received={} settings_datagram=true settings_extended_connect=true unknown_context=true request_fin=true response_fin=true",
        CLIENT_PAYLOAD_LEN, SERVER_PAYLOAD_LEN,
    );
    Ok(())
}

fn validate_request(request: &Request<()>) -> Result<(), Box<dyn Error>> {
    if request.method() != Method::CONNECT
        || request.version() != Version::HTTP_3
        || request.uri().scheme_str() != Some("https")
        || request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            != Some("localhost")
        || request.uri().path() != TARGET_PATH
        || request
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok())
            != Some("?1")
        || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP)
    {
        return Err("invalid CONNECT-UDP request".into());
    }
    Ok(())
}

fn send_context_sequence<H>(
    sender: &mut h3_datagram::datagram_handler::DatagramSender<H, Bytes>,
    payload_byte: u8,
    payload_len: usize,
) -> Result<(), Box<dyn Error>>
where
    H: h3_datagram::quic_traits::SendDatagram<Bytes>,
{
    let mut unknown = Vec::with_capacity(16);
    encode_varint(2, &mut unknown);
    unknown.extend_from_slice(b"unknown-context");
    sender.send_datagram(Bytes::from(unknown))?;

    let mut valid = Vec::with_capacity(payload_len + 1);
    encode_varint(0, &mut valid);
    valid.extend(std::iter::repeat_n(payload_byte, payload_len));
    sender.send_datagram(Bytes::from(valid))?;
    Ok(())
}

async fn read_context_sequence<H>(
    reader: &mut h3_datagram::datagram_handler::DatagramReader<H>,
    stream_id: h3::quic::StreamId,
) -> Result<Vec<u8>, Box<dyn Error>>
where
    H: h3_datagram::quic_traits::RecvDatagram<Buffer = Bytes>,
{
    let mut saw_unknown = false;
    let mut valid = None;
    for _ in 0..2 {
        let datagram = timeout(IO_TIMEOUT, reader.read_datagram())
            .await
            .map_err(|_| "HTTP/3 datagram read timeout")??;
        if datagram.stream_id() != stream_id {
            return Err("datagram associated with unexpected stream".into());
        }
        let payload = datagram.into_payload();
        let (context_id, prefix_len) = decode_varint(&payload).ok_or("missing Context ID")?;
        match context_id {
            0 => valid = Some(payload[prefix_len..].to_vec()),
            2 => saw_unknown = true,
            _ => return Err("unexpected Context ID".into()),
        }
    }
    if !saw_unknown {
        return Err("unknown Context ID was not received".into());
    }
    valid.ok_or_else(|| "Context ID 0 payload was not received".into())
}

async fn read_context_zero<H>(
    reader: &mut h3_datagram::datagram_handler::DatagramReader<H>,
    stream_id: h3::quic::StreamId,
) -> Result<Vec<u8>, Box<dyn Error>>
where
    H: h3_datagram::quic_traits::RecvDatagram<Buffer = Bytes>,
{
    let datagram = timeout(IO_TIMEOUT, reader.read_datagram())
        .await
        .map_err(|_| "HTTP/3 delivery acknowledgment timeout")??;
    if datagram.stream_id() != stream_id {
        return Err("datagram associated with unexpected stream".into());
    }
    let payload = datagram.into_payload();
    let (context_id, prefix_len) = decode_varint(&payload).ok_or("missing Context ID")?;
    if context_id != 0 {
        return Err("delivery acknowledgment used unexpected Context ID".into());
    }
    Ok(payload[prefix_len..].to_vec())
}

fn send_context_zero<H>(
    sender: &mut h3_datagram::datagram_handler::DatagramSender<H, Bytes>,
    payload: &[u8],
) -> Result<(), Box<dyn Error>>
where
    H: h3_datagram::quic_traits::SendDatagram<Bytes>,
{
    let mut encoded = Vec::with_capacity(payload.len() + 1);
    encode_varint(0, &mut encoded);
    encoded.extend_from_slice(payload);
    sender.send_datagram(Bytes::from(encoded))?;
    Ok(())
}

fn encode_address_request(request_id: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(7);
    encode_varint(request_id, &mut value);
    value.extend_from_slice(&[4, 0, 0, 0, 0, 32]);
    encode_capsule(0x02, &value)
}

fn encode_address_assign(request_id: u64, address: [u8; 4]) -> Vec<u8> {
    let mut value = Vec::with_capacity(7);
    encode_varint(request_id, &mut value);
    value.push(4);
    value.extend_from_slice(&address);
    value.push(32);
    encode_capsule(0x01, &value)
}

fn encode_capsule(capsule_type: u64, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 2);
    encode_varint(capsule_type, &mut encoded);
    encode_varint(value.len() as u64, &mut encoded);
    encoded.extend_from_slice(value);
    encoded
}

fn decode_capsule(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (capsule_type, type_len) = decode_varint(bytes)?;
    let (value_len, length_len) = decode_varint(&bytes[type_len..])?;
    let start = type_len + length_len;
    let end = start.checked_add(value_len as usize)?;
    if end != bytes.len() {
        return None;
    }
    Some((capsule_type, &bytes[start..end]))
}

fn validate_address_request(bytes: &[u8], request_id: u64) -> Result<(), Box<dyn Error>> {
    let (capsule_type, value) = decode_capsule(bytes).ok_or("malformed ADDRESS_REQUEST")?;
    let (actual_id, id_len) = decode_varint(value).ok_or("missing request ID")?;
    if capsule_type != 0x02 || actual_id != request_id || value[id_len..] != [4, 0, 0, 0, 0, 32] {
        return Err("invalid ADDRESS_REQUEST".into());
    }
    Ok(())
}

fn validate_address_assign(
    bytes: &[u8],
    request_id: u64,
    address: [u8; 4],
) -> Result<(), Box<dyn Error>> {
    let (capsule_type, value) = decode_capsule(bytes).ok_or("malformed ADDRESS_ASSIGN")?;
    let (actual_id, id_len) = decode_varint(value).ok_or("missing assignment ID")?;
    if value.len() != id_len + 6
        || capsule_type != 0x01
        || actual_id != request_id
        || value[id_len] != 4
        || value[id_len + 1..id_len + 5] != address
        || value[id_len + 5] != 32
    {
        return Err("invalid ADDRESS_ASSIGN".into());
    }
    Ok(())
}

fn validate_ip_request(request: &Request<()>) -> Result<(), Box<dyn Error>> {
    if request.method() != Method::CONNECT
        || request.version() != Version::HTTP_3
        || request.uri().scheme_str() != Some("https")
        || request.uri().authority().map(|value| value.as_str()) != Some("localhost")
        || request.uri().path() != CONNECT_IP_PATH
        || request
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok())
            != Some("?1")
        || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_IP)
    {
        return Err("invalid CONNECT-IP request".into());
    }
    Ok(())
}

async fn udp_round_trip(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut storage = [0u8; 2048];
        let (len, from) = echo.recv_from(&mut storage).await?;
        echo.send_to(&storage[..len], from).await?;
        Ok::<(), io::Error>(())
    });
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    relay.send_to(payload, target).await?;
    let mut response = vec![0u8; 2048];
    let (len, from) = timeout(IO_TIMEOUT, relay.recv_from(&mut response)).await??;
    if from != target {
        return Err("UDP response source mismatch".into());
    }
    response.truncate(len);
    timeout(IO_TIMEOUT, echo_task).await???;
    Ok(response)
}

fn validate_payload(payload: &[u8], expected: u8, len: usize) -> Result<(), Box<dyn Error>> {
    if payload.len() != len || payload.iter().any(|byte| *byte != expected) {
        return Err(format!("unexpected payload len={}, expected={len}", payload.len()).into());
    }
    Ok(())
}

fn encode_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1usize << (first >> 6);
    if bytes.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_varints_round_trip() {
        for value in [0, 2, 63, 64, 16_383, 16_384, 1_073_741_823] {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded);
            assert_eq!(decode_varint(&encoded), Some((value, encoded.len())));
        }
    }

    #[test]
    fn connect_ip_capsules_round_trip() {
        let request = encode_address_request(21);
        validate_address_request(&request, 21).unwrap();
        let assignment = encode_address_assign(21, [192, 0, 2, 21]);
        validate_address_assign(&assignment, 21, [192, 0, 2, 21]).unwrap();
    }
}
