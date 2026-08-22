use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use s2n_quic::{client::Connect, provider::tls, Client, Server};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::time::{sleep, timeout};

const ALPN: &[u8] = b"hq-interop";
const PAYLOADS: [&[u8]; 2] = [b"hello", b"world"];
const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("server") => {
            let port = parse_port(args.next())?;
            let certificate = args.next().context("server requires CERT")?;
            let private_key = args.next().context("server requires KEY")?;
            ensure!(args.next().is_none(), "unexpected server argument");
            run_server(port, &certificate, &private_key).await
        }
        Some("client") => {
            let port = parse_port(args.next())?;
            let ca = args.next().context("client requires CA")?;
            ensure!(args.next().is_none(), "unexpected client argument");
            run_client(port, &ca).await
        }
        _ => bail!("usage: netz-quic-s2n-interop server PORT CERT KEY | client PORT CA"),
    }
}

fn parse_port(value: Option<String>) -> Result<u16> {
    let port = value.context("missing port")?.parse::<u16>()?;
    ensure!(port != 0, "port must be non-zero");
    Ok(port)
}

async fn run_server(port: u16, certificate: &str, private_key: &str) -> Result<()> {
    let mut tls_builder = tls::default::Server::builder();
    tls_builder
        .config_mut()
        .set_security_policy(&tls::default::security::DEFAULT_TLS13)?;
    let tls = tls_builder
        .with_application_protocols([ALPN])?
        .with_certificate(Path::new(certificate), Path::new(private_key))?
        .build()?;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut server = Server::builder().with_tls(tls)?.with_io(address)?.start()?;
    println!("s2n-quic interop server listening={address}");

    let mut connection = timeout(TIMEOUT, server.accept())
        .await
        .context("incoming connection timed out")?
        .context("server endpoint closed before accepting a connection")?;
    ensure!(
        connection.application_protocol()?.as_ref() == ALPN,
        "unexpected ALPN"
    );
    ensure!(
        connection.server_name()?.as_deref() == Some("localhost"),
        "unexpected SNI"
    );

    let mut streams = Vec::with_capacity(PAYLOADS.len());
    for (index, expected) in PAYLOADS.into_iter().enumerate() {
        let mut stream = timeout(TIMEOUT, connection.accept_bidirectional_stream())
            .await
            .context("bidirectional stream timed out")??
            .context("connection closed before the expected stream")?;
        ensure!(stream.id() == (index as u64) * 4, "unexpected stream id");
        let request = receive_all(&mut stream).await?;
        ensure!(request == expected, "unexpected request payload");
        stream.send(Bytes::copy_from_slice(expected)).await?;
        streams.push(stream);
    }

    // Accept and populate both streams before emitting their FINs. Netz sends
    // both requests concurrently, so serial close while accepting would
    // deadlock behind the second request's unread response.
    for stream in &mut streams {
        stream.finish()?;
    }
    // Let the endpoint transmit both queued responses before application close
    // supersedes stream output in this deliberately short-lived fixture.
    sleep(Duration::from_millis(250)).await;
    connection.close(57u8.into());
    // Connection::close only queues CONNECTION_CLOSE. Keep the endpoint alive
    // briefly so the packet is emitted before this one-shot process exits.
    sleep(Duration::from_millis(250)).await;
    println!(
        "s2n-quic server interoperated with netz: version=1 alpn=hq-interop sni=localhost streams=2 bytes=10 peer_close=57"
    );
    Ok(())
}

async fn run_client(port: u16, ca: &str) -> Result<()> {
    // Clear platform roots first so a successful connection proves that the
    // checked-in netz localhost certificate, rather than ambient trust, was
    // used to authenticate the server.
    let tls = tls::default::Client::builder()
        .with_empty_trust_store()?
        .with_certificate(Path::new(ca))?
        .with_application_protocols([ALPN])?
        .build()?;
    let mut client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()?;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let connect = Connect::new(address).with_server_name("localhost");
    let mut connection = timeout(TIMEOUT, client.connect(connect))
        .await
        .context("QUIC handshake timed out")??;
    ensure!(
        connection.application_protocol()?.as_ref() == ALPN,
        "unexpected ALPN"
    );

    for (index, payload) in PAYLOADS.into_iter().enumerate() {
        let mut stream = timeout(TIMEOUT, connection.open_bidirectional_stream())
            .await
            .context("stream open timed out")??;
        ensure!(stream.id() == (index as u64) * 4, "unexpected stream id");
        stream.send(Bytes::copy_from_slice(payload)).await?;
        stream.finish()?;
        let response = receive_all(&mut stream).await?;
        ensure!(response == payload, "unexpected echo payload");
    }

    let close = timeout(TIMEOUT, connection.accept_bidirectional_stream())
        .await
        .context("peer close timed out")?
        .expect_err("netz server opened an unexpected stream");
    match close {
        s2n_quic::connection::Error::Application { error, .. } => {
            ensure!(u64::from(error) == 58, "unexpected peer close code");
        }
        other => bail!("unexpected peer close: {other}"),
    }

    drop(connection);
    client.wait_idle().await?;
    println!(
        "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop streams=2 bytes=10 peer_close=58"
    );
    Ok(())
}

async fn receive_all(stream: &mut s2n_quic::stream::BidirectionalStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        match timeout(TIMEOUT, stream.receive())
            .await
            .context("stream receive timed out")??
        {
            Some(chunk) => bytes.extend_from_slice(&chunk),
            None => return Ok(bytes),
        }
    }
}
