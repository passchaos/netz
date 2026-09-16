use anyhow::{bail, ensure, Context, Result};
use quinn::rustls::{
    self,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
};
use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, ConnectionError, Endpoint, ServerConfig, TransportConfig, VarInt,
};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};

mod datagram;

const ALPN: &[u8] = b"hq-interop";
const TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("server") => {
            let port = parse_port(args.next())?;
            let cert = args.next().context("server requires CERT")?;
            let key = args.next().context("server requires KEY")?;
            ensure!(args.next().is_none(), "unexpected server argument");
            run_server(port, &cert, &key).await
        }
        Some("client") => {
            let port = parse_port(args.next())?;
            let ca = args.next().context("client requires CA")?;
            ensure!(args.next().is_none(), "unexpected client argument");
            run_client(port, &ca).await
        }
        _ => bail!("usage: netz-quic-quinn-interop server PORT CERT KEY | client PORT CA"),
    }
}

fn parse_port(value: Option<String>) -> Result<u16> {
    let port = value.context("missing port")?.parse::<u16>()?;
    ensure!(port != 0, "port must be non-zero");
    Ok(port)
}

fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        .datagram_receive_buffer_size(Some(64 * 1024))
        .datagram_send_buffer_size(64 * 1024)
        .mtu_discovery_config(None);
    Arc::new(config)
}

async fn run_server(port: u16, cert_path: &str, key_path: &str) -> Result<()> {
    let certificates = CertificateDer::pem_file_iter(Path::new(cert_path))
        .context("reading Quinn server certificate")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing Quinn server certificate")?;
    let private_key = PrivateKeyDer::from_pem_file(Path::new(key_path))
        .context("reading Quinn server private key")?;
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_config)?));
    server_config.transport_config(transport_config());

    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let endpoint = Endpoint::server(server_config, address)?;
    println!("Quinn interop server listening={address}");
    println!(
        "Quinn interop runtime: endpoint_role=server client_io=zio-std-io server_io=quinn-tokio-rustls"
    );
    let incoming = timeout(TIMEOUT, endpoint.accept())
        .await
        .context("incoming Quinn connection timed out")?
        .context("Quinn endpoint closed before accepting a connection")?;
    let connection = timeout(TIMEOUT, incoming)
        .await
        .context("Quinn server handshake timed out")??;
    verify_handshake(&connection, true)?;
    let outcome = datagram::run(&connection, datagram::Role::Server).await?;

    sleep(Duration::from_millis(250)).await;
    connection.close(VarInt::from_u32(57), b"quinn interop complete");
    timeout(TIMEOUT, endpoint.wait_idle())
        .await
        .context("Quinn server close timed out")?;
    println!(
        "Quinn server interoperated with netz: verified=true version=1 alpn=hq-interop sni=localhost datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={} quinn_boundary_bytes={} oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls",
        outcome.netz_boundary_bytes,
        outcome.quinn_boundary_bytes,
    );
    Ok(())
}

async fn run_client(port: u16, ca_path: &str) -> Result<()> {
    println!(
        "Quinn interop runtime: endpoint_role=client client_io=quinn-tokio-rustls server_io=zio-std-io"
    );
    let mut roots = rustls::RootCertStore::empty();
    for cert in
        CertificateDer::pem_file_iter(Path::new(ca_path)).context("reading Quinn client CA")?
    {
        roots.add(cert.context("parsing Quinn client CA")?)?;
    }
    let mut rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];
    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?));
    client_config.transport_config(transport_config());

    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let connection = timeout(TIMEOUT, endpoint.connect(address, "localhost")?)
        .await
        .context("Quinn client handshake timed out")??;
    verify_handshake(&connection, false)?;
    let outcome = datagram::run(&connection, datagram::Role::Client).await?;

    let close = timeout(TIMEOUT, connection.closed())
        .await
        .context("netz application close timed out")?;
    match close {
        ConnectionError::ApplicationClosed(close) => {
            ensure!(close.error_code.into_inner() == 58, "unexpected close code");
            ensure!(
                close.reason.as_ref() == b"netz interop complete",
                "unexpected close reason"
            );
        }
        other => bail!("unexpected netz close: {other}"),
    }
    endpoint.wait_idle().await;
    println!(
        "Quinn client interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={} quinn_boundary_bytes={} oversized_rejected=true stream_sibling=4 peer_close=58 client_io=quinn-tokio-rustls server_io=zio-std-io",
        outcome.netz_boundary_bytes,
        outcome.quinn_boundary_bytes,
    );
    Ok(())
}

fn verify_handshake(connection: &Connection, server: bool) -> Result<()> {
    let data = connection
        .handshake_data()
        .context("missing Quinn handshake data")?
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow::anyhow!("unexpected Quinn handshake data type"))?;
    ensure!(data.protocol.as_deref() == Some(ALPN), "unexpected ALPN");
    if server {
        ensure!(
            data.server_name.as_deref() == Some("localhost"),
            "unexpected SNI"
        );
    }
    Ok(())
}
