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

mod bench;
mod datagram;
mod handshake_bench;

const ALPN: &[u8] = b"hq-interop";
const TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("handshake-bench-server") => {
            let port = parse_port(args.next())?;
            let cert = args.next().context("benchmark server requires CERT")?;
            let key = args.next().context("benchmark server requires KEY")?;
            let role_pair = args.next().context("benchmark server requires ROLE_PAIR")?;
            let config = handshake_bench::Config::parse(args)?;
            handshake_bench::run_server(port, &cert, &key, &role_pair, config).await
        }
        Some("handshake-bench-client") => {
            let port = parse_port(args.next())?;
            let ca = args.next().context("benchmark client requires CA")?;
            let role_pair = args.next().context("benchmark client requires ROLE_PAIR")?;
            let config = handshake_bench::Config::parse(args)?;
            handshake_bench::run_client(port, &ca, &role_pair, config).await
        }
        Some("bench-server") => {
            let port = parse_port(args.next())?;
            let cert = args.next().context("benchmark server requires CERT")?;
            let key = args.next().context("benchmark server requires KEY")?;
            let role_pair = args.next().context("benchmark server requires ROLE_PAIR")?;
            ensure!(
                role_pair == "netz-client+quinn-server"
                    || role_pair == "quinn-client+quinn-server",
                "invalid benchmark role pair"
            );
            let config = bench::Config::parse(args)?;
            run_bench_server(port, &cert, &key, &role_pair, config).await
        }
        Some("bench-client") => {
            let port = parse_port(args.next())?;
            let ca = args.next().context("benchmark client requires CA")?;
            let role_pair = args.next().context("benchmark client requires ROLE_PAIR")?;
            ensure!(
                role_pair == "quinn-client+quinn-server"
                    || role_pair == "quinn-client+netz-server",
                "invalid benchmark role pair"
            );
            let config = bench::Config::parse(args)?;
            run_bench_client(port, &ca, &role_pair, config).await
        }
        Some("server") => {
            let port = parse_port(args.next())?;
            let cert = args.next().context("server requires CERT")?;
            let key = args.next().context("server requires KEY")?;
            let fault = datagram::Fault::parse(args.next().as_deref())?;
            ensure!(args.next().is_none(), "unexpected server argument");
            run_server(port, &cert, &key, fault).await
        }
        Some("client") => {
            let port = parse_port(args.next())?;
            let ca = args.next().context("client requires CA")?;
            let fault = datagram::Fault::parse(args.next().as_deref())?;
            ensure!(args.next().is_none(), "unexpected client argument");
            run_client(port, &ca, fault).await
        }
        _ => bail!("usage: netz-quic-quinn-interop server PORT CERT KEY [none|loss|reorder] | client PORT CA [none|loss|reorder] | bench-server PORT CERT KEY ROLE_PAIR [OPTIONS] | bench-client PORT CA ROLE_PAIR [OPTIONS] | handshake-bench-server PORT CERT KEY ROLE_PAIR [OPTIONS] | handshake-bench-client PORT CA ROLE_PAIR [OPTIONS]"),
    }
}

fn parse_port(value: Option<String>) -> Result<u16> {
    let port = value.context("missing port")?.parse::<u16>()?;
    ensure!(port != 0, "port must be non-zero");
    Ok(port)
}

fn transport_config_with_mtu(benchmark: bool) -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        .datagram_receive_buffer_size(Some(64 * 1024))
        .datagram_send_buffer_size(64 * 1024)
        .mtu_discovery_config(None);
    if benchmark {
        config.initial_mtu(1200).min_mtu(1200);
    }
    Arc::new(config)
}

fn server_config(cert_path: &str, key_path: &str, benchmark: bool) -> Result<ServerConfig> {
    let certificates = CertificateDer::pem_file_iter(Path::new(cert_path))
        .context("reading Quinn server certificate")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing Quinn server certificate")?;
    let private_key = PrivateKeyDer::from_pem_file(Path::new(key_path))
        .context("reading Quinn server private key")?;
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    rustls_config.alpn_protocols = vec![if benchmark { bench::ALPN } else { ALPN }.to_vec()];
    let mut config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_config)?));
    config.transport_config(transport_config_with_mtu(benchmark));
    Ok(config)
}

fn client_config(ca_path: &str, benchmark: bool) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in
        CertificateDer::pem_file_iter(Path::new(ca_path)).context("reading Quinn client CA")?
    {
        roots.add(cert.context("parsing Quinn client CA")?)?;
    }
    let mut rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![if benchmark { bench::ALPN } else { ALPN }.to_vec()];
    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?));
    config.transport_config(transport_config_with_mtu(benchmark));
    Ok(config)
}

async fn run_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
    fault: datagram::Fault,
) -> Result<()> {
    let server_config = server_config(cert_path, key_path, false)?;

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
    let outcome = datagram::run(&connection, datagram::Role::Server, fault).await?;

    sleep(Duration::from_millis(250)).await;
    connection.close(VarInt::from_u32(57), b"quinn interop complete");
    timeout(TIMEOUT, endpoint.wait_idle())
        .await
        .context("Quinn server close timed out")?;
    match fault {
        datagram::Fault::None => println!(
            "Quinn server interoperated with netz: verified=true version=1 alpn=hq-interop sni=localhost datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={} quinn_boundary_bytes={} oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls",
            outcome.netz_boundary_bytes, outcome.quinn_boundary_bytes,
        ),
        datagram::Fault::Loss => println!(
            "Quinn server interoperated with netz: verified=true version=1 alpn=hq-interop sni=localhost datagram=true fault=loss fault_scope=netz-client-outbound netz_datagrams_received={} first_datagram_missing=true unreliable_not_retransmitted=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls",
            outcome.netz_datagrams_received,
        ),
        datagram::Fault::Reorder => println!(
            "Quinn server interoperated with netz: verified=true version=1 alpn=hq-interop sni=localhost datagram=true fault=reorder fault_scope=netz-client-outbound netz_datagrams_received={} reordered={} all_datagrams_received=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls",
            outcome.netz_datagrams_received, outcome.reordered,
        ),
    }
    Ok(())
}

async fn run_client(port: u16, ca_path: &str, fault: datagram::Fault) -> Result<()> {
    println!(
        "Quinn interop runtime: endpoint_role=client client_io=quinn-tokio-rustls server_io=zio-std-io"
    );
    let client_config = client_config(ca_path, false)?;

    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let connection = timeout(TIMEOUT, endpoint.connect(address, "localhost")?)
        .await
        .context("Quinn client handshake timed out")??;
    verify_handshake(&connection, false)?;
    let outcome = datagram::run(&connection, datagram::Role::Client, fault).await?;

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
    match fault {
        datagram::Fault::None => println!(
            "Quinn client interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={} quinn_boundary_bytes={} oversized_rejected=true stream_sibling=4 peer_close=58 client_io=quinn-tokio-rustls server_io=zio-std-io",
            outcome.netz_boundary_bytes, outcome.quinn_boundary_bytes,
        ),
        datagram::Fault::Loss => println!(
            "Quinn client interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true fault=loss fault_scope=netz-server-outbound netz_datagrams_received={} first_datagram_missing=true unreliable_not_retransmitted=true stream_sibling=4 peer_close=58 client_io=quinn-tokio-rustls server_io=zio-std-io",
            outcome.netz_datagrams_received,
        ),
        datagram::Fault::Reorder => println!(
            "Quinn client interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true fault=reorder fault_scope=netz-server-outbound netz_datagrams_received={} reordered={} all_datagrams_received=true stream_sibling=4 peer_close=58 client_io=quinn-tokio-rustls server_io=zio-std-io",
            outcome.netz_datagrams_received, outcome.reordered,
        ),
    }
    Ok(())
}

async fn run_bench_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
    role_pair: &str,
    config: bench::Config,
) -> Result<()> {
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let endpoint = Endpoint::server(server_config(cert_path, key_path, true)?, address)?;
    println!("QUINN_DATAGRAM_BENCH_PORT={port}");
    let incoming = timeout(config.timeout(), endpoint.accept())
        .await
        .context("benchmark connection timed out")?
        .context("benchmark endpoint closed")?;
    let connection = timeout(config.timeout(), incoming)
        .await
        .context("benchmark handshake timed out")??;
    verify_bench_handshake(&connection)?;
    let result = bench::run_server(&connection, config, role_pair).await?;
    sleep(Duration::from_millis(100)).await;
    connection.close(VarInt::from_u32(59), b"datagram benchmark complete");
    timeout(config.timeout(), endpoint.wait_idle())
        .await
        .context("benchmark server close timed out")?;
    ensure!(
        result.received_bytes != 0 && result.checksum != 0,
        "empty benchmark result"
    );
    Ok(())
}

async fn run_bench_client(
    port: u16,
    ca_path: &str,
    role_pair: &str,
    config: bench::Config,
) -> Result<()> {
    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config(ca_path, true)?);
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let connection = timeout(config.timeout(), endpoint.connect(address, "localhost")?)
        .await
        .context("benchmark handshake timed out")??;
    verify_bench_handshake(&connection)?;
    bench::print_config(
        role_pair,
        "client",
        config,
        connection
            .max_datagram_size()
            .context("DATAGRAM disabled")?,
    );
    bench::run_client(&connection, config, role_pair).await?;
    let close = timeout(config.timeout(), connection.closed())
        .await
        .context("benchmark close timed out")?;
    match close {
        ConnectionError::ApplicationClosed(close) => {
            ensure!(close.error_code.into_inner() == 59, "unexpected close code");
            ensure!(
                close.reason.as_ref() == b"datagram benchmark complete",
                "unexpected close reason"
            );
        }
        other => bail!("unexpected benchmark close: {other}"),
    }
    endpoint.wait_idle().await;
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

fn verify_bench_handshake(connection: &Connection) -> Result<()> {
    let data = connection
        .handshake_data()
        .context("missing benchmark handshake data")?
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow::anyhow!("unexpected benchmark handshake data type"))?;
    ensure!(
        data.protocol.as_deref() == Some(bench::ALPN),
        "unexpected benchmark ALPN"
    );
    Ok(())
}
