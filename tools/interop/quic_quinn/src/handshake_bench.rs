use anyhow::{bail, ensure, Context, Result};
use quinn::rustls::{
    self,
    crypto::ring::{cipher_suite, kx_group},
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
};
use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, ConnectionError, Endpoint, EndpointConfig, ServerConfig,
    TokioRuntime, TransportConfig, VarInt,
};
use std::{
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};

pub const ALPN: &[u8] = b"netz-handshake-bench";
const MARKER_LEN: usize = 16;
const CLOSE_CODE: u32 = 67;
const CLOSE_REASON: &[u8] = b"handshake benchmark complete";

#[derive(Clone, Copy, Debug)]
pub struct Config {
    warmup: usize,
    iterations: usize,
    run: usize,
    timeout_ms: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            warmup: 10,
            iterations: 100,
            run: 1,
            timeout_ms: 10_000,
        }
    }
}

impl Config {
    pub fn parse(args: impl Iterator<Item = String>) -> Result<Self> {
        let mut result = Self::default();
        for argument in args {
            if let Some(value) = argument.strip_prefix("--warmup=") {
                result.warmup = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--iterations=") {
                result.iterations = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--run=") {
                result.run = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--timeout-ms=") {
                result.timeout_ms = value.parse()?;
            } else {
                bail!("unexpected handshake benchmark argument: {argument}");
            }
        }
        ensure!(result.warmup <= 4096, "warmup is too large");
        ensure!(
            (1..=4096).contains(&result.iterations),
            "invalid iterations"
        );
        ensure!(result.run != 0, "invalid run");
        ensure!(
            (1..=600_000).contains(&result.timeout_ms),
            "invalid timeout"
        );
        result.total().context("connection count overflow")?;
        Ok(result)
    }

    fn total(self) -> Option<usize> {
        self.warmup.checked_add(self.iterations)
    }

    fn timeout(self) -> Duration {
        Duration::from_millis(u64::from(self.timeout_ms))
    }
}

pub async fn run_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
    role_pair: &str,
    config: Config,
) -> Result<()> {
    ensure!(
        role_pair == "netz-client+quinn-server" || role_pair == "quinn-client+quinn-server",
        "invalid handshake benchmark role pair",
    );
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let endpoint = server_endpoint(address, cert_path, key_path, config)?;
    println!(
        "QUINN_HANDSHAKE_BENCH_PORT={}",
        endpoint.local_addr()?.port()
    );
    let mut checksum = 0u64;
    for round in 0..config.total().unwrap() {
        let incoming = timeout(config.timeout(), endpoint.accept())
            .await
            .context("benchmark connection timed out")?
            .context("benchmark endpoint closed")?;
        let connection = timeout(config.timeout(), incoming)
            .await
            .context("benchmark handshake timed out")??;
        validate_handshake(&connection, false)?;
        serve_echo_and_close(&connection, round, config.timeout())
            .await
            .with_context(|| format!("handshake server round {round}"))?;
        checksum = checksum.wrapping_add(round as u64);
        drop(connection);
        tokio::task::yield_now().await;
    }
    println!(
        "record=server-complete implementation=quinn protocol=quic-v1 mode=handshake role_pair={role_pair} endpoint_role=server run={} warmup={} iterations={} client_io={} server_io={} timeout_ms={} connections={} echo_bytes={} checksum={checksum} echo_verified=true peer_close=true complete=true",
        config.run, config.warmup, config.iterations, client_io(role_pair),
        server_io(role_pair), config.timeout_ms, config.total().unwrap(),
        config.total().unwrap() * 32,
    );
    endpoint.close(VarInt::from_u32(0), b"benchmark complete");
    endpoint.wait_idle().await;
    Ok(())
}

pub async fn run_client(port: u16, ca_path: &str, role_pair: &str, config: Config) -> Result<()> {
    ensure!(
        role_pair == "quinn-client+quinn-server" || role_pair == "quinn-client+netz-server",
        "invalid handshake benchmark role pair",
    );
    let peer: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let client_config = client_config(ca_path, config)?;
    let mut latencies = Vec::with_capacity(config.iterations);
    let mut checksum = 0u64;
    for round in 0..config.total().unwrap() {
        let endpoint = client_endpoint()?;
        let started = Instant::now();
        let connection = timeout(
            config.timeout(),
            endpoint.connect_with(client_config.clone(), peer, "localhost")?,
        )
        .await
        .context("benchmark handshake timed out")??;
        let elapsed = started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
        validate_handshake(&connection, true)?;
        client_echo_and_close(&connection, round, config.timeout())
            .await
            .with_context(|| format!("handshake client round {round}"))?;
        // Preserve the per-round socket briefly after the timed handshake and
        // verified echo so the peer can observe the submitted close packet.
        sleep(Duration::from_millis(
            if round + 1 == config.total().unwrap() {
                100
            } else {
                5
            },
        ))
        .await;
        checksum = checksum.wrapping_add(round as u64);
        if round >= config.warmup {
            latencies.push(elapsed);
            println!(
                "record=handshake-sample implementation=quinn protocol=quic-v1 mode=handshake role_pair={role_pair} endpoint_role=client run={} sample={} client_io={} server_io={} timeout_ms={} elapsed_ns={elapsed} verified=true",
                config.run, latencies.len(), client_io(role_pair),
                server_io(role_pair), config.timeout_ms,
            );
        }
    }
    latencies.sort_unstable();
    let total_elapsed_ns: u64 = latencies.iter().copied().sum();
    println!(
        "record=result implementation=quinn protocol=quic-v1 mode=handshake role_pair={role_pair} endpoint_role=client run={} timing_scope=client-connect-only client_io={} server_io={} timeout_ms={} verification=certificate resumption=disabled key_exchange=x25519 cipher=aes-128-gcm-sha256 warmup={} iterations={} connections={} echo_bytes={} checksum={checksum} total_elapsed_ns={total_elapsed_ns} p50_ns={} p99_ns={} echo_verified=true complete=true",
        config.run, client_io(role_pair), server_io(role_pair), config.timeout_ms,
        config.warmup, config.iterations, config.total().unwrap(),
        config.total().unwrap() * 32, percentile(&latencies, 50),
        percentile(&latencies, 99),
    );
    Ok(())
}

fn tls_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
        kx_groups: vec![kx_group::X25519],
        ..rustls::crypto::ring::default_provider()
    }
}

fn transport_config(config: Config) -> Result<Arc<TransportConfig>> {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(config.timeout().try_into()?))
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(None);
    Ok(Arc::new(transport))
}

fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.supported_versions(vec![1]);
    config
}

fn server_endpoint(
    address: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Config,
) -> Result<Endpoint> {
    let certificates = CertificateDer::pem_file_iter(Path::new(cert_path))
        .context("reading Quinn handshake certificate")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing Quinn handshake certificate")?;
    let private_key = PrivateKeyDer::from_pem_file(Path::new(key_path))
        .context("reading Quinn handshake private key")?;
    let mut tls = rustls::ServerConfig::builder_with_provider(tls_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    let mut server = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    server.transport_config(transport_config(config)?);
    let socket = std::net::UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    Ok(Endpoint::new(
        endpoint_config(),
        Some(server),
        socket,
        Arc::new(TokioRuntime),
    )?)
}

fn client_endpoint() -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    Ok(Endpoint::new(
        endpoint_config(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )?)
}

fn client_config(ca_path: &str, config: Config) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in
        CertificateDer::pem_file_iter(Path::new(ca_path)).context("reading Quinn handshake CA")?
    {
        roots.add(cert.context("parsing Quinn handshake CA")?)?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(tls_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();
    let mut client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    client.transport_config(transport_config(config)?);
    Ok(client)
}

fn validate_handshake(connection: &Connection, require_peer_certificate: bool) -> Result<()> {
    let data = connection
        .handshake_data()
        .context("missing Quinn handshake data")?
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow::anyhow!("unexpected Quinn handshake data type"))?;
    ensure!(data.protocol.as_deref() == Some(ALPN), "unexpected ALPN");
    ensure!(
        data.protocol_version
            .as_deref()
            .and_then(|value| value.downcast_ref::<rustls::ProtocolVersion>())
            == Some(&rustls::ProtocolVersion::TLSv1_3),
        "unexpected TLS version",
    );
    ensure!(
        data.cipher_suite
            .as_deref()
            .and_then(|value| value.downcast_ref::<rustls::CipherSuite>())
            == Some(&rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
        "unexpected cipher suite",
    );
    if require_peer_certificate {
        let certificates = connection
            .peer_identity()
            .context("missing peer certificate")?
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| anyhow::anyhow!("unexpected peer identity type"))?;
        ensure!(!certificates.is_empty(), "empty peer certificate chain");
    }
    Ok(())
}

async fn serve_echo_and_close(
    connection: &Connection,
    round: usize,
    deadline: Duration,
) -> Result<()> {
    let (mut send, mut recv) = timeout(deadline, connection.accept_bi())
        .await
        .context("accepting benchmark stream timed out")??;
    ensure!(u64::from(send.id()) == 0, "unexpected stream ID");
    let expected = marker(round);
    let received = timeout(deadline, recv.read_to_end(MARKER_LEN))
        .await
        .context("reading benchmark marker timed out")??;
    ensure!(received == expected, "invalid handshake benchmark marker");
    timeout(deadline, send.write_all(&expected))
        .await
        .context("writing benchmark echo timed out")??;
    send.finish()?;
    let close = timeout(deadline, connection.closed())
        .await
        .context("waiting for benchmark close timed out")?;
    match close {
        ConnectionError::ApplicationClosed(value) => {
            ensure!(
                value.error_code.into_inner() == u64::from(CLOSE_CODE),
                "unexpected close code"
            );
            ensure!(
                value.reason.as_ref() == CLOSE_REASON,
                "unexpected close reason"
            );
        }
        other => bail!("unexpected benchmark close: {other}"),
    }
    Ok(())
}

async fn client_echo_and_close(
    connection: &Connection,
    round: usize,
    deadline: Duration,
) -> Result<()> {
    let (mut send, mut recv) = timeout(deadline, connection.open_bi())
        .await
        .context("opening benchmark stream timed out")??;
    ensure!(u64::from(send.id()) == 0, "unexpected stream ID");
    let expected = marker(round);
    timeout(deadline, send.write_all(&expected))
        .await
        .context("writing benchmark marker timed out")??;
    send.finish()?;
    let received = timeout(deadline, recv.read_to_end(MARKER_LEN))
        .await
        .context("reading benchmark echo timed out")??;
    ensure!(received == expected, "invalid handshake benchmark echo");
    connection.close(VarInt::from_u32(CLOSE_CODE), CLOSE_REASON);
    Ok(())
}

fn marker(round: usize) -> [u8; MARKER_LEN] {
    let mut value = [0; MARKER_LEN];
    value[0..8].copy_from_slice(b"NZQHSB1\0");
    value[8..].copy_from_slice(&(round as u64).to_be_bytes());
    value
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    sorted[(sorted.len() * percent / 100).min(sorted.len() - 1)]
}

fn client_io(role_pair: &str) -> &'static str {
    if role_pair.starts_with("netz-client") {
        "zio-std-io"
    } else {
        "quinn-tokio-rustls"
    }
}

fn server_io(role_pair: &str) -> &'static str {
    if role_pair.ends_with("netz-server") {
        "zio-std-io"
    } else {
        "quinn-tokio-rustls"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_and_marker_are_stable() {
        let config = Config::parse(
            [
                "--warmup=2",
                "--iterations=5",
                "--run=3",
                "--timeout-ms=1000",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(config.total(), Some(7));
        assert_eq!(config.run, 3);
        assert!(Config::parse(["--iterations=0"].into_iter().map(str::to_owned)).is_err());
        assert_ne!(marker(0), marker(1));
        assert_eq!(&marker(0)[0..8], b"NZQHSB1\0");
    }
}
