use anyhow::{bail, ensure, Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at};
use wtransport::config::{IpBindConfig, QuicTransportConfig};
use wtransport::endpoint::ConnectOptions;
use wtransport::stream::{RecvStream, SendStream};
use wtransport::{ClientConfig, Connection, Endpoint, Identity, ServerConfig};

const CONTROL_MAGIC: &[u8; 6] = b"NZWTB2";
const CONTROL_LEN: usize = 82;
const PING_MAGIC: &[u8; 6] = b"NZPING";
const PING_HEADER_LEN: usize = 14;
const MAX_DATAGRAM_SIZE: u16 = 1200;
const MAX_STREAMS: u64 = 4096;
const MAX_PARALLEL_STREAMS: u16 = 256;
const STREAM_MASK_WORDS: usize = MAX_PARALLEL_STREAMS as usize / u64::BITS as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Stream,
    DatagramPingPong,
}

impl Mode {
    fn wire(self) -> u8 {
        match self {
            Self::Stream => 1,
            Self::DatagramPingPong => 2,
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "stream" | "stream-upload" => Ok(Self::Stream),
            "datagram-pingpong" => Ok(Self::DatagramPingPong),
            _ => bail!("unknown benchmark mode: {value}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Stream => "stream-upload",
            Self::DatagramPingPong => "datagram-pingpong",
        }
    }

    fn direction(self) -> &'static str {
        match self {
            Self::Stream => "upload",
            Self::DatagramPingPong => "roundtrip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Config {
    mode: Mode,
    warmup: u32,
    iterations: u32,
    streams: u16,
    payload_bytes: u32,
    bytes_per_stream: u64,
    chunk_bytes: u32,
    stream_window: u64,
    timeout_ms: u32,
    netz_ack_every: u64,
    netz_max_ack_delay_us: u64,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut mode = None;
        let mut warmup = None;
        let mut iterations = None;
        let mut streams = 1u16;
        let mut payload_bytes = 32u32;
        let mut bytes_per_stream = 4 * 1024 * 1024u64;
        let mut chunk_bytes = 16 * 1024u32;
        let mut stream_window = 1024 * 1024u64;
        let mut timeout_ms = 30_000u32;
        let mut netz_ack_every = 2u64;
        let mut netz_max_ack_delay_us = 25_000u64;
        for arg in args {
            let (name, value) = arg
                .split_once('=')
                .with_context(|| format!("benchmark option must use --name=value: {arg}"))?;
            match name {
                "--mode" => mode = Some(Mode::parse(value)?),
                "--warmup" => warmup = Some(parse_positive(value, name)?),
                "--iterations" => iterations = Some(parse_positive(value, name)?),
                "--streams" => streams = parse_positive(value, name)?,
                "--payload-bytes" => payload_bytes = parse_positive(value, name)?,
                "--bytes-per-stream" => bytes_per_stream = parse_positive(value, name)?,
                "--chunk-bytes" => chunk_bytes = parse_positive(value, name)?,
                "--stream-window" => stream_window = parse_positive(value, name)?,
                "--timeout-ms" => timeout_ms = parse_positive(value, name)?,
                "--netz-ack-every" => netz_ack_every = parse_positive(value, name)?,
                "--netz-max-ack-delay-us" => {
                    netz_max_ack_delay_us = value.parse().context("invalid ACK delay")?
                }
                "--direction" => ensure!(value == "upload", "only --direction=upload is supported"),
                "--verify-cert" => ensure!(
                    value == "false",
                    "benchmark test identity requires --verify-cert=false"
                ),
                _ => bail!("unknown benchmark option: {name}"),
            }
        }
        let mode = mode.context("benchmark requires --mode=stream|datagram-pingpong")?;
        let warmup: u32 = warmup.unwrap_or(match mode {
            Mode::Stream => 20,
            Mode::DatagramPingPong => 200,
        });
        let iterations = iterations.unwrap_or(match mode {
            Mode::Stream => 5,
            Mode::DatagramPingPong => 5_000,
        });
        ensure!(
            streams <= MAX_PARALLEL_STREAMS,
            "--streams must not exceed {MAX_PARALLEL_STREAMS}"
        );
        ensure!(
            netz_max_ack_delay_us <= 25_000,
            "--netz-max-ack-delay-us must not exceed 25000"
        );
        ensure!(
            chunk_bytes as u64 <= bytes_per_stream,
            "--chunk-bytes exceeds --bytes-per-stream"
        );
        if mode == Mode::DatagramPingPong {
            ensure!(
                payload_bytes as usize >= PING_HEADER_LEN,
                "--payload-bytes must be at least {PING_HEADER_LEN}"
            );
        }
        let round_count = warmup
            .checked_add(iterations)
            .context("warmup plus iterations overflow")?;
        let rounds = u64::from(round_count);
        let total_streams = rounds
            .checked_mul(u64::from(streams))
            .context("stream count overflow")?;
        if mode == Mode::Stream {
            ensure!(
                total_streams <= MAX_STREAMS,
                "benchmark stream count must not exceed {MAX_STREAMS}"
            );
        }
        Ok(Self {
            mode,
            warmup,
            iterations,
            streams,
            payload_bytes,
            bytes_per_stream,
            chunk_bytes,
            stream_window,
            timeout_ms,
            netz_ack_every,
            netz_max_ack_delay_us,
        })
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.timeout_ms))
    }

    fn rounds(&self) -> u32 {
        self.warmup
            .checked_add(self.iterations)
            .expect("round count validated while parsing")
    }

    fn connection_window(&self) -> Result<u64> {
        self.stream_window
            .checked_mul(u64::from(self.streams) + 8)
            .context("connection window overflow")
    }

    fn stream_count_limit(&self) -> Result<u64> {
        let used = if self.mode == Mode::Stream {
            u64::from(self.rounds())
                .checked_mul(u64::from(self.streams))
                .context("stream count limit overflow")?
        } else {
            0
        };
        used.checked_add(8).context("stream count limit overflow")
    }
}

fn parse_positive<T>(value: &str, name: &str) -> Result<T>
where
    T: std::str::FromStr + PartialEq + From<u8>,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let parsed = value
        .parse::<T>()
        .with_context(|| format!("invalid {name}"))?;
    ensure!(parsed != T::from(0), "{name} must be non-zero");
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Kind {
    Config = 1,
    ConfigAck = 2,
    RoundReady = 3,
    Go = 4,
    RoundDone = 5,
    BenchmarkDone = 6,
    BenchmarkAck = 7,
    CloseReady = 8,
    CloseAck = 9,
    RoundAck = 10,
}

impl Kind {
    fn parse(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Config),
            2 => Ok(Self::ConfigAck),
            3 => Ok(Self::RoundReady),
            4 => Ok(Self::Go),
            5 => Ok(Self::RoundDone),
            6 => Ok(Self::BenchmarkDone),
            7 => Ok(Self::BenchmarkAck),
            8 => Ok(Self::CloseReady),
            9 => Ok(Self::CloseAck),
            10 => Ok(Self::RoundAck),
            _ => bail!("unknown benchmark control kind: {value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Control {
    kind: Kind,
    mode: Mode,
    round: u32,
    config: Config,
    received_bytes: u64,
    checksum: u64,
}

struct ControlChannel {
    send: SendStream,
    recv: RecvStream,
}

impl Control {
    fn new(kind: Kind, config: &Config, round: u32) -> Self {
        Self {
            kind,
            mode: config.mode,
            round,
            config: config.clone(),
            received_bytes: 0,
            checksum: 0,
        }
    }

    fn encode(&self) -> [u8; CONTROL_LEN] {
        let mut out = [0u8; CONTROL_LEN];
        out[0..6].copy_from_slice(CONTROL_MAGIC);
        out[6] = self.kind as u8;
        out[7] = self.mode.wire();
        out[8..12].copy_from_slice(&self.round.to_be_bytes());
        out[12..16].copy_from_slice(&self.config.warmup.to_be_bytes());
        out[16..20].copy_from_slice(&self.config.iterations.to_be_bytes());
        out[20..22].copy_from_slice(&self.config.streams.to_be_bytes());
        out[22..26].copy_from_slice(&self.config.payload_bytes.to_be_bytes());
        out[26..34].copy_from_slice(&self.config.bytes_per_stream.to_be_bytes());
        out[34..38].copy_from_slice(&self.config.chunk_bytes.to_be_bytes());
        out[38..46].copy_from_slice(&self.config.stream_window.to_be_bytes());
        out[46..50].copy_from_slice(&self.config.timeout_ms.to_be_bytes());
        out[50..58].copy_from_slice(&self.config.netz_ack_every.to_be_bytes());
        out[58..66].copy_from_slice(&self.config.netz_max_ack_delay_us.to_be_bytes());
        out[66..74].copy_from_slice(&self.received_bytes.to_be_bytes());
        out[74..82].copy_from_slice(&self.checksum.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == CONTROL_LEN,
            "invalid benchmark control length"
        );
        ensure!(
            &bytes[0..6] == CONTROL_MAGIC,
            "invalid benchmark control magic"
        );
        let mode = match bytes[7] {
            1 => Mode::Stream,
            2 => Mode::DatagramPingPong,
            value => bail!("unknown benchmark mode: {value}"),
        };
        let config = Config {
            mode,
            warmup: read_u32(bytes, 12),
            iterations: read_u32(bytes, 16),
            streams: read_u16(bytes, 20),
            payload_bytes: read_u32(bytes, 22),
            bytes_per_stream: read_u64(bytes, 26),
            chunk_bytes: read_u32(bytes, 34),
            stream_window: read_u64(bytes, 38),
            timeout_ms: read_u32(bytes, 46),
            netz_ack_every: read_u64(bytes, 50),
            netz_max_ack_delay_us: read_u64(bytes, 58),
        };
        Ok(Self {
            kind: Kind::parse(bytes[6])?,
            mode,
            round: read_u32(bytes, 8),
            config,
            received_bytes: read_u64(bytes, 66),
            checksum: read_u64(bytes, 74),
        })
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

async fn send_control(channel: &mut ControlChannel, control: &Control) -> Result<()> {
    timeout(
        control.config.timeout(),
        channel.send.write_all(&control.encode()),
    )
    .await
    .with_context(|| format!("{:?} write timed out", control.kind))??;
    Ok(())
}

async fn receive_control(
    channel: &mut ControlChannel,
    config: &Config,
    kind: Kind,
) -> Result<Control> {
    let mut bytes = [0u8; CONTROL_LEN];
    timeout(config.timeout(), channel.recv.read_exact(&mut bytes))
        .await
        .with_context(|| format!("{kind:?} read timed out"))??;
    let control = Control::decode(&bytes)?;
    ensure!(
        control.kind == kind,
        "expected {kind:?}, received {:?}",
        control.kind
    );
    ensure!(
        control.config == *config,
        "benchmark configuration mismatch"
    );
    Ok(control)
}

fn transport_config(config: &Config) -> Result<QuicTransportConfig> {
    let mut transport = QuicTransportConfig::default();
    let stream_window = wtransport::quinn::VarInt::try_from(config.stream_window)?;
    let connection_window = wtransport::quinn::VarInt::try_from(config.connection_window()?)?;
    let stream_limit = wtransport::quinn::VarInt::try_from(config.stream_count_limit()?)?;
    transport
        .stream_receive_window(stream_window)
        .receive_window(connection_window)
        .send_window(config.connection_window()?)
        .max_concurrent_bidi_streams(stream_limit)
        .max_concurrent_uni_streams(stream_limit)
        .initial_mtu(MAX_DATAGRAM_SIZE)
        .min_mtu(MAX_DATAGRAM_SIZE)
        .mtu_discovery_config(None)
        .enable_segmentation_offload(false);
    Ok(transport)
}

pub async fn run_client(args: &[String], traffic: bool) -> Result<Config> {
    let (port, options) = parse_port(args)?;
    ensure!(port != 0, "benchmark server port must be non-zero");
    let config = Config::parse(options)?;
    let tls = wtransport::tls::client::build_default_tls_config(
        Arc::new(wtransport::tls::rustls::RootCertStore::empty()),
        Some(Arc::new(
            wtransport::tls::client::NoServerVerification::new(),
        )),
    );
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_custom_tls_and_transport(tls, transport_config(&config)?)
        .build();
    let endpoint = Endpoint::client(client_config)?;
    let options = ConnectOptions::builder(format!("https://127.0.0.1:{port}/benchmark"))
        .add_header("user-agent", "wtransport-benchmark")
        .build();
    let connection = timeout(config.timeout(), endpoint.connect(options))
        .await
        .context("benchmark CONNECT timed out")??;
    validate_datagram_limit(&connection, &config)?;
    print_config(
        "wtransport",
        "wtransport-client+netz-server",
        "client",
        &config,
        &connection,
    );
    let mut control = open_control_client(&connection, &config).await?;
    match config.mode {
        Mode::Stream => {
            run_stream_client(
                &connection,
                &mut control,
                &config,
                "wtransport",
                "wtransport-client+netz-server",
            )
            .await?
        }
        Mode::DatagramPingPong => {
            run_ping_client(
                &connection,
                &mut control,
                &config,
                "wtransport",
                "wtransport-client+netz-server",
            )
            .await?
        }
    }
    send_control(
        &mut control,
        &Control::new(Kind::CloseReady, &config, config.rounds()),
    )
    .await?;
    let close_ack = receive_control(&mut control, &config, Kind::CloseAck).await?;
    ensure!(
        close_ack.round == config.rounds(),
        "CLOSE_ACK round mismatch"
    );
    timeout(config.timeout(), control.send.finish())
        .await
        .context("control stream finish timed out")??;
    let terminal = timeout(config.timeout(), control.recv.read(&mut [0u8; 1]))
        .await
        .context("control stream peer FIN timed out")??;
    ensure!(terminal.is_none(), "unexpected data after CLOSE_ACK");
    if traffic {
        print_traffic(
            "wtransport",
            "wtransport-client+netz-server",
            "client",
            &config,
            connection.quic_connection().stats(),
        );
    }
    Ok(config)
}

pub async fn run_churn_client(
    args: &[String],
    fault: &str,
    proxy_control_port: u16,
) -> Result<Config> {
    let (port, options) = parse_port(args)?;
    ensure!(port != 0, "churn proxy port must be non-zero");
    let config = Config::parse(options)?;
    ensure!(config.mode == Mode::Stream, "churn requires stream mode");
    let tls = wtransport::tls::client::build_default_tls_config(
        Arc::new(wtransport::tls::rustls::RootCertStore::empty()),
        Some(Arc::new(
            wtransport::tls::client::NoServerVerification::new(),
        )),
    );
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_custom_tls_and_transport(tls, transport_config(&config)?)
        .build();
    let endpoint = Endpoint::client(client_config)?;
    let options = ConnectOptions::builder(format!("https://127.0.0.1:{port}/benchmark"))
        .add_header("user-agent", "wtransport-benchmark")
        .build();
    let connection = timeout(config.timeout(), endpoint.connect(options))
        .await
        .context("churn CONNECT timed out")??;
    validate_datagram_limit(&connection, &config)?;
    print_config(
        "wtransport",
        "wtransport-client+netz-server",
        "client",
        &config,
        &connection,
    );
    let mut control = open_control_client(&connection, &config).await?;
    crate::churn::run_client_connection(
        &connection,
        &mut control.send,
        &mut control.recv,
        config.streams,
        config.bytes_per_stream,
        config.timeout(),
        fault,
        proxy_control_port,
    )
    .await?;
    endpoint.wait_idle().await;
    Ok(config)
}

pub async fn run_server(args: &[String], traffic: bool) -> Result<Config> {
    let (port, options) = parse_port(args)?;
    let config = Config::parse(options)?;
    let identity = Identity::self_signed(["localhost", "127.0.0.1"])?;
    let server_config = ServerConfig::builder()
        .with_bind_config(IpBindConfig::LocalV4, port)
        .with_custom_transport(identity, transport_config(&config)?)
        .build();
    let endpoint = Endpoint::server(server_config)?;
    println!("WTRANSPORT_BENCH_PORT={}", endpoint.local_addr()?.port());
    let request = timeout(config.timeout(), endpoint.accept())
        .await
        .context("benchmark incoming QUIC connection timed out")?
        .await?;
    ensure!(
        request.path() == "/benchmark",
        "unexpected benchmark CONNECT path"
    );
    let connection = request.accept().await?;
    validate_datagram_limit(&connection, &config)?;
    print_config(
        "wtransport",
        "netz-client+wtransport-server",
        "server",
        &config,
        &connection,
    );
    let mut control = accept_control_server(&connection, &config).await?;
    match config.mode {
        Mode::Stream => run_stream_server(&connection, &mut control, &config).await?,
        Mode::DatagramPingPong => run_ping_server(&connection, &mut control, &config).await?,
    }
    let close_ready = receive_control(&mut control, &config, Kind::CloseReady).await?;
    ensure!(
        close_ready.round == config.rounds(),
        "CLOSE_READY round mismatch"
    );
    send_control(
        &mut control,
        &Control::new(Kind::CloseAck, &config, config.rounds()),
    )
    .await?;
    let terminal = timeout(config.timeout(), control.recv.read(&mut [0u8; 1]))
        .await
        .context("control stream peer FIN timed out")??;
    ensure!(terminal.is_none(), "unexpected data after CLOSE_READY");
    timeout(config.timeout(), control.send.finish())
        .await
        .context("control stream finish timed out")??;
    print_server_complete("wtransport", "netz-client+wtransport-server", &config);
    if traffic {
        print_traffic(
            "wtransport",
            "netz-client+wtransport-server",
            "server",
            &config,
            connection.quic_connection().stats(),
        );
    }
    Ok(config)
}

pub async fn run_churn_server(args: &[String], fault: &str) -> Result<Config> {
    let (port, options) = parse_port(args)?;
    let config = Config::parse(options)?;
    ensure!(config.mode == Mode::Stream, "churn requires stream mode");
    let identity = Identity::self_signed(["localhost", "127.0.0.1"])?;
    let server_config = ServerConfig::builder()
        .with_bind_config(IpBindConfig::LocalV4, port)
        .with_custom_transport(identity, transport_config(&config)?)
        .build();
    let endpoint = Endpoint::server(server_config)?;
    println!("WTRANSPORT_CHURN_PORT={}", endpoint.local_addr()?.port());
    let request = timeout(config.timeout(), endpoint.accept())
        .await
        .context("churn incoming QUIC connection timed out")?
        .await?;
    ensure!(
        request.path() == "/benchmark",
        "unexpected churn CONNECT path"
    );
    let connection = request.accept().await?;
    validate_datagram_limit(&connection, &config)?;
    print_config(
        "wtransport",
        "netz-client+wtransport-server",
        "server",
        &config,
        &connection,
    );
    let mut control = accept_control_server(&connection, &config).await?;
    crate::churn::run_server_connection(
        &connection,
        &mut control.send,
        &mut control.recv,
        config.streams,
        config.bytes_per_stream,
        config.timeout(),
        fault,
    )
    .await?;
    connection.close(wtransport::VarInt::from_u32(0), b"churn complete");
    endpoint.wait_idle().await;
    Ok(config)
}

fn parse_port(args: &[String]) -> Result<(u16, &[String])> {
    let value = args.first().context("benchmark mode requires PORT")?;
    let port = value.parse::<u16>().context("invalid benchmark port")?;
    Ok((port, &args[1..]))
}

fn validate_datagram_limit(connection: &Connection, config: &Config) -> Result<()> {
    let limit = connection
        .max_datagram_size()
        .context("peer did not negotiate DATAGRAM")?;
    if config.mode == Mode::DatagramPingPong {
        ensure!(
            config.payload_bytes as usize <= limit,
            "ping payload exceeds negotiated maximum {limit}"
        );
    }
    Ok(())
}

fn print_config(
    implementation: &str,
    role_pair: &str,
    endpoint_role: &str,
    config: &Config,
    connection: &Connection,
) {
    println!(
        "record=config implementation={implementation} protocol=webtransport transport=h3 mode={} direction={} role_pair={role_pair} endpoint_role={endpoint_role} client_io={} server_io={} connection_scope=persistent benchmark_scope=same-application-shape warmup={} iterations={} streams={} bytes_per_stream={} payload_bytes={} chunk_bytes={} stream_window_requested={} stream_window_effective={} connection_window={} max_datagram_size={} timeout_ms={} quic_version=1 netz_ack_every={} netz_max_ack_delay_us={} cipher=negotiated-unexposed cert_verify=false gso=false gro=implementation-default pacing=true",
        config.mode.name(),
        config.mode.direction(),
        client_io(role_pair),
        server_io(role_pair),
        config.warmup,
        config.iterations,
        config.streams,
        config.bytes_per_stream,
        config.payload_bytes,
        config.chunk_bytes,
        config.stream_window,
        config.stream_window,
        config.connection_window().unwrap(),
        connection.max_datagram_size().unwrap_or(0),
        config.timeout_ms,
        config.netz_ack_every,
        config.netz_max_ack_delay_us,
    );
}

async fn open_control_client(connection: &Connection, config: &Config) -> Result<ControlChannel> {
    let opening = timeout(config.timeout(), connection.open_bi())
        .await
        .context("control stream credit timed out")??;
    let (send, recv) = timeout(config.timeout(), opening)
        .await
        .context("control stream association timed out")??;
    let mut channel = ControlChannel { send, recv };
    send_control(&mut channel, &Control::new(Kind::Config, config, 0)).await?;
    let ack = receive_control(&mut channel, config, Kind::ConfigAck).await?;
    ensure!(ack.round == 0, "invalid CONFIG_ACK round");
    Ok(channel)
}

async fn accept_control_server(connection: &Connection, config: &Config) -> Result<ControlChannel> {
    let (send, recv) = timeout(config.timeout(), connection.accept_bi())
        .await
        .context("control stream timed out")??;
    let mut channel = ControlChannel { send, recv };
    let message = receive_control(&mut channel, config, Kind::Config).await?;
    ensure!(message.round == 0, "invalid CONFIG round");
    send_control(&mut channel, &Control::new(Kind::ConfigAck, config, 0)).await?;
    Ok(channel)
}

fn stream_byte(offset: usize, stream_index: usize) -> u8 {
    ((offset.wrapping_mul(131) + stream_index.wrapping_mul(17)) & 0xff) as u8
}

fn stream_prelude(round: u32, stream_index: u16) -> [u8; 12] {
    let mut prelude = [0u8; 12];
    prelude[0..6].copy_from_slice(b"NZSTRM");
    prelude[6..10].copy_from_slice(&round.to_be_bytes());
    prelude[10..12].copy_from_slice(&stream_index.to_be_bytes());
    prelude
}

fn verify_stream_prelude(prelude: &[u8], config: &Config, round: u32) -> Result<usize> {
    ensure!(
        prelude.len() == 12,
        "invalid benchmark stream prelude length"
    );
    ensure!(
        &prelude[0..6] == b"NZSTRM",
        "invalid benchmark stream prelude magic"
    );
    ensure!(
        read_u32(prelude, 6) == round,
        "benchmark stream prelude round mismatch"
    );
    let stream_index = read_u16(prelude, 10) as usize;
    ensure!(
        stream_index < config.streams as usize,
        "benchmark stream index out of range"
    );
    Ok(stream_index)
}

fn build_stream_payloads(config: &Config) -> Result<(Vec<Vec<u8>>, u64)> {
    let bytes =
        usize::try_from(config.bytes_per_stream).context("bytes-per-stream exceeds usize")?;
    let mut payloads = Vec::with_capacity(config.streams as usize);
    let mut checksum = 0u64;
    for stream_index in 0..config.streams as usize {
        let mut payload = vec![0u8; bytes];
        for (offset, byte) in payload.iter_mut().enumerate() {
            *byte = stream_byte(offset, stream_index);
            checksum = checksum.wrapping_add(u64::from(*byte));
        }
        payloads.push(payload);
    }
    Ok((payloads, checksum))
}

async fn run_stream_client(
    connection: &Connection,
    control: &mut ControlChannel,
    config: &Config,
    implementation: &str,
    role_pair: &str,
) -> Result<()> {
    let (payloads, expected_checksum) = build_stream_payloads(config)?;
    let logical_bytes = config
        .bytes_per_stream
        .checked_mul(u64::from(config.streams))
        .context("logical byte count overflow")?;
    for round in 0..config.rounds() {
        let mut senders = Vec::with_capacity(config.streams as usize);
        let mut receivers = Vec::with_capacity(config.streams as usize);
        for stream_index in 0..config.streams {
            let opening = timeout(config.timeout(), connection.open_bi())
                .await
                .context("stream credit timed out")??;
            let (mut sender, receiver) = timeout(config.timeout(), opening)
                .await
                .context("stream association timed out")??;
            sender
                .write_all(&stream_prelude(round, stream_index))
                .await?;
            senders.push(sender);
            receivers.push(receiver);
        }
        send_control(control, &Control::new(Kind::RoundReady, config, round)).await?;
        let go = receive_control(control, config, Kind::Go).await?;
        ensure!(go.round == round, "GO round mismatch");
        let send_deadline = tokio::time::Instant::now() + config.timeout();
        let started = Instant::now();
        let chunk = config.chunk_bytes as usize;
        let total = payloads[0].len();
        let mut offset = 0usize;
        while offset < total {
            let end = (offset + chunk).min(total);
            for (stream_index, sender) in senders.iter_mut().enumerate() {
                timeout_at(
                    send_deadline,
                    sender.write_all(&payloads[stream_index][offset..end]),
                )
                .await
                .context("stream write timed out")??;
            }
            offset = end;
        }
        for sender in &mut senders {
            sender.quic_stream_mut().finish()?;
        }
        let done = receive_control(control, config, Kind::RoundDone).await?;
        let elapsed = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        ensure!(done.round == round, "ROUND_DONE round mismatch");
        ensure!(
            done.received_bytes == logical_bytes,
            "ROUND_DONE byte mismatch"
        );
        ensure!(
            done.checksum == expected_checksum,
            "ROUND_DONE checksum mismatch"
        );
        send_control(control, &Control::new(Kind::RoundAck, config, round)).await?;
        for mut receiver in receivers {
            let mut unexpected = [0u8; 1];
            let terminal = timeout(config.timeout(), receiver.read(&mut unexpected))
                .await
                .context("reverse stream FIN timed out")??;
            ensure!(terminal.is_none(), "unexpected reverse stream payload");
        }
        if round >= config.warmup {
            let sample = round - config.warmup + 1;
            let mib_s = if elapsed == 0 {
                0.0
            } else {
                logical_bytes as f64 * 1_000_000_000.0 / elapsed as f64 / (1024.0 * 1024.0)
            };
            println!(
                "record=result implementation={implementation} protocol=webtransport transport=h3 mode={} direction={} role_pair={role_pair} endpoint_role=client client_io={} server_io={} connection_scope=persistent benchmark_scope=same-application-shape warmup={} iterations={} streams={} bytes_per_stream={} payload_bytes={} chunk_bytes={} stream_window={} timeout_ms={} netz_ack_every={} netz_max_ack_delay_us={} sample={sample} elapsed_ns={elapsed} logical_MiB_s={mib_s:.3} sent_bytes={logical_bytes} received_bytes={} streams_finished={} checksum={} complete=true",
                config.mode.name(),
                config.mode.direction(),
                client_io(role_pair),
                server_io(role_pair),
                config.warmup,
                config.iterations,
                config.streams,
                config.bytes_per_stream,
                config.payload_bytes,
                config.chunk_bytes,
                config.stream_window,
                config.timeout_ms,
                config.netz_ack_every,
                config.netz_max_ack_delay_us,
                done.received_bytes,
                config.streams,
                done.checksum,
            );
        }
    }
    send_control(
        control,
        &Control::new(Kind::BenchmarkDone, config, config.rounds()),
    )
    .await?;
    let ack = receive_control(control, config, Kind::BenchmarkAck).await?;
    ensure!(ack.round == config.rounds(), "BENCHMARK_ACK round mismatch");
    Ok(())
}

async fn run_stream_server(
    connection: &Connection,
    control: &mut ControlChannel,
    config: &Config,
) -> Result<()> {
    for round in 0..config.rounds() {
        let ready = receive_control(control, config, Kind::RoundReady).await?;
        ensure!(ready.round == round, "ROUND_READY round mismatch");
        let mut streams = Vec::with_capacity(config.streams as usize);
        let mut seen = [0u64; STREAM_MASK_WORDS];
        for _ in 0..config.streams {
            let (sender, mut receiver) = timeout(config.timeout(), connection.accept_bi())
                .await
                .context("incoming benchmark stream timed out")??;
            let mut prelude = [0u8; 12];
            timeout(config.timeout(), receiver.read_exact(&mut prelude))
                .await
                .context("benchmark stream prelude timed out")??;
            let stream_index = verify_stream_prelude(&prelude, config, round)?;
            ensure!(
                mark_stream(&mut seen, stream_index),
                "duplicate benchmark stream index"
            );
            streams.push((
                stream_index,
                sender,
                receiver,
                vec![0u8; config.chunk_bytes as usize],
            ));
        }
        let mut readers = JoinSet::new();
        for (stream_index, sender, mut receiver, mut buffer) in streams {
            let config = config.clone();
            readers.spawn(async move {
                let mut received = 0usize;
                let mut checksum = 0u64;
                loop {
                    let count = timeout(config.timeout(), receiver.read(&mut buffer))
                        .await
                        .context("benchmark stream read timed out")??;
                    let Some(count) = count else { break };
                    ensure!(
                        received + count <= config.bytes_per_stream as usize,
                        "benchmark stream exceeds configured size"
                    );
                    for (index, byte) in buffer[..count].iter().copied().enumerate() {
                        ensure!(
                            byte == stream_byte(received + index, stream_index),
                            "benchmark stream payload mismatch"
                        );
                        checksum = checksum.wrapping_add(u64::from(byte));
                    }
                    received += count;
                }
                ensure!(
                    received == config.bytes_per_stream as usize,
                    "benchmark stream ended early"
                );
                Ok::<_, anyhow::Error>((sender, received as u64, checksum))
            });
        }
        send_control(control, &Control::new(Kind::Go, config, round)).await?;
        let mut received = 0u64;
        let mut checksum = 0u64;
        let mut round_senders = Vec::with_capacity(config.streams as usize);
        while let Some(result) = readers.join_next().await {
            let (sender, bytes, stream_checksum) =
                result.context("benchmark stream reader task failed")??;
            round_senders.push(sender);
            received = received.wrapping_add(bytes);
            checksum = checksum.wrapping_add(stream_checksum);
        }
        let mut done = Control::new(Kind::RoundDone, config, round);
        done.received_bytes = received;
        done.checksum = checksum;
        send_control(control, &done).await?;
        let ack = receive_control(control, config, Kind::RoundAck).await?;
        ensure!(ack.round == round, "ROUND_ACK round mismatch");
        for sender in &mut round_senders {
            sender.quic_stream_mut().finish()?;
        }
    }
    let done = receive_control(control, config, Kind::BenchmarkDone).await?;
    ensure!(
        done.round == config.rounds(),
        "BENCHMARK_DONE round mismatch"
    );
    send_control(
        control,
        &Control::new(Kind::BenchmarkAck, config, config.rounds()),
    )
    .await
}

fn fill_ping(buffer: &mut [u8], sequence: u64) {
    buffer[0..6].copy_from_slice(PING_MAGIC);
    buffer[6..14].copy_from_slice(&sequence.to_be_bytes());
    for (index, byte) in buffer[PING_HEADER_LEN..].iter_mut().enumerate() {
        *byte = ((sequence.wrapping_mul(17) + (index as u64).wrapping_mul(131)) & 0xff) as u8;
    }
}

fn verify_ping(bytes: &[u8], sequence: u64) -> Result<()> {
    ensure!(bytes.len() >= PING_HEADER_LEN, "ping datagram is too short");
    ensure!(&bytes[0..6] == PING_MAGIC, "ping magic mismatch");
    ensure!(read_u64(bytes, 6) == sequence, "ping sequence mismatch");
    for (index, byte) in bytes[PING_HEADER_LEN..].iter().copied().enumerate() {
        let expected =
            ((sequence.wrapping_mul(17) + (index as u64).wrapping_mul(131)) & 0xff) as u8;
        ensure!(byte == expected, "ping payload mismatch");
    }
    Ok(())
}

fn add_checksum(checksum: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *checksum = checksum.wrapping_add(u64::from(*byte));
    }
}

async fn run_ping_client(
    connection: &Connection,
    control: &mut ControlChannel,
    config: &Config,
    implementation: &str,
    role_pair: &str,
) -> Result<()> {
    send_control(control, &Control::new(Kind::RoundReady, config, 0)).await?;
    let go = receive_control(control, config, Kind::Go).await?;
    ensure!(go.round == 0, "GO round mismatch");
    let total = config.rounds();
    let mut payload = vec![0u8; config.payload_bytes as usize];
    let mut samples = Vec::with_capacity(config.iterations as usize);
    let mut checksum = 0u64;
    for sequence in 0..total {
        fill_ping(&mut payload, u64::from(sequence));
        let started = Instant::now();
        connection.send_datagram(&payload)?;
        let echo = timeout(config.timeout(), connection.receive_datagram())
            .await
            .context("ping echo timed out")??;
        let elapsed = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        ensure!(*echo == payload, "ping echo mismatch");
        verify_ping(&echo, u64::from(sequence))?;
        add_checksum(&mut checksum, &echo);
        if sequence >= config.warmup {
            samples.push(elapsed);
        }
    }
    let mut done = Control::new(Kind::BenchmarkDone, config, total);
    done.received_bytes = u64::from(total) * u64::from(config.payload_bytes);
    done.checksum = checksum;
    send_control(control, &done).await?;
    let ack = receive_control(control, config, Kind::BenchmarkAck).await?;
    ensure!(ack.round == total, "BENCHMARK_ACK round mismatch");
    ensure!(
        ack.received_bytes == done.received_bytes,
        "BENCHMARK_ACK byte mismatch"
    );
    ensure!(ack.checksum == checksum, "BENCHMARK_ACK checksum mismatch");
    samples.sort_unstable();
    let sum: u128 = samples.iter().map(|value| u128::from(*value)).sum();
    let mean = (sum / samples.len() as u128) as u64;
    println!(
        "record=result implementation={implementation} protocol=webtransport transport=h3 mode={} direction={} role_pair={role_pair} endpoint_role=client client_io={} server_io={} connection_scope=persistent benchmark_scope=same-application-shape warmup={} iterations={} streams={} bytes_per_stream={} payload_bytes={} chunk_bytes={} stream_window={} timeout_ms={} netz_ack_every={} netz_max_ack_delay_us={} p50_ns={} p90_ns={} p99_ns={} p999_ns={} mean_ns={mean} min_ns={} max_ns={} sent_bytes={} received_bytes={} checksum={checksum} complete=true",
        config.mode.name(),
        config.mode.direction(),
        client_io(role_pair),
        server_io(role_pair),
        config.warmup,
        config.iterations,
        config.streams,
        config.bytes_per_stream,
        config.payload_bytes,
        config.chunk_bytes,
        config.stream_window,
        config.timeout_ms,
        config.netz_ack_every,
        config.netz_max_ack_delay_us,
        percentile(&samples, 50, 100),
        percentile(&samples, 90, 100),
        percentile(&samples, 99, 100),
        percentile(&samples, 999, 1000),
        samples[0],
        samples[samples.len() - 1],
        u64::from(total) * u64::from(config.payload_bytes),
        u64::from(total) * u64::from(config.payload_bytes),
    );
    Ok(())
}

async fn run_ping_server(
    connection: &Connection,
    control: &mut ControlChannel,
    config: &Config,
) -> Result<()> {
    let ready = receive_control(control, config, Kind::RoundReady).await?;
    ensure!(ready.round == 0, "ROUND_READY round mismatch");
    send_control(control, &Control::new(Kind::Go, config, 0)).await?;
    let total = config.rounds();
    let mut checksum = 0u64;
    for sequence in 0..total {
        let datagram = timeout(config.timeout(), connection.receive_datagram())
            .await
            .context("ping request timed out")??;
        ensure!(
            datagram.len() == config.payload_bytes as usize,
            "ping payload length mismatch"
        );
        verify_ping(&datagram, u64::from(sequence))?;
        add_checksum(&mut checksum, &datagram);
        connection.send_datagram(&*datagram)?;
    }
    let done = receive_control(control, config, Kind::BenchmarkDone).await?;
    let expected_bytes = u64::from(total) * u64::from(config.payload_bytes);
    ensure!(done.round == total, "BENCHMARK_DONE round mismatch");
    ensure!(
        done.received_bytes == expected_bytes,
        "BENCHMARK_DONE byte mismatch"
    );
    ensure!(
        done.checksum == checksum,
        "BENCHMARK_DONE checksum mismatch"
    );
    let mut ack = Control::new(Kind::BenchmarkAck, config, total);
    ack.received_bytes = expected_bytes;
    ack.checksum = checksum;
    send_control(control, &ack).await
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    let rank = (sorted.len() * numerator).div_ceil(denominator);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn stream_checksum(config: &Config) -> u64 {
    let mut checksum = 0u64;
    for stream_index in 0..usize::from(config.streams) {
        for offset in 0..config.bytes_per_stream as usize {
            checksum = checksum.wrapping_add(u64::from(stream_byte(offset, stream_index)));
        }
    }
    checksum
}

fn ping_checksum(config: &Config) -> u64 {
    let mut storage = [0u8; MAX_DATAGRAM_SIZE as usize];
    let payload = &mut storage[..config.payload_bytes as usize];
    let mut checksum = 0u64;
    for sequence in 0..config.rounds() {
        fill_ping(payload, u64::from(sequence));
        add_checksum(&mut checksum, payload);
    }
    checksum
}

fn print_server_complete(implementation: &str, role_pair: &str, config: &Config) {
    let (bytes, checksum) = match config.mode {
        Mode::Stream => (
            u64::from(config.iterations) * u64::from(config.streams) * config.bytes_per_stream,
            u64::from(config.iterations).wrapping_mul(stream_checksum(config)),
        ),
        Mode::DatagramPingPong => (
            u64::from(config.rounds()) * u64::from(config.payload_bytes),
            ping_checksum(config),
        ),
    };
    println!(
        "record=server-complete implementation={implementation} protocol=webtransport transport=h3 mode={} direction={} role_pair={role_pair} endpoint_role=server client_io={} server_io={} connection_scope=persistent benchmark_scope=same-application-shape warmup={} iterations={} streams={} bytes_per_stream={} payload_bytes={} chunk_bytes={} stream_window={} timeout_ms={} netz_ack_every={} netz_max_ack_delay_us={} sent_bytes={bytes} received_bytes={bytes} checksum={checksum} server_complete=true",
        config.mode.name(),
        config.mode.direction(),
        client_io(role_pair),
        server_io(role_pair),
        config.warmup,
        config.iterations,
        config.streams,
        config.bytes_per_stream,
        config.payload_bytes,
        config.chunk_bytes,
        config.stream_window,
        config.timeout_ms,
        config.netz_ack_every,
        config.netz_max_ack_delay_us,
    );
}

fn print_traffic(
    implementation: &str,
    role_pair: &str,
    endpoint_role: &str,
    config: &Config,
    stats: wtransport::quinn::ConnectionStats,
) {
    println!(
        "record=traffic implementation={implementation} protocol=webtransport transport=h3 mode={} direction={} role_pair={role_pair} endpoint_role={endpoint_role} client_io={} server_io={} connection_scope=persistent warmup={} iterations={} streams={} bytes_per_stream={} payload_bytes={} chunk_bytes={} stream_window={} timeout_ms={} netz_ack_every={} netz_max_ack_delay_us={} traffic_scope=connection socket_boundary=userspace-udp-payload traffic_source=quinn-connection-stats udp_sent_datagrams={} udp_sent_payload_bytes={} udp_received_datagrams={} udp_received_payload_bytes={} logical_udp_segments=true complete=true",
        config.mode.name(),
        config.mode.direction(),
        client_io(role_pair),
        server_io(role_pair),
        config.warmup,
        config.iterations,
        config.streams,
        config.bytes_per_stream,
        config.payload_bytes,
        config.chunk_bytes,
        config.stream_window,
        config.timeout_ms,
        config.netz_ack_every,
        config.netz_max_ack_delay_us,
        stats.udp_tx.datagrams,
        stats.udp_tx.bytes,
        stats.udp_rx.datagrams,
        stats.udp_rx.bytes,
    );
}

#[cfg(feature = "allocation-stats")]
pub(crate) fn print_memory(
    role: &str,
    config: &Config,
    stats: crate::counting_allocator::Snapshot,
) {
    let (role_pair, endpoint_role) = if role == "bench-client" {
        ("wtransport-client+netz-server", "client")
    } else {
        ("netz-client+wtransport-server", "server")
    };
    println!(
        "record=memory implementation=wtransport protocol=webtransport transport=h3 mode={} direction={} role_pair={role_pair} endpoint_role={endpoint_role} client_io={} server_io={} connection_scope=persistent warmup={} iterations={} streams={} bytes_per_stream={} payload_bytes={} chunk_bytes={} stream_window={} timeout_ms={} netz_ack_every={} netz_max_ack_delay_us={} memory_scope=process-start-through-runtime-teardown allocator_scope=rust-system-requested alloc_count={} free_count={} realloc_count={} total_allocated_bytes={} total_freed_bytes={} live_bytes_end={} peak_live_bytes={} complete=true",
        config.mode.name(),
        config.mode.direction(),
        client_io(role_pair),
        server_io(role_pair),
        config.warmup,
        config.iterations,
        config.streams,
        config.bytes_per_stream,
        config.payload_bytes,
        config.chunk_bytes,
        config.stream_window,
        config.timeout_ms,
        config.netz_ack_every,
        config.netz_max_ack_delay_us,
        stats.alloc_count,
        stats.free_count,
        stats.realloc_count,
        stats.total_allocated,
        stats.total_freed,
        stats.current_bytes,
        stats.peak_bytes,
    );
}

fn client_io(role_pair: &str) -> &'static str {
    if role_pair.starts_with("netz-client") {
        "zio-std-io"
    } else {
        "wtransport-quinn-tokio"
    }
}

fn server_io(role_pair: &str) -> &'static str {
    if role_pair.ends_with("netz-server") {
        "zio-std-io"
    } else {
        "wtransport-quinn-tokio"
    }
}

fn mark_stream(mask: &mut [u64; STREAM_MASK_WORDS], stream_index: usize) -> bool {
    debug_assert!(stream_index < MAX_PARALLEL_STREAMS as usize);
    let word = &mut mask[stream_index / u64::BITS as usize];
    let bit = 1u64 << (stream_index % u64::BITS as usize);
    if *word & bit != 0 {
        return false;
    }
    *word |= bit;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_round_trip_preserves_every_field() {
        let config = Config::parse(&[
            "--mode=stream".into(),
            "--warmup=3".into(),
            "--iterations=7".into(),
            "--streams=4".into(),
            "--payload-bytes=64".into(),
            "--bytes-per-stream=65536".into(),
            "--chunk-bytes=4096".into(),
            "--stream-window=131072".into(),
            "--timeout-ms=9000".into(),
            "--netz-ack-every=7".into(),
            "--netz-max-ack-delay-us=1234".into(),
            "--verify-cert=false".into(),
        ])
        .unwrap();
        let mut control = Control::new(Kind::RoundDone, &config, 5);
        control.received_bytes = 262_144;
        control.checksum = 33_423_360;
        assert_eq!(Control::decode(&control.encode()).unwrap(), control);
    }

    #[test]
    fn parsing_rejects_unknown_zero_and_ping_too_short() {
        assert!(Config::parse(&["--mode=unknown".into()]).is_err());
        assert!(Config::parse(&["--mode=stream".into(), "--streams=0".into(),]).is_err());
        assert!(Config::parse(&[
            "--mode=datagram-pingpong".into(),
            "--payload-bytes=13".into(),
        ])
        .is_err());
        assert!(Config::parse(&["--mode=stream".into(), "--direction=download".into(),]).is_err());
        assert_eq!(
            Config::parse(&["--mode=datagram-pingpong".into()])
                .unwrap()
                .warmup,
            200
        );
    }

    #[test]
    fn parsing_and_tracking_support_256_parallel_streams() {
        let config = Config::parse(&[
            "--mode=stream".into(),
            "--warmup=1".into(),
            "--iterations=1".into(),
            "--streams=256".into(),
        ])
        .unwrap();
        assert_eq!(config.streams, 256);
        assert!(Config::parse(&[
            "--mode=stream".into(),
            "--warmup=1".into(),
            "--iterations=1".into(),
            "--streams=257".into(),
        ])
        .is_err());

        let mut mask = [0u64; STREAM_MASK_WORDS];
        assert!(mark_stream(&mut mask, 63));
        assert!(mark_stream(&mut mask, 64));
        assert!(mark_stream(&mut mask, 255));
        assert!(!mark_stream(&mut mask, 64));
        assert_eq!(mask.iter().map(|word| word.count_ones()).sum::<u32>(), 3);
    }

    #[test]
    fn deterministic_payload_validators_detect_corruption() {
        let config = Config::parse(&["--mode=stream".into(), "--iterations=1".into()]).unwrap();
        let prelude = stream_prelude(9, 0);
        assert_eq!(verify_stream_prelude(&prelude, &config, 9).unwrap(), 0);

        let mut ping = [0u8; 32];
        fill_ping(&mut ping, 17);
        verify_ping(&ping, 17).unwrap();
        ping[31] ^= 1;
        assert!(verify_ping(&ping, 17).is_err());
    }

    #[tokio::test]
    async fn benchmark_entrypoints_reject_missing_port() {
        assert!(run_client(&[], false).await.is_err());
        assert!(run_server(&[], false).await.is_err());
    }
}
