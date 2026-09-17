use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use quinn::Connection;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const TIMEOUT_MAX_MS: u32 = 10 * 60 * 1000;
pub const ALPN: &[u8] = b"netz-datagram-bench";
const RECORD_LEN: usize = 40;
const RECORD_MAGIC: &[u8; 8] = b"NZDGBN01";
const PAYLOAD_MAGIC: &[u8; 4] = b"NZDG";
const MAX_PAYLOAD: usize = 1024;
const MAX_WINDOW: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Config = 1,
    Ready = 2,
    Done = 3,
    Ack = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub warmup: u32,
    pub iterations: u32,
    pub payload_bytes: u16,
    pub window: u16,
    pub timeout_ms: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            warmup: 200,
            iterations: 5000,
            payload_bytes: 32,
            window: 1,
            timeout_ms: 30_000,
        }
    }
}

impl Config {
    pub fn parse(args: impl Iterator<Item = String>) -> Result<Self> {
        let mut config = Self::default();
        for argument in args {
            if let Some(value) = argument.strip_prefix("--warmup=") {
                config.warmup = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--iterations=") {
                config.iterations = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--payload-bytes=") {
                config.payload_bytes = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--window=") {
                config.window = value.parse()?;
            } else if let Some(value) = argument.strip_prefix("--timeout-ms=") {
                config.timeout_ms = value.parse()?;
            } else {
                bail!("unexpected benchmark argument: {argument}");
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(self) -> Result<()> {
        ensure!(self.warmup <= 100_000, "warmup is too large");
        ensure!(
            (1..=1_000_000).contains(&self.iterations),
            "invalid iterations"
        );
        ensure!(
            (12..=MAX_PAYLOAD as u16).contains(&self.payload_bytes),
            "invalid payload bytes"
        );
        ensure!(
            (1..=MAX_WINDOW).contains(&self.window),
            "invalid DATAGRAM window"
        );
        ensure!(
            (1..=TIMEOUT_MAX_MS).contains(&self.timeout_ms),
            "invalid timeout"
        );
        self.rounds().context("round count overflow")?;
        ensure!(
            self.total_bytes().context("byte count overflow")? <= u64::from(u32::MAX),
            "byte count exceeds wire record"
        );
        Ok(())
    }

    fn rounds(self) -> Option<u32> {
        self.warmup.checked_add(self.iterations)
    }

    fn total_bytes(self) -> Option<u64> {
        self.total_datagrams()?
            .checked_mul(u64::from(self.payload_bytes))
    }

    fn total_datagrams(self) -> Option<u64> {
        u64::from(self.rounds()?).checked_mul(u64::from(self.window))
    }

    pub fn timeout(self) -> Duration {
        Duration::from_millis(u64::from(self.timeout_ms))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    kind: Kind,
    config: Config,
    received_bytes: u64,
    checksum: u64,
}

impl Record {
    fn new(kind: Kind, config: Config) -> Self {
        Self {
            kind,
            config,
            received_bytes: 0,
            checksum: 0,
        }
    }

    fn encode(self) -> Result<[u8; RECORD_LEN]> {
        let mut out = [0; RECORD_LEN];
        out[0..8].copy_from_slice(RECORD_MAGIC);
        out[8] = self.kind as u8;
        out[9] = 2;
        out[12..16].copy_from_slice(&self.config.warmup.to_be_bytes());
        out[16..20].copy_from_slice(&self.config.iterations.to_be_bytes());
        out[20..22].copy_from_slice(&self.config.payload_bytes.to_be_bytes());
        out[22..24].copy_from_slice(&self.config.window.to_be_bytes());
        out[24..28].copy_from_slice(&self.config.timeout_ms.to_be_bytes());
        out[28..32].copy_from_slice(
            &u32::try_from(self.received_bytes)
                .context("received bytes exceed wire record")?
                .to_be_bytes(),
        );
        out[32..40].copy_from_slice(&self.checksum.to_be_bytes());
        Ok(out)
    }

    fn decode(bytes: &[u8; RECORD_LEN]) -> Result<Self> {
        ensure!(
            &bytes[0..8] == RECORD_MAGIC && bytes[9] == 2 && bytes[10..12] == [0, 0],
            "invalid benchmark control header"
        );
        let kind = match bytes[8] {
            1 => Kind::Config,
            2 => Kind::Ready,
            3 => Kind::Done,
            4 => Kind::Ack,
            _ => bail!("invalid benchmark control kind"),
        };
        let config = Config {
            warmup: u32::from_be_bytes(bytes[12..16].try_into()?),
            iterations: u32::from_be_bytes(bytes[16..20].try_into()?),
            payload_bytes: u16::from_be_bytes(bytes[20..22].try_into()?),
            window: u16::from_be_bytes(bytes[22..24].try_into()?),
            timeout_ms: u32::from_be_bytes(bytes[24..28].try_into()?),
        };
        config.validate()?;
        Ok(Self {
            kind,
            config,
            received_bytes: u64::from(u32::from_be_bytes(bytes[28..32].try_into()?)),
            checksum: u64::from_be_bytes(bytes[32..40].try_into()?),
        })
    }
}

pub struct Outcome {
    pub received_bytes: u64,
    pub checksum: u64,
}

pub async fn run_client(connection: &Connection, config: Config, role_pair: &str) -> Result<()> {
    let (mut send, mut recv) = timeout(config.timeout(), connection.open_bi())
        .await
        .context("opening benchmark control stream timed out")??;
    ensure!(u64::from(send.id()) == 0, "unexpected control stream id");
    send_record(&mut send, Record::new(Kind::Config, config)).await?;
    expect_record(
        receive_record(&mut recv, false, config).await?,
        Kind::Ready,
        config,
    )?;

    let datagram_limit = connection
        .max_datagram_size()
        .context("DATAGRAM was not negotiated")?;
    ensure!(
        datagram_limit >= usize::from(config.payload_bytes),
        "payload exceeds negotiated DATAGRAM size"
    );
    let mut samples = Vec::with_capacity(config.iterations as usize);
    let window = usize::from(config.window);
    let mut payloads = vec![vec![0; usize::from(config.payload_bytes)]; window];
    let mut seen = vec![false; window];
    let mut checksum = 0u64;
    for round in 0..config.rounds().unwrap() {
        let first_sequence = round * u32::from(config.window);
        for (index, payload) in payloads.iter_mut().enumerate() {
            fill_payload(payload, first_sequence + index as u32);
        }
        let started = Instant::now();
        for payload in &payloads {
            connection.send_datagram(Bytes::copy_from_slice(payload))?;
        }
        seen.fill(false);
        for _ in 0..window {
            let echoed = timeout(config.timeout(), connection.read_datagram())
                .await
                .context("benchmark DATAGRAM receive timed out")??;
            let sequence = verify_window_payload(&echoed, first_sequence, config)?;
            let index = (sequence - first_sequence) as usize;
            ensure!(!seen[index], "duplicate benchmark DATAGRAM");
            seen[index] = true;
            add_checksum(&mut checksum, &echoed);
        }
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if round >= config.warmup {
            samples.push(elapsed);
        }
    }

    let mut done = Record::new(Kind::Done, config);
    done.received_bytes = config.total_bytes().unwrap();
    done.checksum = checksum;
    send_record(&mut send, done).await?;
    send.finish()?;
    let ack = receive_record(&mut recv, true, config).await?;
    expect_record(ack, Kind::Ack, config)?;
    ensure!(
        ack.received_bytes == done.received_bytes && ack.checksum == checksum,
        "invalid benchmark completion acknowledgement"
    );

    samples.sort_unstable();
    print_result(role_pair, config, datagram_limit, &samples, checksum);
    Ok(())
}

pub async fn run_server(
    connection: &Connection,
    expected: Config,
    role_pair: &str,
) -> Result<Outcome> {
    let (mut send, mut recv) = timeout(expected.timeout(), connection.accept_bi())
        .await
        .context("accepting benchmark control stream timed out")??;
    ensure!(u64::from(send.id()) == 0, "unexpected control stream id");
    let config_record = receive_record(&mut recv, false, expected).await?;
    expect_record(config_record, Kind::Config, expected)?;
    print_config(
        role_pair,
        "server",
        expected,
        connection
            .max_datagram_size()
            .context("DATAGRAM was not negotiated")?,
    );
    send_record(&mut send, Record::new(Kind::Ready, expected)).await?;

    let mut checksum = 0u64;
    let window = usize::from(expected.window);
    let mut received = Vec::with_capacity(window);
    let mut seen = vec![false; window];
    for round in 0..expected.rounds().unwrap() {
        let first_sequence = round * u32::from(expected.window);
        received.clear();
        seen.fill(false);
        for _ in 0..window {
            let payload = timeout(expected.timeout(), connection.read_datagram())
                .await
                .context("benchmark DATAGRAM receive timed out")??;
            let sequence = verify_window_payload(&payload, first_sequence, expected)?;
            let index = (sequence - first_sequence) as usize;
            ensure!(!seen[index], "duplicate benchmark DATAGRAM");
            seen[index] = true;
            add_checksum(&mut checksum, &payload);
            received.push(payload);
        }
        for payload in received.drain(..) {
            connection.send_datagram(payload)?;
        }
    }

    let done = receive_record(&mut recv, true, expected).await?;
    expect_record(done, Kind::Done, expected)?;
    let received_bytes = expected.total_bytes().unwrap();
    ensure!(
        done.received_bytes == received_bytes && done.checksum == checksum,
        "invalid benchmark completion"
    );
    let mut ack = Record::new(Kind::Ack, expected);
    ack.received_bytes = received_bytes;
    ack.checksum = checksum;
    send_record(&mut send, ack).await?;
    send.finish()?;
    print_server_complete(role_pair, expected, received_bytes, checksum);
    Ok(Outcome {
        received_bytes,
        checksum,
    })
}

pub fn print_config(role_pair: &str, endpoint_role: &str, config: Config, limit: usize) {
    println!(
        "record=config implementation=quinn protocol=quic-datagram mode={} role_pair={role_pair} endpoint_role={endpoint_role} client_io={} server_io={} connection_scope=fresh-per-sample benchmark_scope=same-application-shape timing_scope={} warmup={} iterations={} payload_bytes={} window={} total_datagrams={} timeout_ms={} steady_state_mtu=1200 datagram_limit={limit} quic_version=1 cert_verify=true pacing=implementation-specific udp_batching={} complete=true",
        mode(config),
        client_io(role_pair),
        server_io(role_pair),
        timing_scope(config),
        config.warmup,
        config.iterations,
        config.payload_bytes,
        config.window,
        config.total_datagrams().unwrap(),
        config.timeout_ms,
        udp_batching(config),
    );
}

fn print_result(role_pair: &str, config: Config, limit: usize, samples: &[u64], checksum: u64) {
    let sum: u128 = samples.iter().map(|&x| u128::from(x)).sum();
    println!(
        "record=result implementation=quinn protocol=quic-datagram mode={} role_pair={role_pair} endpoint_role=client client_io={} server_io={} connection_scope=fresh-per-sample benchmark_scope=same-application-shape timing_scope={} warmup={} iterations={} payload_bytes={} window={} total_datagrams={} timeout_ms={} datagram_limit={limit} p50_ns={} p90_ns={} p99_ns={} p999_ns={} mean_ns={} min_ns={} max_ns={} received_bytes={} checksum={} completion_exchange_verified=true close_code=59 complete=true",
        mode(config),
        client_io(role_pair),
        server_io(role_pair),
        timing_scope(config),
        config.warmup,
        config.iterations,
        config.payload_bytes,
        config.window,
        config.total_datagrams().unwrap(),
        config.timeout_ms,
        percentile(samples, 50, 100),
        percentile(samples, 90, 100),
        percentile(samples, 99, 100),
        percentile(samples, 999, 1000),
        sum / samples.len() as u128,
        samples[0],
        samples[samples.len() - 1],
        config.total_bytes().unwrap(),
        checksum,
    );
}

fn print_server_complete(role_pair: &str, config: Config, received_bytes: u64, checksum: u64) {
    println!(
        "record=server-complete implementation=quinn protocol=quic-datagram mode={} role_pair={role_pair} endpoint_role=server client_io={} server_io={} timing_scope={} warmup={} iterations={} payload_bytes={} window={} total_datagrams={} timeout_ms={} received_bytes={received_bytes} checksum={checksum} completion_exchange_verified=true close_code=59 complete=true",
        mode(config),
        client_io(role_pair),
        server_io(role_pair),
        timing_scope(config),
        config.warmup,
        config.iterations,
        config.payload_bytes,
        config.window,
        config.total_datagrams().unwrap(),
        config.timeout_ms,
    );
}

async fn send_record(stream: &mut quinn::SendStream, record: Record) -> Result<()> {
    let bytes = record.encode()?;
    timeout(record.config.timeout(), stream.write_all(&bytes))
        .await
        .context("benchmark control send timed out")??;
    Ok(())
}

async fn receive_record(
    stream: &mut quinn::RecvStream,
    expect_fin: bool,
    config: Config,
) -> Result<Record> {
    let mut bytes = [0; RECORD_LEN];
    timeout(config.timeout(), stream.read_exact(&mut bytes))
        .await
        .context("benchmark control receive timed out")??;
    if expect_fin {
        let tail = timeout(config.timeout(), stream.read_chunk(1, true))
            .await
            .context("benchmark control FIN timed out")??;
        ensure!(tail.is_none(), "benchmark control carried trailing bytes");
    }
    Record::decode(&bytes)
}

fn expect_record(record: Record, kind: Kind, config: Config) -> Result<()> {
    ensure!(
        record.kind == kind && record.config == config,
        "invalid benchmark control record"
    );
    Ok(())
}

fn fill_payload(payload: &mut [u8], sequence: u32) {
    payload[0..4].copy_from_slice(PAYLOAD_MAGIC);
    payload[4..12].copy_from_slice(&u64::from(sequence).to_be_bytes());
    for (index, byte) in payload[12..].iter_mut().enumerate() {
        *byte = sequence
            .wrapping_mul(17)
            .wrapping_add((index as u32).wrapping_mul(131)) as u8;
    }
}

fn verify_payload(payload: &[u8], sequence: u32, expected_len: u16) -> Result<()> {
    ensure!(
        payload.len() == usize::from(expected_len)
            && &payload[0..4] == PAYLOAD_MAGIC
            && u64::from_be_bytes(payload[4..12].try_into()?) == u64::from(sequence),
        "invalid benchmark DATAGRAM header"
    );
    for (index, &byte) in payload[12..].iter().enumerate() {
        let expected = sequence
            .wrapping_mul(17)
            .wrapping_add((index as u32).wrapping_mul(131)) as u8;
        ensure!(byte == expected, "invalid benchmark DATAGRAM payload");
    }
    Ok(())
}

fn verify_window_payload(payload: &[u8], first_sequence: u32, config: Config) -> Result<u32> {
    ensure!(
        payload.len() == usize::from(config.payload_bytes)
            && payload.get(0..4) == Some(PAYLOAD_MAGIC),
        "invalid benchmark DATAGRAM header"
    );
    let sequence = u64::from_be_bytes(payload[4..12].try_into()?)
        .try_into()
        .context("benchmark DATAGRAM sequence overflow")?;
    ensure!(
        sequence >= first_sequence && sequence < first_sequence + u32::from(config.window),
        "benchmark DATAGRAM outside current window"
    );
    verify_payload(payload, sequence, config.payload_bytes)?;
    Ok(sequence)
}

fn add_checksum(checksum: &mut u64, payload: &[u8]) {
    for &byte in payload {
        *checksum = checksum.wrapping_add(u64::from(byte));
    }
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    let rank = sorted.len().saturating_mul(numerator).div_ceil(denominator);
    sorted[rank.max(1) - 1]
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

fn mode(config: Config) -> &'static str {
    if config.window == 1 {
        "pingpong"
    } else {
        "windowed-pingpong"
    }
}

fn timing_scope(config: Config) -> &'static str {
    if config.window == 1 {
        "post-handshake-single-outstanding-roundtrip"
    } else {
        "post-handshake-window-roundtrip"
    }
}

fn udp_batching(config: Config) -> &'static str {
    if config.window == 1 {
        "single-message"
    } else {
        "quinn-runtime-auto"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_payload_match_wire_contract() {
        let config = Config {
            window: 64,
            ..Config::default()
        };
        let mut record = Record::new(Kind::Done, config);
        record.received_bytes = config.total_bytes().unwrap();
        record.checksum = 0x0123_4567_89ab_cdef;
        assert_eq!(Record::decode(&record.encode().unwrap()).unwrap(), record);

        let mut payload = vec![0; usize::from(config.payload_bytes)];
        fill_payload(&mut payload, 123);
        verify_payload(&payload, 123, config.payload_bytes).unwrap();
        assert!(verify_payload(&payload, 124, config.payload_bytes).is_err());
        assert!(Config {
            window: 0,
            ..config
        }
        .validate()
        .is_err());
        assert!(Config {
            window: 65,
            ..config
        }
        .validate()
        .is_err());
    }
}
