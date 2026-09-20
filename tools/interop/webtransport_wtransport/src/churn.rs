use anyhow::{bail, ensure, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout_at, Instant};
use wtransport::error::StreamReadError;
use wtransport::stream::{RecvStream, SendStream};
use wtransport::{Connection, VarInt};

const READY: &[u8; 8] = b"NZWTRDY1";
const SIBLING_READY: &[u8; 8] = b"NZWTSIB1";
const RESET_SENT: &[u8; 8] = b"NZWTRSNT";
const RESETS_OBSERVED: &[u8; 8] = b"NZWTRST1";
const FIN_SENT: &[u8; 8] = b"NZWTFSNT";
const ACK: &[u8; 8] = b"NZWTACK1";
const RESULT_MAGIC: &[u8; 8] = b"NZWTRES2";
const MAX_STREAMS: u16 = 256;
const RESET_MASK_WORDS: usize = 4;
const RESULT_LEN: usize = 32 + RESET_MASK_WORDS * 8 + 8;
const STREAM_MAGIC: &[u8; 8] = b"NZWTSTRM";
const STREAM_PRELUDE_LEN: usize = 12;
const SIBLING_START: &[u8] = b"sibling-before-churn";
const SIBLING_END: &[u8] = b"-after-churn";
const SIBLING_RESPONSE: &[u8] = b"sibling-survived";
const CLOSE_READY: &[u8; 8] = b"NZWTCLSR";
const FAULT_KICK: &[u8] = b"fault-kick";
const RESET_AFTER_BYTES: usize = 256;
const RESET_CODE_BASE: u32 = 0x4000;
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;

#[derive(Debug)]
struct StreamResult {
    index: usize,
    bytes: u64,
    checksum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResultSummary {
    streams: u16,
    fins: u16,
    resets: u16,
    received_bytes: u64,
    checksum: u64,
    reset_mask: [u64; RESET_MASK_WORDS],
    reset_code_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProxyStats {
    considered: u64,
    dropped: u64,
    held: u64,
    reordered: u64,
}

pub(crate) async fn run_client_connection(
    connection: &Connection,
    control_send: &mut SendStream,
    control_recv: &mut RecvStream,
    stream_count: u16,
    bytes_per_stream: u64,
    timeout: Duration,
    fault: &str,
    reset_seed: u64,
    proxy_control_port: u16,
) -> Result<()> {
    ensure!(matches!(fault, "loss" | "reorder"), "invalid churn fault");
    ensure!(
        stream_count >= 2 && stream_count <= MAX_STREAMS,
        "invalid churn stream count"
    );
    ensure!(
        bytes_per_stream >= RESET_AFTER_BYTES as u64,
        "churn stream is shorter than reset prefix"
    );
    let deadline = Instant::now() + timeout;
    let stream = timeout_at(
        deadline,
        TcpStream::connect(("127.0.0.1", proxy_control_port)),
    )
    .await
    .context("proxy control connect timed out")??;
    let (read_half, write_half) = stream.into_split();
    let mut proxy = (BufReader::new(read_half), write_half);

    let sibling_opening = timeout_at(deadline, connection.open_bi())
        .await
        .context("churn sibling stream credit timed out")??;
    let (mut sibling_send, mut sibling_recv) = timeout_at(deadline, sibling_opening)
        .await
        .context("churn sibling association timed out")??;
    write_all_until(
        &mut sibling_send,
        SIBLING_START,
        deadline,
        "churn sibling prefix",
    )
    .await?;
    let mut sibling_ready = [0u8; SIBLING_READY.len()];
    read_exact_until(
        control_recv,
        &mut sibling_ready,
        deadline,
        "churn sibling ready",
    )
    .await?;
    ensure!(sibling_ready == *SIBLING_READY, "invalid sibling ready");

    let stream_bytes = usize::try_from(bytes_per_stream).context("stream size exceeds usize")?;
    let mut senders = Vec::with_capacity(usize::from(stream_count));
    for stream_index in 0..stream_count {
        let opening = timeout_at(deadline, connection.open_uni())
            .await
            .context("churn stream credit timed out")??;
        let mut sender = timeout_at(deadline, opening)
            .await
            .context("churn stream association timed out")??;
        let prelude = stream_prelude(stream_index);
        write_all_until(&mut sender, &prelude, deadline, "churn stream prelude").await?;
        let prefix = payload(usize::from(stream_index), 0, RESET_AFTER_BYTES);
        write_all_until(&mut sender, &prefix, deadline, "churn stream prefix").await?;
        senders.push(sender);
    }
    let mut marker = [0u8; READY.len()];
    read_exact_until(control_recv, &mut marker, deadline, "churn READY").await?;
    ensure!(marker == *READY, "invalid churn READY");

    proxy_command(&mut proxy, "arm-once", "armed", deadline).await?;
    for (index, sender) in senders.iter_mut().enumerate() {
        if should_reset(reset_seed, usize::from(stream_count), index) {
            sender.reset(mapped_stream_error(RESET_CODE_BASE + index as u32))?;
        }
    }
    write_all_until(control_send, RESET_SENT, deadline, "churn RESET_SENT").await?;
    connection.send_datagram(FAULT_KICK)?;
    let mut observed = [0u8; RESETS_OBSERVED.len()];
    read_exact_until(
        control_recv,
        &mut observed,
        deadline,
        "churn RESETS_OBSERVED",
    )
    .await?;
    ensure!(observed == *RESETS_OBSERVED, "invalid RESETS_OBSERVED");
    let reset_faults =
        parse_proxy_stats(&proxy_command(&mut proxy, "disarm", "disarmed", deadline).await?)?;

    proxy_command(&mut proxy, "arm-once", "armed", deadline).await?;
    for (index, sender) in senders.iter_mut().enumerate() {
        if should_reset(reset_seed, usize::from(stream_count), index) {
            continue;
        }
        let remainder = payload(index, RESET_AFTER_BYTES, stream_bytes - RESET_AFTER_BYTES);
        write_all_until(sender, &remainder, deadline, "churn FIN stream payload").await?;
        sender.quic_stream_mut().finish()?;
    }
    write_all_until(control_send, FIN_SENT, deadline, "churn FIN_SENT").await?;
    connection.send_datagram(FAULT_KICK)?;

    let mut encoded_result = [0u8; RESULT_LEN];
    read_exact_until(control_recv, &mut encoded_result, deadline, "churn result").await?;
    let result = decode_result(&encoded_result)?;
    ensure!(
        result == expected_result(stream_count, stream_bytes, reset_seed),
        "churn result mismatch"
    );
    let fin_faults =
        parse_proxy_stats(&proxy_command(&mut proxy, "disarm", "disarmed", deadline).await?)?;

    write_all_until(
        &mut sibling_send,
        SIBLING_END,
        deadline,
        "churn sibling suffix",
    )
    .await?;
    sibling_send.quic_stream_mut().finish()?;
    let mut response = [0u8; SIBLING_RESPONSE.len()];
    read_exact_and_fin_until(
        &mut sibling_recv,
        &mut response,
        deadline,
        "churn sibling response",
    )
    .await?;
    ensure!(
        response == SIBLING_RESPONSE,
        "invalid churn sibling response"
    );

    write_all_until(control_send, ACK, deadline, "churn ACK").await?;
    let mut extra = [0u8; 1];
    let terminal = timeout_at(deadline, control_recv.read(&mut extra))
        .await
        .context("churn control FIN timed out")??;
    ensure!(terminal.is_none(), "unexpected data after churn ACK");
    write_all_until(control_send, CLOSE_READY, deadline, "churn CLOSE_READY").await?;
    control_send.quic_stream_mut().finish()?;
    ensure!(
        fin_faults.considered >= reset_faults.considered,
        "proxy counters regressed"
    );
    let reset_dropped = reset_faults.dropped;
    let reset_held = reset_faults.held;
    let reset_reordered = reset_faults.reordered;
    let fin_dropped = fin_faults.dropped - reset_faults.dropped;
    let fin_held = fin_faults.held - reset_faults.held;
    let fin_reordered = fin_faults.reordered - reset_faults.reordered;
    match fault {
        "loss" => ensure!(
            reset_dropped == 1 && fin_dropped == 1,
            "loss did not affect each churn phase exactly once"
        ),
        "reorder" => ensure!(
            reset_held == 1 && reset_reordered == 1 && fin_held == 1 && fin_reordered == 1,
            "reordering did not affect each churn phase exactly once"
        ),
        _ => unreachable!(),
    }
    match timeout_at(deadline, connection.closed()).await {
        Ok(wtransport::error::ConnectionError::ApplicationClosed(close)) => {
            ensure!(
                close.code().into_inner() == 0,
                "unexpected churn close code"
            );
            ensure!(
                close.reason() == b"churn complete",
                "unexpected churn close reason"
            );
        }
        Ok(error) => bail!("unexpected churn close result: {error}"),
        Err(_) => bail!("churn peer close timed out"),
    }
    let stopped =
        parse_proxy_stats(&proxy_command(&mut proxy, "stop", "stopped", deadline).await?)?;
    ensure!(
        stopped == fin_faults,
        "proxy counters changed after final disarm"
    );
    println!(
        "wtransport client churn passed: fault={fault} fault_scope=wtransport-client-outbound reset_seed={reset_seed} streams={} fin={} reset={} bytes={} checksum={} reset_mask=0x{} reset_code_sum={} considered={} dropped={} held={} reordered={} reset_dropped={} reset_held={} reset_reordered={} fin_dropped={} fin_held={} fin_reordered={} sibling=true peer-close=true client_io=wtransport-quinn-tokio server_io=zio-std-io",
        result.streams,
        result.fins,
        result.resets,
        result.received_bytes,
        result.checksum,
        format_reset_mask(&result.reset_mask),
        result.reset_code_sum,
        stopped.considered,
        stopped.dropped,
        stopped.held,
        stopped.reordered,
        reset_dropped,
        reset_held,
        reset_reordered,
        fin_dropped,
        fin_held,
        fin_reordered,
    );
    Ok(())
}

async fn proxy_command(
    proxy: &mut (
        BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
    ),
    command: &str,
    expected: &str,
    deadline: Instant,
) -> Result<String> {
    timeout_at(deadline, proxy.1.write_all(command.as_bytes()))
        .await
        .context("proxy command write timed out")??;
    timeout_at(deadline, proxy.1.write_all(b"\n"))
        .await
        .context("proxy command newline timed out")??;
    timeout_at(deadline, proxy.1.flush())
        .await
        .context("proxy command flush timed out")??;
    let mut response = String::new();
    timeout_at(deadline, proxy.0.read_line(&mut response))
        .await
        .context("proxy response timed out")??;
    ensure!(response.starts_with(expected), "unexpected proxy response");
    Ok(response)
}

fn parse_proxy_stats(response: &str) -> Result<ProxyStats> {
    let mut stats = ProxyStats {
        considered: 0,
        dropped: 0,
        held: 0,
        reordered: 0,
    };
    let mut seen = 0u8;
    for field in response.split_whitespace().skip(1) {
        let (name, value) = field.split_once('=').context("malformed proxy counter")?;
        let parsed = value.parse::<u64>().context("invalid proxy counter")?;
        let bit = match name {
            "considered" => {
                stats.considered = parsed;
                1
            }
            "dropped" => {
                stats.dropped = parsed;
                2
            }
            "held" => {
                stats.held = parsed;
                4
            }
            "reordered" => {
                stats.reordered = parsed;
                8
            }
            _ => bail!("unknown proxy counter {name}"),
        };
        ensure!(seen & bit == 0, "duplicate proxy counter {name}");
        seen |= bit;
    }
    ensure!(seen == 0x0f, "incomplete proxy counters");
    Ok(stats)
}

pub(crate) async fn run_server_connection(
    connection: &Connection,
    control_send: &mut SendStream,
    control_recv: &mut RecvStream,
    stream_count: u16,
    bytes_per_stream: u64,
    timeout: Duration,
    fault: &str,
    reset_seed: u64,
) -> Result<()> {
    ensure!(matches!(fault, "loss" | "reorder"), "invalid churn fault");
    ensure!(
        stream_count >= 2 && stream_count <= MAX_STREAMS,
        "invalid churn stream count"
    );
    ensure!(
        bytes_per_stream >= RESET_AFTER_BYTES as u64,
        "churn stream is shorter than reset prefix"
    );
    let deadline = Instant::now() + timeout;

    let (mut sibling_send, mut sibling_recv) = timeout_at(deadline, connection.accept_bi())
        .await
        .context("churn sibling accept timed out")??;
    let mut sibling_start = [0u8; SIBLING_START.len()];
    read_exact_until(
        &mut sibling_recv,
        &mut sibling_start,
        deadline,
        "churn sibling prefix",
    )
    .await?;
    ensure!(
        sibling_start == SIBLING_START,
        "invalid churn sibling prefix"
    );

    let mut streams = Vec::with_capacity(usize::from(stream_count));
    let mut seen = [0u64; RESET_MASK_WORDS];
    for _ in 0..stream_count {
        let mut receiver = timeout_at(deadline, connection.accept_uni())
            .await
            .context("churn stream accept timed out")??;
        let mut prelude = [0u8; STREAM_PRELUDE_LEN];
        read_exact_until(
            &mut receiver,
            &mut prelude,
            deadline,
            "churn stream prelude",
        )
        .await?;
        ensure!(&prelude[0..8] == STREAM_MAGIC, "invalid churn stream magic");
        ensure!(prelude[10..12] == [0, 0], "nonzero stream reserved bytes");
        let index = usize::from(u16::from_be_bytes(prelude[8..10].try_into().unwrap()));
        ensure!(
            index < usize::from(stream_count),
            "churn stream index out of range"
        );
        ensure!(mark_bit(&mut seen, index), "duplicate churn stream index");

        let mut prefix = [0u8; RESET_AFTER_BYTES];
        read_exact_until(&mut receiver, &mut prefix, deadline, "churn stream prefix").await?;
        verify_payload(&prefix, index, 0)?;
        streams.push((index, receiver, checksum_bytes(&prefix)));
    }
    write_all_until(control_send, READY, deadline, "churn READY").await?;

    let mut reset_readers = JoinSet::new();
    let mut fin_streams = Vec::with_capacity(usize::from(stream_count) / 2);
    for (index, mut receiver, prefix_checksum) in streams {
        if !should_reset(reset_seed, usize::from(stream_count), index) {
            fin_streams.push((index, receiver, prefix_checksum));
            continue;
        }
        reset_readers.spawn(async move {
            let mut unexpected = [0u8; 1];
            match timeout_at(deadline, receiver.read(&mut unexpected))
                .await
                .context("churn reset observation timed out")?
            {
                Err(StreamReadError::Reset(code)) => ensure!(
                    code == mapped_stream_error(RESET_CODE_BASE + u32::try_from(index).unwrap()),
                    "unexpected churn reset code {code}"
                ),
                Ok(Some(count)) => {
                    bail!("reset stream {index} delivered {count} bytes after acknowledged prefix")
                }
                Ok(None) => bail!("reset stream {index} finished normally"),
                Err(error) => return Err(error.into()),
            }
            Ok::<_, anyhow::Error>(StreamResult {
                index,
                bytes: RESET_AFTER_BYTES as u64,
                checksum: prefix_checksum,
            })
        });
    }

    let mut received_bytes = 0u64;
    let mut checksum = 0u64;
    let mut resets = 0u16;
    let mut reset_mask = [0u64; RESET_MASK_WORDS];
    let mut reset_code_sum = 0u64;
    while let Some(result) = reset_readers.join_next().await {
        let result = result.context("churn reset reader task failed")??;
        received_bytes = received_bytes.wrapping_add(result.bytes);
        checksum = checksum.wrapping_add(result.checksum);
        resets += 1;
        ensure!(
            mark_bit(&mut reset_mask, result.index),
            "duplicate churn reset index"
        );
        reset_code_sum =
            reset_code_sum.wrapping_add(u64::from(RESET_CODE_BASE) + result.index as u64);
    }
    ensure!(
        resets
            == (0..usize::from(stream_count))
                .filter(|index| should_reset(reset_seed, usize::from(stream_count), *index))
                .count() as u16,
        "churn reset count mismatch"
    );

    let mut marker = [0u8; RESET_SENT.len()];
    read_exact_until(control_recv, &mut marker, deadline, "churn RESET_SENT").await?;
    ensure!(marker == *RESET_SENT, "invalid churn RESET_SENT marker");
    write_all_until(
        control_send,
        RESETS_OBSERVED,
        deadline,
        "churn RESETS_OBSERVED",
    )
    .await?;

    let mut fin_readers = JoinSet::new();
    for (index, mut receiver, prefix_checksum) in fin_streams {
        fin_readers.spawn(async move {
            let mut received = RESET_AFTER_BYTES;
            let mut checksum = prefix_checksum;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                match timeout_at(deadline, receiver.read(&mut buffer))
                    .await
                    .context("churn FIN stream read timed out")?
                {
                    Ok(Some(count)) => {
                        ensure!(
                            received + count <= bytes_per_stream as usize,
                            "churn FIN stream exceeds configured size"
                        );
                        verify_payload(&buffer[..count], index, received)?;
                        checksum = checksum.wrapping_add(checksum_bytes(&buffer[..count]));
                        received += count;
                    }
                    Ok(None) => {
                        ensure!(
                            received == bytes_per_stream as usize,
                            "churn FIN stream ended early"
                        );
                        return Ok::<_, anyhow::Error>(StreamResult {
                            index,
                            bytes: received as u64,
                            checksum,
                        });
                    }
                    Err(StreamReadError::Reset(code)) => {
                        bail!("FIN stream {index} was reset with {code}");
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        });
    }
    let mut fins = 0u16;
    while let Some(result) = fin_readers.join_next().await {
        let result = result.context("churn FIN reader task failed")??;
        received_bytes = received_bytes.wrapping_add(result.bytes);
        checksum = checksum.wrapping_add(result.checksum);
        fins += 1;
    }
    ensure!(
        fins + resets == stream_count,
        "churn terminal count mismatch"
    );
    let mut fin_marker = [0u8; FIN_SENT.len()];
    read_exact_until(control_recv, &mut fin_marker, deadline, "churn FIN_SENT").await?;
    ensure!(fin_marker == *FIN_SENT, "invalid churn FIN_SENT marker");

    let result = encode_result(
        stream_count,
        fins,
        resets,
        received_bytes,
        checksum,
        reset_mask,
        reset_code_sum,
    );
    write_all_until(control_send, &result, deadline, "churn result").await?;

    let mut sibling_end = [0u8; SIBLING_END.len()];
    read_exact_until(
        &mut sibling_recv,
        &mut sibling_end,
        deadline,
        "churn sibling suffix",
    )
    .await?;
    ensure!(sibling_end == SIBLING_END, "invalid churn sibling suffix");
    let mut extra = [0u8; 1];
    let terminal = timeout_at(deadline, sibling_recv.read(&mut extra))
        .await
        .context("churn sibling FIN timed out")??;
    ensure!(terminal.is_none(), "unexpected churn sibling data");
    write_all_until(
        &mut sibling_send,
        SIBLING_RESPONSE,
        deadline,
        "churn sibling response",
    )
    .await?;
    timeout_at(deadline, sibling_send.finish())
        .await
        .context("churn sibling response FIN timed out")??;

    let mut ack = [0u8; ACK.len()];
    read_exact_until(control_recv, &mut ack, deadline, "churn ACK").await?;
    ensure!(ack == *ACK, "invalid churn ACK");
    let terminal = timeout_at(deadline, control_recv.read(&mut extra))
        .await
        .context("churn control FIN timed out")??;
    ensure!(terminal.is_none(), "unexpected data after churn ACK");
    timeout_at(deadline, control_send.finish())
        .await
        .context("churn control response FIN timed out")??;
    println!(
        "wtransport server churn passed: fault={fault} fault_scope=netz-client-outbound reset_seed={reset_seed} streams={stream_count} fin={fins} reset={resets} bytes={received_bytes} checksum={checksum} reset_mask=0x{} reset_code_sum={reset_code_sum} sibling=true client_io=zio-std-io server_io=wtransport-quinn-tokio",
        format_reset_mask(&reset_mask),
    );
    Ok(())
}

async fn read_exact_until(
    stream: &mut RecvStream,
    out: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<()> {
    timeout_at(deadline, stream.read_exact(out))
        .await
        .with_context(|| format!("{label} timed out"))??;
    Ok(())
}

async fn write_all_until(
    stream: &mut SendStream,
    bytes: &[u8],
    deadline: Instant,
    label: &str,
) -> Result<()> {
    timeout_at(deadline, stream.write_all(bytes))
        .await
        .with_context(|| format!("{label} timed out"))??;
    Ok(())
}

async fn read_exact_and_fin_until(
    stream: &mut RecvStream,
    out: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<()> {
    read_exact_until(stream, out, deadline, label).await?;
    let mut extra = [0u8; 1];
    let terminal = timeout_at(deadline, stream.read(&mut extra))
        .await
        .with_context(|| format!("{label} FIN timed out"))??;
    ensure!(terminal.is_none(), "unexpected data after {label}");
    Ok(())
}

fn should_reset(seed: u64, stream_count: usize, index: usize) -> bool {
    debug_assert!((2..=MAX_STREAMS.into()).contains(&stream_count));
    debug_assert!(index < stream_count);
    if index == 0 {
        return true;
    }
    if index == 1 {
        return false;
    }
    let mut value =
        seed.wrapping_add(SPLITMIX_INCREMENT.wrapping_mul((index as u64).wrapping_add(1)));
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    value & 1 != 0
}

fn mapped_stream_error(application_code: u32) -> VarInt {
    let code = u64::from(application_code);
    VarInt::try_from_u64(0x52e4_a40f_a8db + code + code / 0x1e)
        .expect("mapped WebTransport error fits a QUIC varint")
}

fn payload_byte(offset: usize, stream_index: usize) -> u8 {
    ((offset.wrapping_mul(131) + stream_index.wrapping_mul(17)) & 0xff) as u8
}

fn stream_prelude(index: u16) -> [u8; STREAM_PRELUDE_LEN] {
    let mut bytes = [0u8; STREAM_PRELUDE_LEN];
    bytes[0..8].copy_from_slice(STREAM_MAGIC);
    bytes[8..10].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn payload(stream_index: usize, offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len)
        .map(|value| payload_byte(value, stream_index))
        .collect()
}

fn verify_payload(bytes: &[u8], stream_index: usize, offset: usize) -> Result<()> {
    for (index, byte) in bytes.iter().copied().enumerate() {
        ensure!(
            byte == payload_byte(offset + index, stream_index),
            "churn payload mismatch on stream {stream_index}"
        );
    }
    Ok(())
}

fn checksum_bytes(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)))
}

fn mark_bit(mask: &mut [u64; RESET_MASK_WORDS], index: usize) -> bool {
    let word = &mut mask[index / 64];
    let bit = 1u64 << (index % 64);
    if *word & bit != 0 {
        return false;
    }
    *word |= bit;
    true
}

fn encode_reset_mask(out: &mut [u8], mask: &[u64; RESET_MASK_WORDS]) {
    assert_eq!(out.len(), RESET_MASK_WORDS * 8);
    for (wire_index, word) in mask.iter().rev().enumerate() {
        out[wire_index * 8..][..8].copy_from_slice(&word.to_be_bytes());
    }
}

fn decode_reset_mask(bytes: &[u8]) -> [u64; RESET_MASK_WORDS] {
    assert_eq!(bytes.len(), RESET_MASK_WORDS * 8);
    let mut mask = [0u64; RESET_MASK_WORDS];
    for (wire_index, word) in mask.iter_mut().rev().enumerate() {
        *word = u64::from_be_bytes(bytes[wire_index * 8..][..8].try_into().unwrap());
    }
    mask
}

fn format_reset_mask(mask: &[u64; RESET_MASK_WORDS]) -> String {
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        mask[3], mask[2], mask[1], mask[0]
    )
}

fn encode_result(
    streams: u16,
    fins: u16,
    resets: u16,
    received_bytes: u64,
    checksum: u64,
    reset_mask: [u64; RESET_MASK_WORDS],
    reset_code_sum: u64,
) -> [u8; RESULT_LEN] {
    let mut bytes = [0u8; RESULT_LEN];
    bytes[0..8].copy_from_slice(RESULT_MAGIC);
    bytes[8..10].copy_from_slice(&streams.to_be_bytes());
    bytes[10..12].copy_from_slice(&fins.to_be_bytes());
    bytes[12..14].copy_from_slice(&resets.to_be_bytes());
    bytes[16..24].copy_from_slice(&received_bytes.to_be_bytes());
    bytes[24..32].copy_from_slice(&checksum.to_be_bytes());
    encode_reset_mask(&mut bytes[32..64], &reset_mask);
    bytes[64..72].copy_from_slice(&reset_code_sum.to_be_bytes());
    bytes
}

fn decode_result(bytes: &[u8; RESULT_LEN]) -> Result<ResultSummary> {
    ensure!(&bytes[0..8] == RESULT_MAGIC, "invalid churn result magic");
    ensure!(
        bytes[14..16] == [0, 0],
        "nonzero churn result reserved bytes"
    );
    Ok(ResultSummary {
        streams: u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        fins: u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
        resets: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
        received_bytes: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        checksum: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        reset_mask: decode_reset_mask(&bytes[32..64]),
        reset_code_sum: u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
    })
}

fn expected_result(stream_count: u16, bytes_per_stream: usize, reset_seed: u64) -> ResultSummary {
    let mut result = ResultSummary {
        streams: stream_count,
        fins: 0,
        resets: 0,
        received_bytes: 0,
        checksum: 0,
        reset_mask: [0; RESET_MASK_WORDS],
        reset_code_sum: 0,
    };
    for index in 0..usize::from(stream_count) {
        let reset = should_reset(reset_seed, usize::from(stream_count), index);
        let count = if reset {
            RESET_AFTER_BYTES
        } else {
            bytes_per_stream
        };
        result.received_bytes += count as u64;
        result.checksum = result
            .checksum
            .wrapping_add(checksum_bytes(&payload(index, 0, count)));
        if reset {
            result.resets += 1;
            assert!(mark_bit(&mut result.reset_mask, index));
            result.reset_code_sum += u64::from(RESET_CODE_BASE) + index as u64;
        } else {
            result.fins += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_encoding_is_stable() {
        let mask = [0xaaaa_aaaa, 0, 0, 0];
        let bytes = encode_result(32, 16, 16, 266_240, 33_945_600, mask, 262_400);
        assert_eq!(&bytes[0..8], RESULT_MAGIC);
        assert_eq!(u16::from_be_bytes(bytes[8..10].try_into().unwrap()), 32);
        assert_eq!(u16::from_be_bytes(bytes[10..12].try_into().unwrap()), 16);
        assert_eq!(u16::from_be_bytes(bytes[12..14].try_into().unwrap()), 16);
        assert_eq!(
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            266_240
        );
        assert_eq!(
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            33_945_600
        );
        assert_eq!(decode_reset_mask(&bytes[32..64]), mask);
        assert_eq!(
            u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
            262_400
        );
        assert_eq!(decode_result(&bytes).unwrap().reset_mask, mask);
        assert_eq!(
            format_reset_mask(&mask),
            "00000000000000000000000000000000000000000000000000000000aaaaaaaa"
        );
    }

    #[test]
    fn expected_results_cover_32_64_and_256_stream_shapes() {
        let seed = 0x0123_4567_89ab_cdef;
        assert_eq!(
            expected_result(32, 16_384, seed),
            ResultSummary {
                streams: 32,
                fins: 17,
                resets: 15,
                received_bytes: 282_368,
                checksum: 36_001_920,
                reset_mask: [0xac80_f7c1, 0, 0, 0],
                reset_code_sum: 245_990,
            }
        );
        let result = expected_result(64, 16_384, seed);
        assert_eq!(result.fins, 35);
        assert_eq!(result.resets, 29);
        assert_eq!(result.received_bytes, 580_864);
        assert_eq!(result.checksum, 74_060_160);
        assert_eq!(result.reset_mask, [0x8177_34c8_ac80_f7c1, 0, 0, 0]);
        assert_eq!(result.reset_code_sum, 476_034);
        let large = expected_result(256, 16_384, seed);
        assert_eq!(large.fins, 122);
        assert_eq!(large.resets, 134);
        assert_eq!(large.received_bytes, 2_033_152);
        assert_eq!(large.checksum, 259_226_880);
        assert_eq!(
            large.reset_mask,
            [
                0x8177_34c8_ac80_f7c1,
                0x53ac_3c58_2f1d_6af9,
                0x5f37_54fe_3fba_3187,
                0x2071_7754_f9d1_1ba5,
            ]
        );
        assert_eq!(large.reset_code_sum, 2_212_897);
        assert!(should_reset(2, usize::from(MAX_STREAMS), 255));
        assert!(should_reset(seed, 2, 0));
        assert!(!should_reset(seed, 2, 1));
    }

    #[test]
    fn proxy_stats_parser_rejects_duplicate_and_missing_fields() {
        assert_eq!(
            parse_proxy_stats("disarmed considered=10 dropped=2 held=0 reordered=0\n").unwrap(),
            ProxyStats {
                considered: 10,
                dropped: 2,
                held: 0,
                reordered: 0,
            }
        );
        assert!(parse_proxy_stats("disarmed considered=1 dropped=0 held=0").is_err());
        assert!(parse_proxy_stats(
            "disarmed considered=1 considered=2 dropped=0 held=0 reordered=0"
        )
        .is_err());
    }
}
