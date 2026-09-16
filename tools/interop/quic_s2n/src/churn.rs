use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use s2n_quic::{application, stream::BidirectionalStream, Connection};
use std::time::Duration;
use tokio::time::timeout;

pub const STREAMS: usize = 32;
pub const BYTES_PER_STREAM: usize = 16 * 1024;
pub const PREFIX_BYTES: usize = 256;
pub const RESET_CODE_BASE: u64 = 0x4000;
const TIMEOUT: Duration = Duration::from_secs(30);
const START: &[u8] = b"NZS2NCH1";
const READY: &[u8] = b"NZS2NRD1";
const DONE: &[u8] = b"NZS2NDN1";
const ACK: &[u8] = b"NZS2NAK1";
const RESULT_LEN: usize = 48;
const MAX_CHUNK_LEN: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChurnResult {
    pub streams: u16,
    pub fins: u16,
    pub resets: u16,
    pub received_bytes: u64,
    pub checksum: u64,
    pub reset_mask: u64,
    pub reset_code_sum: u64,
}

impl ChurnResult {
    fn encode(self) -> [u8; RESULT_LEN] {
        let mut out = [0; RESULT_LEN];
        out[0..8].copy_from_slice(b"NZS2NRS1");
        out[8..10].copy_from_slice(&self.streams.to_be_bytes());
        out[10..12].copy_from_slice(&self.fins.to_be_bytes());
        out[12..14].copy_from_slice(&self.resets.to_be_bytes());
        out[16..24].copy_from_slice(&self.received_bytes.to_be_bytes());
        out[24..32].copy_from_slice(&self.checksum.to_be_bytes());
        out[32..40].copy_from_slice(&self.reset_mask.to_be_bytes());
        out[40..48].copy_from_slice(&self.reset_code_sum.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8; RESULT_LEN]) -> Result<Self> {
        ensure!(&bytes[0..8] == b"NZS2NRS1", "invalid churn result marker");
        ensure!(bytes[14..16] == [0, 0], "invalid churn result padding");
        Ok(Self {
            streams: u16::from_be_bytes(bytes[8..10].try_into()?),
            fins: u16::from_be_bytes(bytes[10..12].try_into()?),
            resets: u16::from_be_bytes(bytes[12..14].try_into()?),
            received_bytes: u64::from_be_bytes(bytes[16..24].try_into()?),
            checksum: u64::from_be_bytes(bytes[24..32].try_into()?),
            reset_mask: u64::from_be_bytes(bytes[32..40].try_into()?),
            reset_code_sum: u64::from_be_bytes(bytes[40..48].try_into()?),
        })
    }
}

pub async fn run_sender(connection: &mut Connection) -> Result<ChurnResult> {
    let mut control = open_bidi(connection, 0).await?;
    send(&mut control, START, "churn start").await?;

    let mut streams = Vec::with_capacity(STREAMS);
    for index in 0..STREAMS {
        let expected_id = 4 + index as u64 * 4;
        let mut stream = open_bidi(connection, expected_id).await?;
        let prefix = payload(index, 0, PREFIX_BYTES);
        send(&mut stream, &prefix, "churn prefix").await?;
        streams.push(stream);
    }
    expect_marker(&mut control, READY, false, "churn ready").await?;

    for (index, stream) in streams.iter_mut().enumerate() {
        if should_reset(index) {
            stream.reset(application::Error::new(RESET_CODE_BASE + index as u64)?)?;
            continue;
        }
        let mut offset = PREFIX_BYTES;
        while offset < BYTES_PER_STREAM {
            let count = MAX_CHUNK_LEN.min(BYTES_PER_STREAM - offset);
            let chunk = payload(index, offset, count);
            send(stream, &chunk, "churn FIN payload").await?;
            offset += count;
        }
        stream.finish()?;
    }

    send(&mut control, DONE, "churn done").await?;
    let encoded = receive_exact(&mut control, RESULT_LEN, false, "churn result").await?;
    let encoded: [u8; RESULT_LEN] = encoded.try_into().expect("fixed result length");
    let result = ChurnResult::decode(&encoded)?;
    ensure!(result == expected_result(), "unexpected churn result");
    send(&mut control, ACK, "churn ack").await?;
    control.finish()?;
    Ok(result)
}

pub async fn run_receiver(connection: &mut Connection) -> Result<ChurnResult> {
    let mut control = accept_bidi(connection, 0).await?;
    expect_marker(&mut control, START, false, "churn start").await?;

    let mut streams = Vec::with_capacity(STREAMS);
    let mut result = ChurnResult {
        streams: STREAMS as u16,
        fins: 0,
        resets: 0,
        received_bytes: 0,
        checksum: 0,
        reset_mask: 0,
        reset_code_sum: 0,
    };
    for index in 0..STREAMS {
        let expected_id = 4 + index as u64 * 4;
        let mut stream = accept_bidi(connection, expected_id).await?;
        let prefix = receive_exact(&mut stream, PREFIX_BYTES, false, "churn prefix").await?;
        result.received_bytes += prefix.len() as u64;
        result.checksum = result
            .checksum
            .wrapping_add(verify_payload(&prefix, index, 0)?);
        streams.push(stream);
    }
    send(&mut control, READY, "churn ready").await?;

    for (index, stream) in streams.iter_mut().enumerate() {
        if should_reset(index) {
            let reset = receive_reset(stream, "churn reset").await?;
            ensure!(
                reset == RESET_CODE_BASE + index as u64,
                "unexpected churn reset code"
            );
            result.resets += 1;
            result.reset_mask |= 1u64 << index;
            result.reset_code_sum += reset;
            continue;
        }

        let mut offset = PREFIX_BYTES;
        loop {
            let chunk = timeout(TIMEOUT, stream.receive())
                .await
                .with_context(|| format!("churn stream {index} receive timed out"))??;
            match chunk {
                Some(bytes) => {
                    ensure!(
                        offset + bytes.len() <= BYTES_PER_STREAM,
                        "churn stream exceeds final size"
                    );
                    result.checksum = result
                        .checksum
                        .wrapping_add(verify_payload(&bytes, index, offset)?);
                    result.received_bytes += bytes.len() as u64;
                    offset += bytes.len();
                }
                None => break,
            }
        }
        ensure!(offset == BYTES_PER_STREAM, "unexpected churn FIN size");
        result.fins += 1;
    }

    expect_marker(&mut control, DONE, false, "churn done").await?;
    ensure!(result == expected_result(), "unexpected churn result");
    send(&mut control, &result.encode(), "churn result").await?;
    expect_marker(&mut control, ACK, true, "churn ack").await?;
    Ok(result)
}

pub fn expected_result() -> ChurnResult {
    let mut result = ChurnResult {
        streams: STREAMS as u16,
        fins: 0,
        resets: 0,
        received_bytes: 0,
        checksum: 0,
        reset_mask: 0,
        reset_code_sum: 0,
    };
    for index in 0..STREAMS {
        let count = if should_reset(index) {
            PREFIX_BYTES
        } else {
            BYTES_PER_STREAM
        };
        result.received_bytes += count as u64;
        result.checksum = result.checksum.wrapping_add(
            (0..count)
                .map(|offset| payload_byte(index, offset) as u64)
                .sum(),
        );
        if should_reset(index) {
            result.resets += 1;
            result.reset_mask |= 1u64 << index;
            result.reset_code_sum += RESET_CODE_BASE + index as u64;
        } else {
            result.fins += 1;
        }
    }
    result
}

async fn open_bidi(connection: &mut Connection, expected_id: u64) -> Result<BidirectionalStream> {
    let stream = timeout(TIMEOUT, connection.open_bidirectional_stream())
        .await
        .context("churn stream open timed out")??;
    ensure!(stream.id() == expected_id, "unexpected churn stream id");
    Ok(stream)
}

async fn accept_bidi(connection: &mut Connection, expected_id: u64) -> Result<BidirectionalStream> {
    let stream = timeout(TIMEOUT, connection.accept_bidirectional_stream())
        .await
        .context("churn stream accept timed out")??
        .context("connection closed before churn stream")?;
    ensure!(stream.id() == expected_id, "unexpected churn stream id");
    Ok(stream)
}

async fn send(stream: &mut BidirectionalStream, bytes: &[u8], label: &str) -> Result<()> {
    timeout(TIMEOUT, stream.send(Bytes::copy_from_slice(bytes)))
        .await
        .with_context(|| format!("{label} timed out"))??;
    Ok(())
}

async fn expect_marker(
    stream: &mut BidirectionalStream,
    expected: &[u8],
    expect_fin: bool,
    label: &str,
) -> Result<()> {
    let bytes = receive_exact(stream, expected.len(), expect_fin, label).await?;
    ensure!(bytes == expected, "invalid {label}");
    Ok(())
}

async fn receive_exact(
    stream: &mut BidirectionalStream,
    expected_len: usize,
    expect_fin: bool,
    label: &str,
) -> Result<Vec<u8>> {
    let mut received = Vec::with_capacity(expected_len);
    let mut fin = false;
    while received.len() < expected_len || expect_fin && !fin {
        match timeout(TIMEOUT, stream.receive())
            .await
            .with_context(|| format!("{label} timed out"))??
        {
            Some(chunk) => {
                ensure!(
                    received.len() + chunk.len() <= expected_len,
                    "{label} exceeds expected length"
                );
                received.extend_from_slice(&chunk);
            }
            None => fin = true,
        }
    }
    ensure!(fin == expect_fin, "unexpected {label} FIN state");
    Ok(received)
}

async fn receive_reset(stream: &mut BidirectionalStream, label: &str) -> Result<u64> {
    loop {
        match timeout(TIMEOUT, stream.receive())
            .await
            .with_context(|| format!("{label} timed out"))?
        {
            Ok(Some(_)) => bail!("unexpected data after churn prefix"),
            Ok(None) => bail!("churn stream finished instead of resetting"),
            Err(s2n_quic::stream::Error::StreamReset { error, .. }) => {
                return Ok(u64::from(error));
            }
            Err(other) => bail!("unexpected churn stream error: {other}"),
        }
    }
}

fn should_reset(index: usize) -> bool {
    index % 2 == 1
}

fn payload(stream_index: usize, offset: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| payload_byte(stream_index, offset + index))
        .collect()
}

fn verify_payload(bytes: &[u8], stream_index: usize, offset: usize) -> Result<u64> {
    let mut checksum = 0u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        ensure!(
            byte == payload_byte(stream_index, offset + index),
            "invalid churn payload"
        );
        checksum = checksum.wrapping_add(byte as u64);
    }
    Ok(checksum)
}

fn payload_byte(stream_index: usize, offset: usize) -> u8 {
    (offset.wrapping_mul(131) + stream_index.wrapping_mul(17)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_result_matches_cross_language_constants() {
        assert_eq!(
            expected_result(),
            ChurnResult {
                streams: 32,
                fins: 16,
                resets: 16,
                received_bytes: 266_240,
                checksum: 33_945_600,
                reset_mask: 0xaaaa_aaaa,
                reset_code_sum: 262_400,
            }
        );
        let encoded = expected_result().encode();
        assert_eq!(ChurnResult::decode(&encoded).unwrap(), expected_result());
    }
}
