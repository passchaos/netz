use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use core::task::Poll;
use futures_util::future::poll_fn;
use s2n_quic::{
    provider::datagram::default::{Receiver, Sender},
    stream::BidirectionalStream,
    Connection,
};
use std::time::Duration;
use tokio::time::timeout;

pub const S2N_BOUNDARY_BYTES: usize = 62;

const TIMEOUT: Duration = Duration::from_secs(20);
const START: &[u8] = b"NZDGRAM1";
const READY: &[u8] = b"NZDGRRD1";
const DRAIN: &[u8] = b"NZDGRGO1";
const RECEIVED: &[u8] = b"NZDGRRX1";
const DONE: &[u8] = b"NZDGRDN1";
const ACK: &[u8] = b"NZDGRAK1";
const SIBLING_PAYLOAD: &[u8] = b"world";
const LOCAL_SMALL: [&[u8]; 2] = [b"s2n-alpha", b"s2n-beta"];
const PEER_SMALL: [&[u8]; 2] = [b"netz-alpha", b"netz-beta"];

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

pub struct Outcome {
    pub boundary_bytes: usize,
}

pub async fn run(connection: &mut Connection, role: Role) -> Result<Outcome> {
    let mut control = match role {
        Role::Client => {
            let mut stream = open_bidi(connection, 0).await?;
            send(&mut stream, START, "datagram start").await?;
            stream
        }
        Role::Server => {
            let mut stream = accept_bidi(connection, 0).await?;
            expect_marker(&mut stream, START, false, "datagram start").await?;
            stream
        }
    };

    enqueue_datagrams(connection)?;
    match role {
        Role::Client => {
            expect_marker(&mut control, READY, false, "peer datagram ready").await?;
            send(&mut control, READY, "datagram ready").await?;
            expect_marker(&mut control, DRAIN, false, "datagram drain").await?;
        }
        Role::Server => {
            send(&mut control, READY, "datagram ready").await?;
            expect_marker(&mut control, READY, false, "peer datagram ready").await?;
            send(&mut control, DRAIN, "datagram drain").await?;
        }
    }

    let boundary_bytes = receive_peer_datagrams(connection).await?;
    match role {
        Role::Client => {
            send(&mut control, RECEIVED, "datagram received").await?;
            expect_marker(&mut control, RECEIVED, false, "peer datagram received").await?;
        }
        Role::Server => {
            expect_marker(&mut control, RECEIVED, false, "peer datagram received").await?;
            send(&mut control, RECEIVED, "datagram received").await?;
        }
    }

    match role {
        Role::Client => {
            let mut sibling = open_bidi(connection, 4).await?;
            send(&mut sibling, SIBLING_PAYLOAD, "sibling request").await?;
            sibling.finish()?;
            expect_marker(&mut sibling, SIBLING_PAYLOAD, true, "sibling response").await?;
            send(&mut control, DONE, "datagram done").await?;
            control.finish()?;
            expect_marker(&mut control, ACK, true, "datagram ack").await?;
        }
        Role::Server => {
            let mut sibling = accept_bidi(connection, 4).await?;
            expect_marker(&mut sibling, SIBLING_PAYLOAD, true, "sibling request").await?;
            send(&mut sibling, SIBLING_PAYLOAD, "sibling response").await?;
            sibling.finish()?;
            expect_marker(&mut control, DONE, true, "datagram done").await?;
            send(&mut control, ACK, "datagram ack").await?;
            control.finish()?;
        }
    }

    Ok(Outcome { boundary_bytes })
}

fn enqueue_datagrams(connection: &Connection) -> Result<()> {
    for payload in LOCAL_SMALL {
        enqueue(connection, Bytes::copy_from_slice(payload))?;
    }
    enqueue(
        connection,
        Bytes::from(boundary_payload(S2N_BOUNDARY_BYTES, BoundarySource::S2n)),
    )?;

    let error = connection
        .datagram_mut(|sender: &mut Sender| sender.send_datagram(Bytes::from(vec![0; 65])))
        .context("querying s2n datagram sender")?
        .expect_err("65-byte datagram exceeded netz's advertised frame limit");
    // DatagramError is #[non_exhaustive], so downstream crates cannot name
    // its unit variants in a pattern. Its Debug value still identifies the
    // exact rejection returned by the official default provider.
    ensure!(
        format!("{error:?}") == "ExceedsPeerTransportLimits",
        "unexpected oversized datagram error: {error}"
    );
    Ok(())
}

fn enqueue(connection: &Connection, payload: Bytes) -> Result<()> {
    connection
        .datagram_mut(|sender: &mut Sender| sender.send_datagram(payload))
        .context("querying s2n datagram sender")?
        .map_err(|error| anyhow!("enqueueing s2n datagram: {error}"))
}

async fn receive_peer_datagrams(connection: &Connection) -> Result<usize> {
    let mut seen = [false; 3];
    let mut boundary_bytes = None;
    for _ in 0..seen.len() {
        let payload = timeout(TIMEOUT, receive_datagram(connection))
            .await
            .context("peer datagram receive timed out")??;
        let index = if payload.as_ref() == PEER_SMALL[0] {
            0
        } else if payload.as_ref() == PEER_SMALL[1] {
            1
        } else if boundary_matches(&payload, BoundarySource::Netz) {
            ensure!(
                payload.len() > S2N_BOUNDARY_BYTES,
                "netz boundary did not exercise the path limit"
            );
            boundary_bytes = Some(payload.len());
            2
        } else {
            bail!("unexpected peer datagram payload");
        };
        ensure!(!seen[index], "duplicate peer datagram payload");
        seen[index] = true;
    }
    boundary_bytes.context("missing netz boundary datagram")
}

async fn receive_datagram(connection: &Connection) -> Result<Bytes> {
    poll_fn(|cx| {
        match connection.datagram_mut(|receiver: &mut Receiver| receiver.poll_recv_datagram(cx)) {
            Ok(result) => result
                .map(|value| value.map_err(|error| anyhow!("receiving s2n datagram: {error}"))),
            Err(error) => Poll::Ready(Err(anyhow::Error::from(error))),
        }
    })
    .await
}

#[derive(Clone, Copy)]
enum BoundarySource {
    Netz,
    S2n,
}

fn boundary_payload(len: usize, source: BoundarySource) -> Vec<u8> {
    let (multiplier, increment) = match source {
        BoundarySource::Netz => (29usize, 7usize),
        BoundarySource::S2n => (31usize, 11usize),
    };
    (0..len)
        .map(|index| index.wrapping_mul(multiplier).wrapping_add(increment) as u8)
        .collect()
}

fn boundary_matches(payload: &[u8], source: BoundarySource) -> bool {
    payload == boundary_payload(payload.len(), source)
}

async fn open_bidi(connection: &mut Connection, expected_id: u64) -> Result<BidirectionalStream> {
    let stream = timeout(TIMEOUT, connection.open_bidirectional_stream())
        .await
        .context("datagram stream open timed out")??;
    ensure!(stream.id() == expected_id, "unexpected datagram stream id");
    Ok(stream)
}

async fn accept_bidi(connection: &mut Connection, expected_id: u64) -> Result<BidirectionalStream> {
    let stream = timeout(TIMEOUT, connection.accept_bidirectional_stream())
        .await
        .context("datagram stream accept timed out")??
        .context("connection closed before datagram stream")?;
    ensure!(stream.id() == expected_id, "unexpected datagram stream id");
    Ok(stream)
}

async fn send(stream: &mut BidirectionalStream, payload: &[u8], label: &str) -> Result<()> {
    timeout(TIMEOUT, stream.send(Bytes::copy_from_slice(payload)))
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
    let mut received = Vec::with_capacity(expected.len());
    let mut fin = false;
    while received.len() < expected.len() || expect_fin && !fin {
        match timeout(TIMEOUT, stream.receive())
            .await
            .with_context(|| format!("{label} timed out"))??
        {
            Some(chunk) => {
                ensure!(
                    received.len() + chunk.len() <= expected.len(),
                    "{label} exceeds expected length"
                );
                received.extend_from_slice(&chunk);
            }
            None => fin = true,
        }
    }
    ensure!(received == expected, "invalid {label}");
    ensure!(fin == expect_fin, "unexpected {label} FIN state");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_payloads_are_distinct_and_exact() {
        let netz = boundary_payload(1163, BoundarySource::Netz);
        let s2n = boundary_payload(S2N_BOUNDARY_BYTES, BoundarySource::S2n);
        assert_eq!(netz.len(), 1163);
        assert_eq!(s2n.len(), S2N_BOUNDARY_BYTES);
        assert!(boundary_matches(&netz, BoundarySource::Netz));
        assert!(boundary_matches(&s2n, BoundarySource::S2n));
        assert_ne!(&netz[..S2N_BOUNDARY_BYTES], s2n);
    }
}
