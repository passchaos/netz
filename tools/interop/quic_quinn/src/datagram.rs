use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use quinn::{Connection, SendDatagramError};
use std::time::Duration;
use tokio::time::timeout;

pub const QUINN_BOUNDARY_BYTES: usize = 55;

const TIMEOUT: Duration = Duration::from_secs(20);
const START: &[u8] = b"NZDGRAM1";
const READY: &[u8] = b"NZDGRRD1";
const DRAIN: &[u8] = b"NZDGRGO1";
const RECEIVED: &[u8] = b"NZDGRRX1";
const DONE: &[u8] = b"NZDGRDN1";
const ACK: &[u8] = b"NZDGRAK1";
const SIBLING_PAYLOAD: &[u8] = b"world";
const LOCAL_SMALL: [&[u8]; 2] = [b"quinn-alpha", b"quinn-beta"];
const PEER_SMALL: [&[u8]; 2] = [b"netz-alpha", b"netz-beta"];

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    None,
    Loss,
    Reorder,
}

impl Fault {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("none") => Ok(Self::None),
            Some("loss") => Ok(Self::Loss),
            Some("reorder") => Ok(Self::Reorder),
            Some(other) => bail!("unsupported DATAGRAM fault: {other}"),
        }
    }
}

pub struct Outcome {
    pub netz_boundary_bytes: usize,
    pub quinn_boundary_bytes: usize,
    pub netz_datagrams_received: usize,
    pub reordered: bool,
}

pub async fn run(connection: &Connection, role: Role, fault: Fault) -> Result<Outcome> {
    let (mut control_send, mut control_recv) = match role {
        Role::Client => {
            let streams = timeout(TIMEOUT, connection.open_bi())
                .await
                .context("opening Quinn control stream timed out")??;
            ensure!(
                u64::from(streams.0.id()) == 0,
                "unexpected control stream id"
            );
            streams
        }
        Role::Server => {
            let streams = timeout(TIMEOUT, connection.accept_bi())
                .await
                .context("accepting Quinn control stream timed out")??;
            ensure!(
                u64::from(streams.0.id()) == 0,
                "unexpected control stream id"
            );
            streams
        }
    };
    if role == Role::Client {
        send(&mut control_send, START, "datagram start").await?;
    } else {
        expect_exact(&mut control_recv, START, false, "datagram start").await?;
    }

    let quinn_boundary_bytes = connection
        .max_datagram_size()
        .context("DATAGRAM was not negotiated with netz")?;
    ensure!(
        quinn_boundary_bytes == QUINN_BOUNDARY_BYTES,
        "unexpected Quinn DATAGRAM boundary: {quinn_boundary_bytes}"
    );
    for payload in LOCAL_SMALL {
        connection.send_datagram(Bytes::copy_from_slice(payload))?;
    }
    connection.send_datagram(Bytes::from(boundary_payload(
        quinn_boundary_bytes,
        BoundarySource::Quinn,
    )))?;
    expect_too_large(connection.send_datagram(Bytes::from(vec![0; quinn_boundary_bytes + 1])))?;

    match role {
        Role::Client => {
            expect_exact(&mut control_recv, READY, false, "peer datagram ready").await?;
            send(&mut control_send, READY, "datagram ready").await?;
            expect_exact(&mut control_recv, DRAIN, false, "datagram drain").await?;
        }
        Role::Server => {
            send(&mut control_send, READY, "datagram ready").await?;
            expect_exact(&mut control_recv, READY, false, "peer datagram ready").await?;
            send(&mut control_send, DRAIN, "datagram drain").await?;
        }
    }

    let received = receive_peer_datagrams(connection, fault).await?;
    match role {
        Role::Client => {
            send(&mut control_send, RECEIVED, "datagram received").await?;
            expect_exact(&mut control_recv, RECEIVED, false, "peer datagram received").await?;
        }
        Role::Server => {
            expect_exact(&mut control_recv, RECEIVED, false, "peer datagram received").await?;
            send(&mut control_send, RECEIVED, "datagram received").await?;
        }
    }

    match role {
        Role::Client => {
            let (mut send_stream, mut recv_stream) = timeout(TIMEOUT, connection.open_bi())
                .await
                .context("opening sibling stream timed out")??;
            ensure!(
                u64::from(send_stream.id()) == 4,
                "unexpected sibling stream id"
            );
            send(&mut send_stream, SIBLING_PAYLOAD, "sibling request").await?;
            send_stream.finish()?;
            expect_exact(&mut recv_stream, SIBLING_PAYLOAD, true, "sibling response").await?;
            send(&mut control_send, DONE, "datagram done").await?;
            control_send.finish()?;
            expect_exact(&mut control_recv, ACK, true, "datagram ack").await?;
        }
        Role::Server => {
            let (mut send_stream, mut recv_stream) = timeout(TIMEOUT, connection.accept_bi())
                .await
                .context("accepting sibling stream timed out")??;
            ensure!(
                u64::from(send_stream.id()) == 4,
                "unexpected sibling stream id"
            );
            expect_exact(&mut recv_stream, SIBLING_PAYLOAD, true, "sibling request").await?;
            send(&mut send_stream, SIBLING_PAYLOAD, "sibling response").await?;
            send_stream.finish()?;
            expect_exact(&mut control_recv, DONE, true, "datagram done").await?;
            send(&mut control_send, ACK, "datagram ack").await?;
            control_send.finish()?;
        }
    }
    if fault == Fault::Loss {
        ensure!(
            timeout(Duration::from_millis(100), connection.read_datagram())
                .await
                .is_err(),
            "lost DATAGRAM was retransmitted",
        );
    }

    Ok(Outcome {
        netz_boundary_bytes: received.boundary_bytes,
        quinn_boundary_bytes,
        netz_datagrams_received: received.count,
        reordered: received.reordered,
    })
}

struct ReceivedDatagrams {
    boundary_bytes: usize,
    count: usize,
    reordered: bool,
}

async fn receive_peer_datagrams(
    connection: &Connection,
    fault: Fault,
) -> Result<ReceivedDatagrams> {
    let mut seen = [false; 3];
    let mut netz_boundary_bytes = None;
    let expected_count = if fault == Fault::Loss { 2 } else { seen.len() };
    let mut reordered = false;
    for _ in 0..expected_count {
        let payload = timeout(TIMEOUT, connection.read_datagram())
            .await
            .context("receiving peer DATAGRAM timed out")??;
        let index = if payload.as_ref() == PEER_SMALL[0] {
            0
        } else if payload.as_ref() == PEER_SMALL[1] {
            1
        } else if boundary_matches(&payload, BoundarySource::Netz) {
            ensure!(
                payload.len() > QUINN_BOUNDARY_BYTES,
                "netz boundary did not exercise the path limit"
            );
            netz_boundary_bytes = Some(payload.len());
            2
        } else {
            bail!("unexpected peer DATAGRAM payload");
        };
        if fault == Fault::Loss && index == 0 {
            bail!("lost DATAGRAM was retransmitted");
        }
        if index == 1 && !seen[0] {
            reordered = true;
        }
        ensure!(!seen[index], "duplicate peer DATAGRAM payload");
        seen[index] = true;
    }
    ensure!(
        if fault == Fault::Loss {
            !seen[0] && seen[1] && seen[2]
        } else {
            seen.into_iter().all(|value| value)
        },
        "unexpected DATAGRAM set",
    );
    if fault == Fault::Reorder {
        ensure!(reordered, "DATAGRAM reordering was not observed");
    }
    Ok(ReceivedDatagrams {
        boundary_bytes: netz_boundary_bytes.context("missing netz boundary DATAGRAM")?,
        count: expected_count,
        reordered,
    })
}

fn expect_too_large(result: std::result::Result<(), SendDatagramError>) -> Result<()> {
    match result {
        Err(SendDatagramError::TooLarge) => Ok(()),
        Err(other) => bail!("unexpected oversized DATAGRAM error: {other}"),
        Ok(()) => bail!("oversized DATAGRAM was accepted"),
    }
}

#[derive(Clone, Copy)]
enum BoundarySource {
    Netz,
    Quinn,
}

fn boundary_payload(len: usize, source: BoundarySource) -> Vec<u8> {
    let (multiplier, increment) = match source {
        BoundarySource::Netz => (29usize, 7usize),
        BoundarySource::Quinn => (37usize, 13usize),
    };
    (0..len)
        .map(|index| index.wrapping_mul(multiplier).wrapping_add(increment) as u8)
        .collect()
}

fn boundary_matches(payload: &[u8], source: BoundarySource) -> bool {
    payload == boundary_payload(payload.len(), source)
}

async fn send(stream: &mut quinn::SendStream, payload: &[u8], label: &str) -> Result<()> {
    timeout(TIMEOUT, stream.write_all(payload))
        .await
        .with_context(|| format!("{label} timed out"))??;
    Ok(())
}

async fn expect_exact(
    stream: &mut quinn::RecvStream,
    expected: &[u8],
    expect_fin: bool,
    label: &str,
) -> Result<()> {
    let mut payload = vec![0; expected.len()];
    timeout(TIMEOUT, stream.read_exact(&mut payload))
        .await
        .with_context(|| format!("{label} timed out"))??;
    ensure!(payload == expected, "invalid {label}");
    if expect_fin {
        let tail = timeout(TIMEOUT, stream.read_chunk(1, true))
            .await
            .with_context(|| format!("{label} FIN timed out"))??;
        ensure!(tail.is_none(), "{label} carried trailing data");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_payloads_are_distinct_and_exact() {
        let netz = boundary_payload(1171, BoundarySource::Netz);
        let quinn = boundary_payload(QUINN_BOUNDARY_BYTES, BoundarySource::Quinn);
        assert_eq!(netz.len(), 1171);
        assert_eq!(quinn.len(), QUINN_BOUNDARY_BYTES);
        assert!(boundary_matches(&netz, BoundarySource::Netz));
        assert!(boundary_matches(&quinn, BoundarySource::Quinn));
        assert_ne!(&netz[..QUINN_BOUNDARY_BYTES], quinn);
    }

    #[test]
    fn fault_modes_parse_strictly() {
        assert_eq!(Fault::parse(None).unwrap(), Fault::None);
        assert_eq!(Fault::parse(Some("none")).unwrap(), Fault::None);
        assert_eq!(Fault::parse(Some("loss")).unwrap(), Fault::Loss);
        assert_eq!(Fault::parse(Some("reorder")).unwrap(), Fault::Reorder);
        assert!(Fault::parse(Some("corrupt")).is_err());
    }
}
