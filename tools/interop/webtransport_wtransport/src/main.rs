use anyhow::{bail, ensure, Context, Result};
use std::time::Duration;
use tokio::time::timeout;
use wtransport::{ClientConfig, Endpoint, VarInt};

const CLIENT_DATAGRAM: &[u8] = b"wtransport datagram";
const SERVER_DATAGRAM: &[u8] = b"netz datagram";
const CLIENT_BIDI: &[u8] = b"wtransport bidi";
const SERVER_BIDI: &[u8] = b"netz bidi";
const CLIENT_UNI: &[u8] = b"wtransport uni";
const SERVER_UNI: &[u8] = b"netz uni";
const CLOSE_READY: &[u8] = b"close ready";
const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let port = std::env::args()
        .nth(1)
        .context("usage: netz-webtransport-wtransport PORT")?
        .parse::<u16>()
        .context("invalid server port")?;
    ensure!(port != 0, "server port must be non-zero");

    let config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let endpoint = Endpoint::client(config)?;
    let url = format!("https://127.0.0.1:{port}/interop");
    let connection = timeout(TIMEOUT, endpoint.connect(url))
        .await
        .context("CONNECT timed out")??;

    connection.send_datagram(CLIENT_DATAGRAM)?;
    let datagram = timeout(TIMEOUT, connection.receive_datagram())
        .await
        .context("DATAGRAM response timed out")??;
    ensure!(&*datagram == SERVER_DATAGRAM, "unexpected DATAGRAM payload");

    let bidi_opening = timeout(TIMEOUT, connection.open_bi())
        .await
        .context("bidirectional stream credit timed out")??;
    let (mut bidi_send, mut bidi_recv) = timeout(TIMEOUT, bidi_opening)
        .await
        .context("bidirectional stream association timed out")??;
    bidi_send.write_all(CLIENT_BIDI).await?;
    bidi_send.finish().await?;
    let mut bidi_reply = [0; SERVER_BIDI.len()];
    timeout(TIMEOUT, bidi_recv.read_exact(&mut bidi_reply))
        .await
        .context("bidirectional stream response timed out")??;
    ensure!(
        bidi_reply == SERVER_BIDI,
        "unexpected bidirectional payload"
    );

    let uni_opening = timeout(TIMEOUT, connection.open_uni())
        .await
        .context("unidirectional stream credit timed out")??;
    let mut uni_send = timeout(TIMEOUT, uni_opening)
        .await
        .context("unidirectional stream association timed out")??;
    uni_send.write_all(CLIENT_UNI).await?;
    uni_send.finish().await?;
    let mut uni_recv = timeout(TIMEOUT, connection.accept_uni())
        .await
        .context("server unidirectional stream timed out")??;
    let mut uni_reply = [0; SERVER_UNI.len()];
    timeout(TIMEOUT, uni_recv.read_exact(&mut uni_reply))
        .await
        .context("server unidirectional payload timed out")??;
    ensure!(uni_reply == SERVER_UNI, "unexpected unidirectional payload");
    connection.send_datagram(CLOSE_READY)?;

    match timeout(TIMEOUT, connection.receive_datagram()).await {
        Ok(Err(wtransport::error::ConnectionError::ApplicationClosed(close))) => {
            ensure!(close.code().into_inner() == 77, "unexpected close code");
            ensure!(close.reason() == b"netz done", "unexpected close reason");
        }
        Ok(Err(error)) => bail!("unexpected close result: {error}"),
        Ok(Ok(_)) => bail!("unexpected DATAGRAM before session close"),
        Err(_) => bail!("session close timed out"),
    }

    // The netz server sends an application-level WebTransport close capsule.
    // wtransport consumes that capsule and then closes QUIC with H3_NO_ERROR.
    endpoint.close(VarInt::from_u32(0), b"interop complete");
    endpoint.wait_idle().await;
    println!("wtransport client interop passed: CONNECT DATAGRAM bidi uni close");
    Ok(())
}
