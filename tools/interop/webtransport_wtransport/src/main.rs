use anyhow::{bail, ensure, Context, Result};
use std::time::Duration;
use tokio::time::timeout;
use wtransport::error::{StreamReadError, StreamWriteError};
use wtransport::{ClientConfig, Endpoint, Identity, ServerConfig, VarInt};

const CLIENT_DATAGRAM: &[u8] = b"wtransport datagram";
const SERVER_DATAGRAM: &[u8] = b"netz datagram";
const CLIENT_BIDI: &[u8] = b"wtransport bidi";
const SERVER_BIDI: &[u8] = b"netz bidi";
const CLIENT_UNI: &[u8] = b"wtransport uni";
const SERVER_UNI: &[u8] = b"netz uni";
const CLIENT_RESET: &[u8] = b"wtransport reset";
const SERVER_STOP: &[u8] = b"netz stop";
const REUSE_REQUEST: &[u8] = b"after cancel";
const REUSE_RESPONSE: &[u8] = b"session reused";
const RESET_READY: &[u8] = b"reset ready";
const CANCEL_DONE: &[u8] = b"cancel done";
const CLOSE_READY: &[u8] = b"close ready";
const TIMEOUT: Duration = Duration::from_secs(10);

fn mapped_stream_error(application_code: u32) -> VarInt {
    let code = u64::from(application_code);
    VarInt::try_from_u64(0x52e4_a40f_a8db + code + code / 0x1e)
        .expect("mapped WebTransport error fits a QUIC varint")
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .context("usage: netz-webtransport-wtransport client PORT | server")?;
    if mode == "server" {
        return run_server().await;
    }
    ensure!(mode == "client", "unknown mode: {mode}");
    let port = args
        .next()
        .context("client mode requires PORT")?
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
    let max_datagram_size = connection
        .max_datagram_size()
        .context("peer did not negotiate DATAGRAM")?;
    let oversized = vec![0xa5; max_datagram_size + 1];
    ensure!(
        matches!(
            connection.send_datagram(&oversized),
            Err(wtransport::error::SendDatagramError::TooLarge)
        ),
        "oversized DATAGRAM was not rejected"
    );

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

    let reset_opening = timeout(TIMEOUT, connection.open_uni())
        .await
        .context("reset stream credit timed out")??;
    let mut reset_send = timeout(TIMEOUT, reset_opening)
        .await
        .context("reset stream association timed out")??;
    reset_send.write_all(CLIENT_RESET).await?;
    let reset_ready = timeout(TIMEOUT, connection.receive_datagram())
        .await
        .context("reset-ready DATAGRAM timed out")??;
    ensure!(
        &*reset_ready == RESET_READY,
        "unexpected reset-ready payload"
    );
    reset_send.reset(mapped_stream_error(71))?;

    let mut stopped_recv = timeout(TIMEOUT, connection.accept_uni())
        .await
        .context("stop stream timed out")??;
    let mut stop_payload = [0; SERVER_STOP.len()];
    timeout(TIMEOUT, stopped_recv.read_exact(&mut stop_payload))
        .await
        .context("stop stream payload timed out")??;
    ensure!(
        stop_payload == SERVER_STOP,
        "unexpected stop stream payload"
    );
    // Open and finish the reuse request before cancellation. The netz peer
    // withholds the reply until it observes STOP_SENDING after loss recovery.
    let reuse_opening = timeout(TIMEOUT, connection.open_bi())
        .await
        .context("reuse stream credit timed out")??;
    let (mut reuse_send, mut reuse_recv) = timeout(TIMEOUT, reuse_opening)
        .await
        .context("reuse stream association timed out")??;
    reuse_send.write_all(REUSE_REQUEST).await?;
    reuse_send.finish().await?;
    stopped_recv.stop(mapped_stream_error(72));
    let cancel_done = timeout(TIMEOUT, connection.receive_datagram())
        .await
        .context("cancel-done DATAGRAM timed out")??;
    ensure!(
        &*cancel_done == CANCEL_DONE,
        "unexpected cancel-done payload"
    );

    let mut reuse_reply = [0; REUSE_RESPONSE.len()];
    timeout(TIMEOUT, reuse_recv.read_exact(&mut reuse_reply))
        .await
        .context("reuse stream response timed out")??;
    ensure!(reuse_reply == REUSE_RESPONSE, "unexpected reuse response");
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

    // Netz sends WT_DRAIN_SESSION immediately before the application-level
    // close. wtransport has no public drain event, so observing this exact
    // close proves its CONNECT driver skipped DRAIN without losing the next
    // capsule's framing; it then closes QUIC with H3_NO_ERROR.
    endpoint.close(VarInt::from_u32(0), b"interop complete");
    endpoint.wait_idle().await;
    println!("wtransport client interop passed: CONNECT DATAGRAM max_datagram_size={max_datagram_size} oversized_rejected=true bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-close=true close");
    Ok(())
}

async fn run_server() -> Result<()> {
    let identity = Identity::self_signed(["localhost", "127.0.0.1"])?;
    let config = ServerConfig::builder()
        .with_bind_config(wtransport::config::IpBindConfig::LocalV4, 0)
        .with_identity(identity)
        .build();
    let endpoint = Endpoint::server(config)?;
    println!("WTRANSPORT_PORT={}", endpoint.local_addr()?.port());

    let request = timeout(TIMEOUT, endpoint.accept())
        .await
        .context("incoming QUIC connection timed out")?
        .await?;
    ensure!(request.path() == "/interop", "unexpected CONNECT path");
    let connection = request.accept().await?;
    let max_datagram_size = connection
        .max_datagram_size()
        .context("peer did not negotiate DATAGRAM")?;
    let oversized = vec![0xa5; max_datagram_size + 1];
    ensure!(
        matches!(
            connection.send_datagram(&oversized),
            Err(wtransport::error::SendDatagramError::TooLarge)
        ),
        "oversized DATAGRAM was not rejected"
    );

    let datagram = timeout(TIMEOUT, connection.receive_datagram())
        .await
        .context("DATAGRAM request timed out")??;
    ensure!(&*datagram == CLIENT_DATAGRAM, "unexpected DATAGRAM request");
    connection.send_datagram(SERVER_DATAGRAM)?;

    let (mut bidi_send, mut bidi_recv) = timeout(TIMEOUT, connection.accept_bi())
        .await
        .context("bidirectional stream timed out")??;
    let mut bidi_request = [0; CLIENT_BIDI.len()];
    bidi_recv.read_exact(&mut bidi_request).await?;
    ensure!(
        bidi_request == CLIENT_BIDI,
        "unexpected bidirectional request"
    );
    bidi_send.write_all(SERVER_BIDI).await?;
    bidi_send.finish().await?;

    let mut uni_recv = timeout(TIMEOUT, connection.accept_uni())
        .await
        .context("client unidirectional stream timed out")??;
    let mut uni_request = [0; CLIENT_UNI.len()];
    uni_recv.read_exact(&mut uni_request).await?;
    ensure!(
        uni_request == CLIENT_UNI,
        "unexpected unidirectional request"
    );
    let uni_opening = timeout(TIMEOUT, connection.open_uni())
        .await
        .context("server unidirectional stream credit timed out")??;
    let mut uni_send = timeout(TIMEOUT, uni_opening)
        .await
        .context("server unidirectional association timed out")??;
    uni_send.write_all(SERVER_UNI).await?;
    uni_send.finish().await?;

    let mut reset_recv = timeout(TIMEOUT, connection.accept_uni())
        .await
        .context("netz reset stream timed out")??;
    let mut reset_payload = [0; CLIENT_RESET.len()];
    timeout(TIMEOUT, reset_recv.read_exact(&mut reset_payload))
        .await
        .context("netz reset payload timed out")??;
    ensure!(reset_payload == CLIENT_RESET, "unexpected reset payload");
    connection.send_datagram(RESET_READY)?;
    let stop_opening = timeout(TIMEOUT, connection.open_uni())
        .await
        .context("stop stream credit timed out")??;
    let mut stop_send = timeout(TIMEOUT, stop_opening)
        .await
        .context("stop stream association timed out")??;
    stop_send.write_all(SERVER_STOP).await?;
    match timeout(TIMEOUT, stop_send.stopped())
        .await
        .context("netz STOP_SENDING timed out")?
    {
        StreamWriteError::Stopped(code) => ensure!(
            code == mapped_stream_error(74),
            "unexpected stop code: {code}"
        ),
        other => bail!("unexpected stopped result: {other:?}"),
    }

    let mut after_reset = [0; 1];
    match timeout(TIMEOUT, reset_recv.read(&mut after_reset))
        .await
        .context("netz RESET_STREAM timed out")?
    {
        Err(StreamReadError::Reset(code)) => ensure!(
            code == mapped_stream_error(73),
            "unexpected reset code: {code}"
        ),
        other => bail!("unexpected reset result: {other:?}"),
    }
    connection.send_datagram(CANCEL_DONE)?;

    let (mut reuse_send, mut reuse_recv) = timeout(TIMEOUT, connection.accept_bi())
        .await
        .context("reuse bidirectional stream timed out")??;
    let mut reuse_request = [0; REUSE_REQUEST.len()];
    reuse_recv.read_exact(&mut reuse_request).await?;
    ensure!(reuse_request == REUSE_REQUEST, "unexpected reuse request");
    reuse_send.write_all(REUSE_RESPONSE).await?;
    reuse_send.finish().await?;

    let ready = timeout(TIMEOUT, connection.receive_datagram())
        .await
        .context("close-ready DATAGRAM timed out")??;
    ensure!(&*ready == CLOSE_READY, "unexpected close-ready payload");
    connection.close(VarInt::from_u32(0), b"interop complete");
    endpoint.wait_idle().await;
    println!(
        "wtransport server interop passed: CONNECT DATAGRAM max_datagram_size={max_datagram_size} oversized_rejected=true bidi uni reset=73 stop=74 reuse=true"
    );
    Ok(())
}
