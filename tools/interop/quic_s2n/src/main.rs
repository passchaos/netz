use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use s2n_quic::{client::Connect, provider::tls, Client, Connection, Server};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::time::{sleep, timeout};

mod churn;
mod datagram;

const ALPN: &[u8] = b"hq-interop";
const PAYLOADS: [&[u8]; 2] = [b"hello", b"world"];
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scenario {
    Echo,
    Reset,
    Stop,
    LossyReset,
    LossyStop,
    ReorderedReset,
    ReorderedStop,
    MixedChurn,
    MixedChurnLoss,
    MixedChurnReorder,
    Datagram,
    Flow,
    Retry,
}

#[derive(Debug)]
struct RetryPolicy {
    force: bool,
}

impl s2n_quic::provider::endpoint_limits::Limiter for RetryPolicy {
    fn on_connection_attempt(
        &mut self,
        _attempt: &s2n_quic::provider::endpoint_limits::ConnectionAttempt,
    ) -> s2n_quic::provider::endpoint_limits::Outcome {
        if self.force {
            // A validated Retry Initial bypasses this limiter; only an
            // unvalidated attempt reaches this branch.
            s2n_quic::provider::endpoint_limits::Outcome::retry()
        } else {
            s2n_quic::provider::endpoint_limits::Outcome::allow()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("server") => {
            let port = parse_port(args.next())?;
            let certificate = args.next().context("server requires CERT")?;
            let private_key = args.next().context("server requires KEY")?;
            let scenario = parse_scenario(args.next())?;
            ensure!(args.next().is_none(), "unexpected server argument");
            run_server(port, &certificate, &private_key, scenario).await
        }
        Some("client") => {
            let port = parse_port(args.next())?;
            let ca = args.next().context("client requires CA")?;
            let scenario = parse_scenario(args.next())?;
            ensure!(args.next().is_none(), "unexpected client argument");
            run_client(port, &ca, scenario).await
        }
        _ => bail!(
            "usage: netz-quic-s2n-interop server PORT CERT KEY [echo|reset|stop|flow|retry|mixed-churn|mixed-churn-loss|mixed-churn-reorder|datagram] | client PORT CA [echo|reset|stop|lossy-reset|lossy-stop|reordered-reset|reordered-stop|mixed-churn|mixed-churn-loss|mixed-churn-reorder|datagram]"
        ),
    }
}

fn parse_scenario(value: Option<String>) -> Result<Scenario> {
    match value.as_deref().unwrap_or("echo") {
        "echo" => Ok(Scenario::Echo),
        "reset" => Ok(Scenario::Reset),
        "stop" => Ok(Scenario::Stop),
        "lossy-reset" => Ok(Scenario::LossyReset),
        "lossy-stop" => Ok(Scenario::LossyStop),
        "reordered-reset" => Ok(Scenario::ReorderedReset),
        "reordered-stop" => Ok(Scenario::ReorderedStop),
        "mixed-churn" => Ok(Scenario::MixedChurn),
        "mixed-churn-loss" => Ok(Scenario::MixedChurnLoss),
        "mixed-churn-reorder" => Ok(Scenario::MixedChurnReorder),
        "datagram" => Ok(Scenario::Datagram),
        "flow" => Ok(Scenario::Flow),
        "retry" => Ok(Scenario::Retry),
        value => bail!("unknown scenario: {value}"),
    }
}

fn parse_port(value: Option<String>) -> Result<u16> {
    let port = value.context("missing port")?.parse::<u16>()?;
    ensure!(port != 0, "port must be non-zero");
    Ok(port)
}

async fn run_server(
    port: u16,
    certificate: &str,
    private_key: &str,
    scenario: Scenario,
) -> Result<()> {
    ensure!(
        !matches!(scenario, Scenario::LossyReset | Scenario::LossyStop),
        "lossy cancellation scenarios are client-only"
    );
    let mut tls_builder = tls::default::Server::builder();
    tls_builder
        .config_mut()
        .set_security_policy(&tls::default::security::DEFAULT_TLS13)?;
    let tls = tls_builder
        .with_application_protocols([ALPN])?
        .with_certificate(Path::new(certificate), Path::new(private_key))?
        .build()?;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let datagram_provider = s2n_quic::provider::datagram::default::Endpoint::builder()
        .with_send_capacity(8)?
        .with_recv_capacity(8)?
        .build()?;
    let mut server = Server::builder()
        .with_tls(tls)?
        .with_limits(scenario_limits(scenario)?)?
        .with_endpoint_limits(RetryPolicy {
            force: scenario == Scenario::Retry,
        })?
        .with_datagram(datagram_provider)?
        .with_io(address)?
        .start()?;
    println!("s2n-quic interop server listening={address}");
    println!(
        "s2n-quic interop runtime: endpoint_role=server client_io=zio-std-io server_io=s2n-quic-tokio"
    );

    let mut connection = timeout(TIMEOUT, server.accept())
        .await
        .context("incoming connection timed out")?
        .context("server endpoint closed before accepting a connection")?;
    ensure!(
        connection.application_protocol()?.as_ref() == ALPN,
        "unexpected ALPN"
    );
    ensure!(
        connection.server_name()?.as_deref() == Some("localhost"),
        "unexpected SNI"
    );

    let mut datagram_outcome = None;
    match scenario {
        Scenario::Echo | Scenario::Retry => echo_two_streams(&mut connection).await?,
        Scenario::Reset => serve_reset(&mut connection).await?,
        Scenario::Stop => serve_stop(&mut connection).await?,
        Scenario::ReorderedReset => serve_peer_reset_reordered(&mut connection).await?,
        Scenario::ReorderedStop => serve_peer_stop_reordered(&mut connection).await?,
        Scenario::MixedChurn => {
            churn::run_receiver(&mut connection, churn::ReceiverRole::Server).await?;
        }
        Scenario::MixedChurnLoss | Scenario::MixedChurnReorder => {
            churn::run_receiver(&mut connection, churn::ReceiverRole::Server).await?;
        }
        Scenario::LossyReset | Scenario::LossyStop => unreachable!(),
        Scenario::Flow => serve_flow(&mut connection).await?,
        Scenario::Datagram => {
            datagram_outcome = Some(datagram::run(&mut connection, datagram::Role::Server).await?);
        }
    }
    // Let the endpoint transmit both queued responses before application close
    // supersedes stream output in this deliberately short-lived fixture.
    sleep(Duration::from_millis(250)).await;
    connection.close(57u8.into());
    // Connection::close only queues CONNECTION_CLOSE. Keep the endpoint alive
    // briefly so the packet is emitted before this one-shot process exits.
    sleep(Duration::from_millis(250)).await;
    match scenario {
        Scenario::Echo => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop sni=localhost streams=2 bytes=10 peer_close=57"
        ),
        Scenario::Reset => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=57"
        ),
        Scenario::Stop => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop stop_error=42 reset_error=42 concurrent_sibling=4 echo_bytes=5 peer_close=57"
        ),
        Scenario::ReorderedReset => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop reset_error=41 reordered=true sibling_before_cancel=true concurrent_sibling=4 echo_bytes=5 peer_close=57"
        ),
        Scenario::ReorderedStop => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop stop_error=42 reset_error=42 reordered=true sibling_before_cancel=true concurrent_sibling=4 echo_bytes=5 peer_close=57"
        ),
        Scenario::MixedChurn => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop mixed_churn=true streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true peer_close=57"
        ),
        Scenario::MixedChurnLoss => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop mixed_churn=true fault=loss fault_scope=netz-client-outbound streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true reset_faults=1 fin_faults=1 peer_close=57"
        ),
        Scenario::MixedChurnReorder => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop mixed_churn=true fault=reorder fault_scope=netz-client-outbound streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true reset_faults=1 fin_faults=1 peer_close=57"
        ),
        Scenario::LossyReset | Scenario::LossyStop => unreachable!(),
        Scenario::Flow => println!(
            "s2n-quic server interoperated with netz: version=1 alpn=hq-interop initial_max_data=8192 initial_max_stream_data=2048 stream_bytes=12288 echo_bytes=12288 peer_close=57"
        ),
        Scenario::Retry => println!(
            "s2n-quic server interoperated with netz: version=1 retry=true alpn=hq-interop sni=localhost streams=2 bytes=10 peer_close=57"
        ),
        Scenario::Datagram => println!(
            "s2n-quic server interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={} s2n_boundary_bytes={} oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=s2n-quic-tokio",
            datagram_outcome.as_ref().unwrap().boundary_bytes,
            datagram::S2N_BOUNDARY_BYTES,
        ),
    }
    Ok(())
}

async fn run_client(port: u16, ca: &str, scenario: Scenario) -> Result<()> {
    ensure!(
        scenario != Scenario::Flow && scenario != Scenario::Retry,
        "flow and retry are server-only scenarios"
    );
    println!(
        "s2n-quic interop runtime: endpoint_role=client client_io=s2n-quic-tokio server_io=zio-std-io"
    );
    // Clear platform roots first so a successful connection proves that the
    // checked-in netz localhost certificate, rather than ambient trust, was
    // used to authenticate the server.
    let tls = tls::default::Client::builder()
        .with_empty_trust_store()?
        .with_certificate(Path::new(ca))?
        .with_application_protocols([ALPN])?
        .build()?;
    let datagram_provider = s2n_quic::provider::datagram::default::Endpoint::builder()
        .with_send_capacity(8)?
        .with_recv_capacity(8)?
        .build()?;
    let mut client = Client::builder()
        .with_tls(tls)?
        .with_limits(scenario_limits(scenario)?)?
        .with_datagram(datagram_provider)?
        .with_io("0.0.0.0:0")?
        .start()?;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let connect = Connect::new(address).with_server_name("localhost");
    let mut connection = timeout(TIMEOUT, client.connect(connect))
        .await
        .context("QUIC handshake timed out")??;
    ensure!(
        connection.application_protocol()?.as_ref() == ALPN,
        "unexpected ALPN"
    );

    let mut datagram_outcome = None;
    match scenario {
        Scenario::Echo => request_two_echoes(&mut connection).await?,
        Scenario::Reset => request_reset(&mut connection).await?,
        Scenario::Stop => request_stop(&mut connection).await?,
        Scenario::LossyReset => request_peer_reset(&mut connection).await?,
        Scenario::LossyStop => request_stop(&mut connection).await?,
        Scenario::ReorderedReset => request_peer_reset_reordered(&mut connection).await?,
        Scenario::ReorderedStop => request_stop_reordered(&mut connection).await?,
        Scenario::MixedChurn => {
            churn::run_sender(&mut connection).await?;
        }
        Scenario::MixedChurnLoss | Scenario::MixedChurnReorder => {
            churn::run_receiver(&mut connection, churn::ReceiverRole::Client).await?;
        }
        Scenario::Flow => unreachable!(),
        Scenario::Retry => unreachable!(),
        Scenario::Datagram => {
            datagram_outcome = Some(datagram::run(&mut connection, datagram::Role::Client).await?);
        }
    }

    let close = timeout(TIMEOUT, connection.accept_bidirectional_stream())
        .await
        .context("peer close timed out")?
        .expect_err("netz server opened an unexpected stream");
    match close {
        s2n_quic::connection::Error::Application { error, .. } => {
            ensure!(u64::from(error) == 58, "unexpected peer close code");
        }
        other => bail!("unexpected peer close: {other}"),
    }

    drop(connection);
    client.wait_idle().await?;
    match scenario {
        Scenario::Echo => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop streams=2 bytes=10 peer_close=58"
        ),
        Scenario::Reset => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=58"
        ),
        Scenario::Stop => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 concurrent_sibling=4 echo_bytes=5 peer_close=58"
        ),
        Scenario::LossyReset => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop reset_error=41 dropped_cancel_datagrams=1 retransmitted=true concurrent_sibling=4 echo_bytes=5 peer_close=58"
        ),
        Scenario::LossyStop => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 dropped_cancel_datagrams=1 retransmitted=true concurrent_sibling=4 echo_bytes=5 peer_close=58"
        ),
        Scenario::ReorderedReset => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop reset_error=41 held_cancel_datagrams=1 reordered=true sibling_before_cancel=true concurrent_sibling=4 echo_bytes=5 peer_close=58"
        ),
        Scenario::ReorderedStop => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 held_cancel_datagrams=1 reordered=true sibling_before_cancel=true concurrent_sibling=4 echo_bytes=5 peer_close=58"
        ),
        Scenario::MixedChurn => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop mixed_churn=true streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true peer_close=58"
        ),
        Scenario::MixedChurnLoss => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop mixed_churn=true fault=loss fault_scope=netz-server-outbound streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true reset_faults=1 fin_faults=1 peer_close=58"
        ),
        Scenario::MixedChurnReorder => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop mixed_churn=true fault=reorder fault_scope=netz-server-outbound streams=32 fin=16 reset=16 bytes=266240 checksum=33945600 reset_mask=0x00000000aaaaaaaa reset_code_sum=262400 reset_prefix_bytes=256 terminal_states_verified=true reset_faults=1 fin_faults=1 peer_close=58"
        ),
        Scenario::Flow => unreachable!(),
        Scenario::Retry => unreachable!(),
        Scenario::Datagram => println!(
            "s2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes={} s2n_boundary_bytes={} oversized_rejected=true stream_sibling=4 peer_close=58 client_io=s2n-quic-tokio server_io=zio-std-io",
            datagram_outcome.as_ref().unwrap().boundary_bytes,
            datagram::S2N_BOUNDARY_BYTES,
        ),
    }
    Ok(())
}

fn scenario_limits(scenario: Scenario) -> Result<s2n_quic::provider::limits::Limits> {
    let limits = s2n_quic::provider::limits::Limits::new();
    if matches!(
        scenario,
        Scenario::MixedChurn | Scenario::MixedChurnLoss | Scenario::MixedChurnReorder
    ) {
        return Ok(limits
            .with_data_window(2 * 1024 * 1024)?
            .with_bidirectional_local_data_window(64 * 1024)?
            .with_bidirectional_remote_data_window(64 * 1024)?
            .with_max_open_local_bidirectional_streams(64)?
            .with_max_open_remote_bidirectional_streams(64)?);
    }
    if scenario != Scenario::Flow {
        return Ok(limits);
    }
    // These receive limits are advertised to netz. The 12 KiB request cannot
    // complete without multiple MAX_DATA and MAX_STREAM_DATA updates.
    Ok(limits
        .with_data_window(8 * 1024)?
        .with_bidirectional_remote_data_window(2 * 1024)?)
}

async fn accept_bidi(connection: &mut Connection) -> Result<s2n_quic::stream::BidirectionalStream> {
    timeout(TIMEOUT, connection.accept_bidirectional_stream())
        .await
        .context("bidirectional stream timed out")??
        .context("connection closed before the expected stream")
}

async fn echo_two_streams(connection: &mut Connection) -> Result<()> {
    let mut streams = Vec::with_capacity(PAYLOADS.len());
    for (index, expected) in PAYLOADS.into_iter().enumerate() {
        let mut stream = accept_bidi(connection).await?;
        ensure!(stream.id() == (index as u64) * 4, "unexpected stream id");
        let request = receive_all(&mut stream).await?;
        ensure!(request == expected, "unexpected request payload");
        stream.send(Bytes::copy_from_slice(expected)).await?;
        streams.push(stream);
    }

    // Accept and populate both streams before emitting their FINs. Netz sends
    // both requests concurrently, so serial close while accepting would
    // deadlock behind the second request's unread response.
    for stream in &mut streams {
        stream.finish()?;
    }
    Ok(())
}

async fn serve_reset(connection: &mut Connection) -> Result<()> {
    let mut target = accept_bidi(connection).await?;
    ensure!(target.id() == 0, "unexpected target stream id");
    ensure!(
        receive_all(&mut target).await? == b"reset",
        "unexpected reset request"
    );
    target.reset(41u8.into())?;
    echo_sibling(connection).await
}

async fn serve_stop(connection: &mut Connection) -> Result<()> {
    let mut target = accept_bidi(connection).await?;
    ensure!(target.id() == 0, "unexpected target stream id");
    receive_prefix(&mut target, b"stop").await?;
    target.stop_sending(42u8.into())?;
    let reset = timeout(TIMEOUT, async {
        loop {
            match target.receive().await {
                Ok(Some(_)) => {}
                Ok(None) => bail!("target finished instead of resetting"),
                Err(error) => break Ok(error),
            }
        }
    })
    .await
    .context("RESET_STREAM response timed out")??;
    match reset {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 42, "unexpected reset code");
        }
        other => bail!("unexpected reset result: {other}"),
    }
    echo_sibling(connection).await
}

async fn serve_peer_reset_reordered(connection: &mut Connection) -> Result<()> {
    let mut target = accept_bidi(connection).await?;
    ensure!(target.id() == 0, "unexpected target stream id");
    receive_prefix(&mut target, b"reset").await?;
    target.send(Bytes::from_static(b"target")).await?;

    let mut sibling = accept_bidi(connection).await?;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling payload"
    );
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;
    sibling.finish()?;

    let reset = timeout(TIMEOUT, async {
        loop {
            match target.receive().await {
                Ok(Some(_)) => {}
                Ok(None) => bail!("target finished instead of resetting"),
                Err(error) => break Ok::<s2n_quic::stream::Error, anyhow::Error>(error),
            }
        }
    })
    .await
    .context("reordered RESET_STREAM timed out")??;
    match reset {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 41, "unexpected reset code");
        }
        other => bail!("unexpected reset result: {other}"),
    }
    Ok(())
}

async fn serve_peer_stop_reordered(connection: &mut Connection) -> Result<()> {
    let mut target = accept_bidi(connection).await?;
    ensure!(target.id() == 0, "unexpected target stream id");
    receive_prefix(&mut target, b"stop").await?;
    target.send(Bytes::from_static(b"target")).await?;

    let mut sibling = accept_bidi(connection).await?;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling payload"
    );
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;
    sibling.finish()?;

    let stopped = timeout(TIMEOUT, async {
        loop {
            match target.send(Bytes::from_static(b"x")).await {
                Ok(()) => sleep(Duration::from_millis(1)).await,
                Err(error) => break Ok::<s2n_quic::stream::Error, anyhow::Error>(error),
            }
        }
    })
    .await
    .context("reordered STOP_SENDING timed out")??;
    match stopped {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 42, "unexpected stop code");
        }
        other => bail!("unexpected stop result: {other}"),
    }
    Ok(())
}

async fn echo_sibling(connection: &mut Connection) -> Result<()> {
    let mut sibling = accept_bidi(connection).await?;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling payload"
    );
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;
    sibling.finish()?;
    Ok(())
}

async fn serve_flow(connection: &mut Connection) -> Result<()> {
    let mut stream = accept_bidi(connection).await?;
    ensure!(stream.id() == 0, "unexpected flow-control stream id");
    let request = receive_all(&mut stream).await?;
    ensure!(
        request.len() == 12_288 && request.iter().all(|byte| *byte == b'f'),
        "unexpected flow-control request"
    );
    stream.send(Bytes::from(request)).await?;
    // This is the only response in the flow-control scenario. Waiting for the
    // FIN ACK guarantees netz received all 12 KiB before application close
    // supersedes any outstanding stream data.
    timeout(TIMEOUT, stream.close())
        .await
        .context("flow-control response acknowledgement timed out")??;
    Ok(())
}

async fn request_two_echoes(connection: &mut Connection) -> Result<()> {
    for (index, payload) in PAYLOADS.into_iter().enumerate() {
        let mut stream = timeout(TIMEOUT, connection.open_bidirectional_stream())
            .await
            .context("stream open timed out")??;
        ensure!(stream.id() == (index as u64) * 4, "unexpected stream id");
        stream.send(Bytes::copy_from_slice(payload)).await?;
        stream.finish()?;
        ensure!(
            receive_all(&mut stream).await? == payload,
            "unexpected echo payload"
        );
    }
    Ok(())
}

async fn request_reset(connection: &mut Connection) -> Result<()> {
    let mut target = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(target.id() == 0, "unexpected target stream id");
    target.send(Bytes::from_static(b"reset")).await?;
    target.reset(41u8.into())?;
    request_sibling(connection).await
}

async fn request_peer_reset(connection: &mut Connection) -> Result<()> {
    let mut target = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(target.id() == 0, "unexpected target stream id");
    target.send(Bytes::from_static(b"reset")).await?;

    let mut sibling = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;

    // Keep stream 4 open while the peer's first RESET_STREAM datagram is
    // deliberately lost. Its FIN acts as an application-level receipt: the
    // netz server cannot finish the sibling or close the connection until this
    // client has observed the retransmitted cancellation with the exact code.
    let reset_result = timeout(TIMEOUT, async {
        loop {
            match target.receive().await {
                Ok(Some(_)) => {}
                Ok(None) => bail!("target finished instead of resetting"),
                Err(error) => break Ok(error),
            }
        }
    })
    .await
    .context("RESET_STREAM timed out after injected loss")??;
    match reset_result {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 41, "unexpected reset code");
        }
        other => bail!("unexpected reset result: {other}"),
    }

    sibling.finish()?;
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling echo"
    );
    Ok(())
}

async fn request_peer_reset_reordered(connection: &mut Connection) -> Result<()> {
    let mut target = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(target.id() == 0, "unexpected target stream id");
    target.send(Bytes::from_static(b"reset")).await?;

    let mut sibling = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;
    sibling.finish()?;
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling echo"
    );

    let reset_result = timeout(TIMEOUT, async {
        loop {
            match target.receive().await {
                Ok(Some(_)) => {}
                Ok(None) => bail!("target finished instead of resetting"),
                Err(error) => break Ok::<s2n_quic::stream::Error, anyhow::Error>(error),
            }
        }
    })
    .await
    .context("reordered RESET_STREAM timed out")??;
    match reset_result {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 41, "unexpected reset code");
        }
        other => bail!("unexpected reset result: {other}"),
    }
    Ok(())
}

async fn request_stop(connection: &mut Connection) -> Result<()> {
    let mut target = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(target.id() == 0, "unexpected target stream id");
    target.send(Bytes::from_static(b"stop")).await?;

    let sibling = request_sibling(connection);
    let stopped = async {
        loop {
            match target.send(Bytes::from_static(b"x")).await {
                Ok(()) => sleep(Duration::from_millis(1)).await,
                Err(error) => break Ok(error),
            }
        }
    };
    let ((), stop_result) = tokio::try_join!(sibling, async {
        timeout(TIMEOUT, stopped)
            .await
            .context("STOP_SENDING timed out")?
    })?;
    match stop_result {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 42, "unexpected stop code");
        }
        other => bail!("unexpected stop result: {other}"),
    }
    Ok(())
}

async fn request_stop_reordered(connection: &mut Connection) -> Result<()> {
    let mut target = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(target.id() == 0, "unexpected target stream id");
    target.send(Bytes::from_static(b"stop")).await?;

    let mut sibling = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;
    sibling.finish()?;
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling echo"
    );

    let stop_result = timeout(TIMEOUT, async {
        loop {
            match target.send(Bytes::from_static(b"x")).await {
                Ok(()) => sleep(Duration::from_millis(1)).await,
                Err(error) => break Ok::<s2n_quic::stream::Error, anyhow::Error>(error),
            }
        }
    })
    .await
    .context("reordered STOP_SENDING timed out")??;
    match stop_result {
        s2n_quic::stream::Error::StreamReset { error, .. } => {
            ensure!(u64::from(error) == 42, "unexpected stop code");
        }
        other => bail!("unexpected stop result: {other}"),
    }
    Ok(())
}

async fn request_sibling(connection: &mut Connection) -> Result<()> {
    let mut sibling = timeout(TIMEOUT, connection.open_bidirectional_stream()).await??;
    ensure!(sibling.id() == 4, "unexpected sibling stream id");
    sibling.send(Bytes::copy_from_slice(PAYLOADS[1])).await?;
    sibling.finish()?;
    ensure!(
        receive_all(&mut sibling).await? == PAYLOADS[1],
        "unexpected sibling echo"
    );
    Ok(())
}

async fn receive_prefix(
    stream: &mut s2n_quic::stream::BidirectionalStream,
    expected: &[u8],
) -> Result<()> {
    let mut received = Vec::new();
    while received.len() < expected.len() {
        let chunk = timeout(TIMEOUT, stream.receive())
            .await
            .context("stream prefix timed out")??
            .context("stream finished before expected prefix")?;
        received.extend_from_slice(&chunk);
    }
    ensure!(received.starts_with(expected), "unexpected stream prefix");
    Ok(())
}

async fn receive_all(stream: &mut s2n_quic::stream::BidirectionalStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        match timeout(TIMEOUT, stream.receive())
            .await
            .context("stream receive timed out")??
        {
            Some(chunk) => bytes.extend_from_slice(&chunk),
            None => return Ok(bytes),
        }
    }
}
