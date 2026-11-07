//! Public reference codecs over Quinn permit intentionally invalid responses.
//! The semantic Connecting::respond API correctly refuses unoffered selections.
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::{fs, io::Cursor, sync::Arc};
use tokio::{io::AsyncReadExt, sync::Mutex, sync::Notify, task::JoinSet};
use web_transport_quinn::proto;

const ALPN_ERROR: u64 = 0x0817_b3dd;
const SESSION_GONE: u64 = 0x170d_7b68;
const WT_BIDI: u64 = 0x41;
const WT_UNI: u32 = 0x54;

#[derive(Default)]
struct State {
    requests: Vec<Value>,
    resets: Vec<Value>,
    datagrams: Vec<Value>,
    streams: Vec<Value>,
    // Dropping a CONNECT half would cancel it, so retain accepted streams.
    connect_streams: Vec<(SendStream, RecvStream)>,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}
async fn integer(recv: &mut RecvStream) -> Result<u64> {
    Ok(proto::VarInt::read(recv).await?.into_inner())
}
fn put_integer(output: &mut Vec<u8>, value: u32) {
    proto::VarInt::from_u32(value).encode(output);
}

fn normal_close(reason: &quinn::ConnectionError) -> bool {
    matches!(reason, quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0)
}

async fn stream(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    shared: Arc<Shared>,
) -> Result<()> {
    let kind = integer(&mut recv).await?;
    if kind == WT_BIDI {
        let session_id = integer(&mut recv).await?;
        ensure!(session_id == 0, "bad-session application stream leaked");
        let body = recv.read_to_end(256).await?;
        ensure!(body == b"sibling-stream");
        send.write_all(&body).await?;
        send.finish()?;
        shared
            .state
            .lock()
            .await
            .streams
            .push(json!({"session_id":session_id,"body":String::from_utf8(body)?}));
        return Ok(());
    }
    ensure!(kind == 1, "unexpected HTTP/3 request frame {kind}");
    let length = integer(&mut recv).await?;
    ensure!(length <= 65536, "unbounded request head");
    let mut block = vec![0; length as usize];
    recv.read_exact(&mut block).await?;
    let mut request_wire = Vec::new();
    put_integer(&mut request_wire, 1);
    put_integer(&mut request_wire, length as u32);
    request_wire.extend_from_slice(&block);
    let request = proto::ConnectRequest::decode(&mut request_wire.as_slice())?;
    let path = request.url.path().to_owned();
    let session_id = VarInt::from(send.id()).into_inner();
    let selected = match path.as_str() {
        "/ordered" => Some("p2"),
        "/escaped" => Some(super::ESCAPED),
        "/reuse" => Some("p1"),
        "/missing" => None,
        "/unoffered" => Some("unoffered"),
        _ => bail!("unexpected CONNECT path {path}"),
    };
    let expected_offers: Vec<&str> = match path.as_str() {
        "/ordered" => vec!["p2", "p1"],
        "/escaped" => vec![super::ESCAPED, "p1"],
        _ => vec!["p1"],
    };
    ensure!(
        request.protocols == expected_offers,
        "offer order/decoded values changed"
    );
    let bad = path == "/missing" || path == "/unoffered";
    let mut optimistic = if bad {
        let mut stream = conn.open_uni().await?;
        let mut data = Vec::new();
        put_integer(&mut data, WT_UNI);
        put_integer(&mut data, session_id as u32);
        data.extend_from_slice(b"must-not-be-delivered");
        stream.write_all(&data).await?;
        Some(stream)
    } else {
        None
    };
    let response = if let Some(value) = selected {
        proto::ConnectResponse::OK.with_protocol(value)
    } else {
        proto::ConnectResponse::OK
    };
    let mut response_wire = Vec::new();
    response.encode(&mut response_wire)?;
    shared.state.lock().await.requests.push(json!({"path":path,"session_id":session_id,
        "offered":request.protocols,"selected":selected,"request_head_hex":hex(&request_wire),"response_head_hex":hex(&response_wire)}));
    // Bypass only the reference's offer validation for the two bad successes.
    send.write_all(&response_wire).await?;
    if !bad {
        shared.state.lock().await.connect_streams.push((send, recv));
        return Ok(());
    }
    let mut byte = [0u8; 1];
    let reset = match recv.read(&mut byte).await {
        Err(quinn::ReadError::Reset(code)) => code.into_inner(),
        value => bail!("bad CONNECT did not receive RESET_STREAM: {value:?}"),
    };
    ensure!(reset == ALPN_ERROR, "wrong scoped WT_ALPN_ERROR");
    let stopped = send
        .stopped()
        .await?
        .context("CONNECT FIN replaced STOP_SENDING")?
        .into_inner();
    ensure!(stopped == ALPN_ERROR, "wrong CONNECT STOP_SENDING code");
    let optimistic = optimistic.take().context("missing optimistic UNI")?;
    let optimistic_id = VarInt::from(optimistic.id()).into_inner();
    let optimistic_stop = optimistic
        .stopped()
        .await?
        .context("optimistic UNI was not canceled")?
        .into_inner();
    ensure!(
        optimistic_stop == SESSION_GONE,
        "wrong optimistic-stream scope"
    );
    ensure!(
        conn.close_reason().is_none(),
        "protocol rejection closed the connection"
    );
    shared.state.lock().await.resets.push(json!({"path":path,"session_id":session_id,"reset_code":reset,
        "stop_code":stopped,"optimistic_stream_id":optimistic_id,"optimistic_stop_code":optimistic_stop,"connection_alive":true}));
    shared.changed.notify_waiters();
    Ok(())
}

async fn datagram(conn: Connection, bytes: Bytes, shared: Arc<Shared>) -> Result<()> {
    let mut payload = bytes.as_ref();
    let session_id = proto::VarInt::decode(&mut payload)?.into_inner() * 4;
    let label = std::str::from_utf8(payload)?.to_owned();
    let (expected_id, barriers) = match label.as_str() {
        "before-errors" => (0, 0),
        "after-missing" => (0, 1),
        "after-unoffered" => (0, 2),
        "escaped-live" => (12, 2),
        "new-session-live" => (20, 2),
        _ => bail!("unexpected application datagram {label}"),
    };
    ensure!(
        session_id == expected_id,
        "datagram crossed session ownership"
    );
    loop {
        let notified = shared.changed.notified();
        if shared.state.lock().await.resets.len() >= barriers {
            break;
        }
        notified.await;
    }
    // The client sees the echo only after the independent peer observed every
    // required CONNECT reset and optimistic-stream STOP_SENDING.
    conn.send_datagram(bytes)?;
    shared
        .state
        .lock()
        .await
        .datagrams
        .push(json!({"session_id":session_id,"body":label,"scoped_resets_observed":barriers}));
    Ok(())
}

pub async fn server(certificate: &str, key: &str) -> Result<()> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fs::read(certificate)?)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key)?)),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(32u32.into())
        .max_concurrent_uni_streams(16u32.into());
    config.transport_config(Arc::new(transport));
    let endpoint = Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    println!(
        "WT_PROTOCOL_REFERENCE_PORT={}",
        endpoint.local_addr()?.port()
    );
    let conn = endpoint
        .accept()
        .await
        .context("missing connection")?
        .await?;
    let mut settings = proto::Settings::default();
    settings.enable_webtransport(8);
    let mut send_control = conn.open_uni().await?;
    settings.write(&mut send_control).await?;
    let mut critical = Vec::new();
    loop {
        let mut recv = conn.accept_uni().await?;
        let kind = integer(&mut recv).await?;
        if kind == 0 {
            let mut prefixed = Cursor::new(vec![0]).chain(&mut recv);
            let peer = proto::Settings::read(&mut prefixed).await?;
            ensure!(peer.supports_webtransport() > 0);
            drop(prefixed);
            critical.push(recv);
            break;
        }
        ensure!(kind == 2 || kind == 3, "unexpected critical stream type");
        critical.push(recv);
    }
    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        changed: Notify::new(),
    });
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                match accepted {
                    Ok((send,recv)) => {tasks.spawn(stream(conn.clone(),send,recv,shared.clone()));}
                    Err(reason) if normal_close(&reason) => break,
                    Err(reason) => return Err(reason.into()),
                }
            }
            received = conn.read_datagram() => {
                match received {
                    Ok(bytes) => {tasks.spawn(datagram(conn.clone(),bytes,shared.clone()));}
                    Err(reason) if normal_close(&reason) => break,
                    Err(reason) => return Err(reason.into()),
                }
            }
            Some(result) = tasks.join_next() => result??,
            reason = conn.closed() => {
                ensure!(normal_close(&reason),"unexpected connection close: {reason}");
                break;
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    let state = shared.state.lock().await;
    ensure!(
        state.requests.len() == 5
            && state.resets.len() == 2
            && state.datagrams.len() == 5
            && state.streams.len() == 1,
        "incomplete protocol/isolation transcript"
    );
    println!(
        "WT_PROTOCOL_REFERENCE_SERVER_RESULT {}",
        json!({"status":"passed","connection_count":1,
        "request_decoder":"web-transport-proto","requests":state.requests,"resets":state.resets,
        "datagrams":state.datagrams,"streams":state.streams,"optimistic_streams_scoped":true})
    );
    drop(state);
    drop(send_control);
    drop(critical);
    endpoint.wait_idle().await;
    Ok(())
}
