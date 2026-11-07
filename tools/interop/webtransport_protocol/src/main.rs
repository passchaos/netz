use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use serde_json::json;
use std::{fs, time::Duration};
use tokio::time::timeout;
use web_transport_quinn::{proto, ClientBuilder, ClientError, ConnectError};

mod raw;
const ESCAPED: &str = "q\"u\\oted";
const TIMEOUT: Duration = Duration::from_secs(5);

async fn semantic_client(port: u16, certificate: &str) -> Result<()> {
    let client = ClientBuilder::new()
        .with_server_certificates(vec![CertificateDer::from(fs::read(certificate)?)])?;
    let mut cases = Vec::new();
    for (name, offers, selected) in [
        ("ordered", vec!["p2", "p1"], "p2"),
        ("escaped", vec![ESCAPED, "p1"], ESCAPED),
    ] {
        let request = proto::ConnectRequest::new(
            format!("https://127.0.0.1:{port}/{name}").parse::<url::Url>()?,
        )
        .with_protocols(offers.iter().map(|value| value.to_string()));
        let session = timeout(TIMEOUT, client.connect(request)).await??;
        ensure!(
            session.protocol() == Some(selected),
            "wrong Session.protocol()"
        );
        ensure!(session.request().context("missing request")?.protocols == offers);
        let datagram = format!("semantic-datagram-{name}");
        session.send_datagram(Bytes::from(datagram.clone()))?;
        ensure!(timeout(TIMEOUT, session.read_datagram()).await??.as_ref() == datagram.as_bytes());
        let (mut send, mut recv) = timeout(TIMEOUT, session.open_bi()).await??;
        let stream = format!("semantic-stream-{name}");
        timeout(TIMEOUT, send.write_all(stream.as_bytes())).await??;
        send.finish()?;
        ensure!(timeout(TIMEOUT, recv.read_to_end(256)).await?? == stream.as_bytes());
        cases.push(
            json!({"name":name,"offers":offers,"selected":session.protocol(),
            "application_datagrams":1,"application_streams":1}),
        );
        session.close(0, b"semantic case complete");
    }
    let request = proto::ConnectRequest::new(
        format!("https://127.0.0.1:{port}/required-no-overlap").parse::<url::Url>()?,
    )
    .with_protocol("absent");
    match timeout(TIMEOUT, client.connect(request)).await? {
        Err(ClientError::HttpError(ConnectError::ProtoError(
            proto::ConnectError::WrongStatus(Some(status)),
        ))) if status.as_u16() == 406 => {}
        Err(error) => bail!("required negotiation failed with the wrong error: {error:?}"),
        Ok(_) => bail!("required no-overlap unexpectedly established a session"),
    }
    cases.push(json!({"name":"required-no-overlap","status":406,"application_datagrams":0,"application_streams":0}));
    println!(
        "WT_PROTOCOL_REFERENCE_CLIENT_RESULT {}",
        json!({"status":"passed","semantic_session_protocol":true,
        "ordered_overlap":true,"escaped_identifiers":true,"required_rejected_before_application_io":true,"cases":cases})
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("client") if args.len() == 4 => {
            timeout(
                Duration::from_secs(25),
                semantic_client(args[2].parse()?, &args[3]),
            )
            .await
            .context("semantic client deadline")??;
        }
        Some("server") if args.len() == 4 => {
            timeout(Duration::from_secs(25), raw::server(&args[2], &args[3]))
                .await
                .context("raw server deadline")??;
        }
        _ => bail!("usage: protocol-peer client PORT CERT.der | server CERT.der KEY.pk8"),
    }
    Ok(())
}
