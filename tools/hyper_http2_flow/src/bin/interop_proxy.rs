//! One-shot Hyper HTTP/1.1 CONNECT proxy for the netz TLS HTTP/2 gate.

use std::convert::Infallible;
use std::env;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[allow(dead_code)]
#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::TokioIo;

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    assert!(args.next().is_none(), "unexpected extra argument");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    runtime.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind Hyper CONNECT proxy");
        println!("Hyper CONNECT proxy listening on 127.0.0.1:{port}");
        io::stdout().flush().expect("flush readiness line");
        let (stream, _) = listener.accept().await.expect("accept netz client");
        stream.set_nodelay(true).expect("proxy TCP_NODELAY");
        let (result_tx, result_rx) = oneshot::channel();
        let result_tx = Arc::new(Mutex::new(Some(result_tx)));
        http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| {
                    let result_tx = Arc::clone(&result_tx);
                    async move { handle(request, result_tx).await }
                }),
            )
            .with_upgrades()
            .await
            .expect("serve CONNECT request");
        let authority = result_rx
            .await
            .expect("CONNECT tunnel result sender")
            .expect("CONNECT tunnel");
        println!(
            "Hyper CONNECT proxy tunneled netz TLS HTTP/2: authority={authority} proxy_authorization=true client_io=zio-std-io proxy_io=hyper-tokio"
        );
    });
}

async fn handle(
    request: Request<hyper::body::Incoming>,
    result_tx: Arc<Mutex<Option<oneshot::Sender<Result<String, io::Error>>>>>,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, Infallible> {
    let mut response = Response::new(Empty::<Bytes>::new().boxed());
    if request.method() != Method::CONNECT
        || request
            .headers()
            .get("proxy-authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Basic aHlwZXItcHJveHk=")
    {
        *response.status_mut() = StatusCode::PROXY_AUTHENTICATION_REQUIRED;
        return Ok(response);
    }
    let authority = match request.uri().authority() {
        Some(value) => value.as_str().to_owned(),
        None => {
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        }
    };
    let sender = result_tx
        .lock()
        .expect("CONNECT result lock")
        .take()
        .expect("one CONNECT request");
    let connect_authority = authority.clone();
    tokio::spawn(async move {
        let result = tunnel(request, &connect_authority)
            .await
            .map(|_| connect_authority);
        let _ = sender.send(result);
    });
    Ok(response)
}

async fn tunnel(request: Request<hyper::body::Incoming>, authority: &str) -> io::Result<()> {
    let upgraded = hyper::upgrade::on(request)
        .await
        .map_err(io::Error::other)?;
    let mut origin = TcpStream::connect(authority).await?;
    origin.set_nodelay(true)?;
    let mut client = TokioIo::new(upgraded);
    match copy_bidirectional(&mut client, &mut origin).await {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}
