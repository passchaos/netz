//! One-shot cleartext HTTP/2 server for the netz client interoperability gate.
//!
//! Keeping this beside the equal-shape Hyper benchmark reuses its locked
//! dependency graph and the exact audited `~/Work/hyper` path dependency.

use std::convert::Infallible;
use std::env;
use std::io::{self, Write};

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::net::TcpListener;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{TokioExecutor, TokioIo};

fn main() {
    let port: u16 = env::args()
        .nth(1)
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    runtime.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind Hyper interoperability server");
        println!("Hyper HTTP/2 interop server listening on 127.0.0.1:{port}");
        io::stdout().flush().expect("flush readiness line");

        let (stream, _) = listener.accept().await.expect("accept netz client");
        stream.set_nodelay(true).expect("server TCP_NODELAY");
        server_http2::Builder::new(TokioExecutor)
            .serve_connection(TokioIo::new(stream), service_fn(handle))
            .await
            .expect("serve netz HTTP/2 client");
    });
}

async fn handle(
    request: Request<Incoming>,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, io::Error> {
    if request.method() != Method::POST
        || request.uri().path_and_query().map(|value| value.as_str()) != Some("/interop?from=netz")
        || request.version() != Version::HTTP_2
        || request.headers().get("x-netz-request")
            != Some(&HeaderValue::from_static("request-header"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected netz request head",
        ));
    }

    let mut body = Vec::new();
    let mut trailers = None;
    let mut incoming = request.into_body();
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(io::Error::other)?;
        match frame.into_data() {
            Ok(data) => body.extend_from_slice(&data),
            Err(frame) => {
                if let Ok(value) = frame.into_trailers() {
                    trailers = Some(value);
                }
            }
        }
    }
    if body != b"request-body"
        || trailers
            .as_ref()
            .and_then(|values| values.get("x-netz-trailer"))
            != Some(&HeaderValue::from_static("request-trailer"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected netz request body or trailers",
        ));
    }

    let mut response_trailers = HeaderMap::new();
    response_trailers.insert(
        "x-hyper-trailer",
        HeaderValue::from_static("response-trailer"),
    );
    let frames = stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hyper-"))),
        Ok(Frame::data(Bytes::from_static(b"response"))),
        Ok(Frame::trailers(response_trailers)),
    ]);
    let mut response = Response::new(StreamBody::new(frames).boxed());
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        "x-hyper-response",
        HeaderValue::from_static("response-header"),
    );
    Ok(response)
}
