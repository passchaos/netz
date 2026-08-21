//! One-shot Hyper HTTP/2 client for the netz server interoperability gate.
//!
//! The request and response intentionally contain multiple DATA frames and
//! trailers so this reverse direction proves more than the HTTP/2 handshake.

use std::convert::Infallible;
use std::env;

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http2 as client_http2;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri, Version};
use tokio::net::TcpStream;

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
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect netz interoperability server");
        stream.set_nodelay(true).expect("client TCP_NODELAY");
        let (mut sender, connection) = client_http2::Builder::new(TokioExecutor)
            .handshake(TokioIo::new(stream))
            .await
            .expect("Hyper HTTP/2 handshake");
        tokio::spawn(async move {
            connection.await.expect("drive Hyper HTTP/2 connection");
        });

        let mut request_trailers = HeaderMap::new();
        request_trailers.insert(
            "x-hyper-trailer",
            HeaderValue::from_static("request-trailer"),
        );
        let request_frames = stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hyper-"))),
            Ok(Frame::data(Bytes::from_static(b"request"))),
            Ok(Frame::trailers(request_trailers)),
        ]);
        let request = Request::builder()
            .method(Method::POST)
            .uri(
                Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query("/interop?from=hyper")
                    .build()
                    .expect("request URI"),
            )
            .header("x-hyper-request", "request-header")
            .body(StreamBody::new(request_frames))
            .expect("request");
        let response = sender
            .send_request(request)
            .await
            .expect("send Hyper request");
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("x-netz-response"),
            Some(&HeaderValue::from_static("response-header")),
        );

        let mut body = Vec::new();
        let mut trailers = None;
        let mut incoming = response.into_body();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.expect("response body frame");
            match frame.into_data() {
                Ok(data) => body.extend_from_slice(&data),
                Err(frame) => {
                    if let Ok(value) = frame.into_trailers() {
                        trailers = Some(value);
                    }
                }
            }
        }
        assert_eq!(body, b"netz-response");
        assert_eq!(
            trailers
                .as_ref()
                .and_then(|values| values.get("x-netz-trailer")),
            Some(&HeaderValue::from_static("response-trailer")),
        );
        println!("Hyper HTTP/2 client interoperated with netz: status=201 body=13 trailers=1");
    });
}
