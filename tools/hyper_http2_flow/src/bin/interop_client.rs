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

type RequestBody =
    StreamBody<stream::Iter<std::array::IntoIter<Result<Frame<Bytes>, Infallible>, 3>>>;

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

        let cancel_request = Request::builder()
            .method(Method::GET)
            .uri(
                Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query("/cancel?from=hyper")
                    .build()
                    .expect("cancel request URI"),
            )
            .body(empty_body())
            .expect("cancel request");
        let cancel_response = sender
            .send_request(cancel_request)
            .await
            .expect("send cancellation request");
        assert_eq!(cancel_response.status(), StatusCode::OK);
        let mut cancel_body = cancel_response.into_body();
        let first = cancel_body
            .frame()
            .await
            .expect("first cancellation body frame")
            .expect("valid cancellation body frame")
            .into_data()
            .expect("cancellation DATA frame");
        assert_eq!(first, Bytes::from_static(b"cancel-me"));
        // Dropping an unfinished Incoming body emits RST_STREAM(CANCEL). The
        // netz server waits for that exact reset before accepting this request.
        drop(cancel_body);

        let after_cancel_request = Request::builder()
            .method(Method::GET)
            .uri(
                Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query("/after-cancel?from=hyper")
                    .build()
                    .expect("post-cancel request URI"),
            )
            .body(empty_body())
            .expect("post-cancel request");
        let response = sender
            .send_request(after_cancel_request)
            .await
            .expect("send post-cancel request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect post-cancel response")
            .to_bytes();
        assert_eq!(body, Bytes::from_static(b"after-cancel"));
        println!(
            "Hyper HTTP/2 client canceled netz stream and reused connection: rst=CANCEL status=200"
        );
    });
}

fn empty_body() -> RequestBody {
    StreamBody::new(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::new())),
        Ok(Frame::data(Bytes::new())),
        Ok(Frame::data(Bytes::new())),
    ]))
}
