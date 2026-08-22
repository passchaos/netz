//! One-shot Hyper HTTP/2 client for the netz server interoperability gate.
//!
//! The request and response intentionally contain multiple DATA frames and
//! trailers so this reverse direction proves more than the HTTP/2 handshake.

use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{future, stream};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http2 as client_http2;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri, Version};
use tokio::net::TcpStream;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{MaybeTls, TokioExecutor, TokioIo};

const CONSTRAINED_STREAM_WINDOW: u32 = 8 * 1024;
const CONSTRAINED_CONNECTION_WINDOW: u32 = 65_535;
const CANCEL_RESPONSE_BYTES: usize = 128 * 1024;
const SIBLING_RESPONSE_BYTES: usize = 16 * 1024;

type RequestBody = BoxBody<Bytes, Infallible>;

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    let ca_path = args.next();
    assert!(args.next().is_none(), "unexpected extra argument");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    runtime.block_on(async move {
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect netz interoperability server");
        stream.set_nodelay(true).expect("client TCP_NODELAY");
        let io = match ca_path {
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                roots.add_parsable_certificates(
                    rustls_pemfile::certs(&mut BufReader::new(
                        File::open(Path::new(&ca)).expect("open CA certificate"),
                    ))
                    .map(|result| result.expect("parse CA certificate")),
                );
                let mut config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                config.alpn_protocols = vec![b"h2".to_vec()];
                let server_name = rustls::pki_types::ServerName::try_from("localhost")
                    .expect("valid server name");
                let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(server_name, stream)
                    .await
                    .expect("connect TLS with h2 ALPN");
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                MaybeTls::Client(tls)
            }
            None => MaybeTls::Clear(stream),
        };
        let mut builder = client_http2::Builder::new(TokioExecutor);
        builder
            .initial_stream_window_size(CONSTRAINED_STREAM_WINDOW)
            .initial_connection_window_size(CONSTRAINED_CONNECTION_WINDOW);
        let (mut sender, connection) = builder
            .handshake(TokioIo::new(io))
            .await
            .expect("Hyper HTTP/2 handshake");
        tokio::spawn(async move {
            // The one-shot netz fixture closes immediately after its final
            // response. A concurrent close can surface as BrokenPipe after
            // every request assertion below has already completed.
            let _ = connection.await;
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
            .body(StreamBody::new(request_frames).boxed())
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
        let sibling_request = Request::builder()
            .method(Method::GET)
            .uri(
                Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query("/sibling?from=hyper")
                    .build()
                    .expect("sibling request URI"),
            )
            .body(empty_body())
            .expect("sibling request");

        let mut sibling_sender = sender.clone();
        let mut graceful_sender = sender.clone();
        let cancel_flow = async move {
            let cancel_response = sender
                .send_request(cancel_request)
                .await
                .expect("send cancellation request");
            assert_eq!(cancel_response.status(), StatusCode::OK);
            assert_eq!(
                cancel_response.headers().get("content-length"),
                Some(&HeaderValue::from_static("131072")),
            );
            assert_eq!(
                cancel_response.headers().get("x-netz-cancel-body"),
                Some(&HeaderValue::from_static("131072")),
            );
            let mut cancel_body = cancel_response.into_body();
            let first = cancel_body
                .frame()
                .await
                .expect("first cancellation body frame")
                .expect("valid cancellation body frame")
                .into_data()
                .expect("cancellation DATA frame");
            assert_eq!(first.len(), CONSTRAINED_STREAM_WINDOW as usize);
            assert!(first.iter().all(|byte| *byte == b'n'));
            // The response is still 120 KiB short of Content-Length. Dropping
            // Incoming emits RST_STREAM(CANCEL) while the sibling is active.
            drop(cancel_body);
            first.len()
        };
        let sibling_flow = async move {
            let response = sibling_sender
                .send_request(sibling_request)
                .await
                .expect("send concurrent sibling request");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get("x-netz-sibling"),
                Some(&HeaderValue::from_static("after-cancel")),
            );
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect sibling response")
                .to_bytes();
            assert_eq!(body.len(), SIBLING_RESPONSE_BYTES);
            assert!(body.iter().all(|byte| *byte == b's'));
            body.len()
        };
        let (cancel_received, sibling_received) =
            future::join(cancel_flow, sibling_flow).await;
        assert_eq!(CANCEL_RESPONSE_BYTES, 128 * 1024);
        println!(
            "Hyper HTTP/2 client canceled flow-blocked netz stream and completed concurrent sibling: rst=CANCEL window={} received={} sibling={}",
            CONSTRAINED_STREAM_WINDOW, cancel_received, sibling_received,
        );

        let graceful_request = Request::builder()
            .method(Method::GET)
            .uri(
                Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query("/graceful?from=hyper")
                    .build()
                    .expect("graceful request URI"),
            )
            .body(empty_body())
            .expect("graceful request");
        let graceful_response = graceful_sender
            .send_request(graceful_request)
            .await
            .expect("active request survives netz GOAWAY");
        assert_eq!(graceful_response.status(), StatusCode::OK);
        let graceful_body = graceful_response
            .into_body()
            .collect()
            .await
            .expect("collect drained response")
            .to_bytes();
        assert_eq!(graceful_body, b"netz-drained".as_slice());

        // Awaiting readiness drives receipt of the peer GOAWAY before the
        // attempted stream 9 request, proving rejection occurs at the HTTP/2
        // connection layer rather than from a coincidental TCP close.
        let refusal = graceful_sender
            .ready()
            .await
            .expect_err("new request unexpectedly allowed after GOAWAY");
        assert!(
            refusal.is_closed(),
            "unexpected post-GOAWAY readiness error: {refusal}"
        );
        println!(
            "Hyper HTTP/2 client drained netz GOAWAY: active_stream=7 new_request_refused=true"
        );
    });
}

fn empty_body() -> RequestBody {
    Empty::<Bytes>::new().boxed()
}
