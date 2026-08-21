//! One-shot cleartext HTTP/2 server for the netz client interoperability gate.
//!
//! Keeping this beside the equal-shape Hyper benchmark reuses its locked
//! dependency graph and the exact audited `~/Work/hyper` path dependency.

use std::convert::Infallible;
use std::env;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::net::TcpListener;
use tokio::sync::Notify;

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
        let canceled = Arc::new(CancelSignal::default());
        server_http2::Builder::new(TokioExecutor)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| handle(request, canceled.clone())),
            )
            .await
            .expect("serve netz HTTP/2 client");
    });
}

async fn handle(
    request: Request<Incoming>,
    canceled: Arc<CancelSignal>,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, io::Error> {
    if request.uri().path_and_query().map(|value| value.as_str()) == Some("/cancel?from=netz") {
        ensure_request(&request, Method::GET, "/cancel?from=netz")?;
        return Ok(Response::new(
            StreamBody::new(CancelResponseFrames {
                first: Some(Bytes::from_static(b"cancel-me")),
                signal: canceled,
            })
            .boxed(),
        ));
    }
    if request.uri().path_and_query().map(|value| value.as_str()) == Some("/after-cancel?from=netz")
    {
        ensure_request(&request, Method::GET, "/after-cancel?from=netz")?;
        while !canceled.observed.load(Ordering::Acquire) {
            canceled.notified.notified().await;
        }
        let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(
            b"after-cancel",
        )))]);
        return Ok(Response::new(StreamBody::new(frames).boxed()));
    }
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

fn ensure_request(
    request: &Request<Incoming>,
    method: Method,
    path: &str,
) -> Result<(), io::Error> {
    if request.method() != method
        || request.uri().path_and_query().map(|value| value.as_str()) != Some(path)
        || request.version() != Version::HTTP_2
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected cancellation request head",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct CancelSignal {
    observed: AtomicBool,
    notified: Notify,
}

struct CancelResponseFrames {
    first: Option<Bytes>,
    signal: Arc<CancelSignal>,
}

impl futures_util::Stream for CancelResponseFrames {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.first.take() {
            Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
            None => Poll::Pending,
        }
    }
}

impl Drop for CancelResponseFrames {
    fn drop(&mut self) {
        self.signal.observed.store(true, Ordering::Release);
        // Keep one permit if the RST_STREAM races ahead of the follow-up
        // handler's wait. notify_waiters() would lose that notification.
        self.signal.notified.notify_one();
    }
}
