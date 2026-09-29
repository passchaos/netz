//! Fixed Hyper server for the HTTP/2 cancellation-race benchmark.

use std::convert::Infallible;
use std::env;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderValue;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{TokioExecutor, TokioIo};

const STREAM_WINDOW: u32 = 8 * 1024;
const CONNECTION_WINDOW: u32 = 65_535;
const OFFERED_BYTES: usize = 128 * 1024;
const SIBLING_BYTES: usize = 16 * 1024;

type ResponseBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().expect("port").parse().expect("valid port");
    let expected_batches: usize = args
        .next()
        .expect("expected batches")
        .parse()
        .expect("valid expected batches");
    assert!(port != 0 && expected_batches != 0 && args.next().is_none());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build server runtime");
    runtime.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind cancellation server");
        println!("Hyper HTTP/2 cancellation benchmark server listening on 127.0.0.1:{port}");
        io::stdout().flush().expect("flush readiness");
        let (stream, _) = listener.accept().await.expect("accept benchmark client");
        stream.set_nodelay(true).expect("server TCP_NODELAY");
        let state = Arc::new(State::new(expected_batches));
        let mut builder = http2::Builder::new(TokioExecutor);
        builder
            .initial_stream_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW);
        let result = builder
            .serve_connection(
                TokioIo::new(stream),
                service_fn({
                    let state = state.clone();
                    move |request| handle(request, state.clone())
                }),
            )
            .await;
        if let Err(error) = result {
            if !error.is_incomplete_message() {
                panic!("serve cancellation benchmark: {error}");
            }
        }
        assert_eq!(state.cancelled.load(Ordering::Acquire), expected_batches);
        assert_eq!(state.siblings.load(Ordering::Acquire), expected_batches);
        assert_eq!(state.reuse.load(Ordering::Acquire), 1);
        println!(
            "record=server-complete implementation=hyper protocol=http2 transport=h2c mode=cancellation-race server_io=hyper-tokio stream_window=8192 connection_window=65535 offered_bytes=131072 canceled_bytes=8192 sibling_bytes=16384 batches={} cancellations_observed={} siblings_completed={} reuse_requests=1 complete=true",
            expected_batches, expected_batches, expected_batches
        );
    });
}

struct State {
    expected_batches: usize,
    cancelled: AtomicUsize,
    siblings: AtomicUsize,
    reuse: AtomicUsize,
    permits: Arc<Semaphore>,
}

impl State {
    fn new(expected_batches: usize) -> Self {
        Self {
            expected_batches,
            cancelled: AtomicUsize::new(0),
            siblings: AtomicUsize::new(0),
            reuse: AtomicUsize::new(0),
            permits: Arc::new(Semaphore::new(0)),
        }
    }
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<ResponseBody>, io::Error> {
    if request.method() != Method::GET || request.version() != Version::HTTP_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request",
        ));
    }
    match request.uri().path() {
        "/cancel" => {
            let mut response = Response::new(
                StreamBody::new(CancelBody {
                    first: Some(Bytes::from(vec![b'c'; OFFERED_BYTES])),
                    state,
                })
                .boxed(),
            );
            response
                .headers_mut()
                .insert("content-length", HeaderValue::from_static("131072"));
            Ok(response)
        }
        "/sibling" => {
            let permit = state
                .permits
                .clone()
                .acquire_owned()
                .await
                .expect("cancellation semaphore");
            permit.forget();
            state.siblings.fetch_add(1, Ordering::AcqRel);
            Ok(Response::new(
                StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                    Bytes::from(vec![b's'; SIBLING_BYTES]),
                ))]))
                .boxed(),
            ))
        }
        "/reuse" => {
            assert_eq!(
                state.cancelled.load(Ordering::Acquire),
                state.expected_batches
            );
            assert_eq!(
                state.siblings.load(Ordering::Acquire),
                state.expected_batches
            );
            state.reuse.fetch_add(1, Ordering::AcqRel);
            Ok(Response::new(
                StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                    Bytes::from_static(b"reuse-ok"),
                ))]))
                .boxed(),
            ))
        }
        _ => {
            let mut response = Response::new(
                StreamBody::new(stream::empty::<Result<Frame<Bytes>, Infallible>>()).boxed(),
            );
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}

struct CancelBody {
    first: Option<Bytes>,
    state: Arc<State>,
}

impl futures_util::Stream for CancelBody {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.first.take() {
            Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
            None => Poll::Pending,
        }
    }
}

impl Drop for CancelBody {
    fn drop(&mut self) {
        self.state.cancelled.fetch_add(1, Ordering::AcqRel);
        self.state.permits.add_permits(1);
    }
}
