//! One-shot cleartext HTTP/2 server for the netz client interoperability gate.
//!
//! Keeping this beside the equal-shape Hyper benchmark reuses its locked
//! dependency graph and the exact audited `~/Work/hyper` path dependency.

use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{MaybeTls, TokioExecutor, TokioIo};

const CONSTRAINED_STREAM_WINDOW: u32 = 8 * 1024;
const CONSTRAINED_CONNECTION_WINDOW: u32 = 65_535;
const CANCEL_RESPONSE_BYTES: usize = 128 * 1024;
const SIBLING_RESPONSE_BYTES: usize = 16 * 1024;

fn main() {
    let mut args = env::args().skip(1);
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    let first = args.next();
    let (tls_paths, pool_mode, redirect_mode) = match first.as_deref() {
        Some("--pool") => (None, true, false),
        Some("--redirect") => (None, false, true),
        Some(cert) => {
            let key = args.next().expect("TLS private key argument");
            let mode = args.next();
            if let Some(value) = mode.as_deref() {
                assert!(
                    value == "--pool" || value == "--redirect",
                    "unexpected mode"
                );
            }
            (
                Some((cert.to_owned(), key)),
                mode.as_deref() == Some("--pool"),
                mode.as_deref() == Some("--redirect"),
            )
        }
        None => (None, false, false),
    };
    assert!(args.next().is_none(), "unexpected extra argument");

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

        if redirect_mode {
            for redirect_index in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept redirect client");
                stream.set_nodelay(true).expect("redirect TCP_NODELAY");
                let io = match tls_paths.as_ref() {
                    Some((cert, key)) => {
                        let tls = TlsAcceptor::from(tls_server_config(cert, key))
                            .accept(stream)
                            .await
                            .expect("accept redirect TLS with h2 ALPN");
                        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                        MaybeTls::Server(tls)
                    }
                    None => MaybeTls::Clear(stream),
                };
                server_http2::Builder::new(TokioExecutor)
                    .serve_connection(
                        TokioIo::new(io),
                        service_fn(move |request| {
                            handle_redirect(request, redirect_index)
                        }),
                    )
                    .await
                    .expect("serve netz HTTP/2 redirect request");
            }
            println!("Hyper HTTP/2 server verified netz redirect: status=303 method=POST-to-GET credentials=same-origin connections=2 client_io=zio-std-io server_io=hyper-tokio");
            return;
        }

        let (stream, _) = listener.accept().await.expect("accept netz client");
        stream.set_nodelay(true).expect("server TCP_NODELAY");
        let io = match tls_paths {
            Some((cert, key)) => {
                let mut tls = TlsAcceptor::from(tls_server_config(&cert, &key))
                    .accept(stream)
                    .await
                    .expect("accept TLS with h2 ALPN");
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                // Exercise rustls's production TLS 1.3 KeyUpdate encoder, not
                // merely a netz-to-netz vector. Its public API requests a
                // reciprocal update; flushing before Hyper starts preserves
                // record order ahead of the HTTP/2 connection bytes.
                tls.get_mut()
                    .1
                    .refresh_traffic_keys()
                    .expect("queue rustls KeyUpdate");
                tls.flush().await.expect("flush rustls KeyUpdate");
                println!("rustls server sent TLS KeyUpdate request");
                io::stdout().flush().expect("flush KeyUpdate marker");
                MaybeTls::Server(tls)
            }
            None => MaybeTls::Clear(stream),
        };
        let signals = Arc::new(LifecycleSignals::default());
        let mut builder = server_http2::Builder::new(TokioExecutor);
        builder
            .initial_stream_window_size(CONSTRAINED_STREAM_WINDOW)
            .initial_connection_window_size(CONSTRAINED_CONNECTION_WINDOW);
        let mut connection = Box::pin(builder.serve_connection(
                TokioIo::new(io),
                service_fn({
                    let signals = signals.clone();
                    move |request| handle(request, signals.clone())
                }),
            ));
        let mut graceful_started = Box::pin(if pool_mode {
            signals.pool_finished.notified()
        } else {
            signals.graceful_started.notified()
        });
        futures_util::future::poll_fn(|cx| {
            if let Poll::Ready(result) = connection.as_mut().poll(cx) {
                result.expect("serve netz HTTP/2 client before drain");
                panic!("HTTP/2 connection closed before graceful request");
            }
            match graceful_started.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        if pool_mode {
            // The pool process closes its idle socket after proving both
            // requests shared it. That can surface as a reset after all
            // asserted work, which is a valid shutdown for this scenario.
            let _ = connection.await;
            println!("Hyper HTTP/2 server completed netz pool batch, shared senders, and redirect reuse: requests=10 batch=3 shared=3 redirects=1 connections=1 client_io=zio-std-io server_io=hyper-tokio");
        } else {
            // Hyper/h2 emits the recommended MAX_STREAM_ID GOAWAY,
            // synchronizes one RTT with PING, then narrows the boundary to the
            // highest request it processed. Release the active response only
            // after shutdown starts so netz must drain through both GOAWAYs.
            connection.as_mut().graceful_shutdown();
            signals.graceful_release.notify_one();
            connection
                .await
                .expect("gracefully drain netz HTTP/2 client");
            println!(
                "Hyper HTTP/2 server gracefully drained netz client: active_stream=9 new_request_refused=true client_io=zio-std-io server_io=hyper-tokio"
            );
        }
    });
}

async fn handle_redirect(
    request: Request<Incoming>,
    redirect_index: usize,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, io::Error> {
    if redirect_index == 0 {
        if request.method() != Method::POST
            || request.uri().path_and_query().map(|value| value.as_str())
                != Some("/redirect-start?from=netz")
            || request.headers().get("authorization")
                != Some(&HeaderValue::from_static("Bearer hyper-h2-redirect"))
            || request.headers().get("content-type")
                != Some(&HeaderValue::from_static("text/plain"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 redirect source request",
            ));
        }
        let collected = request
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?;
        if collected.to_bytes() != b"redirect-body".as_slice() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 redirect source body",
            ));
        }
        let mut response = Response::new(
            StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                Bytes::from_static(b"redirecting"),
            ))]))
            .boxed(),
        );
        *response.status_mut() = StatusCode::SEE_OTHER;
        response.headers_mut().insert(
            "location",
            HeaderValue::from_static("/redirect-final?from=hyper#not-on-wire"),
        );
        return Ok(response);
    }

    if request.method() != Method::GET
        || request.uri().path_and_query().map(|value| value.as_str())
            != Some("/redirect-final?from=hyper")
        || request.headers().get("authorization")
            != Some(&HeaderValue::from_static("Bearer hyper-h2-redirect"))
        || request.headers().contains_key("content-type")
        || request.headers().contains_key("content-length")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected HTTP/2 redirected request",
        ));
    }
    let collected = request
        .into_body()
        .collect()
        .await
        .map_err(io::Error::other)?;
    if !collected.to_bytes().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected HTTP/2 redirected body",
        ));
    }
    Ok(Response::new(
        StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
            Bytes::from_static(b"hyper-h2-redirected"),
        ))]))
        .boxed(),
    ))
}

fn tls_server_config(cert_path: &str, key_path: &str) -> Arc<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open(Path::new(cert_path)).expect("open TLS certificate"),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("parse TLS certificate");
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(Path::new(key_path)).expect("open TLS private key"),
    ))
    .expect("parse TLS private key")
    .expect("TLS private key");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("certificate and private key match");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

async fn handle(
    request: Request<Incoming>,
    signals: Arc<LifecycleSignals>,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, io::Error> {
    if request.uri().path_and_query().map(|value| value.as_str())
        == Some("/pool-redirect-start?from=netz")
    {
        if request.method() != Method::POST
            || request.headers().get("authorization")
                != Some(&HeaderValue::from_static("Bearer h2-pool-redirect"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 pooled redirect source",
            ));
        }
        let collected = request
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?;
        if collected.to_bytes() != b"pool-body".as_slice() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 pooled redirect body",
            ));
        }
        signals.pool_requests.fetch_add(1, Ordering::AcqRel);
        let mut response = Response::new(
            StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                Bytes::from_static(b"redirecting"),
            ))]))
            .boxed(),
        );
        *response.status_mut() = StatusCode::SEE_OTHER;
        response.headers_mut().insert(
            "location",
            HeaderValue::from_static("/pool-redirect-final?from=hyper"),
        );
        return Ok(response);
    }
    if request.uri().path_and_query().map(|value| value.as_str())
        == Some("/pool-redirect-final?from=hyper")
    {
        ensure_request(&request, Method::GET, "/pool-redirect-final?from=hyper")?;
        if request.headers().get("authorization")
            != Some(&HeaderValue::from_static("Bearer h2-pool-redirect"))
            || request.headers().contains_key("content-length")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 pooled redirected request",
            ));
        }
        if signals.pool_requests.fetch_add(1, Ordering::AcqRel) + 1 == 10 {
            signals.pool_finished.notify_one();
        }
        return Ok(Response::new(
            StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                Bytes::from_static(b"pool-redirected"),
            ))]))
            .boxed(),
        ));
    }
    if let Some((path, expected_body, expected_trailer, response_body)) = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .and_then(|path| match path {
            "/pool-shared-one?from=netz" => Some((
                path,
                b"shared-body-one".as_slice(),
                "one",
                Bytes::from_static(b"pool-shared-one"),
            )),
            "/pool-shared-two?from=netz" => Some((
                path,
                b"shared-body-two".as_slice(),
                "two",
                Bytes::from_static(b"pool-shared-two"),
            )),
            "/pool-shared-three?from=netz" => Some((
                path,
                b"shared-body-three".as_slice(),
                "three",
                Bytes::from_static(b"pool-shared-three"),
            )),
            _ => None,
        })
    {
        ensure_request(&request, Method::POST, path)?;
        let collected = request
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?;
        if collected
            .trailers()
            .and_then(|trailers| trailers.get("x-shared-request-finished"))
            .and_then(|value| value.to_str().ok())
            != Some(expected_trailer)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 shared sender trailers",
            ));
        }
        if collected.to_bytes() != expected_body {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected HTTP/2 shared sender body",
            ));
        }
        signals.pool_requests.fetch_add(1, Ordering::AcqRel);
        return Ok(Response::new(
            StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                response_body,
            ))]))
            .boxed(),
        ));
    }
    if let Some(path) = request.uri().path_and_query().map(|value| value.as_str()) {
        let body = match path {
            "/pool-one?from=netz" => Some(Bytes::from_static(b"pool-one")),
            "/pool-two?from=netz" => Some(Bytes::from_static(b"pool-two")),
            "/pool-batch-one?from=netz" => Some(Bytes::from_static(b"pool-batch-one")),
            "/pool-batch-two?from=netz" => Some(Bytes::from_static(b"pool-batch-two")),
            "/pool-batch-three?from=netz" => Some(Bytes::from_static(b"pool-batch-three")),
            _ => None,
        };
        if let Some(body) = body {
            ensure_request(&request, Method::GET, path)?;
            signals.pool_requests.fetch_add(1, Ordering::AcqRel);
            return Ok(Response::new(
                StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(body))])).boxed(),
            ));
        }
    }
    if request.uri().path_and_query().map(|value| value.as_str()) == Some("/cancel?from=netz") {
        ensure_request(&request, Method::GET, "/cancel?from=netz")?;
        let mut response = Response::new(
            StreamBody::new(CancelResponseFrames {
                // A single application frame exceeds both advertised windows.
                // h2 must retain its unsent suffix after delivering exactly
                // the client's 8-KiB stream credit.
                first: Some(Bytes::from(vec![b'h'; CANCEL_RESPONSE_BYTES])),
                signal: signals.cancel.clone(),
            })
            .boxed(),
        );
        response
            .headers_mut()
            .insert("content-length", HeaderValue::from_static("131072"));
        response
            .headers_mut()
            .insert("x-hyper-cancel-body", HeaderValue::from_static("131072"));
        return Ok(response);
    }
    if request.uri().path_and_query().map(|value| value.as_str()) == Some("/sibling?from=netz") {
        ensure_request(&request, Method::GET, "/sibling?from=netz")?;
        while !signals.cancel.observed.load(Ordering::Acquire) {
            signals.cancel.notified.notified().await;
        }
        let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from(
            vec![b's'; SIBLING_RESPONSE_BYTES],
        )))]);
        let mut response = Response::new(StreamBody::new(frames).boxed());
        response
            .headers_mut()
            .insert("x-hyper-sibling", HeaderValue::from_static("after-cancel"));
        return Ok(response);
    }
    if request.uri().path_and_query().map(|value| value.as_str()) == Some("/graceful?from=netz") {
        ensure_request(&request, Method::GET, "/graceful?from=netz")?;
        signals.graceful_started.notify_one();
        signals.graceful_release.notified().await;
        return Ok(Response::new(
            StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                Bytes::from_static(b"hyper-drained"),
            ))]))
            .boxed(),
        ));
    }
    if request.uri().path_and_query().map(|value| value.as_str())
        == Some("/after-keep-alive?from=netz")
    {
        ensure_request(&request, Method::GET, "/after-keep-alive?from=netz")?;
        return Ok(Response::new(
            StreamBody::new(stream::iter([Ok::<_, Infallible>(Frame::data(
                Bytes::from_static(b"hyper-still-alive"),
            ))]))
            .boxed(),
        ));
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

#[derive(Default)]
struct LifecycleSignals {
    cancel: Arc<CancelSignal>,
    graceful_started: Notify,
    graceful_release: Notify,
    pool_requests: AtomicUsize,
    pool_finished: Notify,
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
            // The single 128-KiB body item is only partially written when the
            // 8-KiB HTTP/2 stream window closes. Pending keeps the response
            // unfinished until a peer reset drops this stream.
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
