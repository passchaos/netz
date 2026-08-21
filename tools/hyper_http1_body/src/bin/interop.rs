//! One-shot Hyper HTTP/1 peer for bidirectional process interoperability with
//! netz. The selected role is intentionally explicit so each direction uses a
//! fresh TCP connection and independently proves chunked trailers.

use std::convert::Infallible;
use std::env;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

type Body = StreamBody<ThreeFrameBody>;

fn main() {
    let mut args = env::args().skip(1);
    let role = args.next().expect("server or client role");
    let port: u16 = args
        .next()
        .expect("port argument")
        .parse()
        .expect("valid port");
    assert_ne!(port, 0);
    assert!(args.next().is_none());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    match role.as_str() {
        "server" => runtime.block_on(run_server(port)),
        "client" => runtime.block_on(run_client(port)),
        _ => panic!("unsupported role: {role}"),
    }
}

async fn run_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind Hyper HTTP/1 server");
    println!("Hyper HTTP/1 interop server listening on 127.0.0.1:{port}");
    let (stream, _) = listener.accept().await.expect("accept netz client");
    stream.set_nodelay(true).expect("server TCP_NODELAY");
    server_http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service_fn(handle_request))
        .await
        .expect("serve netz HTTP/1 client");
}

async fn handle_request(request: Request<Incoming>) -> Result<Response<Body>, std::io::Error> {
    if request.method() != Method::POST
        || request.uri().path_and_query().map(|value| value.as_str()) != Some("/interop?from=netz")
        || request.version() != Version::HTTP_11
        || request.headers().get("x-netz-request")
            != Some(&HeaderValue::from_static("request-header"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected netz request head",
        ));
    }
    let (body, trailers) = collect_body(request.into_body()).await?;
    if body != b"netz-request"
        || trailers
            .as_ref()
            .and_then(|values| values.get("x-netz-trailer"))
            != Some(&HeaderValue::from_static("request-trailer"))
    {
        eprintln!("unexpected netz request: body={body:?} trailers={trailers:?}");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected netz request body or trailers",
        ));
    }

    let mut response_trailers = HeaderMap::new();
    response_trailers.insert(
        "x-hyper-trailer",
        HeaderValue::from_static("response-trailer"),
    );
    let mut response = Response::new(body_with_trailers(
        b"hyper-",
        b"response",
        response_trailers,
    ));
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        "x-hyper-response",
        HeaderValue::from_static("response-header"),
    );
    response
        .headers_mut()
        .insert("trailer", HeaderValue::from_static("x-hyper-trailer"));
    Ok(response)
}

async fn run_client(port: u16) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz HTTP/1 server");
    stream.set_nodelay(true).expect("client TCP_NODELAY");
    let (mut sender, connection) = client_http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .expect("Hyper HTTP/1 handshake");
    tokio::spawn(async move {
        connection.await.expect("drive Hyper HTTP/1 connection");
    });

    let mut request_trailers = HeaderMap::new();
    request_trailers.insert(
        "x-hyper-trailer",
        HeaderValue::from_static("request-trailer"),
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/interop?from=hyper")
        .header("host", "localhost")
        .header("x-hyper-request", "request-header")
        .header("trailer", "x-hyper-trailer")
        .header("te", "trailers")
        .body(body_with_trailers(b"hyper-", b"request", request_trailers))
        .expect("request");
    let response = sender
        .send_request(request)
        .await
        .expect("send Hyper HTTP/1 request");
    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get("x-netz-response"),
        Some(&HeaderValue::from_static("response-header")),
    );
    let (body, trailers) = collect_body(response.into_body())
        .await
        .expect("read netz response");
    assert_eq!(body, b"netz-response");
    assert_eq!(
        trailers
            .as_ref()
            .and_then(|values| values.get("x-netz-trailer")),
        Some(&HeaderValue::from_static("response-trailer")),
    );
    println!("Hyper HTTP/1 client interoperated with netz: status=201 body=13 trailers=1");
}

fn body_with_trailers(first: &'static [u8], second: &'static [u8], trailers: HeaderMap) -> Body {
    StreamBody::new(ThreeFrameBody {
        first: Some(Bytes::from_static(first)),
        second: Some(Bytes::from_static(second)),
        trailers: Some(trailers),
    })
}

struct ThreeFrameBody {
    first: Option<Bytes>,
    second: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl futures_core::Stream for ThreeFrameBody {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(data) = self.first.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(data) = self.second.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }
}

async fn collect_body(mut body: Incoming) -> Result<(Vec<u8>, Option<HeaderMap>), std::io::Error> {
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(std::io::Error::other)?;
        match frame.into_data() {
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(frame) => {
                if let Ok(value) = frame.into_trailers() {
                    trailers = Some(value);
                }
            }
        }
    }
    Ok((data, trailers))
}

#[derive(Debug)]
struct TokioIo<T> {
    inner: T,
}

impl<T> TokioIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncRead + Unpin> Read for TokioIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buffer: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let count = unsafe {
            let mut tokio_buffer = tokio::io::ReadBuf::uninit(buffer.as_mut());
            match Pin::new(&mut self.get_mut().inner).poll_read(cx, &mut tokio_buffer) {
                Poll::Ready(Ok(())) => tokio_buffer.filled().len(),
                other => return other,
            }
        };
        unsafe {
            buffer.advance(count);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> Write for TokioIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }
}
