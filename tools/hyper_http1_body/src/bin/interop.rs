//! One-shot Hyper HTTP/1 peer for bidirectional process interoperability with
//! netz. The selected role is intentionally explicit so each direction uses a
//! fresh TCP connection and independently proves chunked trailers.

use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    let tls_path = args.next();
    let tls_key = if role == "server" { args.next() } else { None };
    assert!(args.next().is_none());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    match role.as_str() {
        "server" => runtime.block_on(run_server(port, tls_path, tls_key)),
        "client" => runtime.block_on(run_client(port, tls_path)),
        _ => panic!("unsupported role: {role}"),
    }
}

async fn run_server(port: u16, cert_path: Option<String>, key_path: Option<String>) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind Hyper HTTP/1 server");
    println!("Hyper HTTP/1 interop server listening on 127.0.0.1:{port}");
    let mut connections = Vec::new();
    for connection_index in 0..10 {
        let (stream, _) = listener.accept().await.expect("accept netz client");
        stream.set_nodelay(true).expect("server TCP_NODELAY");
        let tls_acceptor = cert_path.as_ref().map(|cert| {
            TlsAcceptor::from(tls_server_config(
                cert,
                key_path.as_ref().expect("TLS key path"),
            ))
        });
        connections.push(tokio::spawn(async move {
            let io = match tls_acceptor {
                Some(acceptor) => {
                    let mut tls = acceptor.accept(stream).await.expect("accept HTTPS");
                    if connection_index == 0 {
                        tls.get_mut()
                            .1
                            .refresh_traffic_keys()
                            .expect("queue rustls KeyUpdate");
                        tls.flush().await.expect("flush rustls KeyUpdate");
                        println!("rustls HTTP/1 server sent TLS KeyUpdate request");
                    }
                    MaybeTls::Server(tls)
                }
                None => MaybeTls::Clear(stream),
            };
            match connection_index {
                0 | 2 => {
                    server_http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(io),
                            service_fn(move |request| handle_request(request, connection_index)),
                        )
                        .await
                        .expect("serve netz HTTP/1 client");
                }
                1 => serve_informational(io)
                    .await
                    .expect("serve observable informational responses"),
                3 => serve_expect_hints(io)
                    .await
                    .expect("serve 103 then 100 Expect boundary"),
                4 => serve_expect_rejection(io)
                    .await
                    .expect("serve 417 Expect boundary"),
                5 => {
                    let (completion, mut completed) = tokio::sync::mpsc::channel(1);
                    server_http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(io),
                            service_fn(move |request| {
                                handle_connect_request(request, completion.clone())
                            }),
                        )
                        .with_upgrades()
                        .await
                        .expect("serve netz CONNECT tunnel");
                    completed
                        .recv()
                        .await
                        .expect("CONNECT tunnel task completion")
                        .expect("CONNECT tunnel exchange");
                }
                6 => {
                    let (completion, mut completed) = tokio::sync::mpsc::channel(1);
                    server_http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(io),
                            service_fn(move |request| {
                                handle_upgrade_request(request, completion.clone())
                            }),
                        )
                        .with_upgrades()
                        .await
                        .expect("serve netz generic Upgrade");
                    completed
                        .recv()
                        .await
                        .expect("Upgrade task completion")
                        .expect("Upgrade exchange");
                }
                7 => {
                    let requests = Arc::new(AtomicUsize::new(0));
                    let observed = requests.clone();
                    server_http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(io),
                            service_fn(move |request| {
                                handle_pool_request(request, observed.clone())
                            }),
                        )
                        .await
                        .expect("serve netz pooled HTTP/1 requests");
                    assert_eq!(requests.load(Ordering::SeqCst), 4);
                }
                8 | 9 => {
                    server_http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(io),
                            service_fn(move |request| {
                                handle_redirect_request(request, connection_index)
                            }),
                        )
                        .await
                        .expect("serve netz HTTP redirect request");
                }
                _ => unreachable!(),
            }
        }));
    }
    for connection in connections {
        connection.await.expect("join Hyper HTTP/1 connection");
    }
    println!("Hyper/Tokio HTTP/1 fixture verified netz extension method, informational, Expect, CONNECT, Upgrade, redirect, and pooled reuse boundaries: extension=PURGE observed=103,102 expect=103,100 early_final=417 body_sent=0 tunnel_bytes=17/18 upgrade_bytes=18/19 redirect=303/POST-to-GET pooled_requests=4 pooled_redirect=303 pooled_connections=1 client_io=zio-std-io server_io=hyper-tokio");
}

async fn handle_redirect_request(
    request: Request<Incoming>,
    connection_index: usize,
) -> Result<Response<Body>, std::io::Error> {
    if connection_index == 8 {
        if request.method() != Method::POST
            || request.uri().path_and_query().map(|value| value.as_str())
                != Some("/redirect-start?from=netz")
            || request.headers().get("authorization")
                != Some(&HeaderValue::from_static("Bearer hyper-redirect"))
            || request.headers().get("content-type")
                != Some(&HeaderValue::from_static("text/plain"))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected netz redirect source request",
            ));
        }
        let (body, trailers) = collect_body(request.into_body()).await?;
        if body != b"redirect-body" || trailers.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected netz redirect source body",
            ));
        }
        let mut response = Response::new(body_with_trailers(
            b"hyper-",
            b"redirecting",
            HeaderMap::new(),
        ));
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
            != Some(&HeaderValue::from_static("Bearer hyper-redirect"))
        || request.headers().contains_key("content-type")
        || request.headers().contains_key("content-length")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected netz redirected request",
        ));
    }
    let (body, trailers) = collect_body(request.into_body()).await?;
    if !body.is_empty() || trailers.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected netz redirected body",
        ));
    }
    Ok(Response::new(body_with_trailers(
        b"hyper-",
        b"redirected",
        HeaderMap::new(),
    )))
}

async fn handle_pool_request(
    request: Request<Incoming>,
    requests: Arc<AtomicUsize>,
) -> Result<Response<Body>, std::io::Error> {
    let index = requests.fetch_add(1, Ordering::SeqCst);
    match index {
        0 | 1 => {
            let expected = if index == 0 {
                "/pool-one?from=netz"
            } else {
                "/pool-two?from=netz"
            };
            if request.method() != Method::GET
                || request.uri().path_and_query().map(|value| value.as_str()) != Some(expected)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected netz pooled request",
                ));
            }
            Ok(Response::new(body_with_trailers(
                if index == 0 { b"pool-one" } else { b"pool-two" },
                b"",
                HeaderMap::new(),
            )))
        }
        2 => {
            if request.method() != Method::POST
                || request.uri().path_and_query().map(|value| value.as_str())
                    != Some("/pool-redirect-start?from=netz")
                || request.headers().get("authorization")
                    != Some(&HeaderValue::from_static("Bearer pool-redirect"))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected pooled redirect source",
                ));
            }
            let (body, trailers) = collect_body(request.into_body()).await?;
            if body != b"pool-body" || trailers.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected pooled redirect body",
                ));
            }
            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", "/pool-redirect-final?from=hyper")
                .body(empty_body())
                .expect("pooled redirect response"))
        }
        3 => {
            if request.method() != Method::GET
                || request.uri().path_and_query().map(|value| value.as_str())
                    != Some("/pool-redirect-final?from=hyper")
                || request.headers().get("authorization")
                    != Some(&HeaderValue::from_static("Bearer pool-redirect"))
                || request.headers().contains_key("content-length")
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected pooled redirected request",
                ));
            }
            Ok(Response::new(body_with_trailers(
                b"pool-redirected",
                b"",
                HeaderMap::new(),
            )))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "too many netz pooled requests",
        )),
    }
}

async fn serve_informational(mut stream: MaybeTls) -> Result<(), std::io::Error> {
    read_request_head(&mut stream, "GET", "/informational?from=netz", None).await?;
    stream
        .write_all(
            b"HTTP/1.1 103 Early Hints\r\nLink: </asset.css>; rel=preload\r\n\r\n\
              HTTP/1.1 102 Processing\r\nX-Hyper-Progress: accepted\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\nhyper-informational",
        )
        .await
}

async fn handle_upgrade_request(
    mut request: Request<Incoming>,
    completion: tokio::sync::mpsc::Sender<Result<(), String>>,
) -> Result<Response<Body>, std::io::Error> {
    if request.method() != Method::GET
        || request.uri().path_and_query().map(|value| value.as_str()) != Some("/upgrade?from=netz")
        || request.headers().get("connection") != Some(&HeaderValue::from_static("Upgrade"))
        || request.headers().get("upgrade") != Some(&HeaderValue::from_static("netz-test"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected generic Upgrade request",
        ));
    }
    tokio::spawn(async move {
        let result = match hyper::upgrade::on(&mut request).await {
            Ok(upgraded) => serve_upgrade_tunnel(upgraded)
                .await
                .map_err(|error| error.to_string()),
            Err(error) => Err(format!("upgrade generic request: {error}")),
        };
        let _ = completion.send(result).await;
    });
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "Upgrade")
        .header("upgrade", "netz-test")
        .body(empty_body())
        .expect("Upgrade response"))
}

async fn serve_upgrade_tunnel(upgraded: Upgraded) -> Result<(), std::io::Error> {
    let parts = upgraded
        .downcast::<TokioIo<MaybeTls>>()
        .map_err(|_| std::io::Error::other("unexpected upgraded IO type"))?;
    let mut tunnel = parts.io.inner;
    tunnel.write_all(b"hyper upgrade ready").await?;
    let mut payload = parts.read_buf.to_vec();
    while payload.len() < b"netz upgrade bytes".len() {
        let mut chunk = [0; 64];
        let count = tunnel.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Upgrade closed before client payload",
            ));
        }
        payload.extend_from_slice(&chunk[..count]);
    }
    if payload != b"netz upgrade bytes" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected Upgrade payload: {payload:?}"),
        ));
    }
    tunnel.write_all(b"hyper upgrade reply").await
}

async fn handle_connect_request(
    mut request: Request<Incoming>,
    completion: tokio::sync::mpsc::Sender<Result<(), String>>,
) -> Result<Response<Body>, std::io::Error> {
    if request.method() != Method::CONNECT
        || request.uri().authority().map(|value| value.as_str()) != Some("tunnel.example:443")
        || request.headers().get("host") != Some(&HeaderValue::from_static("tunnel.example:443"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected CONNECT request",
        ));
    }
    tokio::spawn(async move {
        let result = match hyper::upgrade::on(&mut request).await {
            Ok(upgraded) => serve_connect_tunnel(upgraded)
                .await
                .map_err(|error| error.to_string()),
            Err(error) => Err(format!("upgrade CONNECT request: {error}")),
        };
        let _ = completion.send(result).await;
    });
    Ok(Response::new(StreamBody::new(ThreeFrameBody {
        first: None,
        second: None,
        trailers: None,
    })))
}

async fn serve_connect_tunnel(upgraded: Upgraded) -> Result<(), std::io::Error> {
    let parts = upgraded
        .downcast::<TokioIo<MaybeTls>>()
        .map_err(|_| std::io::Error::other("unexpected upgraded IO type"))?;
    let mut tunnel = parts.io.inner;
    // Sending immediately after the 200 response intentionally exercises
    // netz's buffered-response-suffix handoff into Tunnel.read().
    tunnel.write_all(b"hyper tunnel ready").await?;
    let mut payload = parts.read_buf.to_vec();
    while payload.len() < b"netz tunnel bytes".len() {
        let mut chunk = [0; 64];
        let count = tunnel.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "CONNECT tunnel closed before client payload",
            ));
        }
        payload.extend_from_slice(&chunk[..count]);
    }
    if payload != b"netz tunnel bytes" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected CONNECT tunnel payload: {payload:?}"),
        ));
    }
    tunnel.write_all(b"hyper tunnel reply").await
}

async fn read_expect_head(
    stream: &mut MaybeTls,
    target: &str,
    content_length: usize,
) -> Result<(), std::io::Error> {
    read_request_head(stream, "POST", target, Some(content_length)).await
}

async fn read_request_head(
    stream: &mut MaybeTls,
    method: &str,
    target: &str,
    expected_body_length: Option<usize>,
) -> Result<(), std::io::Error> {
    let mut bytes = Vec::new();
    let head_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP/1 request head exceeds fixture limit",
            ));
        }
        let mut chunk = [0; 512];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request head",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    if expected_body_length.is_some() && bytes.len() != head_end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "netz sent an expected body before 100 Continue",
        ));
    }
    let head = std::str::from_utf8(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 request head")
    })?;
    let request_line = format!("{method} {target} HTTP/1.1\r\n");
    let expected_headers = expected_body_length.map(|content_length| {
        (
            "Expect: 100-continue\r\n",
            format!("Content-Length: {content_length}\r\n"),
        )
    });
    if !head.starts_with(&request_line)
        || expected_headers
            .as_ref()
            .is_some_and(|(expect, length)| !head.contains(expect) || !head.contains(length))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected Expect request head: {head:?}"),
        ));
    }
    Ok(())
}

async fn serve_expect_hints(mut stream: MaybeTls) -> Result<(), std::io::Error> {
    read_expect_head(&mut stream, "/expect-hints?from=netz", 10).await?;
    stream
        .write_all(
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n\
              HTTP/1.1 100 Continue\r\n\r\n",
        )
        .await?;
    let mut body = [0; 10];
    stream.read_exact(&mut body).await?;
    if &body != b"netz-hints" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected body after 103/100",
        ));
    }
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nhyper-hints-ok",
        )
        .await
}

async fn serve_expect_rejection(mut stream: MaybeTls) -> Result<(), std::io::Error> {
    read_expect_head(&mut stream, "/expect-reject?from=netz", 11).await?;
    stream
        .write_all(
            b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrejected",
        )
        .await?;
    let mut unexpected_body = Vec::new();
    stream.read_to_end(&mut unexpected_body).await?;
    if !unexpected_body.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("netz sent rejected body bytes: {unexpected_body:?}"),
        ));
    }
    Ok(())
}

async fn handle_request(
    request: Request<Incoming>,
    connection_index: usize,
) -> Result<Response<Body>, std::io::Error> {
    if connection_index == 2 {
        return handle_expected_request(request).await;
    }
    if request.uri().path_and_query().map(|value| value.as_str()) == Some("/extension?from=netz") {
        if request.method().as_str() != "PURGE" || request.version() != Version::HTTP_11 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected netz extension method request head",
            ));
        }
        let (body, trailers) = collect_body(request.into_body()).await?;
        if !body.is_empty() || trailers.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected netz extension method request body",
            ));
        }
        return Ok(Response::new(body_with_trailers(
            b"hyper-",
            b"extension",
            HeaderMap::new(),
        )));
    }
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

async fn handle_expected_request(
    request: Request<Incoming>,
) -> Result<Response<Body>, std::io::Error> {
    if request.method() != Method::POST
        || request.uri().path_and_query().map(|value| value.as_str()) != Some("/expect?from=netz")
        || request.version() != Version::HTTP_11
        || request.headers().get("expect") != Some(&HeaderValue::from_static("100-continue"))
        || request.headers().get("content-length") != Some(&HeaderValue::from_static("11"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected netz expect request head",
        ));
    }
    let (body, trailers) = collect_body(request.into_body()).await?;
    if body != b"netz-expect" || trailers.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected netz expect request body",
        ));
    }

    let mut response = Response::new(body_with_trailers(
        b"hyper-",
        b"continued",
        HeaderMap::new(),
    ));
    response
        .headers_mut()
        .insert("x-hyper-continue", HeaderValue::from_static("observed"));
    Ok(response)
}

async fn run_client(port: u16, ca_path: Option<String>) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz HTTP/1 server");
    stream.set_nodelay(true).expect("client TCP_NODELAY");
    let io = match ca_path.as_ref() {
        Some(ca) => MaybeTls::Client(
            TlsConnector::from(tls_client_config(ca))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect HTTPS"),
        ),
        None => MaybeTls::Clear(stream),
    };
    let (mut sender, connection) = client_http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .expect("Hyper HTTP/1 handshake");
    tokio::spawn(async move {
        connection
            .with_upgrades()
            .await
            .expect("drive Hyper HTTP/1 connection");
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
        .header("connection", "TE")
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

    let extension_request = Request::builder()
        .method(Method::from_bytes(b"PURGE").expect("extension method"))
        .uri("/extension?from=hyper")
        .header("host", "localhost")
        .body(empty_body())
        .expect("extension method request");
    let extension_response = sender
        .send_request(extension_request)
        .await
        .expect("send Hyper extension method request");
    assert_eq!(extension_response.status(), StatusCode::OK);
    let (body, trailers) = collect_body(extension_response.into_body())
        .await
        .expect("read netz extension method response");
    assert_eq!(body, b"netz-extension");
    assert!(trailers.is_none());
    println!("Hyper HTTP/1 client sent extension method to netz: method=PURGE response_body=14");

    let informational_count = Arc::new(AtomicUsize::new(0));
    let observed = informational_count.clone();
    let mut expected_request = Request::builder()
        .method(Method::POST)
        .uri("/expect?from=hyper")
        .header("host", "localhost")
        .header("expect", "100-continue")
        .header("content-length", "12")
        .body(body_with_trailers(b"hyper-", b"expect", HeaderMap::new()))
        .expect("expect request");
    hyper::ext::on_informational(&mut expected_request, move |response| {
        assert_eq!(response.status(), StatusCode::CONTINUE);
        assert_eq!(response.version(), Version::HTTP_11);
        observed.fetch_add(1, Ordering::SeqCst);
    });
    let response = sender
        .send_request(expected_request)
        .await
        .expect("send Hyper expect request");
    assert_eq!(informational_count.load(Ordering::SeqCst), 1);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-netz-continue"),
        Some(&HeaderValue::from_static("observed")),
    );
    let (body, trailers) = collect_body(response.into_body())
        .await
        .expect("read netz expect response");
    assert_eq!(body, b"netz-continued");
    assert!(trailers.is_none());
    println!("Hyper HTTP/1 client observed netz 100 Continue: interim=1 body=12 response_body=14");

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz graceful HTTP/1 server");
    stream
        .set_nodelay(true)
        .expect("graceful client TCP_NODELAY");
    let io = match ca_path.as_ref() {
        Some(ca) => MaybeTls::Client(
            TlsConnector::from(tls_client_config(ca))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect graceful HTTPS"),
        ),
        None => MaybeTls::Clear(stream),
    };
    let (mut graceful_sender, graceful_connection) = client_http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .expect("Hyper graceful HTTP/1 handshake");
    tokio::spawn(async move {
        graceful_connection
            .await
            .expect("drive graceful Hyper HTTP/1 connection");
    });
    let response = graceful_sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .uri("/graceful?from=hyper")
                .header("host", "localhost")
                .body(empty_body())
                .expect("graceful request"),
        )
        .await
        .expect("send graceful request");
    assert_eq!(
        response.headers().get("connection"),
        Some(&HeaderValue::from_static("close")),
    );
    let (body, trailers) = collect_body(response.into_body())
        .await
        .expect("read graceful response");
    assert_eq!(body, b"netz-graceful");
    assert!(trailers.is_none());
    assert!(
        !graceful_sender.is_ready(),
        "Hyper must retire a connection after Connection: close",
    );
    println!("Hyper HTTP/1 client observed netz graceful drain: active_response=true connection_close=true next_request=false");

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("tunnel.example:443")
        .header("host", "tunnel.example:443")
        .body(empty_body())
        .expect("CONNECT request");
    let mut response = sender
        .send_request(request)
        .await
        .expect("send Hyper CONNECT request");
    assert_eq!(response.status(), StatusCode::OK);
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .expect("upgrade netz CONNECT response");
    let parts = upgraded
        .downcast::<TokioIo<MaybeTls>>()
        .expect("downcast upgraded netz transport");
    let mut tunnel = parts.io.inner;
    let mut preface = parts.read_buf.to_vec();
    while preface.len() < b"netz tunnel ready".len() {
        let mut chunk = [0; 64];
        let count = tunnel
            .read(&mut chunk)
            .await
            .expect("read netz tunnel preface");
        assert_ne!(count, 0, "netz tunnel closed before preface");
        preface.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(preface, b"netz tunnel ready");
    tunnel
        .write_all(b"hyper tunnel bytes")
        .await
        .expect("write Hyper tunnel payload");
    let mut reply = [0; 17];
    tunnel
        .read_exact(&mut reply)
        .await
        .expect("read netz tunnel reply");
    assert_eq!(&reply, b"netz tunnel reply");
    println!("Hyper HTTP/1 client interoperated with netz CONNECT tunnel: server_preface=17 client_bytes=18 reply_bytes=17");

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz Upgrade server");
    stream.set_nodelay(true).expect("Upgrade TCP_NODELAY");
    let io = match ca_path.as_ref() {
        Some(ca) => MaybeTls::Client(
            TlsConnector::from(tls_client_config(ca))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect Upgrade HTTPS"),
        ),
        None => MaybeTls::Clear(stream),
    };
    let (mut upgrade_sender, upgrade_connection) = client_http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .expect("Hyper generic Upgrade handshake");
    tokio::spawn(async move {
        upgrade_connection
            .with_upgrades()
            .await
            .expect("drive Hyper generic Upgrade connection");
    });
    let request = Request::builder()
        .method(Method::GET)
        .uri("/upgrade?from=hyper")
        .header("host", "localhost")
        .header("connection", "Upgrade")
        .header("upgrade", "netz-test")
        .body(empty_body())
        .expect("Upgrade request");
    let mut response = upgrade_sender
        .send_request(request)
        .await
        .expect("send Hyper Upgrade request");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response.headers().get("upgrade"),
        Some(&HeaderValue::from_static("netz-test")),
    );
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .expect("upgrade netz generic response");
    let parts = upgraded
        .downcast::<TokioIo<MaybeTls>>()
        .expect("downcast generic upgraded netz transport");
    let mut tunnel = parts.io.inner;
    let mut preface = parts.read_buf.to_vec();
    while preface.len() < b"netz upgrade ready".len() {
        let mut chunk = [0; 64];
        let count = tunnel.read(&mut chunk).await.expect("read Upgrade preface");
        assert_ne!(count, 0, "Upgrade closed before server preface");
        preface.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(preface, b"netz upgrade ready");
    tunnel
        .write_all(b"hyper upgrade bytes")
        .await
        .expect("write Upgrade payload");
    let mut reply = [0; 18];
    tunnel
        .read_exact(&mut reply)
        .await
        .expect("read Upgrade reply");
    assert_eq!(&reply, b"netz upgrade reply");
    println!("Hyper HTTP/1 client interoperated with netz generic Upgrade: protocol=netz-test server_preface=18 client_bytes=19 reply_bytes=18 client_io=hyper-tokio server_io=zio-std-io");

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz invalid-trailer server");
    stream
        .set_nodelay(true)
        .expect("invalid-trailer TCP_NODELAY");
    let io = match ca_path.as_ref() {
        Some(ca) => MaybeTls::Client(
            TlsConnector::from(tls_client_config(ca))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect invalid-trailer HTTPS"),
        ),
        None => MaybeTls::Clear(stream),
    };
    let (mut invalid_sender, invalid_connection) = client_http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .expect("Hyper invalid-trailer handshake");
    let invalid_driver = tokio::spawn(invalid_connection);
    let mut connection_trailer = HeaderMap::new();
    connection_trailer.insert("connection", HeaderValue::from_static("close"));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/invalid-trailer?from=hyper")
        .header("host", "localhost")
        .header("trailer", "connection")
        .body(body_with_trailers(
            b"hyper-",
            b"invalid",
            connection_trailer,
        ))
        .expect("invalid-trailer request");
    assert!(
        invalid_sender.send_request(request).await.is_err(),
        "netz must close instead of accepting a connection-control trailer",
    );
    drop(invalid_sender);
    let _ = invalid_driver
        .await
        .expect("join Hyper invalid-trailer connection");
    println!("Hyper HTTP/1 client observed netz reject connection-control trailer: field=connection response=false");

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz unnegotiated-response-trailer server");
    stream
        .set_nodelay(true)
        .expect("unnegotiated-response-trailer TCP_NODELAY");
    let io = match ca_path.as_ref() {
        Some(ca) => MaybeTls::Client(
            TlsConnector::from(tls_client_config(ca))
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost")
                        .expect("valid server name"),
                    stream,
                )
                .await
                .expect("connect unnegotiated-response-trailer HTTPS"),
        ),
        None => MaybeTls::Clear(stream),
    };
    let (mut unnegotiated_sender, unnegotiated_connection) = client_http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .expect("Hyper unnegotiated-response-trailer handshake");
    let unnegotiated_driver = tokio::spawn(unnegotiated_connection);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/unnegotiated-response-trailer?from=hyper")
        .header("host", "localhost")
        .body(empty_body())
        .expect("unnegotiated-response-trailer request");
    assert!(
        unnegotiated_sender.send_request(request).await.is_err(),
        "netz must not emit response trailers without TE: trailers",
    );
    drop(unnegotiated_sender);
    let _ = unnegotiated_driver
        .await
        .expect("join Hyper unnegotiated-response-trailer connection");
    println!("Hyper HTTP/1 client observed netz reject unnegotiated response trailers: request_te=false response=false");
}

fn empty_body() -> Body {
    StreamBody::new(ThreeFrameBody {
        first: None,
        second: None,
        trailers: None,
    })
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
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("certificate and private key match"),
    )
}

fn tls_client_config(ca_path: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        rustls_pemfile::certs(&mut BufReader::new(
            File::open(Path::new(ca_path)).expect("open CA certificate"),
        ))
        .map(|result| result.expect("parse CA certificate")),
    );
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
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

#[derive(Debug)]
enum MaybeTls {
    Clear(TcpStream),
    Client(tokio_rustls::client::TlsStream<TcpStream>),
    Server(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Client(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Server(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::Client(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::Server(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_flush(cx),
            Self::Client(stream) => Pin::new(stream).poll_flush(cx),
            Self::Server(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Clear(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Client(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Server(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
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
