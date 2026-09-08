use std::convert::Infallible;
use std::env;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[path = "../tokiort.rs"]
mod tokiort;
use tokiort::{TokioExecutor, TokioIo, TokioTimer};

const PATH: &str = "/rfc8441-benchmark";
const ORIGIN: &str = "http://example.test";
const PROTOCOL: &str = "netz-benchmark";
const READY: &[u8] = b"NZWSREADY";

#[derive(Clone, Copy)]
struct Config {
    warmup: u32,
    iterations: u32,
    payload_bytes: usize,
    timeout: Duration,
}

impl Config {
    fn parse(args: impl Iterator<Item = String>) -> Self {
        let mut config = Self {
            warmup: 20,
            iterations: 1000,
            payload_bytes: 4096,
            timeout: Duration::from_secs(30),
        };
        for arg in args {
            let (name, value) = arg.split_once('=').expect("--name=value option");
            match name {
                "--warmup" => config.warmup = value.parse().expect("warmup"),
                "--iterations" => config.iterations = value.parse().expect("iterations"),
                "--payload-bytes" => config.payload_bytes = value.parse().expect("payload bytes"),
                "--timeout-ms" => {
                    config.timeout = Duration::from_millis(value.parse().expect("timeout"))
                }
                _ => panic!("unknown option {name}"),
            }
        }
        assert!(config.warmup <= 100_000);
        assert!((1..=1_000_000).contains(&config.iterations));
        assert!((1..=4096).contains(&config.payload_bytes));
        assert!(!config.timeout.is_zero() && config.timeout <= Duration::from_secs(600));
        config
    }
    fn rounds(self) -> u32 {
        self.warmup.checked_add(self.iterations).unwrap()
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let role = args.next().expect("server or client role");
    let port: u16 = args.next().expect("port").parse().expect("valid port");
    assert_ne!(port, 0);
    let config = Config::parse(args);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime");
    match role.as_str() {
        "server" => runtime.block_on(run_server(port, config)),
        "client" => runtime.block_on(run_client(port, config)),
        _ => panic!("invalid role"),
    }
}

async fn run_server(port: u16, config: Config) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    println!("HYPER_WEBSOCKET_H2_BENCH_PORT={port}");
    io::stdout().flush().unwrap();
    let (stream, _) = listener.accept().await.expect("accept");
    stream.set_nodelay(true).unwrap();
    let mut builder = server_http2::Builder::new(TokioExecutor);
    builder
        .enable_connect_protocol()
        .initial_stream_window_size(1024 * 1024)
        .initial_connection_window_size(8 * 1024 * 1024)
        .adaptive_window(false)
        .max_frame_size(16 * 1024);
    let service_config = config;
    builder
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| handle_server(request, service_config)),
        )
        .await
        .expect("serve benchmark connection");
}

async fn handle_server(
    mut request: Request<hyper::body::Incoming>,
    config: Config,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.version(), Version::HTTP_2);
    assert_eq!(request.uri().path(), PATH);
    assert_eq!(request.headers()["origin"], ORIGIN);
    assert_eq!(request.headers()["sec-websocket-version"], "13");
    assert_eq!(request.headers()["sec-websocket-protocol"], PROTOCOL);
    assert_eq!(
        request
            .extensions()
            .get::<hyper::ext::Protocol>()
            .unwrap()
            .as_str(),
        "websocket"
    );
    validate_config_headers(request.headers(), config);
    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let upgraded = timeout(config.timeout, on_upgrade)
            .await
            .expect("upgrade timeout")
            .expect("upgrade");
        let mut stream = TokioIo::new(upgraded);
        run_echo_server(&mut stream, config, true).await;
    });
    let mut response = Response::new(Empty::new());
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("sec-websocket-protocol", PROTOCOL.parse().unwrap());
    Ok(response)
}

async fn run_client(port: u16, config: Config) {
    let stream = timeout(config.timeout, TcpStream::connect(("127.0.0.1", port)))
        .await
        .expect("connect timeout")
        .expect("connect");
    stream.set_nodelay(true).unwrap();
    let mut builder = client_http2::Builder::new(TokioExecutor);
    builder
        .timer(TokioTimer)
        .initial_stream_window_size(1024 * 1024)
        .initial_connection_window_size(8 * 1024 * 1024)
        .adaptive_window(false)
        .max_frame_size(16 * 1024);
    let (mut sender, connection) = builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await
        .expect("H2 handshake");
    let driver = tokio::spawn(async move { connection.await });
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(format!("http://localhost{PATH}"))
        .header("origin", ORIGIN)
        .header("sec-websocket-version", "13")
        .header("sec-websocket-protocol", PROTOCOL)
        .header("x-netz-bench-warmup", config.warmup)
        .header("x-netz-bench-iterations", config.iterations)
        .header("x-netz-bench-payload-bytes", config.payload_bytes)
        .header(
            "x-netz-bench-timeout-ms",
            config.timeout.as_millis().to_string(),
        )
        .body(Empty::<Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let response = timeout(config.timeout, sender.send_request(request))
        .await
        .expect("CONNECT timeout")
        .expect("CONNECT");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["sec-websocket-protocol"], PROTOCOL);
    let upgraded = timeout(config.timeout, hyper::upgrade::on(response))
        .await
        .expect("upgrade timeout")
        .expect("upgrade");
    let mut websocket = TokioIo::new(upgraded);
    let mut ready_storage = vec![0u8; READY.len()];
    let ready = read_frame_into(&mut websocket, false, &mut ready_storage).await;
    assert_eq!(ready.opcode, 2);
    assert_eq!(ready.payload, READY);
    print_config("hyper-client+netz-server", config);
    let (elapsed, checksum) = run_echo_client(&mut websocket, config, true).await;
    print_result("hyper-client+netz-server", config, elapsed, checksum);
    drop(sender);
    timeout(config.timeout, driver)
        .await
        .expect("driver timeout")
        .expect("driver join")
        .ok();
}

async fn run_echo_server(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    config: Config,
    expect_masked: bool,
) {
    let mut wire = vec![0u8; config.payload_bytes.max(READY.len())];
    timeout(
        config.timeout,
        write_frame_into(stream, 2, READY, false, &mut wire),
    )
    .await
    .expect("ready write timeout");
    let mut checksum = 0u64;
    let mut payload = vec![0u8; config.payload_bytes];
    for round in 0..config.rounds() {
        let frame = timeout(
            config.timeout,
            read_frame_into(stream, expect_masked, &mut payload),
        )
        .await
        .expect("read timeout");
        assert_eq!(frame.opcode, 2);
        assert!(frame.fin);
        assert_eq!(frame.payload.len(), config.payload_bytes);
        let value = verify_payload(&frame.payload, round);
        if round >= config.warmup {
            checksum = checksum.wrapping_add(value);
        }
        timeout(
            config.timeout,
            write_frame_into(stream, 2, frame.payload, false, &mut wire),
        )
        .await
        .expect("echo write timeout");
    }
    let mut close_storage = [0u8; 125];
    let close = timeout(
        config.timeout,
        read_frame_into(stream, expect_masked, &mut close_storage),
    )
    .await
    .expect("close timeout");
    assert_eq!(close.opcode, 8);
    assert_eq!(close.payload, [0x03, 0xe8, b'd', b'o', b'n', b'e']);
    timeout(
        config.timeout,
        write_frame_into(stream, 8, close.payload, false, &mut wire),
    )
    .await
    .expect("close write timeout");
    stream.shutdown().await.expect("shutdown");
    println!("protocol=websocket-h2 role_pair=netz-client+hyper-server server_complete=true received_bytes={} checksum={}", u64::from(config.iterations) * config.payload_bytes as u64, checksum);
}

async fn run_echo_client(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    config: Config,
    masked: bool,
) -> (Duration, u64) {
    let mut payload = vec![0u8; config.payload_bytes];
    let mut response = vec![0u8; config.payload_bytes];
    let mut wire = vec![0u8; config.payload_bytes];
    let mut checksum = 0u64;
    for round in 0..config.warmup {
        echo_round(
            stream,
            config,
            round,
            &mut payload,
            &mut response,
            &mut wire,
            masked,
        )
        .await;
    }
    let started = Instant::now();
    for sample in 0..config.iterations {
        let round = config.warmup + sample;
        checksum = checksum.wrapping_add(
            echo_round(
                stream,
                config,
                round,
                &mut payload,
                &mut response,
                &mut wire,
                masked,
            )
            .await,
        );
    }
    let elapsed = started.elapsed();
    write_frame_into(
        stream,
        8,
        &[0x03, 0xe8, b'd', b'o', b'n', b'e'],
        masked,
        &mut wire,
    )
    .await;
    let mut close_storage = [0u8; 125];
    let close = timeout(
        config.timeout,
        read_frame_into(stream, false, &mut close_storage),
    )
    .await
    .expect("close response timeout");
    assert_eq!(close.opcode, 8);
    assert_eq!(close.payload, [0x03, 0xe8, b'd', b'o', b'n', b'e']);
    (elapsed, checksum)
}

async fn echo_round(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    config: Config,
    round: u32,
    payload: &mut [u8],
    response: &mut [u8],
    wire: &mut [u8],
    masked: bool,
) -> u64 {
    let expected = fill_payload(payload, round);
    timeout(
        config.timeout,
        write_frame_into(stream, 2, payload, masked, wire),
    )
    .await
    .expect("write timeout");
    let echo = timeout(config.timeout, read_frame_into(stream, false, response))
        .await
        .expect("read timeout");
    assert_eq!(echo.opcode, 2);
    assert!(echo.fin);
    assert_eq!(verify_payload(&echo.payload, round), expected);
    expected
}

struct Frame<'a> {
    fin: bool,
    opcode: u8,
    payload: &'a [u8],
}
async fn read_frame_into<'a>(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    expect_masked: bool,
    storage: &'a mut [u8],
) -> Frame<'a> {
    let mut fixed = [0u8; 2];
    stream.read_exact(&mut fixed).await.unwrap();
    let fin = fixed[0] & 0x80 != 0;
    assert_eq!(fixed[0] & 0x70, 0);
    let opcode = fixed[0] & 0x0f;
    let masked = fixed[1] & 0x80 != 0;
    assert_eq!(masked, expect_masked);
    let code = fixed[1] & 0x7f;
    let length = match code {
        0..=125 => usize::from(code),
        126 => {
            let mut b = [0; 2];
            stream.read_exact(&mut b).await.unwrap();
            let n = usize::from(u16::from_be_bytes(b));
            assert!(n > 125);
            n
        }
        _ => {
            let mut b = [0; 8];
            stream.read_exact(&mut b).await.unwrap();
            let n = u64::from_be_bytes(b);
            assert!(n > 65535 && n <= usize::MAX as u64);
            n as usize
        }
    };
    assert!(length <= storage.len());
    let mut mask = [0; 4];
    if masked {
        stream.read_exact(&mut mask).await.unwrap();
    }
    let payload = &mut storage[..length];
    stream.read_exact(payload).await.unwrap();
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Frame {
        fin,
        opcode,
        payload,
    }
}
async fn write_frame_into(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    opcode: u8,
    payload: &[u8],
    masked: bool,
    wire: &mut [u8],
) {
    assert!(payload.len() <= 4096 || opcode == 8);
    let mut header = [0u8; 14];
    header[0] = 0x80 | opcode;
    let mask_bit = if masked { 0x80 } else { 0 };
    let mut header_len = 2;
    if payload.len() <= 125 {
        header[1] = mask_bit | payload.len() as u8;
    } else if payload.len() <= 65535 {
        header[1] = mask_bit | 126;
        header[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        header_len = 4;
    } else {
        header[1] = mask_bit | 127;
        header[2..10].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        header_len = 10;
    }
    if masked {
        assert!(wire.len() >= payload.len());
        let mut mask = [0; 4];
        getrandom::getrandom(&mut mask).unwrap();
        header[header_len..header_len + 4].copy_from_slice(&mask);
        header_len += 4;
        for (i, b) in payload.iter().enumerate() {
            wire[i] = *b ^ mask[i % 4];
        }
    }
    stream.write_all(&header[..header_len]).await.unwrap();
    stream
        .write_all(if masked {
            &wire[..payload.len()]
        } else {
            payload
        })
        .await
        .unwrap();
    stream.flush().await.unwrap();
}

fn set_header_expected(headers: &hyper::HeaderMap, name: &str, expected: impl ToString) {
    assert_eq!(
        headers.get(name).unwrap().to_str().unwrap(),
        expected.to_string()
    );
}
fn validate_config_headers(headers: &hyper::HeaderMap, config: Config) {
    set_header_expected(headers, "x-netz-bench-warmup", config.warmup);
    set_header_expected(headers, "x-netz-bench-iterations", config.iterations);
    set_header_expected(headers, "x-netz-bench-payload-bytes", config.payload_bytes);
    set_header_expected(
        headers,
        "x-netz-bench-timeout-ms",
        config.timeout.as_millis(),
    );
}
fn payload_byte(round: u32, offset: usize) -> u8 {
    (offset.wrapping_mul(131).wrapping_add(round as usize * 17)) as u8
}
fn fill_payload(payload: &mut [u8], round: u32) -> u64 {
    let mut c = 0;
    for (i, b) in payload.iter_mut().enumerate() {
        *b = payload_byte(round, i);
        c += u64::from(*b);
    }
    c
}
fn verify_payload(payload: &[u8], round: u32) -> u64 {
    let mut c = 0;
    for (i, b) in payload.iter().enumerate() {
        assert_eq!(*b, payload_byte(round, i));
        c += u64::from(*b);
    }
    c
}
fn print_config(role: &str, c: Config) {
    println!("protocol=websocket-h2 transport=h2c mode=binary-echo role_pair={role} connection_scope=persistent benchmark_scope=same-application-shape warmup={} iterations={} payload_bytes={} stream_window=1048576 connection_window=8388608 max_frame_size=16384 tcp_nodelay=true compression=false",c.warmup,c.iterations,c.payload_bytes);
}
fn print_result(role: &str, c: Config, e: Duration, checksum: u64) {
    let r = c.iterations as f64 / e.as_secs_f64();
    println!("protocol=websocket-h2 transport=h2c mode=binary-echo role_pair={role} connection_scope=persistent benchmark_scope=same-application-shape elapsed_ns={} ns_per_roundtrip={:.3} roundtrips_per_s={:.3} logical_MiB_s={:.3} sent_bytes={} received_bytes={} checksum={} complete=true",e.as_nanos(),e.as_nanos() as f64/c.iterations as f64,r,r*c.payload_bytes as f64*2.0/(1024.0*1024.0),u64::from(c.iterations)*c.payload_bytes as u64,u64::from(c.iterations)*c.payload_bytes as u64,checksum);
}
