//! Raw independent HTTP/2 peer for gRPC keepalive throttling propagation.
use std::env;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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
    runtime.block_on(run(port));
}

async fn run(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind throttle server");
    println!("Rust HTTP/2 throttle server listening on 127.0.0.1:{port}");
    io::stdout().flush().expect("flush readiness");

    let (mut first, _) = listener.accept().await.expect("accept first channel");
    handshake(&mut first).await;
    write_frame(
        &mut first,
        0x7,
        0,
        0,
        &[
            &0u32.to_be_bytes()[..],
            &0xbu32.to_be_bytes()[..],
            b"too_many_pings",
        ]
        .concat(),
    )
    .await;
    drop(first);

    let (mut second, _) = listener.accept().await.expect("accept replacement channel");
    handshake(&mut second).await;
    let connected = Instant::now();
    let ping = loop {
        let (kind, flags, stream_id, payload) = read_frame(&mut second).await;
        if kind == 0x6 && flags & 0x1 == 0 {
            assert_eq!(stream_id, 0);
            assert_eq!(payload.len(), 8);
            break payload;
        }
    };
    let elapsed = connected.elapsed();
    assert!(
        elapsed >= Duration::from_millis(150),
        "replacement PING was not throttled: {elapsed:?}"
    );
    write_frame(&mut second, 0x6, 0x1, 0, &ping).await;
    println!(
        "Rust HTTP/2 server observed netz gRPC keepalive throttle: configured_ms=100 effective_ms=200 observed_ms={} exact_ack=true client_io=zio-std-io server_io=rust-tokio",
        elapsed.as_millis()
    );
}

async fn handshake(stream: &mut TcpStream) {
    stream.set_nodelay(true).expect("TCP_NODELAY");
    let mut preface = [0u8; PREFACE.len()];
    stream.read_exact(&mut preface).await.expect("read preface");
    assert_eq!(&preface, PREFACE);
    let (kind, flags, stream_id, _) = read_frame(stream).await;
    assert_eq!((kind, flags, stream_id), (0x4, 0, 0));
    write_frame(stream, 0x4, 0, 0, &[]).await;
    write_frame(stream, 0x4, 0x1, 0, &[]).await;
    loop {
        let (kind, flags, stream_id, _) = read_frame(stream).await;
        if kind == 0x4 && flags & 0x1 != 0 {
            assert_eq!(stream_id, 0);
            break;
        }
    }
}

async fn read_frame(stream: &mut TcpStream) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0u8; 9];
    stream
        .read_exact(&mut header)
        .await
        .expect("read frame header");
    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    assert!(len <= 64 * 1024, "unexpected frame length {len}");
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .expect("read frame payload");
    let stream_id = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
    (header[3], header[4], stream_id, payload)
}

async fn write_frame(stream: &mut TcpStream, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    assert!(payload.len() <= 0x00ff_ffff);
    let len = payload.len();
    let mut header = [0u8; 9];
    header[0] = (len >> 16) as u8;
    header[1] = (len >> 8) as u8;
    header[2] = len as u8;
    header[3] = kind;
    header[4] = flags;
    header[5..9].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    stream.write_all(&header).await.expect("write frame header");
    stream
        .write_all(payload)
        .await
        .expect("write frame payload");
    stream.flush().await.expect("flush frame");
}
