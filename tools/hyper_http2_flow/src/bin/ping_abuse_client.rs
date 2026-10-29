//! Independent Rust h2 peer for gRPC server PING enforcement.
use std::env;
use std::future::poll_fn;

use h2::{client, Ping, Reason};
use tokio::net::TcpStream;

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
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect netz gRPC server");
    stream.set_nodelay(true).expect("TCP_NODELAY");
    let (send, mut connection) = client::handshake(stream)
        .await
        .expect("h2 client handshake");
    let mut ping_pong = connection.ping_pong().expect("PING support");
    let driver = tokio::spawn(async move { connection.await });

    for _ in 0..3 {
        ping_pong.send_ping(Ping::opaque()).expect("submit PING");
        poll_fn(|cx| ping_pong.poll_pong(cx))
            .await
            .expect("first three PINGs are acknowledged");
    }
    ping_pong
        .send_ping(Ping::opaque())
        .expect("submit violating PING");
    let _pong_error = poll_fn(|cx| ping_pong.poll_pong(cx))
        .await
        .expect_err("violating PING must not be acknowledged");
    drop(send);
    let connection_error = driver
        .await
        .expect("join h2 connection")
        .expect_err("GOAWAY terminates h2 connection");
    assert_eq!(connection_error.reason(), Some(Reason::ENHANCE_YOUR_CALM));
    println!(
        "Rust h2 client observed netz gRPC PING enforcement: transport=h2c acknowledged=3 violating_ack=false goaway=ENHANCE_YOUR_CALM client_io=h2-tokio server_io=zio-std-io"
    );
}
