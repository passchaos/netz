//! Finish a successful one-shot RPC before dropping its TCP/TLS connection.
const netz = @import("netz");

pub fn finish(connection: *netz.http2.runtime.Connection) !void {
    // The PING barrier and GOAWAY drain pending WINDOW_UPDATE/PING traffic.
    // Closing immediately with unread control bytes can reset TCP while the
    // client is still receiving the response already accepted by netWrite.
    connection.gracefulShutdownWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
        error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => {},
        else => return err,
    };
}
