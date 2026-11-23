//! WebTransport over HTTP/2 (draft-15 capsules) against a local TLS/h2 origin.
//!
//! Browsers ship WebTransport over HTTP/3, but the HTTP/2 capsule form covers
//! non-browser proxy and server-to-server legs. The client sends one virtual
//! stream from slices, the server echoes it, and both sides drain and close
//! the session with explicit budgets.

const std = @import("std");
const netz = @import("netz");

fn nextEvent(
    session: *netz.webtransport.h2.runtime.Session,
) !netz.webtransport.h2.state.Event {
    while (true) {
        const event = try session.receiveWithTimeout(.fromSeconds(5));
        if (event != .progress) return event;
    }
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const key = try netz.tls.testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    var certificate: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        netz.tls.testing.certificate_base64,
    );
    const identity: @FieldType(
        netz.http2.runtime.TlsListenOptions,
        "identity",
    ) = .{
        .certificate_chain = &.{&certificate},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
    };
    const credit: netz.http2.WebTransportSettings = .{
        .enabled = true,
        .max_data = 8192,
        .max_stream_data_uni = 2048,
        .max_stream_data_bidi_local = 2048,
        .max_stream_data_bidi_remote = 2048,
        .max_streams_uni = 8,
        .max_streams_bidi = 8,
    };

    var server = try netz.http2.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = identity,
            .protocol_policy = .tls13_only,
            .limits = .{
                .enable_connect_protocol = true,
                .webtransport = credit,
            },
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http2.runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(
                .fromSeconds(5),
            );
            defer connection.close();
            var pending = try netz.webtransport.h2.runtime
                .readRequestWithTimeout(&connection, .fromSeconds(5));
            defer pending.deinit(self.server.allocator);
            var session = try netz.webtransport.h2.runtime.acceptWithTimeout(
                self.server.allocator,
                &connection,
                pending,
                .{ .protocols = .{ .values = &.{"echo"}, .required = true } },
                .fromSeconds(5),
            );
            defer session.deinit();
            const event = try nextEvent(&session);
            if (event != .stream) return error.UnexpectedEvent;
            try session.sendStreamSlicesWithTimeout(
                event.stream.id,
                &.{ "echo: ", event.stream.data },
                true,
                .fromSeconds(5),
            );
            try session.consume(event.stream.id, event.stream.data.len);
            try session.retireStream(event.stream.id);
            try session.drainWithTimeout(.fromSeconds(5));
            try session.closeWithTimeout(0, "done", .fromSeconds(5));
            _ = nextEvent(&session) catch {};
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    var connection = try netz.http2.runtime.Client.connectTlsAddressWithTimeout(
        allocator,
        io,
        server.address(),
        "localhost",
        "localhost",
        .{ .enable_connect_protocol = true, .webtransport = credit },
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .protocol_policy = .tls13_only,
        },
        .fromSeconds(5),
    );
    defer connection.close();
    var session = try netz.webtransport.h2.runtime.connectWithTimeout(
        allocator,
        &connection,
        .{
            .path = "/echo",
            .authority = "localhost",
            .protocols = .{ .values = &.{"echo"}, .required = true },
        },
        .fromSeconds(5),
    );
    defer session.deinit();

    const stream_id = try session.openStream(.bidirectional);
    try session.sendStreamSlicesWithTimeout(
        stream_id,
        &.{ "hello ", "h2" },
        true,
        .fromSeconds(5),
    );
    const event = try nextEvent(&session);
    if (event != .stream) return error.UnexpectedEvent;
    std.debug.print("WebTransport H2 echo: {s}\n", .{event.stream.data});
    try session.consume(stream_id, event.stream.data.len);
    try session.retireStream(stream_id);
    try session.drainWithTimeout(.fromSeconds(5));
    try session.closeWithTimeout(0, "bye", .fromSeconds(5));
    _ = nextEvent(&session) catch {};

    server_task.await(io);
    if (task.err) |err| return err;
}
