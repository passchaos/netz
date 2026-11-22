//! WSS echo with a pinned server key.
//!
//! Mirrors a browser/tungstenite `wss://` client: the TLS listener uses the
//! test identity, and the vail-backed WSS client trusts exactly that ECDSA
//! P-256 public key instead of the system roots.

const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );

    var server = try netz.websocket.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.websocket.runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(self.server.allocator);
            try connection.sendText(message.payload);
            var close = try connection.receiveFrame();
            defer close.deinit(self.server.allocator);
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://127.0.0.1:{d}/chat",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.websocket.runtime.Client.connectUri(allocator, io, uri, .{
        .vail_tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();

    try client.sendText("hello over WSS");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    std.debug.print("WSS echo: {s}\n", .{response.payload});
    try client.sendClose(.normal_closure, "bye");

    server_task.await(io);
    if (task.err) |err| return err;
}
