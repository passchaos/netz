//! Map a public hostname to a local origin with a custom address resolver.
//!
//! Mirrors `curl --resolve api.example.test:443:127.0.0.1`: the client still
//! uses `api.example.test` for the request authority and TLS SNI, while the
//! resolver returns the loopback address of the local TLS listener.

const std = @import("std");
const netz = @import("netz");

const LocalResolver = struct {
    port: u16,

    fn resolve(
        context: *anyopaque,
        resolve_allocator: std.mem.Allocator,
        _: std.Io,
        host: []const u8,
        port: u16,
        _: ?std.Io.Clock.Timestamp,
    ) netz.http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, host, "api.example.test") or port != self.port) {
            return error.UnknownHostName;
        }
        const addresses = try resolve_allocator.alloc(std.Io.net.IpAddress, 1);
        addresses[0] = .{ .ip4 = .loopback(self.port) };
        return addresses;
    }
};

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

    var server = try netz.http1.runtime.TlsServer.listen(
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
            .limits = .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = .fromSeconds(5),
            .alpn_protocols = &.{"http/1.1"},
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            const host = request.request.header("host") orelse
                return error.MissingHost;
            var expected_storage: [64]u8 = undefined;
            const expected = try std.fmt.bufPrint(
                &expected_storage,
                "api.example.test:{d}",
                .{self.server.address().ip4.port},
            );
            if (!std.mem.eql(u8, expected, host)) return error.UnexpectedHost;
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello from api.example.test",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const port = server.address().ip4.port;
    var resolver = LocalResolver{ .port = port };
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://api.example.test:{d}/resolve",
        .{port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
        .address_resolver = .{
            .context = &resolver,
            .resolve = LocalResolver.resolve,
        },
        .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("custom resolver {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
