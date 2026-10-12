//! Two-connection TLS 1.2/1.3 client used by the OpenSSL ticket gates.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }
    const tls13 = args.len == 4 and std.mem.eql(u8, args[3], "tls13");
    if (args.len == 4 and !tls13) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[2],
    );
    var ca_lock: std.Io.RwLock = .init;

    if (tls13) {
        return runTls13(allocator, io, port, &ca_bundle, &ca_lock);
    }
    return runTls12(allocator, io, port, &ca_bundle, &ca_lock);
}

fn runTls12(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
) !void {
    var ticket: ?netz.tls.stream.Tls12SessionTicket = null;
    defer if (ticket) |*cached| cached.deinit();
    for (0..2) |index| {
        var client = netz.http1.runtime.Client.connectVailTlsAddress(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            "localhost",
            .{ .response_head_timeout = .fromSeconds(5) },
            .{
                .ca_bundle = .{ .bundle = ca_bundle, .lock = ca_lock },
                .alpn_protocols = &.{"http/1.1"},
                .tls12_cipher_suites = &.{
                    .ecdhe_ecdsa_aes_128_gcm_sha256,
                },
                .protocol_policy = .tls12_only,
                .tls12_ticket_resumption = if (index == 0)
                    null
                else
                    &ticket.?,
            },
        ) catch |err| {
            std.debug.print(
                "netz TLS 1.2 connection {d} failed: {s}\n",
                .{ index + 1, @errorName(err) },
            );
            return err;
        };
        defer client.close();
        if (client.negotiatedTlsProtocol() != .tls12 or
            client.wasTlsSessionResumed() != (index == 1))
        {
            return error.InvalidSessionResumption;
        }
        var response = try client.request(.{
            .method = .GET,
            .target = "/",
            .host = "localhost",
        });
        defer response.deinit(allocator);
        if (response.response.status != 200) return error.InvalidResponse;
        if (client.takeTls12SessionTicket()) |renewed| {
            if (ticket) |*cached| cached.deinit();
            ticket = renewed;
        }
        if (ticket == null) return error.MissingSessionTicket;
        std.debug.print(
            "netz connected to OpenSSL TLS 1.2 server resumed={} status=200\n",
            .{client.wasTlsSessionResumed().?},
        );
    }
}

fn runTls13(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
) !void {
    var ticket: ?netz.tls.stream.Tls13SessionTicket = null;
    defer if (ticket) |*cached| cached.deinit();
    for (0..2) |index| {
        var client = netz.http1.runtime.Client.connectVailTlsAddress(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            "localhost",
            .{ .response_head_timeout = .fromSeconds(5) },
            .{
                .ca_bundle = .{ .bundle = ca_bundle, .lock = ca_lock },
                .alpn_protocols = &.{"http/1.1"},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .protocol_policy = .tls13_only,
                .tls13_ticket_resumption = if (index == 0)
                    null
                else
                    &ticket.?,
            },
        ) catch |err| {
            std.debug.print(
                "netz TLS 1.3 connection {d} failed: {s}\n",
                .{ index + 1, @errorName(err) },
            );
            return err;
        };
        defer client.close();
        if (client.negotiatedTlsProtocol() != .tls13 or
            client.wasTlsSessionResumed() != (index == 1))
        {
            return error.InvalidSessionResumption;
        }
        var response = try client.request(.{
            .method = .GET,
            .target = "/",
            .host = "localhost",
        });
        defer response.deinit(allocator);
        if (response.response.status != 200) return error.InvalidResponse;
        if (try client.takeTls13SessionTicket()) |renewed| {
            if (ticket) |*cached| cached.deinit();
            ticket = renewed;
        }
        if (ticket == null) return error.MissingSessionTicket;
        std.debug.print(
            "netz connected to OpenSSL TLS 1.3 server resumed={} status=200\n",
            .{client.wasTlsSessionResumed().?},
        );
    }
}
