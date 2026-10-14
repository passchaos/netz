//! Unified H1/H2 ALPN client against the independent Hyper/rustls fixture.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const expected: netz.http.Protocol = if (std.mem.eql(u8, args[2], "h1"))
        .http1
    else if (std.mem.eql(u8, args[2], "h2"))
        .http2
    else
        return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var pool = try netz.http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/one",
        .{port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/two",
        .{port},
    );
    defer allocator.free(second_uri);
    const label = if (expected == .http2) "h2" else "h1";
    var first = try pool.requestUriWithTimeout(
        first_uri,
        .{ .headers = &.{.{
            .name = "x-netz-unified",
            .value = label,
        }} },
        .fromSeconds(5),
    );
    defer first.deinit();
    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{ .headers = &.{.{
            .name = "x-netz-unified",
            .value = label,
        }} },
        .fromSeconds(5),
    );
    defer second.deinit();
    var first_expected: [4]u8 = undefined;
    var second_expected: [4]u8 = undefined;
    const first_body = try std.fmt.bufPrint(&first_expected, "{s}-1", .{label});
    const second_body = try std.fmt.bufPrint(&second_expected, "{s}-2", .{label});
    if (!std.mem.eql(u8, first.body(), first_body) or
        !std.mem.eql(u8, second.body(), second_body))
    {
        return error.InvalidResponse;
    }
    if (first.protocol() != expected or second.protocol() != expected) {
        return error.InvalidProtocol;
    }
    const stats = pool.stats();
    if (pool.connectionCount() != 1 or pool.idleCount() != 1 or
        stats.total_reused != 1 or stats.total_misses != 1)
    {
        return error.InvalidPoolState;
    }
    std.debug.print(
        "netz unified HTTP pool selected Hyper protocol={s} alpn={s} requests=2 connections=1 reusable=true client_io=zio-std-io server_io=hyper-tokio\n",
        .{ label, if (expected == .http2) "h2" else "http/1.1" },
    );
}
