//! Autobahn Testsuite fuzzingserver testee for the netz WebSocket client.
//!
//! The Autobahn fuzzing server exposes `/getCaseCount`, one `/runCase` URL per
//! case, and `/updateReports`. Each case uses a fresh WebSocket connection;
//! this testee echoes every complete text or binary message and lets the
//! runtime's typed close/protocol-error handling end the connection.

const std = @import("std");
const netz = @import("netz");

const max_message_bytes: usize = 20_000_000;
const connect_attempts: usize = 100;
const agent = "netz";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3) return error.InvalidArgument;
    const base = args[1];
    if (!std.mem.startsWith(u8, base, "ws://") and
        !std.mem.startsWith(u8, base, "wss://"))
    {
        return error.InvalidArgument;
    }
    const requested_agent = if (args.len == 3) args[2] else agent;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const case_count = try fetchCaseCount(allocator, io, base);
    std.debug.print("Autobahn client testee: cases={d} agent={s}\n", .{ case_count, requested_agent });

    for (1..case_count + 1) |case_id| {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}/runCase?case={d}&agent={s}",
            .{ base, case_id, requested_agent },
        );
        defer allocator.free(uri);
        runCase(allocator, io, uri) catch |err| {
            std.debug.print("case {d} ended with {s}\n", .{ case_id, @errorName(err) });
        };
    }

    const update_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/updateReports?agent={s}",
        .{ base, requested_agent },
    );
    defer allocator.free(update_uri);
    var connection = try connectWithRetry(allocator, io, update_uri);
    connection.close();
    std.debug.print("Autobahn client testee complete\n", .{});
}

fn fetchCaseCount(
    allocator: std.mem.Allocator,
    io: std.Io,
    base: []const u8,
) !usize {
    const uri = try std.fmt.allocPrint(allocator, "{s}/getCaseCount", .{base});
    defer allocator.free(uri);
    var connection = try connectWithRetry(allocator, io, uri);
    defer connection.close();
    var message = try connection.receiveMessage();
    defer message.deinit(allocator);
    if (message.opcode != .text) return error.InvalidMessage;
    return std.fmt.parseInt(usize, std.mem.trim(u8, message.payload, " \r\n\t"), 10);
}

fn connectWithRetry(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
) !netz.websocket.runtime.Connection {
    var attempt: usize = 0;
    while (attempt < connect_attempts) : (attempt += 1) {
        return netz.websocket.runtime.Client.connectUri(
            allocator,
            io,
            uri,
            .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .client_max_window_bits = 15,
                .server_max_window_bits = 15,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = max_message_bytes,
                    .max_message_bytes = max_message_bytes,
                },
            },
        ) catch |err| {
            if (attempt + 1 == connect_attempts) return err;
            std.Io.sleep(io, .fromMilliseconds(10), .awake) catch {};
            continue;
        };
    }
    return error.ConnectionRefused;
}

fn runCase(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
) !void {
    var connection = try connectWithRetry(allocator, io, uri);
    defer connection.close();
    while (true) {
        var message = connection.receiveMessage() catch |err| switch (err) {
            error.ConnectionClosed => return,
            else => return err,
        };
        defer message.deinit(allocator);
        switch (message.opcode) {
            .text => try connection.sendText(message.payload),
            .binary => try connection.sendBinary(message.payload),
            else => {},
        }
    }
}
