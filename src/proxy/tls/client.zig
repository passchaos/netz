//! Minimal blocking TLS 1.3 client stream backed by Vail.
//!
//! This adapter is used by protocol tests and by client-side transports that
//! need a verified TLS byte stream without a higher-level runtime dependency.

const std = @import("std");
const vail = @import("vail");

const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;
const record = vail.tls.record;

const max_handshake_message_len: usize = 64 * 1024;
const max_post_handshake_len: usize = 64 * 1024;

const ClientHandshake = vail.tls.client_connection.ClientConnection(
    max_handshake_message_len,
    max_post_handshake_len,
);

pub const Config = struct {
    server_name: ?[]const u8 = null,
    server_verifier: vail.tls.auth.ClientVerifier,
    alpn_protocols: []const []const u8 = &.{},
    record_size_limit: ?u16 = null,
    handshake_timeout: ?std.Io.Duration = null,
    idle_timeout: ?std.Io.Duration = null,
    read_buffer_size: usize = 16 * 1024,
};

pub const Error = error{
    TruncatedHandshake,
    PeerAbortedHandshake,
    TlsAlert,
    TlsStalled,
    PendingBufferTooSmall,
    BufferTooSmall,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    established: ClientHandshake.Established,
    raw: []u8,
    raw_start: usize,
    raw_end: usize,
    pending: []u8,
    pending_start: usize,
    pending_end: usize,
    wire: []u8,
    idle_timeout: ?std.Io.Duration,
    read_mutex: std.Io.Mutex = .init,
    write_mutex: std.Io.Mutex = .init,
    closed: std.atomic.Value(bool) = .init(false),

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        config: Config,
    ) !Connection {
        if (config.read_buffer_size == 0) return error.BufferTooSmall;

        var key_material: vail.tls.key_exchange.ClientKeyMaterial = .{
            .x25519 = undefined,
        };
        io.random(&key_material.x25519);
        var random: [32]u8 = undefined;
        io.random(&random);

        var hello: std.ArrayList(u8) = .empty;
        defer hello.deinit(allocator);
        var handshake = try ClientHandshake.init(.{
            .allocator = allocator,
            .random = random,
            .server_name = config.server_name,
            .key_material = &key_material,
            .alpn_protocols = config.alpn_protocols,
            .record_size_limit = config.record_size_limit,
            .server_verifier = config.server_verifier,
        }, &hello);
        defer handshake.deinit();

        const handshake_deadline = try io_helpers.deadlineFromTimeout(
            io,
            config.handshake_timeout,
        );
        try io_helpers.writeAll(
            io,
            stream,
            hello.items,
            handshake_deadline,
        );
        hello.clearRetainingCapacity();

        const raw = try allocator.alloc(u8, config.read_buffer_size);
        errdefer allocator.free(raw);
        const pending = try allocator.alloc(u8, record.max_plaintext_len);
        errdefer allocator.free(pending);
        const wire = try allocator.alloc(u8, record.max_record_len);
        errdefer allocator.free(wire);

        var raw_start: usize = 0;
        var raw_end: usize = 0;
        var established: ClientHandshake.Established = undefined;
        var is_established = false;
        while (!is_established) {
            if (raw_start == raw_end) {
                raw_start = 0;
                raw_end = try io_helpers.readSome(
                    io,
                    stream,
                    raw,
                    handshake_deadline,
                );
                if (raw_end == 0) return error.TruncatedHandshake;
            }

            const result = try handshake.receiveInto(
                raw[raw_start..raw_end],
                &hello,
                &established,
            );
            raw_start += result.consumed;
            if (hello.items.len != 0) {
                try io_helpers.writeAll(
                    io,
                    stream,
                    hello.items,
                    handshake_deadline,
                );
                hello.clearRetainingCapacity();
            }
            if (result.event) |event| switch (event) {
                .server_hello,
                .hello_retry_request,
                .compatibility_change_cipher_spec,
                => {},
                .established => is_established = true,
                .peer_alert => return error.PeerAbortedHandshake,
                .ech_rejected => return error.PeerAbortedHandshake,
            };
            if (result.consumed == 0 and result.event == null) {
                return error.TlsStalled;
            }
        }

        return .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .established = established,
            .raw = raw,
            .raw_start = raw_start,
            .raw_end = raw_end,
            .pending = pending,
            .pending_start = 0,
            .pending_end = 0,
            .wire = wire,
            .idle_timeout = config.idle_timeout,
        };
    }

    pub fn deinit(self: *Connection) void {
        if (!self.closed.load(.acquire)) {
            if (self.established.application.sealCloseNotify(self.wire)) |len| {
                io_helpers.writeAll(
                    self.io,
                    self.stream,
                    self.wire[0..len],
                    null,
                ) catch {};
            } else |_| {}
        }
        self.established.deinit();
        self.stream.close(self.io);
        self.allocator.free(self.raw);
        self.allocator.free(self.pending);
        self.allocator.free(self.wire);
        self.* = undefined;
    }

    pub fn read(self: *Connection, output: []u8) !usize {
        self.read_mutex.lockUncancelable(self.io);
        defer self.read_mutex.unlock(self.io);
        if (self.pending_start < self.pending_end) {
            const available = self.pending_end - self.pending_start;
            const take = @min(available, output.len);
            @memcpy(output[0..take], self.pending[self.pending_start..][0..take]);
            self.pending_start += take;
            return take;
        }
        if (self.closed.load(.acquire)) return 0;

        while (true) {
            if (self.raw_start == self.raw_end) {
                self.raw_start = 0;
                self.raw_end = try io_helpers.readSome(
                    self.io,
                    self.stream,
                    self.raw,
                    currentDeadline(self.io, self.idle_timeout),
                );
                if (self.raw_end == 0) {
                    self.closed.store(true, .release);
                    return 0;
                }
            }

            const result = try self.established.application.receive(
                self.raw[self.raw_start..self.raw_end],
            );
            self.raw_start += result.consumed;
            if (result.event) |event| switch (event) {
                .application_data => |bytes| {
                    const take = @min(bytes.len, output.len);
                    @memcpy(output[0..take], bytes[0..take]);
                    if (bytes.len > take) {
                        const remainder = bytes.len - take;
                        if (remainder > self.pending.len) {
                            return error.PendingBufferTooSmall;
                        }
                        @memcpy(
                            self.pending[0..remainder],
                            bytes[take..],
                        );
                        self.pending_start = 0;
                        self.pending_end = remainder;
                    }
                    return take;
                },
                .alert => |alert| {
                    if (alert.isCloseNotify()) {
                        self.closed.store(true, .release);
                        return 0;
                    }
                    return error.TlsAlert;
                },
                .key_update => {
                    const len = try self.established.application.sealKeyUpdateResponse(
                        self.wire,
                    );
                    try io_helpers.writeAll(
                        self.io,
                        self.stream,
                        self.wire[0..len],
                        currentDeadline(self.io, self.idle_timeout),
                    );
                },
                .post_handshake => {},
            };
            if (result.consumed == 0 and result.event == null) {
                return error.TlsStalled;
            }
        }
    }

    pub fn writeAll(self: *Connection, bytes: []const u8) !void {
        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);
        if (self.closed.load(.acquire)) return error.TlsAlert;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const take = @min(
                bytes.len - offset,
                record.max_plaintext_len,
            );
            const len = try self.established.application.sealApplicationData(
                bytes[offset..][0..take],
                self.wire,
            );
            try io_helpers.writeAll(
                self.io,
                self.stream,
                self.wire[0..len],
                currentDeadline(self.io, self.idle_timeout),
            );
            offset += take;
        }
    }
};

fn currentDeadline(
    io: std.Io,
    timeout: ?std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, timeout) catch null;
}
