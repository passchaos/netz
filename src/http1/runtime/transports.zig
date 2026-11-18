const std = @import("std");
const net = std.Io.net;
const accept_deadline = @import("../../internal/accept.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const http1 = @import("../mod.zig");
const root_trust = @import("../../trust.zig");
const stream_io = @import("../../internal/stream_io.zig");
const tls_client_reader = @import("tls_client/reader.zig");
const tls_write_retry = @import("../../tls/stream/write_retry.zig");

const runtime = @import("../runtime.zig");
const AsyncServeError = runtime.AsyncServeError;
const CertificateBundle = runtime.CertificateBundle;
const Client = runtime.Client;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const Error = runtime.Error;
const Limits = runtime.Limits;
const ResponseOptions = runtime.ResponseOptions;
const ServeUntilOptions = runtime.ServeUntilOptions;
const TlsClientOptions = runtime.TlsClientOptions;
const TlsListenOptions = runtime.TlsListenOptions;
const mapHttpTimedReadError = runtime.mapHttpTimedReadError;
const readSome = runtime.readSome;
const serveAcceptedConcurrent = runtime.serveAcceptedConcurrent;
const serveAcceptedUntil = runtime.serveAcceptedUntil;
const setTcpNoDelay = runtime.setTcpNoDelay;
const shutdownAfterTlsCloseNotify = runtime.shutdownAfterTlsCloseNotify;
const tls = runtime.tls;
const tls_stream = runtime.tls_stream;
const writeAllToStream = runtime.writeAllToStream;

pub const TlsClientConnection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    net_read_buf: []u8,
    net_write_buf: []u8,
    tls_read_buf: []u8,
    tls_write_buf: []u8,
    net_reader: net.Stream.Reader,
    net_writer: net.Stream.Writer,
    client: tls.Client,
    // Only the thread currently driving this connection mutates the deadline.
    // `std.crypto.tls.Client` calls back into `net_reader` synchronously, so
    // this field scopes one application read without introducing shared timer
    // state or changing ordinary untimed reads.
    timed_read_deadline: ?std.Io.Clock.Timestamp = null,
    // std.Io.Reader erases the cause; net.Stream.Reader cannot represent
    // ConcurrencyUnavailable. Consume this cause once at the public boundary.
    timed_read_error: ?Error = null,
    /// Plaintext represented by the TLS ciphertext currently buffered in
    /// `net_writer` after a bounded application write timed out.
    pending_timed_plaintext_len: usize = 0,
    pending_timed_plaintext_fingerprint: tls_write_retry.Fingerprint = .{},
    write_closed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
    ) Error!*TlsClientConnection {
        const deadline = if (options.handshake_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            break :blk std.Io.Clock.Timestamp.fromNow(io, .{
                .raw = timeout,
                .clock = .awake,
            });
        } else null;
        return initBefore(allocator, io, stream, host, options, deadline);
    }

    /// Complete the standard-library TLS handshake under the earlier of the
    /// caller's absolute deadline and `options.handshake_timeout`.
    pub fn initWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*TlsClientConnection {
        return initBefore(
            allocator,
            io,
            stream,
            host,
            options,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.handshake_timeout,
            ),
        );
    }

    pub fn initWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!*TlsClientConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return initWithDeadline(
            allocator,
            io,
            stream,
            host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn initBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
        handshake_deadline: ?std.Io.Clock.Timestamp,
    ) Error!*TlsClientConnection {
        const net_read_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(net_read_buf);
        const net_write_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(net_write_buf);
        const tls_read_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(tls_read_buf);
        const tls_write_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(tls_write_buf);

        const conn = try allocator.create(TlsClientConnection);
        errdefer allocator.destroy(conn);
        conn.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .net_read_buf = net_read_buf,
            .net_write_buf = net_write_buf,
            .tls_read_buf = tls_read_buf,
            .tls_write_buf = tls_write_buf,
            .net_reader = undefined,
            .net_writer = undefined,
            .client = undefined,
        };
        conn.net_reader = net.Stream.reader(stream, io, conn.net_read_buf);
        conn.net_reader.interface.vtable = &tls_client_reader.vtable;
        conn.net_writer = net.Stream.writer(stream, io, conn.net_write_buf);
        conn.timed_read_deadline = handshake_deadline;
        defer conn.timed_read_deadline = null;

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        try std.Io.randomSecure(io, &entropy);
        const now = std.Io.Timestamp.now(io, .real);

        // Zig's standard TLS client accepts only a certificate bundle, not a
        // platform verification callback. Callers that need OS policy should
        // use the Vail-backed transport.
        if (options.root_source == .platform) {
            return error.PlatformVerifierUnavailable;
        }

        var local_bundle: CertificateBundle = .empty;
        var local_lock: std.Io.RwLock = .init;
        var loaded_local_bundle = false;
        defer if (loaded_local_bundle) local_bundle.deinit(allocator);

        var client_options: tls.Client.Options = .{
            .host = if (options.verify_host) .{ .explicit = host } else .no_verification,
            .ca = .no_verification,
            .write_buffer = conn.tls_write_buf,
            .read_buffer = conn.tls_read_buf,
            .entropy = &entropy,
            .realtime_now = now,
            .allow_truncation_attacks = options.allow_truncation_attacks,
        };
        if (options.verify_host) {
            client_options.ca = if (options.ca_bundle) |ca_bundle|
                .{ .bundle = .{ .gpa = allocator, .io = io, .lock = ca_bundle.lock, .bundle = ca_bundle.bundle } }
            else if (options.root_source == .bundled) blk: {
                local_bundle = root_trust.initBundledBundle(
                    allocator,
                    now,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.CertificateUntrusted,
                };
                loaded_local_bundle = true;
                break :blk .{ .bundle = .{ .gpa = allocator, .io = io, .lock = &local_lock, .bundle = &local_bundle } };
            } else blk: {
                try local_bundle.rescan(allocator, io, now);
                loaded_local_bundle = true;
                break :blk .{ .bundle = .{ .gpa = allocator, .io = io, .lock = &local_lock, .bundle = &local_bundle } };
            };
        }

        conn.client = tls.Client.init(
            &conn.net_reader.interface,
            &conn.net_writer.interface,
            client_options,
        ) catch |err| {
            if (err == error.ReadFailed and
                (conn.timed_read_error != null or conn.net_reader.err != null))
            {
                return conn.takeReadError();
            }
            return err;
        };
        return conn;
    }

    pub fn deinit(self: *TlsClientConnection) void {
        self.pending_timed_plaintext_fingerprint.clear();
        if (!self.write_closed) {
            self.client.end() catch {};
            self.net_writer.interface.flush() catch {};
        }
        self.stream.close(self.io);
        const allocator = self.allocator;
        allocator.free(self.net_read_buf);
        allocator.free(self.net_write_buf);
        allocator.free(self.tls_read_buf);
        allocator.free(self.tls_write_buf);
        allocator.destroy(self);
    }

    pub fn read(self: *TlsClientConnection, buffer: []u8) Error!usize {
        if (buffer.len == 0) return 0;
        const available = self.client.reader.peekGreedy(1) catch |err|
            switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => return self.takeReadError(),
            };
        const count = @min(buffer.len, available.len);
        @memcpy(buffer[0..count], available[0..count]);
        self.client.reader.toss(count);
        return count;
    }

    /// True only when the standard TLS wrapper retains no decrypted
    /// application bytes and is still open for both directions. Ciphertext in
    /// the network Reader remains for TLS to authenticate and classify.
    pub fn isReusableBoundary(self: *const TlsClientConnection) bool {
        return self.client.reader.bufferedLen() == 0 and
            !self.client.eof() and
            self.pending_timed_plaintext_len == 0 and
            !self.write_closed;
    }

    /// Read decrypted application bytes under one absolute socket deadline.
    ///
    /// Zig's TLS client owns the record parser and its plaintext/ciphertext
    /// buffers. Rather than duplicating that private state machine, the
    /// network Reader consults this transient deadline only when TLS needs
    /// more ciphertext. Already-buffered plaintext and complete encrypted
    /// records therefore remain immediately available.
    pub fn readWithDeadline(
        self: *TlsClientConnection,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        if (buffer.len == 0) return 0;
        // TLS may have decrypted an entire record to satisfy an earlier short
        // read. Consume that plaintext before consulting the socket deadline:
        // returning already-owned bytes performs no blocking I/O and must not
        // fail merely because the caller's deadline expired meanwhile.
        const buffered = self.client.reader.buffered();
        if (buffered.len != 0) {
            const count = @min(buffer.len, buffered.len);
            @memcpy(buffer[0..count], buffered[0..count]);
            self.client.reader.toss(count);
            return count;
        }
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.timed_read_deadline == null);
        self.timed_read_deadline = deadline;
        defer self.timed_read_deadline = null;
        return self.read(buffer);
    }

    fn takeReadError(self: *TlsClientConnection) Error {
        if (self.timed_read_error) |err| {
            self.timed_read_error = null;
            return err;
        }
        if (self.net_reader.err) |err| {
            self.net_reader.err = null;
            return err;
        }
        if (self.client.read_err) |err| return switch (err) {
            error.TlsBadLength => error.TlsDecodeError,
            error.TlsSequenceOverflow => error.SequenceOverflow,
            else => |value| value,
        };
        return error.ReadFailed;
    }

    pub fn writeAll(self: *TlsClientConnection, bytes: []const u8) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        if (bytes.len == 0) return;
        try self.client.writer.writeAll(bytes);
        try self.client.writer.flush();
        try self.net_writer.interface.flush();
    }

    /// Write a protocol header and payload with one TLS/network flush.
    ///
    /// Framed protocols such as WebSocket commonly keep their fixed header on
    /// the stack and borrow the application payload. Accepting both slices
    /// avoids concatenating them into a temporary allocation while preserving
    /// one TLS record flush boundary for the logical write.
    pub fn writeAllParts(
        self: *TlsClientConnection,
        header: []const u8,
        payload: []const u8,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        if (header.len == 0 and payload.len == 0) return;
        if (header.len != 0) try self.client.writer.writeAll(header);
        if (payload.len != 0) try self.client.writer.writeAll(payload);
        try self.client.writer.flush();
        try self.net_writer.interface.flush();
    }

    pub fn writeAllSlices(
        self: *TlsClientConnection,
        parts: []const []const u8,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        var has_bytes = false;
        for (parts) |part| {
            if (part.len == 0) continue;
            has_bytes = true;
            try self.client.writer.writeAll(part);
        }
        if (!has_bytes) return;
        try self.client.writer.flush();
        try self.net_writer.interface.flush();
    }

    /// Write plaintext under an absolute socket deadline. Progress advances
    /// only after the complete TLS record carrying that plaintext has reached
    /// the socket. Timeout, cancellation and executor admission failure retain
    /// the encrypted record and consumed sequence number for a later retry.
    /// Retry with the identical pending-record prefix, optionally relocated or
    /// extended with unaccepted tail bytes. A mismatch returns WriteInProgress
    /// before socket I/O. finishPendingTimedWrite explicitly drains that record
    /// without consuming replacement plaintext.
    pub fn writeAllWithDeadline(
        self: *TlsClientConnection,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        if (self.write_closed) return error.ConnectionClosed;

        if (self.pending_timed_plaintext_len != 0) {
            try self.pending_timed_plaintext_fingerprint.validate(self.pending_timed_plaintext_len, bytes);
            try self.finishTimedRecord(committed, deadline);
        }
        while (committed.* < bytes.len) {
            const chunk_len = @min(
                tls.max_ciphertext_inner_record_len,
                bytes.len - committed.*,
            );
            std.debug.assert(self.client.writer.buffered().len == 0);
            std.debug.assert(self.net_writer.interface.buffered().len == 0);
            const plaintext = bytes[committed.*..][0..chunk_len];
            try self.client.writer.writeAll(plaintext);
            // This encrypts into the connection-owned network writer buffer;
            // that buffer is one full TLS record and performs no socket I/O.
            try self.client.writer.flush();
            self.pending_timed_plaintext_len = chunk_len;
            self.finishTimedRecord(committed, deadline) catch |err| {
                self.pending_timed_plaintext_fingerprint.capture(plaintext);
                return err;
            };
        }
    }

    pub fn finishPendingTimedWrite(
        self: *TlsClientConnection,
        committed: *usize,
    ) Error!void {
        committed.* = 0;
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len == 0) return;
        try self.net_writer.interface.flush();
        committed.* = self.pending_timed_plaintext_len;
        self.pending_timed_plaintext_len = 0;
        self.pending_timed_plaintext_fingerprint.clear();
    }

    fn finishTimedRecord(
        self: *TlsClientConnection,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        std.debug.assert(self.pending_timed_plaintext_len != 0);
        while (self.net_writer.interface.buffered().len != 0) {
            const count = try stream_io.writeSomeWithDeadline(
                self.io,
                self.stream,
                self.net_writer.interface.buffered(),
                deadline,
            );
            _ = self.net_writer.interface.consume(count);
        }
        committed.* += self.pending_timed_plaintext_len;
        self.pending_timed_plaintext_len = 0;
        self.pending_timed_plaintext_fingerprint.clear();
    }

    pub fn closeWrite(self: *TlsClientConnection) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        // Once TLS shutdown starts, application writes cannot be retried even
        // if flushing the alert or the socket half-close fails.
        self.write_closed = true;
        try self.client.end();
        try self.net_writer.interface.flush();
        try shutdownAfterTlsCloseNotify(self.io, self.stream);
    }
};

pub const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls_client: *TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,

    pub fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls_client => |conn| conn.read(buffer),
            .tls_vail => |conn| conn.read(buffer),
            .tls_server => |conn| conn.read(buffer),
        };
    }

    pub fn readWithDeadline(
        self: RuntimeTransport,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return switch (self) {
            .tcp => |tcp| stream_io.readSomeWithDeadline(
                tcp.io,
                tcp.stream,
                buffer,
                deadline,
            ) catch |err| return mapHttpTimedReadError(err),
            .tls_client => |conn| conn.readWithDeadline(buffer, deadline),
            .tls_vail => |conn| conn.readWithDeadline(buffer, deadline),
            .tls_server => |conn| conn.readWithDeadline(buffer, deadline),
        };
    }

    pub fn deadlineFromNow(
        self: RuntimeTransport,
        duration: std.Io.Duration,
    ) Error!std.Io.Clock.Timestamp {
        const io = switch (self) {
            .tcp => |tcp| tcp.io,
            .tls_client => |conn| conn.io,
            .tls_vail => |conn| conn.io,
            .tls_server => |conn| conn.io,
        };
        return .fromNow(io, .{ .raw = duration, .clock = .awake });
    }

    pub fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls_client => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
        };
    }

    /// Write one logical plaintext slice under an absolute deadline while
    /// reporting the exact prefix committed to the transport.
    pub fn writeAllWithDeadline(
        self: RuntimeTransport,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllTrackedWithDeadline(
                tcp.io,
                tcp.stream,
                bytes,
                committed,
                deadline,
            ),
            .tls_client => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_vail => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_server => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
        };
    }

    pub fn writeAllPartsWithDeadline(
        self: RuntimeTransport,
        header: []const u8,
        body: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        var part_committed: usize = 0;
        self.writeAllWithDeadline(
            header,
            &part_committed,
            deadline,
        ) catch |err| {
            committed.* = part_committed;
            return err;
        };
        committed.* = part_committed;
        part_committed = 0;
        self.writeAllWithDeadline(
            body,
            &part_committed,
            deadline,
        ) catch |err| {
            committed.* += part_committed;
            return err;
        };
        committed.* += part_committed;
    }

    pub fn writeAllParts(
        self: RuntimeTransport,
        header: []const u8,
        body: []const u8,
    ) Error!void {
        if (body.len == 0) return self.writeAll(header);
        if (header.len == 0) return self.writeAll(body);
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllParts(
                tcp.io,
                tcp.stream,
                header,
                body,
            ),
            .tls_client => |conn| conn.writeAllParts(header, body),
            .tls_vail => |conn| conn.writeAllParts(header, body),
            .tls_server => |conn| conn.writeAllParts(header, body),
        };
    }

    pub fn writeAllSlices(
        self: RuntimeTransport,
        parts: []const []const u8,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllSlicesWide(
                tcp.io,
                tcp.stream,
                parts,
            ),
            .tls_client => |conn| conn.writeAllSlices(parts),
            .tls_vail => |conn| conn.writeAllSlices(parts),
            .tls_server => |conn| conn.writeAllSlices(parts),
        };
    }

    pub fn closeWrite(self: RuntimeTransport) Error!void {
        return switch (self) {
            .tcp => |tcp| tcp.stream.shutdown(tcp.io, .send),
            .tls_client => |conn| conn.closeWrite(),
            .tls_vail => |conn| {
                try conn.sendCloseNotify();
                try shutdownAfterTlsCloseNotify(conn.io, conn.stream);
            },
            .tls_server => |conn| {
                try conn.sendCloseNotify();
                try shutdownAfterTlsCloseNotify(conn.io, conn.stream);
            },
        };
    }

    /// Abort both directions without releasing transport-owned TLS state.
    /// The owning Client/Connection still performs the eventual deinit, while
    /// the shutdown ensures no more HTTP/1 bytes can be misinterpreted after
    /// an upgraded protocol error.
    pub fn abort(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.shutdown(tcp.io, .both) catch {},
            .tls_client => |conn| conn.stream.shutdown(conn.io, .both) catch {},
            .tls_vail => |conn| conn.stream.shutdown(conn.io, .both) catch {},
            .tls_server => |conn| conn.stream.shutdown(conn.io, .both) catch {},
        }
    }

    pub fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls_client => |conn| conn.deinit(),
            .tls_vail => |conn| conn.deinit(),
            .tls_server => |conn| conn.deinit(),
        }
    }
};

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return initWithListener(
            allocator,
            io,
            try bind_address.listen(io, .{ .reuse_address = true }),
            limits,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers to the
    /// returned server, which closes it from `deinit`.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        limits: Limits,
    ) Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = listener,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream);
    }

    pub fn acceptWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStream(stream);
    }

    /// Adopt an already accepted cleartext stream. Protocol adapters can
    /// consume trusted transport prefaces before handing ownership to HTTP/1.
    pub fn acceptStream(
        self: *Server,
        stream: net.Stream,
    ) Error!Connection {
        errdefer stream.close(self.io);
        if (self.limits.tcp_nodelay) {
            try setTcpNoDelay(stream);
        }
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
        };
    }

    pub fn serveOne(self: *Server, context: anytype, comptime handler: anytype) Error!void {
        var connection = try self.accept();
        defer connection.close();
        _ = try connection.serveOne(context, handler);
    }

    pub fn serveConnection(self: *Server, context: anytype, comptime handler: anytype, max_requests: usize) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            Server,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
        max_requests_per_connection: usize,
        options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            Server,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

/// HTTP/1 listener over a Unix-domain stream socket.
///
/// Parsing, body framing, pipelining and response handling are delegated to
/// the same `Connection` used by TCP. Only the accept/address lifecycle is
/// Unix-specific. The socket path itself remains caller-owned; applications
/// are responsible for removing a filesystem socket after `deinit`.
pub const UnixServer = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        limits: Limits,
    ) Error!UnixServer {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try address.listen(io, .{}),
            .limits = limits,
        };
    }

    pub fn deinit(self: *UnixServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn accept(self: *UnixServer) Error!Connection {
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
        };
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptWithDeadline(
        self: *UnixServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        errdefer stream.close(self.io);
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
        };
    }

    pub fn serveOne(
        self: *UnixServer,
        context: anytype,
        comptime handler: anytype,
    ) Error!void {
        var connection = try self.accept();
        defer connection.close();
        try connection.serveOne(context, handler);
    }

    pub fn serveConnection(
        self: *UnixServer,
        context: anytype,
        comptime handler: anytype,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            UnixServer,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
        max_requests_per_connection: usize,
        options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            UnixServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,
    limits: Limits,
    tls: tls_stream.ServerOptions,
    tcp_nodelay: bool,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) Error!TlsServer {
        if (options.identity_provider) |provider| {
            var lease = provider.acquire();
            defer lease.deinit();
            try lease.identity.validate();
        } else {
            try options.identity.validate();
        }
        return .{
            .allocator = allocator,
            .io = io,
            .listener = try bind_address.listen(
                io,
                .{ .reuse_address = true },
            ),
            .limits = options.limits,
            .tls = .{
                .identity = options.identity,
                .identity_provider = options.identity_provider,
                .cipher_suites = options.cipher_suites,
                .tls12_cipher_suites = options.tls12_cipher_suites,
                .protocol_policy = options.protocol_policy,
                .tls13_session_tickets = options.tls13_session_tickets,
                .tls12_session_tickets = options.tls12_session_tickets,
                .max_client_hello_size = options.max_client_hello_size,
                .max_client_handshake_size = options.max_client_handshake_size,
                .handshake_timeout = options.tls_handshake_timeout,
                .client_auth = options.client_auth,
                .alpn_protocols = options.alpn_protocols,
            },
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: TlsServer) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *TlsServer) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream);
    }

    /// Perform the TLS handshake on an already accepted stream. Ownership
    /// transfers at entry, matching the deadline-bounded adoption helpers.
    pub fn acceptStream(
        self: *TlsServer,
        stream: net.Stream,
    ) Error!Connection {
        return self.acceptStreamMaybeBefore(stream, null);
    }

    /// Apply one caller-owned deadline to TCP accept and TLS setup.
    pub fn acceptWithDeadline(
        self: *TlsServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    /// Perform the TLS handshake on an already accepted stream under one
    /// caller-owned deadline. Ownership transfers at entry.
    pub fn acceptStreamWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    pub fn acceptStreamWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        timeout: std.Io.Duration,
    ) Error!Connection {
        // As with the deadline form, validation precedes ownership transfer.
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamWithDeadline(
            stream,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ServerConnection.initWithDeadline(
                self.allocator,
                self.io,
                stream,
                self.tls,
                absolute,
            )
        else
            try tls_stream.ServerConnection.init(
                self.allocator,
                self.io,
                stream,
                self.tls,
            );
        stream_owned = false;
        errdefer tls_connection.deinit();
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
            .tls_server_conn = tls_connection,
        };
    }

    pub fn serveOne(
        self: *TlsServer,
        context: anytype,
        comptime handler: anytype,
    ) Error!void {
        var connection = try self.accept();
        defer connection.close();
        _ = try connection.serveOne(context, handler);
    }

    pub fn serveConnection(
        self: *TlsServer,
        context: anytype,
        comptime handler: anytype,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            TlsServer,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
        max_requests_per_connection: usize,
        options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            TlsServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};
