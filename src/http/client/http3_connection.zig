//! Exclusive QUIC connection owner behind the unified HTTP Connection.
const std = @import("std");
const quic = @import("../../quic/mod.zig");
const native = @import("../../http3/runtime.zig");
const http1 = @import("../../http1/runtime.zig");
const types = @import("types.zig");
const mapping = @import("header_mapping.zig");
const duplex = @import("duplex.zig");
const reader_io = @import("reader_io.zig");
const client_trust = @import("../../quic/client_trust.zig");
const Collector = @import("h3_response.zig").Collector;

pub const Owner = struct {
    allocator: std.mem.Allocator,
    client: native.HandshakeClient,
    authority: []u8,
    hostname: []u8,
    destination_id: [8]u8 = undefined,
    local_id: [8]u8 = undefined,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, uri: std.Uri, options: types.Options, deadline: ?std.Io.Clock.Timestamp) !*Owner {
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.UnsupportedScheme;
        var endpoint = try http1.uriEndpoint(allocator, uri, 443);
        defer endpoint.deinit();
        const self = try allocator.create(Owner);
        errdefer allocator.destroy(self);
        const authority = try allocator.dupe(u8, endpoint.authority);
        errdefer allocator.free(authority);
        const hostname = try allocator.dupe(u8, endpoint.tls_host);
        errdefer allocator.free(hostname);
        self.* = .{ .allocator = allocator, .client = undefined, .authority = authority, .hostname = hostname };
        var config = options.http3.handshake;
        const local_address = options.http3.local_address orelse std.Io.net.IpAddress{ .ip4 = .unspecified(0) };
        if (options.http3.local_address == null and config.alternate_local_address == null) config.alternate_local_address = .{ .ip6 = .unspecified(0) };
        config.address_connect_policy = options.http3.address_connect_policy;
        config.handshake.server_name = self.hostname;
        if (config.handshake.original_destination_connection_id.len == 0) {
            try io.randomSecure(&self.destination_id);
            config.handshake.original_destination_connection_id = &self.destination_id;
        }
        if (config.handshake.local_connection_id.len == 0) {
            try io.randomSecure(&self.local_id);
            config.handshake.local_connection_id = &self.local_id;
        }
        // Verify with the same trust policy as H1/H2 instead of silently
        // skipping server authentication when no H3-specific material is set.
        // The store only needs to live for this synchronous handshake.
        var system_store: ?quic.tls.trust.SystemStore = null;
        defer if (system_store) |*store| store.deinit();
        try client_trust.applyClientTrust(
            allocator,
            io,
            &config.handshake,
            .{
                .server_verifier = options.tls.server_verifier,
                .client_identity = options.tls.client_identity,
                .environ = options.tls.environ,
                .system_store = options.tls.system_store,
                .root_source = options.tls.root_source,
                .ca_bundle_configured = options.tls.ca_bundle != null,
            },
            &system_store,
        );
        if (config.address_resolver == null) config.address_resolver = options.address_resolver;
        self.client = if (deadline) |until|
            try native.HandshakeClient.connectUriWithDeadline(allocator, io, local_address, uri, options.http3.limits, config, until)
        else
            try native.HandshakeClient.connectUri(allocator, io, local_address, uri, options.http3.limits, config);
        return self;
    }

    pub fn deinit(self: *Owner) void {
        const allocator = self.allocator;
        self.client.deinit();
        allocator.free(self.authority);
        allocator.free(self.hostname);
        allocator.destroy(self);
    }

    pub fn start(self: *Owner, target: []const u8, options: types.RequestOptions, length: ?usize, deadline: ?std.Io.Clock.Timestamp) !duplex.Handle {
        var stack: [mapping.max_stack_headers]@import("../../http3/mod.zig").Qpack.HeaderField = undefined;
        var headers = try mapping.mapHttp3(self.allocator, options.headers, &stack);
        defer headers.deinit(self.allocator);
        const head_options: @import("../../http3/mod.zig").Request = .{ .method = options.method, .path = target, .scheme = "https", .authority = self.authority, .headers = headers.items };
        const head_policy: native.HandshakeClient.RequestHeadOptions = .{ .body_length = length, .trailers_pending = options.trailers.len != 0 };
        const id = if (deadline) |until|
            try self.client.startRequestWithOptionsAndDeadline(head_options, head_policy, until)
        else
            try self.client.startRequestWithOptions(head_options, head_policy);
        return duplex.Handle.initHttp3(self.allocator, &self.client, id);
    }

    pub fn request(self: *Owner, target: []const u8, options: types.RequestOptions, deadline: ?std.Io.Clock.Timestamp) !types.OwnedResponse {
        const source = options.bodySource();
        var handle = try self.start(target, options, source.contentLength(), deadline);
        defer handle.deinit();
        switch (source) {
            .slice => |body| try writeBody(&handle, body, deadline),
            .reader => |body| {
                var buffer: [16 * 1024]u8 = undefined;
                while (!handle.response_available) {
                    const count = try reader_io.readBefore(self.client.connectionIo(), body.reader, &buffer, deadline);
                    if (count == 0) break;
                    try writeBody(&handle, buffer[0..count], deadline);
                }
            },
        }
        if (!handle.body_finished and !handle.response_available) {
            if (options.trailers.len != 0) {
                var progress: duplex.UploadProgress = .{};
                if (deadline) |until| try handle.finishTrailersWithDeadline(options.trailers, &progress, until) else try handle.finishTrailers(options.trailers);
            } else {
                var progress: duplex.UploadProgress = .{};
                if (deadline) |until| try handle.finishBodyWithDeadline(&progress, until) else try handle.finishBody();
            }
        }
        var collector = Collector{ .allocator = self.allocator };
        defer collector.deinit();
        if (deadline) |until| _ = try handle.readResponseWithDeadline(collector.responseSink(), until) else _ = try handle.readResponse(collector.responseSink());
        if (handle.h3_response_metadata) |metadata| {
            collector.body_allowed = metadata.body_allowed;
            collector.consumed = metadata.consumed;
            collector.qpack_section_acknowledgments = metadata.qpack_section_acknowledgments;
        }
        return collector.intoResponse(self.allocator);
    }

    fn writeBody(handle: *duplex.Handle, body: []const u8, deadline: ?std.Io.Clock.Timestamp) !void {
        if (body.len == 0) return;
        if (handle.response_available) return;
        var progress: duplex.UploadProgress = .{};
        const result = if (deadline) |until| handle.writeBodyWithDeadline(body, &progress, until) else handle.writeBody(body);
        result catch |err| switch (err) {
            error.ResponseAvailable => {},
            else => return err,
        };
    }
};
