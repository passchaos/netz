//! RFC 1928 UDP ASSOCIATE relay.
//!
//! One TCP control connection owns one bounded UDP association. Client
//! datagrams are accepted only from the authenticated client's endpoint, all
//! destinations pass through the configured ACL, fragmentation is rejected,
//! and the association expires on inactivity or when the control connection
//! closes.

const std = @import("std");
const netz_socks5_udp = @import("../socks5/udp.zig");

const codec = @import("codec.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const io_helpers = @import("../internal/io.zig");
const destination = @import("../runtime/destination.zig");
const stats_mod = @import("../runtime/stats.zig");

const net = std.Io.net;
const udp = netz_socks5_udp;

pub const Config = struct {
    acl: acl.Policy = .{},
    policy_store: ?*reload.Reloadable = null,
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(60),
    poll_interval: std.Io.Duration = .fromMilliseconds(250),
    max_datagram_size: usize = 65535,
    stats: ?*stats_mod.Stats = null,
};

pub const Error = error{
    InvalidIdleTimeout,
    InvalidPollInterval,
    InvalidDatagramSize,
    UdpRequestInvalid,
    DestinationDenied,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    control: net.Stream,
    peer: net.IpAddress,
    relay_socket: net.Socket,
    upstream_socket: net.Socket,
    requested_endpoint: ?net.IpAddress,
    endpoint_mutex: std.Io.Mutex = .init,
    endpoint: ?net.IpAddress = null,
    closed: std.atomic.Value(bool) = .init(false),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        config: Config,
        control: net.Stream,
        peer: net.IpAddress,
        requested: codec.Address,
    ) !Session {
        if (config.idle_timeout.nanoseconds <= 0) {
            return error.InvalidIdleTimeout;
        }
        if (config.poll_interval.nanoseconds <= 0 or
            config.poll_interval.nanoseconds > config.idle_timeout.nanoseconds)
        {
            return error.InvalidPollInterval;
        }
        if (config.max_datagram_size == 0 or
            config.max_datagram_size > 65535)
        {
            return error.InvalidDatagramSize;
        }

        const family: net.IpAddress.Family = switch (requested) {
            .ip => |ip| std.meta.activeTag(ip),
            .domain => return error.UdpRequestInvalid,
        };
        const bind_address = switch (family) {
            .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
            .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
        };
        const relay_socket = try bind_address.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        errdefer relay_socket.close(io);
        const upstream_socket = try bind_address.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        errdefer upstream_socket.close(io);

        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .control = control,
            .peer = peer,
            .relay_socket = relay_socket,
            .upstream_socket = upstream_socket,
            .requested_endpoint = requestedEndpoint(peer, requested),
        };
    }

    pub fn deinit(self: *Session) void {
        self.relay_socket.close(self.io);
        self.upstream_socket.close(self.io);
        self.* = undefined;
    }

    pub fn address(self: *const Session) net.IpAddress {
        return self.relay_socket.address;
    }

    pub fn run(self: *Session) !void {
        const relay_buffer = try self.allocator.alloc(
            u8,
            self.config.max_datagram_size,
        );
        defer self.allocator.free(relay_buffer);
        const framing_buffer = try self.allocator.alloc(
            u8,
            self.config.max_datagram_size + codec.max_socks5_request_len,
        );
        defer self.allocator.free(framing_buffer);

        const upstream_thread = try std.Thread.spawn(
            .{},
            upstreamLoop,
            .{self},
        );
        var upstream_joined = false;
        defer if (!upstream_joined) {
            self.closed.store(true, .release);
            self.control.shutdown(self.io, .both) catch {};
            upstream_thread.join();
        };

        const control_thread = try std.Thread.spawn(
            .{},
            controlLoop,
            .{self},
        );
        var control_joined = false;
        defer if (!control_joined) {
            self.closed.store(true, .release);
            self.control.shutdown(self.io, .both) catch {};
            control_thread.join();
        };

        var last_activity = std.Io.Timestamp.now(self.io, .awake);
        const idle_nanoseconds = self.config.idle_timeout.nanoseconds;
        const poll_timeout: std.Io.Timeout = .{
            .duration = .{
                .raw = self.config.poll_interval,
                .clock = .awake,
            },
        };

        while (!self.closed.load(.acquire)) {
            const message = self.relay_socket.receiveTimeout(
                self.io,
                relay_buffer,
                poll_timeout,
            ) catch |err| switch (err) {
                error.Timeout => {
                    const now = std.Io.Timestamp.now(self.io, .awake);
                    if (now.nanoseconds - last_activity.nanoseconds >=
                        idle_nanoseconds)
                    {
                        break;
                    }
                    continue;
                },
                else => break,
            };
            last_activity = std.Io.Timestamp.now(self.io, .awake);
            if (message.flags.trunc) continue;
            if (!self.acceptClientSource(message.from)) continue;

            const datagram = udp.decodeDatagram(message.data) catch continue;
            const resolved_destination = self.resolveDestination(
                datagram.source,
            ) catch continue;
            self.upstream_socket.send(
                self.io,
                &resolved_destination,
                datagram.payload,
            ) catch continue;
            if (self.config.stats) |value| {
                value.addBytesIn(@intCast(datagram.payload.len));
            }
        }

        self.closed.store(true, .release);
        self.control.shutdown(self.io, .both) catch {};
        upstream_thread.join();
        upstream_joined = true;
        control_thread.join();
        control_joined = true;
    }

    fn upstreamLoop(self: *Session) void {
        const buffer = self.allocator.alloc(
            u8,
            self.config.max_datagram_size,
        ) catch {
            self.closed.store(true, .release);
            return;
        };
        defer self.allocator.free(buffer);
        const framing_buffer = self.allocator.alloc(
            u8,
            self.config.max_datagram_size + codec.max_socks5_request_len,
        ) catch {
            self.closed.store(true, .release);
            return;
        };
        defer self.allocator.free(framing_buffer);

        const poll_timeout: std.Io.Timeout = .{
            .duration = .{
                .raw = self.config.poll_interval,
                .clock = .awake,
            },
        };
        while (!self.closed.load(.acquire)) {
            const message = self.upstream_socket.receiveTimeout(
                self.io,
                buffer,
                poll_timeout,
            ) catch |err| switch (err) {
                error.Timeout => continue,
                else => break,
            };
            if (message.flags.trunc) continue;
            const endpoint = self.pinnedEndpoint() orelse continue;
            const encoded = udp.encodeDatagram(
                framing_buffer,
                .{ .ip = message.from },
                message.data,
            ) catch continue;
            self.relay_socket.send(
                self.io,
                &endpoint,
                encoded,
            ) catch continue;
            if (self.config.stats) |value| {
                value.addBytesOut(@intCast(message.data.len));
            }
        }
    }

    fn controlLoop(self: *Session) void {
        var buffer: [64]u8 = undefined;
        while (!self.closed.load(.acquire)) {
            const count = io_helpers.readSome(
                self.io,
                self.control,
                &buffer,
                null,
            ) catch break;
            if (count == 0) break;
        }
        self.closed.store(true, .release);
    }

    fn acceptClientSource(
        self: *Session,
        source: net.IpAddress,
    ) bool {
        self.endpoint_mutex.lockUncancelable(self.io);
        defer self.endpoint_mutex.unlock(self.io);

        if (self.endpoint) |pinned| {
            return source.eql(&pinned);
        }
        if (self.requested_endpoint) |requested| {
            if (!source.eql(&requested)) return false;
            self.endpoint = source;
            return true;
        }
        if (!sameIp(source, self.peer)) return false;
        self.endpoint = source;
        return true;
    }

    fn pinnedEndpoint(self: *Session) ?net.IpAddress {
        self.endpoint_mutex.lockUncancelable(self.io);
        defer self.endpoint_mutex.unlock(self.io);
        return self.endpoint;
    }

    fn resolveDestination(
        self: *Session,
        target: udp.Address,
    ) !net.IpAddress {
        const resolved: destination.Target = switch (target) {
            .ip => |ip| .{ .ip = ip },
            .domain => |domain| .{ .domain = .{
                .host = domain.host,
                .port = domain.port,
            } },
        };
        return destination.resolveTarget(
            self.allocator,
            self.io,
            reload.policyFor(self.config.acl, self.config.policy_store),
            resolved,
            .udp_associate,
            self.config.connect_timeout,
        );
    }
};

fn requestedEndpoint(
    peer: net.IpAddress,
    requested: codec.Address,
) ?net.IpAddress {
    const ip = switch (requested) {
        .ip => |value| value,
        .domain => return null,
    };
    if (ip.getPort() == 0) return null;
    if (isUnspecified(ip)) {
        var endpoint = peer;
        endpoint.setPort(ip.getPort());
        return endpoint;
    }
    return ip;
}

fn isUnspecified(ip: net.IpAddress) bool {
    return switch (ip) {
        .ip4 => |value| std.mem.allEqual(u8, &value.bytes, 0),
        .ip6 => |value| std.mem.allEqual(u8, &value.bytes, 0),
    };
}

fn sameIp(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes),
        },
    };
}

test "UDP session rejects invalid configuration before binding" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try (net.IpAddress{
        .ip4 = .loopback(listener.socket.address.ip4.port),
    }).connect(io, .{ .mode = .stream });
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);

    const peer = net.IpAddress{ .ip4 = .loopback(0) };
    try std.testing.expectError(
        error.InvalidIdleTimeout,
        Session.init(
            allocator,
            io,
            .{ .idle_timeout = .fromMilliseconds(0) },
            server,
            peer,
            .{ .ip = .{ .ip4 = .unspecified(0) } },
        ),
    );
    try std.testing.expectError(
        error.InvalidPollInterval,
        Session.init(
            allocator,
            io,
            .{
                .idle_timeout = .fromMilliseconds(10),
                .poll_interval = .fromMilliseconds(20),
            },
            server,
            peer,
            .{ .ip = .{ .ip4 = .unspecified(0) } },
        ),
    );
    try std.testing.expectError(
        error.InvalidDatagramSize,
        Session.init(
            allocator,
            io,
            .{ .max_datagram_size = 0 },
            server,
            peer,
            .{ .ip = .{ .ip4 = .unspecified(0) } },
        ),
    );
    try std.testing.expectError(
        error.UdpRequestInvalid,
        Session.init(
            allocator,
            io,
            .{},
            server,
            peer,
            .{ .domain = .{ .host = "example.com", .port = 53 } },
        ),
    );
}

test "UDP endpoint pinning prefers the requested port and otherwise locks the peer IP" {
    const peer = net.IpAddress{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 10 },
        .port = 9000,
    } };
    const requested = requestedEndpoint(
        peer,
        .{ .ip = .{ .ip4 = .{
            .bytes = .{ 0, 0, 0, 0 },
            .port = 7777,
        } } },
    );
    try std.testing.expect(requested != null);
    try std.testing.expectEqual(@as(u16, 7777), requested.?.getPort());
    try std.testing.expect(sameIp(requested.?, peer));

    try std.testing.expect(requestedEndpoint(
        peer,
        .{ .ip = .{ .ip4 = .unspecified(0) } },
    ) == null);
}
