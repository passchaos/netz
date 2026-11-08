//! Shadowsocks AEAD UDP relay with bounded per-client associations.

const std = @import("std");

const cipher = @import("cipher.zig");
const replay = @import("replay.zig");
const codec = @import("../socks/codec.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const destination = @import("../runtime/destination.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;

pub const Config = struct {
    method: cipher.Algorithm,
    password: []const u8,
    acl: acl.Policy = .{},
    /// Optional hot-reloadable ACL. Takes precedence over `acl`.
    policy_store: ?*reload.Reloadable = null,
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(60),
    poll_interval: std.Io.Duration = .fromMilliseconds(250),
    max_datagram_size: usize = 65535,
    max_associations: usize = 256,
    replay: ?*replay.Cache = null,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Error = error{
    InvalidPassword,
    InvalidIdleTimeout,
    InvalidPollInterval,
    InvalidDatagramSize,
    AssociationLimitExceeded,
    ReplayDetected,
    MalformedDatagram,
    DestinationDenied,
};

const max_cleanup_batch: usize = 1024;

const Association = struct {
    server: *Server,
    client: net.IpAddress,
    socket: net.Socket,
    closed: std.atomic.Value(bool) = .init(false),
    last_activity: std.atomic.Value(i64) = .init(0),
    thread: std.Thread = undefined,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    socket: net.Socket,
    family: net.IpAddress.Family,
    master_key: [32]u8,
    master_key_len: usize,
    associations: std.ArrayList(*Association) = .empty,
    mutex: std.Io.Mutex = .init,
    running: std.atomic.Value(bool) = .init(true),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        listen_address: net.IpAddress,
        config: Config,
    ) !Server {
        if (config.password.len == 0) return error.InvalidPassword;
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
        if (config.max_associations == 0) {
            return error.AssociationLimitExceeded;
        }

        const socket = try listen_address.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        errdefer socket.close(io);

        var master_key: [32]u8 = undefined;
        const key_length = config.method.keyLength();
        _ = try cipher.deriveMasterKey(
            config.password,
            key_length,
            &master_key,
        );
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .socket = socket,
            .family = std.meta.activeTag(listen_address),
            .master_key = master_key,
            .master_key_len = key_length,
        };
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);
        self.mutex.lockUncancelable(self.io);
        var associations = self.associations;
        self.associations = .empty;
        self.mutex.unlock(self.io);
        for (associations.items) |association| {
            association.closed.store(true, .release);
            association.thread.join();
            association.socket.close(self.io);
            self.allocator.destroy(association);
        }
        associations.deinit(self.allocator);
        std.crypto.secureZero(u8, &self.master_key);
        self.socket.close(self.io);
        self.* = undefined;
    }

    pub fn requestStop(self: *Server) void {
        self.running.store(false, .release);
    }

    pub fn address(self: *const Server) net.IpAddress {
        return self.socket.address;
    }

    pub fn serve(self: *Server) !void {
        const storage = try self.allocator.alloc(
            u8,
            self.config.max_datagram_size,
        );
        defer self.allocator.free(storage);
        const plaintext = try self.allocator.alloc(
            u8,
            self.config.max_datagram_size,
        );
        defer self.allocator.free(plaintext);

        const poll_timeout: std.Io.Timeout = .{
            .duration = .{
                .raw = self.config.poll_interval,
                .clock = .awake,
            },
        };

        while (self.running.load(.acquire)) {
            self.cleanupClosed();
            const message = self.socket.receiveTimeout(
                self.io,
                storage,
                poll_timeout,
            ) catch |err| switch (err) {
                error.Timeout => continue,
                else => break,
            };
            if (message.flags.trunc) continue;
            self.processDatagram(message.from, message.data, plaintext) catch
                continue;
        }
    }

    fn processDatagram(
        self: *Server,
        client: net.IpAddress,
        packet: []const u8,
        plaintext: []u8,
    ) !void {
        if (self.config.rate_limiter) |value| {
            const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            if (!value.allow(client, 1, now)) return error.RateLimited;
        }
        const association = try self.getOrCreate(client);
        const salt_len = self.config.method.keyLength();
        if (packet.len < salt_len + 16) return error.MalformedDatagram;
        const salt = packet[0..salt_len];
        if (self.config.replay) |cache| {
            if (!cache.accept(salt)) return error.ReplayDetected;
        }

        var subkey: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &subkey);
        try cipher.deriveSubkey(
            self.config.method,
            self.master_key[0..self.master_key_len],
            salt,
            subkey[0..self.master_key_len],
        );
        var aead = try cipher.Aead.init(
            self.config.method,
            subkey[0..self.master_key_len],
        );
        defer aead.deinit();

        const cipher_len = packet.len - salt_len - 16;
        if (cipher_len > plaintext.len) return error.MalformedDatagram;
        const tag = packet[packet.len - 16 ..][0..16].*;
        aead.decrypt(
            plaintext[0..cipher_len],
            packet[salt_len..][0..cipher_len],
            tag,
            "",
            @splat(0),
        ) catch return error.MalformedDatagram;

        const decoded = try codec.decodeSocks5Address(
            plaintext[0..cipher_len],
            0,
        );
        const payload = plaintext[decoded.end..cipher_len];
        const target: destination.Target = switch (decoded.address) {
            .ip => |ip| .{ .ip = ip },
            .domain => |domain| .{ .domain = .{
                .host = domain.host,
                .port = domain.port,
            } },
        };
        const resolved = try destination.resolveTarget(
            self.allocator,
            self.io,
            reload.policyFor(self.config.acl, self.config.policy_store),
            target,
            .udp_associate,
            self.config.connect_timeout,
        );
        try association.socket.send(self.io, &resolved, payload);
        if (self.config.stats) |value| {
            value.addBytesIn(@intCast(payload.len));
        }
        association.last_activity.store(
            @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds),
            .release,
        );
    }

    fn getOrCreate(self: *Server, client: net.IpAddress) !*Association {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.associations.items) |association| {
            if (!association.closed.load(.acquire) and
                association.client.eql(&client))
            {
                return association;
            }
        }
        if (self.associations.items.len >= self.config.max_associations) {
            return error.AssociationLimitExceeded;
        }

        const association = try self.allocator.create(Association);
        errdefer self.allocator.destroy(association);
        const bind_address = switch (self.family) {
            .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
            .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
        };
        const socket = try bind_address.bind(
            self.io,
            .{ .mode = .dgram, .protocol = .udp },
        );
        errdefer socket.close(self.io);
        association.* = .{
            .server = self,
            .client = client,
            .socket = socket,
            .last_activity = .init(
                @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds),
            ),
        };
        association.thread = try std.Thread.spawn(
            .{},
            receiverLoop,
            .{association},
        );
        errdefer {
            association.closed.store(true, .release);
            association.thread.join();
        }
        try self.associations.append(self.allocator, association);
        return association;
    }

    fn cleanupClosed(self: *Server) void {
        var batch: [max_cleanup_batch]*Association = undefined;
        var count: usize = 0;
        self.mutex.lockUncancelable(self.io);
        var index: usize = 0;
        while (index < self.associations.items.len and count < batch.len) {
            if (self.associations.items[index].closed.load(.acquire)) {
                const association = self.associations.swapRemove(index);
                batch[count] = association;
                count += 1;
            } else {
                index += 1;
            }
        }
        self.mutex.unlock(self.io);

        for (batch[0..count]) |association| {
            association.thread.join();
            self.allocator.destroy(association);
        }
    }

    fn receiverLoop(association: *Association) void {
        const server = association.server;
        const buffer = server.allocator.alloc(
            u8,
            server.config.max_datagram_size,
        ) catch {
            association.closed.store(true, .release);
            return;
        };
        defer server.allocator.free(buffer);
        const reply_plain = server.allocator.alloc(
            u8,
            server.config.max_datagram_size + 19,
        ) catch {
            association.closed.store(true, .release);
            return;
        };
        defer server.allocator.free(reply_plain);
        const reply_wire = server.allocator.alloc(
            u8,
            server.config.max_datagram_size + 19 + cipher.max_salt_len + 16,
        ) catch {
            association.closed.store(true, .release);
            return;
        };
        defer server.allocator.free(reply_wire);

        const poll_timeout: std.Io.Timeout = .{
            .duration = .{
                .raw = server.config.poll_interval,
                .clock = .awake,
            },
        };
        while (!association.closed.load(.acquire)) {
            const message = association.socket.receiveTimeout(
                server.io,
                buffer,
                poll_timeout,
            ) catch |err| switch (err) {
                error.Timeout => {
                    const now = std.Io.Timestamp.now(server.io, .awake).nanoseconds;
                    const last = association.last_activity.load(.acquire);
                    if (@as(i96, now) - @as(i96, last) >=
                        server.config.idle_timeout.nanoseconds)
                    {
                        break;
                    }
                    continue;
                },
                else => break,
            };
            if (message.flags.trunc) continue;
            const wire = encryptReply(
                server,
                message.from,
                message.data,
                reply_plain,
                reply_wire,
            ) catch continue;
            server.socket.send(
                server.io,
                &association.client,
                wire,
            ) catch continue;
            if (server.config.stats) |value| {
                value.addBytesOut(@intCast(message.data.len));
            }
        }
        association.closed.store(true, .release);
    }
};

fn encryptReply(
    server: *Server,
    source: net.IpAddress,
    payload: []const u8,
    plaintext: []u8,
    wire: []u8,
) ![]const u8 {
    const address_len = try codec.encodeSocks5Address(plaintext, .{ .ip = source });
    if (plaintext.len - address_len < payload.len) return error.MalformedDatagram;
    @memcpy(plaintext[address_len..][0..payload.len], payload);
    const total_plain = address_len + payload.len;

    const salt_len = server.config.method.keyLength();
    if (wire.len < salt_len + total_plain + 16) {
        return error.MalformedDatagram;
    }
    const salt = wire[0..salt_len];
    server.io.random(salt);
    var subkey: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &subkey);
    try cipher.deriveSubkey(
        server.config.method,
        server.master_key[0..server.master_key_len],
        salt,
        subkey[0..server.master_key_len],
    );
    var aead = try cipher.Aead.init(
        server.config.method,
        subkey[0..server.master_key_len],
    );
    defer aead.deinit();
    aead.encrypt(
        wire[salt_len..][0..total_plain],
        @ptrCast(&wire[salt_len + total_plain]),
        plaintext[0..total_plain],
        "",
        @splat(0),
    );
    return wire[0 .. salt_len + total_plain + 16];
}

test "Shadowsocks UDP server validates configuration" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.InvalidPassword,
        Server.init(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .method = .aes_256_gcm,
            .password = "",
        }),
    );
    try std.testing.expectError(
        error.InvalidIdleTimeout,
        Server.init(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .method = .aes_256_gcm,
            .password = "secret",
            .idle_timeout = .fromMilliseconds(0),
        }),
    );
    try std.testing.expectError(
        error.InvalidPollInterval,
        Server.init(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .method = .aes_256_gcm,
            .password = "secret",
            .idle_timeout = .fromMilliseconds(10),
            .poll_interval = .fromMilliseconds(20),
        }),
    );
}
