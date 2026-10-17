//! Stable, allocation-free identity for one shared HTTP/3 driver turn.
//!
//! Commands borrow URI and Alt-Svc storage from producer stacks. A route
//! driver can outlive any one command, so it copies the bounded identity fields
//! it needs while leaving request payload ownership with the producer.

const std = @import("std");
const http3 = @import("../../../mod.zig");
const connection_budget = @import("../../../../internal/connection_budget.zig");

const net = std.Io.net;
const max_alpn_len: usize = std.math.maxInt(u8);

pub const Error = error{
    InvalidHeader,
    InvalidUri,
};

pub const Key = struct {
    origin_host: [net.HostName.max_len]u8 = undefined,
    origin_host_len: usize,
    origin_port: u16,
    alt_svc: ?AltSvcKey,
    reclaimer: ?connection_budget.Reclaimer,

    const AltSvcKey = struct {
        alpn: [max_alpn_len]u8 = undefined,
        alpn_len: usize,
        connect_host: [net.HostName.max_len]u8 = undefined,
        connect_host_len: usize,
        origin_host: [net.HostName.max_len]u8 = undefined,
        origin_host_len: usize,
        port: u16,

        fn init(target: http3.AltSvcTarget) Error!AltSvcKey {
            if (target.alpn.len > max_alpn_len or
                target.connect_host.len > net.HostName.max_len or
                target.origin_host.len > net.HostName.max_len)
            {
                return error.InvalidHeader;
            }
            var self: AltSvcKey = .{
                .alpn_len = target.alpn.len,
                .connect_host_len = target.connect_host.len,
                .origin_host_len = target.origin_host.len,
                .port = target.port,
            };
            @memcpy(self.alpn[0..self.alpn_len], target.alpn);
            @memcpy(
                self.connect_host[0..self.connect_host_len],
                target.connect_host,
            );
            @memcpy(
                self.origin_host[0..self.origin_host_len],
                target.origin_host,
            );
            return self;
        }

        fn matches(
            self: *const AltSvcKey,
            target: http3.AltSvcTarget,
        ) bool {
            return self.port == target.port and
                std.mem.eql(
                    u8,
                    self.alpn[0..self.alpn_len],
                    target.alpn,
                ) and
                std.ascii.eqlIgnoreCase(
                    self.connect_host[0..self.connect_host_len],
                    target.connect_host,
                ) and
                std.ascii.eqlIgnoreCase(
                    self.origin_host[0..self.origin_host_len],
                    target.origin_host,
                );
        }

        fn eql(self: *const AltSvcKey, other: *const AltSvcKey) bool {
            return self.port == other.port and
                std.mem.eql(
                    u8,
                    self.alpn[0..self.alpn_len],
                    other.alpn[0..other.alpn_len],
                ) and
                std.ascii.eqlIgnoreCase(
                    self.connect_host[0..self.connect_host_len],
                    other.connect_host[0..other.connect_host_len],
                ) and
                std.ascii.eqlIgnoreCase(
                    self.origin_host[0..self.origin_host_len],
                    other.origin_host[0..other.origin_host_len],
                );
        }
    };

    pub fn init(
        uri_text: []const u8,
        alt_svc: ?http3.AltSvcTarget,
        reclaimer: ?connection_budget.Reclaimer,
    ) Error!Key {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (uri.user != null or uri.password != null or
            !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        {
            return error.InvalidUri;
        }
        const host_component = uri.host orelse return error.InvalidUri;
        var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const raw_host = host_component.toRaw(&host_buffer) catch
            return error.InvalidUri;
        const host = normalizedUriHost(raw_host) orelse
            return error.InvalidUri;
        if (host.len > net.HostName.max_len) return error.InvalidUri;
        var self: Key = .{
            .origin_host_len = host.len,
            .origin_port = uri.port orelse 443,
            .alt_svc = if (alt_svc) |target|
                try AltSvcKey.init(target)
            else
                null,
            .reclaimer = reclaimer,
        };
        @memcpy(self.origin_host[0..host.len], host);
        return self;
    }

    pub fn matches(
        self: *const Key,
        uri_text: []const u8,
        alt_svc: ?http3.AltSvcTarget,
        reclaimer: ?connection_budget.Reclaimer,
    ) bool {
        const uri = std.Uri.parse(uri_text) catch return false;
        if (uri.user != null or uri.password != null or
            !std.ascii.eqlIgnoreCase(uri.scheme, "https") or
            (uri.port orelse 443) != self.origin_port)
        {
            return false;
        }
        const host_component = uri.host orelse return false;
        var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const raw_host = host_component.toRaw(&host_buffer) catch return false;
        const host = normalizedUriHost(raw_host) orelse return false;
        if (!std.ascii.eqlIgnoreCase(
            self.origin_host[0..self.origin_host_len],
            host,
        )) return false;
        if (!sameReclaimer(self.reclaimer, reclaimer)) return false;
        if (self.alt_svc == null or alt_svc == null) {
            return self.alt_svc == null and alt_svc == null;
        }
        return self.alt_svc.?.matches(alt_svc.?);
    }

    pub fn eql(self: *const Key, other: *const Key) bool {
        if (self.origin_port != other.origin_port or
            !std.ascii.eqlIgnoreCase(
                self.origin_host[0..self.origin_host_len],
                other.origin_host[0..other.origin_host_len],
            ) or
            !sameReclaimer(self.reclaimer, other.reclaimer))
        {
            return false;
        }
        if (self.alt_svc == null or other.alt_svc == null) {
            return self.alt_svc == null and other.alt_svc == null;
        }
        return self.alt_svc.?.eql(&other.alt_svc.?);
    }
};

fn sameReclaimer(
    a: ?connection_budget.Reclaimer,
    b: ?connection_budget.Reclaimer,
) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.context == b.?.context and a.?.reclaim == b.?.reclaim;
}

fn normalizedUriHost(raw: []const u8) ?[]const u8 {
    if (raw.len == 0) return null;
    if (raw[0] == '[') {
        if (raw.len < 3 or raw[raw.len - 1] != ']') return null;
        const inner = raw[1 .. raw.len - 1];
        if (std.mem.indexOfScalar(u8, inner, '[') != null or
            std.mem.indexOfScalar(u8, inner, ']') != null)
        {
            return null;
        }
        return inner;
    }
    if (std.mem.indexOfScalar(u8, raw, '[') != null or
        std.mem.indexOfScalar(u8, raw, ']') != null)
    {
        return null;
    }
    return raw;
}

test "shared HTTP/3 route key normalizes origins and isolates route policy" {
    const Reclaim = struct {
        fn run(_: *anyopaque) bool {
            return false;
        }
    };
    var context_a: u8 = 0;
    var context_b: u8 = 0;
    const reclaimer_a: connection_budget.Reclaimer = .{
        .context = &context_a,
        .reclaim = Reclaim.run,
    };
    const target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "edge.example",
        .origin_host = "example.com",
        .port = 8443,
    };
    const key = try Key.init(
        "https://EXAMPLE.com/path",
        target,
        reclaimer_a,
    );
    try std.testing.expect(key.matches(
        "https://example.COM:443/other",
        .{
            .alpn = "h3",
            .connect_host = "EDGE.example",
            .origin_host = "EXAMPLE.com",
            .port = 8443,
        },
        reclaimer_a,
    ));
    try std.testing.expect(!key.matches(
        "https://example.com:444/other",
        target,
        reclaimer_a,
    ));
    try std.testing.expect(!key.matches(
        "https://example.com/other",
        target,
        .{ .context = &context_b, .reclaim = Reclaim.run },
    ));
    try std.testing.expect(!key.matches(
        "https://example.com/other",
        .{
            .alpn = "h3-29",
            .connect_host = "edge.example",
            .origin_host = "example.com",
            .port = 8443,
        },
        reclaimer_a,
    ));

    const ip6 = try Key.init("https://[2001:db8::1]/", null, null);
    try std.testing.expect(ip6.matches(
        "https://[2001:DB8::1]:443/next",
        null,
        null,
    ));
    try std.testing.expectError(
        error.InvalidUri,
        Key.init("http://example.com/", null, null),
    );
    try std.testing.expectError(
        error.InvalidUri,
        Key.init("https://user@example.com/", null, null),
    );

    const oversized_alpn = [_]u8{'x'} ** (max_alpn_len + 1);
    try std.testing.expectError(
        error.InvalidHeader,
        Key.init("https://example.com/", .{
            .alpn = &oversized_alpn,
            .connect_host = "edge.example",
            .origin_host = "example.com",
            .port = 443,
        }, null),
    );
}
