//! Stable, allocation-free identity for one shared HTTP/3 driver turn.
//!
//! Commands borrow URI and Alt-Svc storage from producer stacks. A route
//! driver can outlive any one command, so it copies the bounded identity fields
//! it needs while leaving request payload ownership with the producer.

const std = @import("std");
const authority = @import("../../../../http/authority/mod.zig");
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
                authority.hostEquivalent(
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
                authority.hostEquivalent(
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
        const raw_host = switch (host_component) {
            .raw, .percent_encoded => |value| value,
        };
        var host_buffer: [net.HostName.max_len]u8 = undefined;
        const host = authority.canonicalHostInto(&host_buffer, raw_host) catch
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
        const raw_host = switch (host_component) {
            .raw, .percent_encoded => |value| value,
        };
        var host_buffer: [net.HostName.max_len]u8 = undefined;
        const host = authority.canonicalHostInto(&host_buffer, raw_host) catch return false;
        if (!authority.hostEquivalent(
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
            !authority.hostEquivalent(
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

    pub fn origin(self: *const Key) http3.Origin {
        return .{
            .scheme = "https",
            .host = self.origin_host[0..self.origin_host_len],
            .port = self.origin_port,
        };
    }
};

fn sameReclaimer(
    a: ?connection_budget.Reclaimer,
    b: ?connection_budget.Reclaimer,
) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.context == b.?.context and a.?.reclaim == b.?.reclaim;
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

test "shared HTTP/3 route key recognizes canonical IPv6 and escaped host aliases" {
    const aliases = [_][2][]const u8{
        .{ "https://%65xample.test/path", "https://EXAMPLE.test:443/other" },
        .{ "https://[2001:DB8:0:0:0:0:0:1]/path", "https://[2001:db8::1]:443/other" },
        .{ "https://[::ffff:c000:201]/path", "https://[::ffff:192.0.2.1]:443/other" },
    };
    for (aliases) |pair| {
        const first = try Key.init(pair[0], null, null);
        const second = try Key.init(pair[1], null, null);
        try std.testing.expect(first.matches(pair[1], null, null));
        try std.testing.expect(first.eql(&second));
        try std.testing.expect(http3.sameOrigin(first.origin(), second.origin()));
    }
    const encoded = try Key.init("https://a%2Bb.test/", null, null);
    try std.testing.expect(!encoded.matches("https://a+b.test/", null, null));
    try std.testing.expect(!encoded.matches("https://a%2Bb.test:444/", null, null));
}
