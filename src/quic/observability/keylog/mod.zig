//! NSS SSLKEYLOGFILE-compatible TLS traffic-secret writer.
//!
//! The module accepts an arbitrary `std.Io.Writer`; applications decide
//! whether that writer targets SSLKEYLOGFILE, an in-memory test sink, or a
//! protected diagnostics channel. I/O failures are always propagated.

const std = @import("std");

pub const Label = enum {
    client_early_traffic_secret,
    client_handshake_traffic_secret,
    server_handshake_traffic_secret,
    client_traffic_secret_0,
    server_traffic_secret_0,

    pub fn text(self: Label) []const u8 {
        return switch (self) {
            .client_early_traffic_secret => "CLIENT_EARLY_TRAFFIC_SECRET",
            .client_handshake_traffic_secret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            .server_handshake_traffic_secret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            .client_traffic_secret_0 => "CLIENT_TRAFFIC_SECRET_0",
            .server_traffic_secret_0 => "SERVER_TRAFFIC_SECRET_0",
        };
    }
};

pub const Log = struct {
    writer: *std.Io.Writer,

    pub fn init(writer: *std.Io.Writer) Log {
        return .{ .writer = writer };
    }

    pub fn writeSecret(
        self: *Log,
        label: Label,
        client_random: [32]u8,
        secret: [32]u8,
    ) std.Io.Writer.Error!void {
        try self.writer.writeAll(label.text());
        try self.writer.writeByte(' ');
        try self.writer.printHex(&client_random, .lower);
        try self.writer.writeByte(' ');
        try self.writer.printHex(&secret, .lower);
        try self.writer.writeByte('\n');
    }

    pub fn writeHandshakeSecrets(
        self: *Log,
        client_random: [32]u8,
        client_secret: [32]u8,
        server_secret: [32]u8,
    ) std.Io.Writer.Error!void {
        try self.writeSecret(
            .client_handshake_traffic_secret,
            client_random,
            client_secret,
        );
        try self.writeSecret(
            .server_handshake_traffic_secret,
            client_random,
            server_secret,
        );
    }

    pub fn writeApplicationSecrets(
        self: *Log,
        client_random: [32]u8,
        client_secret: [32]u8,
        server_secret: [32]u8,
    ) std.Io.Writer.Error!void {
        try self.writeSecret(
            .client_traffic_secret_0,
            client_random,
            client_secret,
        );
        try self.writeSecret(
            .server_traffic_secret_0,
            client_random,
            server_secret,
        );
    }
};

test "NSS keylog emits exact lowercase traffic-secret lines" {
    var storage: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var log = Log.init(&writer);
    try log.writeSecret(
        .client_handshake_traffic_secret,
        [_]u8{0xab} ** 32,
        [_]u8{0x01} ** 32,
    );
    try std.testing.expectEqualStrings(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET " ++
            ("ab" ** 32) ++ " " ++ ("01" ** 32) ++ "\n",
        writer.buffered(),
    );
}

test "NSS keylog propagates sink failure" {
    var writer: std.Io.Writer = .failing;
    var log = Log.init(&writer);
    try std.testing.expectError(
        error.WriteFailed,
        log.writeSecret(
            .server_traffic_secret_0,
            [_]u8{0} ** 32,
            [_]u8{1} ** 32,
        ),
    );
}
