//! Envoy v3 Secret resources delivered by the Secret Discovery Service.
const std = @import("std");
const pb = @import("../../protobuf.zig");
const tls_material = @import("../tls_material.zig");

pub const type_url = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

pub const Error = pb.Error || std.mem.Allocator.Error || error{
    InvalidSdsResource,
    SdsLimitExceeded,
    UnsupportedSdsFeature,
};

pub const Limits = struct {
    max_bytes: usize = 1024 * 1024,
    max_text_bytes: usize = 4096,
    max_san_matchers: usize = 64,
    max_certificate_hashes: usize = 64,
};

pub const TlsCertificate = struct {
    certificate_chain: []const u8,
    private_key: []const u8,
};

pub const ValidationContext = struct {
    trusted_ca: []const u8,
    san_matchers: []const tls_material.SanMatcher = &.{},
    verify_certificate_hashes: []const [32]u8 = &.{},
};

pub const Kind = union(enum) {
    tls_certificate: TlsCertificate,
    validation_context: ValidationContext,
};

pub const Secret = struct {
    name: []const u8,
    kind: Kind,

    /// Project the decoded secret onto the inline TLS configuration consumed
    /// by cluster projections. SAN matchers and the trust bundle are retained
    /// by the owning arena.
    pub fn tlsConfig(self: Secret) tls_material.Config {
        return switch (self.kind) {
            .tls_certificate => |value| .{
                .certificate_chain = value.certificate_chain,
                .private_key = value.private_key,
            },
            .validation_context => |value| .{
                .trusted_ca = value.trusted_ca,
                .san_matchers = value.san_matchers,
                .verify_certificate_hashes = value.verify_certificate_hashes,
            },
        };
    }
};

pub const Owned = struct {
    wire: []const u8 = "",
    arena: std.heap.ArenaAllocator,
    value: Secret,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn text(reader: *pb.Reader, limits: Limits) Error![]const u8 {
    const value = try reader.string();
    if (value.len > limits.max_text_bytes) return error.SdsLimitExceeded;
    return value;
}

/// Only inline material is accepted. File, environment and watched-directory
/// sources belong to the bootstrap certificate providers, not to ADS SDS.
fn dataSource(bytes: []const u8, limits: Limits) Error![]const u8 {
    var inline_bytes: ?[]const u8 = null;
    var inline_string: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            if (field.wire_type != 2 or inline_bytes != null or inline_string != null) {
                return error.InvalidSdsResource;
            }
            inline_bytes = try reader.bytesValue();
        },
        2 => {
            if (field.wire_type != 2 or inline_bytes != null or inline_string != null) {
                return error.InvalidSdsResource;
            }
            inline_string = try text(&reader, limits);
        },
        3, 4, 5 => return error.UnsupportedSdsFeature,
        else => try reader.skip(field),
    };
    return inline_bytes orelse inline_string orelse error.InvalidSdsResource;
}

fn sanMatcher(bytes: []const u8, limits: Limits) Error!tls_material.SanMatcher {
    var kind: ?tls_material.SanMatch = null;
    var value: []const u8 = "";
    var ignore_case = false;
    var count: usize = 0;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1, 2, 3, 7 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            value = try text(&reader, limits);
            kind = switch (field.number) {
                1 => .exact,
                2 => .prefix,
                3 => .suffix,
                else => .contains,
            };
            count += 1;
        },
        5, 8 => return error.UnsupportedSdsFeature,
        6 => {
            if (field.wire_type != 0) return error.InvalidSdsResource;
            ignore_case = (try reader.varint()) != 0;
        },
        else => try reader.skip(field),
    };
    if (count != 1) return error.InvalidSdsResource;
    return .{ .kind = kind.?, .value = value, .ignore_case = ignore_case };
}

fn tlsCertificate(bytes: []const u8, limits: Limits) Error!TlsCertificate {
    var chain: ?[]const u8 = null;
    var key: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            chain = try dataSource(try reader.bytesValue(), limits);
        },
        2 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            key = try dataSource(try reader.bytesValue(), limits);
        },
        3, 4, 5, 6 => return error.UnsupportedSdsFeature,
        else => try reader.skip(field),
    };
    return .{
        .certificate_chain = chain orelse return error.InvalidSdsResource,
        .private_key = key orelse return error.InvalidSdsResource,
    };
}

fn certificateHash(value: []const u8) Error![32]u8 {
    if (value.len != 64) return error.InvalidSdsResource;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidSdsResource;
    return result;
}

fn validationContext(
    arena: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) Error!ValidationContext {
    var trusted_ca: ?[]const u8 = null;
    var matchers: std.ArrayList(tls_material.SanMatcher) = .empty;
    var hashes: std.ArrayList([32]u8) = .empty;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            trusted_ca = try dataSource(try reader.bytesValue(), limits);
        },
        2 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            if (matchers.items.len >= limits.max_san_matchers) {
                return error.SdsLimitExceeded;
            }
            try matchers.append(arena, try sanMatcher(try reader.bytesValue(), limits));
        },
        3 => {
            // UNSPECIFIED performs ordinary chain verification with trusted_ca.
            if (field.wire_type != 0) return error.InvalidSdsResource;
            if (try reader.varint() != 0) return error.UnsupportedSdsFeature;
        },
        4 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            if (hashes.items.len >= limits.max_certificate_hashes) {
                return error.SdsLimitExceeded;
            }
            try hashes.append(arena, try certificateHash(try text(&reader, limits)));
        },
        6 => {
            if (field.wire_type != 0) return error.InvalidSdsResource;
            if ((try reader.varint()) != 0) return error.UnsupportedSdsFeature;
        },
        5, 7, 8, 9, 10, 11, 12, 13 => return error.UnsupportedSdsFeature,
        else => try reader.skip(field),
    };
    return .{
        .trusted_ca = trusted_ca orelse return error.InvalidSdsResource,
        .san_matchers = try matchers.toOwnedSlice(arena),
        .verify_certificate_hashes = try hashes.toOwnedSlice(arena),
    };
}

pub fn decode(
    gpa: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) Error!Owned {
    if (bytes.len > limits.max_bytes) return error.SdsLimitExceeded;
    var result = Owned{ .arena = .init(gpa), .value = undefined };
    errdefer result.deinit();
    const arena = result.arena.allocator();
    const image = try arena.dupe(u8, bytes);
    result.wire = image;
    var reader: pb.Reader = .{ .bytes = image };
    var name: []const u8 = "";
    var certificate: ?[]const u8 = null;
    var validation: ?[]const u8 = null;
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            if (field.wire_type != 2) return error.InvalidSdsResource;
            name = try text(&reader, limits);
        },
        2 => {
            if (field.wire_type != 2 or certificate != null or validation != null) {
                return error.InvalidSdsResource;
            }
            certificate = try reader.bytesValue();
        },
        3 => {
            if (field.wire_type != 2 or certificate != null or validation != null) {
                return error.InvalidSdsResource;
            }
            validation = try reader.bytesValue();
        },
        4, 5 => return error.UnsupportedSdsFeature,
        else => try reader.skip(field),
    };
    if (name.len == 0) return error.InvalidSdsResource;
    result.value = .{
        .name = name,
        .kind = if (certificate) |value|
            .{ .tls_certificate = try tlsCertificate(value, limits) }
        else if (validation) |value|
            .{ .validation_context = try validationContext(arena, value, limits) }
        else
            return error.InvalidSdsResource,
    };
    return result;
}
