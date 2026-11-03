//! Owned client API Listener. Parsed inline RDS is reused at publication.
const std = @import("std");
const model = @import("model.zig");
const pb = @import("protobuf.zig");
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8, limits: model.Limits) model.Error!model.Owned {
    if (bytes.len > limits.max_bytes) return error.LdsLimitExceeded;
    var owned = model.Owned{ .arena = .init(gpa), .value = undefined };
    errdefer owned.deinit();
    const arena = owned.arena.allocator();
    const image = try arena.dupe(u8, bytes);
    owned.wire = image;
    var reader = pb.Reader{ .bytes = image };
    var name: []const u8 = "";
    var api: ?[]const u8 = null;
    var server = false;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limits.max_text_bytes) else if (field.number == 19 and field.wire_type == 2) api = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) {
            _ = try reader.bytesValue();
            server = true;
        } else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidLdsResource;
    if (api == null) return if (server) error.UnsupportedLdsFeature else error.InvalidLdsResource;
    var api_reader = pb.Reader{ .bytes = api.? };
    var extension: ?[]const u8 = null;
    while (try api_reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) extension = try api_reader.bytesValue() else try api_reader.skip(field);
    }
    const typed = try pb.any(extension orelse return error.InvalidLdsResource, limits.max_text_bytes);
    if (!std.mem.eql(u8, typed.type_name, model.hcm_type)) return error.UnsupportedLdsFeature;
    const hcm = try @import("hcm.zig").decode(arena, typed.value, limits);
    if (hcm.route_source == .inline_rds) {
        owned.inline_rds = @import("../rds.zig").decode(gpa, hcm.route_source.inline_rds, limits.rds) catch |err| return switch (err) {
            error.InvalidRdsResource => error.InvalidLdsResource,
            error.RdsLimitExceeded, error.RegexLimitExceeded => error.LdsLimitExceeded,
            error.UnsupportedRdsFeature => error.UnsupportedLdsFeature,
            else => @errorCast(err),
        };
    }
    owned.value = .{ .name = name, .hcm = hcm };
    if (owned.storageBytes() > limits.max_storage_bytes) return error.LdsLimitExceeded;
    return owned;
}
