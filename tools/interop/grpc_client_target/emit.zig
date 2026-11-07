//! Resolve the exact bootstrap/target consumed by the independent C-Core peer.
const std = @import("std");
const netz = @import("netz");

const Result = struct {
    status: []const u8,
    err: ?[]const u8 = null,
    listener_name: ?[]const u8 = null,
    discovery_authority: ?[]const u8 = null,
    listener_resource_authority: ?[]const u8 = null,
    data_authority: ?[]const u8 = null,
};

fn emit(io: std.Io, value: Result) !void {
    var buffer: [8192]u8 = undefined;
    var output = std.Io.File.stdout().writer(io, &buffer);
    try std.json.Stringify.value(value, .{}, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 and args.len != 4) return error.InvalidArguments;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], gpa, .limited(1024 * 1024));
    defer gpa.free(bytes);
    const configuration = netz.grpc.xds.bootstrap.parse(gpa, bytes, .{}) catch |err| {
        try emit(init.io, .{ .status = "error", .err = @errorName(err) });
        return;
    };
    defer configuration.deinit();
    const resolved = netz.grpc.xds.client_target.resolveWithOptions(gpa, configuration, args[2], .{
        .default_authority = if (args.len == 4) args[3] else null,
    }) catch |err| {
        try emit(init.io, .{ .status = "error", .err = @errorName(err) });
        return;
    };
    defer resolved.deinit();
    try emit(init.io, .{
        .status = "ok",
        .listener_name = resolved.listener_name,
        .discovery_authority = resolved.discovery_authority,
        .listener_resource_authority = resolved.listener_resource_authority,
        .data_authority = resolved.data_authority,
    });
}
