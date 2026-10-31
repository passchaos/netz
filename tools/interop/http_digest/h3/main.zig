const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5 and args.len != 6) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[2], 10);
    const version: netz.quic.Version = if (std.mem.eql(u8, args[3], "1")) .version_1 else if (std.mem.eql(u8, args[3], "2")) .version_2 else return error.InvalidArgument;
    var backend = try netz.runtime.Backend.init(init.gpa);
    defer backend.deinit();
    if (std.mem.eql(u8, args[1], "client") and args.len == 5 and port != 0) {
        try @import("client.zig").run(init.gpa, backend.io(), port, version, args[4]);
    } else if (std.mem.eql(u8, args[1], "server") and args.len == 6) {
        try @import("server.zig").run(init.gpa, backend.io(), port, version, args[4], args[5]);
    } else return error.InvalidArgument;
}
