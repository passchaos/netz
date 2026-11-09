const std = @import("std");
const kron = @import("kron");

pub fn main(init: std.process.Init) !void {
    const logging = try kron.Logging.create(init.gpa, init.io, .{
        .outputs = &.{.{
            .name = "netz",
            .target = .stderr,
            .mode = .asynchronous,
            .format = .text,
            .filter = "info",
            .queue = .{ .memory = .{
                .capacity = 1024,
                .max_record_bytes = 4096,
            } },
            .overflow = .drop_newest,
        }},
    });
    defer logging.destroy();
    kron.setGlobalLogging(logging);
    defer kron.clearGlobalLogging();

    kron.info("netz", "netz logging example started", .{
        .component = "example",
    });
    kron.warn("netz", "example warning", .{
        .code = @as(u32, 42),
        .detail = "bounded queue drops before blocking",
    });
    try logging.flush();
    try logging.shutdown();
}
