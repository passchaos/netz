//! Emit a speculative netz QPACK field section for a read-only reference
//! decoder. This process boundary proves that the wire representation is not
//! merely self-consistent with netz's own decoder.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var encoder =
        netz.http3.runtime.QpackEncodeState.initAwaitingPeerSettings(
            allocator,
            4096,
        );
    defer encoder.deinit();
    try encoder.configurePeerLimits(256, 1);
    _ = try encoder.insertField("x-peer", "speculative-value");

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 4, &.{
        .{ .name = "x-peer", .value = "speculative-value" },
        .{ .name = "x-peer", .value = "literal-tail" },
    });

    const instructions = encoder.pendingEncoderInstructions();
    if (instructions.len > std.math.maxInt(u32)) {
        return error.OutputTooLarge;
    }
    var instruction_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &instruction_len, @intCast(instructions.len), .big);
    var writer_buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writer(init.io, &writer_buffer);
    try writer.interface.writeAll(&instruction_len);
    try writer.interface.writeAll(instructions);
    try writer.interface.writeAll(block.items);
    try writer.interface.flush();
}
