//! Finalize a fully received message before advancing to another wire frame.
//! Compressed input stays owned by the connection across decoder OOM, while
//! the caller's destination is released. Takeover history commits only once
//! decoding and text validation both succeed.
const std = @import("std");
const websocket = @import("../../mod.zig");
const common = @import("../common.zig");

pub fn finish(connection: anytype, out: []u8) websocket.Error!common.Message {
    const state = &connection.message_into;
    std.debug.assert(state.complete);
    const opcode = state.opcode orelse return error.InvalidFrame;
    const compressed = state.compressed;
    const payload = if (compressed)
        if (connection.compression_receive_context_takeover)
            connection.compression_receive.previewContextInto(
                connection.allocator,
                out[0..connection.limits.max_message_bytes],
                connection.compression_receive.payload.items[0..state.written],
                connection.compression_receive_max_window_bits,
            ) catch |err| return if (err == error.PreviewPending) error.InvalidFrame else @errorCast(err)
        else
            try websocket.decompressMessageVortInto(
                out[0..connection.limits.max_message_bytes],
                connection.compression_receive.payload.items[0..state.written],
                connection.compression_receive.payload.allocatedSlice(),
            )
    else
        out[0..state.written];
    if (state.payloadNeedsFinalUtf8Validation() and !std.unicode.utf8ValidateSlice(payload)) {
        if (connection.compression_receive_context_takeover) connection.compression_receive.discardContextPreview();
        return error.InvalidUtf8;
    }
    if (compressed and connection.compression_receive_context_takeover) connection.compression_receive.commitContextPreview();
    state.reset();
    return .{ .opcode = opcode, .payload = payload, .was_compressed = compressed };
}
