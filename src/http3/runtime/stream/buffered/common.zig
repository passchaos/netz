const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const Error = @import("../../error.zig").Error;

const net = @import("std").Io.net;

pub const AssembledStream = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
};

pub fn messageBlockedByQpack(
    bytes: []const u8,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        ) catch |err| switch (err) {
            error.OutOfMemory,
            error.ExcessiveLoad,
            error.QpackBlocked,
            error.QpackDecompressionFailed,
            => return err,
            else => return error.QpackDecompressionFailed,
        };
        if (prefix.required_insert_count > table.insert_count) return true;
    }
    return false;
}

/// Return whether any complete field section in an assembled message created
/// a dynamic-table dependency. A receiver that rejects the HTTP semantics
/// after successful QPACK decoding uses this to decide whether it also owes
/// the encoder a Stream Cancellation instruction.
pub fn messageUsesDynamicQpack(
    bytes: []const u8,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        ) catch |err| switch (err) {
            error.OutOfMemory,
            error.ExcessiveLoad,
            error.QpackBlocked,
            error.QpackDecompressionFailed,
            => return err,
            else => return error.QpackDecompressionFailed,
        };
        if (prefix.required_insert_count != 0) return true;
    }
    return false;
}

pub fn receiveUsesDynamicQpack(
    receive: quic.stream_state.RecvState,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    const relative_start = receive.read_offset - receive.storage_offset;
    const relative_end = receive.contiguous_end - receive.storage_offset;
    const available = receive.buffer.items[relative_start..relative_end];
    var offset: usize = 0;
    while (offset < available.len) {
        const frame = http3.Frame.parse(available[offset..]) catch |err| switch (err) {
            // A reset can interrupt any frame. Only complete field-section
            // frames can have established a QPACK dependency at this point.
            error.BufferTooShort => return false,
            else => return err,
        };
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = try http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        );
        if (prefix.required_insert_count != 0) return true;
    }
    return false;
}

/// Return whether the currently contiguous bytes contain a complete field
/// section whose Required Insert Count is still unavailable. Incomplete frame
/// or prefix bytes are not blocked yet and remain retryable.
pub fn receiveBlockedByQpack(
    receive: quic.stream_state.RecvState,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    const relative_start = receive.read_offset - receive.storage_offset;
    const relative_end = receive.contiguous_end - receive.storage_offset;
    const available = receive.buffer.items[relative_start..relative_end];
    var offset: usize = 0;
    while (offset < available.len) {
        const frame = http3.Frame.parse(available[offset..]) catch |err| switch (err) {
            error.BufferTooShort => return false,
            else => return err,
        };
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        ) catch |err| switch (err) {
            error.BufferTooShort => return false,
            error.OutOfMemory,
            error.ExcessiveLoad,
            error.QpackBlocked,
            error.QpackDecompressionFailed,
            => return err,
            else => return error.QpackDecompressionFailed,
        };
        if (prefix.required_insert_count > table.insert_count) return true;
    }
    return false;
}

fn frameFieldSectionPayload(
    frame_type: u64,
    payload: []const u8,
) Error!?[]const u8 {
    return switch (frame_type) {
        http3.FrameType.headers => payload,
        http3.FrameType.push_promise => (try http3.parsePushPromisePayload(payload)).field_section,
        else => null,
    };
}
