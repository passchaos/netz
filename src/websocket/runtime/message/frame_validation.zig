const websocket = @import("../../mod.zig");

pub const DataKind = enum {
    none,
    binary,
    text,
    compressed_text,
};

/// Validation may complete before an owned frame's payload allocation does.
/// If decoding fails while the wire bytes remain buffered, restore the state
/// that belongs to that prefix so a retry validates and delivers it once.
/// Capture before buffering the body: a prior timeout may already have checked
/// part of the same frame and its UTF-8 cursor must also survive rollback.
pub const Checkpoint = struct {
    kind: DataKind,
    text_utf8: websocket.Utf8Validator,
    validated: usize,

    pub fn capture(connection: anytype) Checkpoint {
        return .{
            .kind = connection.incoming_data_kind,
            .text_utf8 = connection.incoming_text_utf8,
            .validated = connection.incoming_frame_validated,
        };
    }

    pub fn restore(self: Checkpoint, connection: anytype) void {
        connection.incoming_data_kind = self.kind;
        connection.incoming_text_utf8 = self.text_utf8;
        connection.incoming_frame_validated = self.validated;
    }

    pub fn parseOwned(
        self: Checkpoint,
        connection: anytype,
        bytes: []const u8,
        header: websocket.FrameHeader,
        options: websocket.ParseFrameOptions,
    ) websocket.Error!websocket.Frame {
        return websocket.parseFrameWithHeader(
            connection.allocator,
            bytes,
            header,
            options,
        ) catch |err| {
            self.restore(connection);
            return err;
        };
    }
};
