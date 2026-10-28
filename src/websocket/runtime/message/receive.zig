//! Allocating message receive transactions shared by H1, H2 and H3.
const std = @import("std");
const websocket = @import("../../mod.zig");
const common = @import("../common.zig");
const frame_validation = @import("frame_validation.zig");
const message_state = @import("state.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;

        pub fn receive(connection: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!common.OwnedMessage {
            if (Context.receiveFailed(connection)) return error.ConnectionClosed;
            if (connection.message_into.active()) return error.InvalidFrame;
            if (try Context.pendingControl(connection, .message, deadline)) |opcode| {
                std.debug.assert((try Context.resumeControl(connection, deadline)) == null);
                if (opcode == .close) return error.ConnectionClosed;
            }
            try Context.checkWrites(connection);
            errdefer |err| Context.afterError(connection, err, deadline);
            if (connection.message_assembler == null) {
                connection.message_assembler = websocket.MessageAssembler.initLimited(connection.allocator, connection.limits.max_message_bytes);
            }
            while (true) {
                const validation = frame_validation.Checkpoint.capture(connection);
                const checkpoint = websocket.MessageAssembler.Checkpoint.capture(&connection.message_assembler.?);
                const frame = try Context.readFrame(connection, deadline);
                switch (frame.header.opcode) {
                    .ping => {
                        if (canSend(connection, .pong)) {
                            try Context.beginControl(connection, .pong, frame.payload, .message, null, deadline, frame.consumed);
                            std.debug.assert((try Context.resumeControl(connection, deadline)) == null);
                        } else Context.discard(connection, frame.consumed);
                    },
                    .pong => Context.discard(connection, frame.consumed),
                    .close => {
                        connection.close_received.store(true, .release);
                        clearAssembler(connection);
                        if (!connection.close_sent.load(.acquire)) {
                            try Context.beginControl(connection, .close, frame.payload, .message, null, deadline, frame.consumed);
                            std.debug.assert((try Context.resumeControl(connection, deadline)) == null);
                        } else Context.discard(connection, frame.consumed);
                        Context.onClose(connection);
                        return error.ConnectionClosed;
                    },
                    else => {
                        const maybe_message = connection.message_assembler.?.feedUtf8Validated(frame, connection.incoming_text_utf8) catch |err| {
                            if (err == error.OutOfMemory) {
                                restoreFrame(connection, validation, frame);
                            } else {
                                Context.discard(connection, frame.consumed);
                                clearAssembler(connection);
                            }
                            return @errorCast(err);
                        };
                        const message = maybe_message orelse {
                            Context.discard(connection, frame.consumed);
                            continue;
                        };
                        const received = preview(connection, message) catch |err| {
                            if (err == error.OutOfMemory) {
                                checkpoint.restoreDetached(&connection.message_assembler.?, message);
                                restoreFrame(connection, validation, frame);
                            } else {
                                connection.allocator.free(message.payload);
                                Context.discard(connection, frame.consumed);
                                clearAssembler(connection);
                            }
                            return @errorCast(err);
                        };
                        if (message.compressed) connection.allocator.free(message.payload);
                        Context.discard(connection, frame.consumed);
                        clearAssembler(connection);
                        return received;
                    },
                }
            }
        }

        /// The assembler keeps the compressed input owned until this preview
        /// succeeds. Failed allocations never advance the takeover dictionary.
        fn preview(connection: *Connection, message: websocket.MessageAssembler.Message) Error!common.OwnedMessage {
            if (!message.compressed) return .{ .opcode = message.opcode, .payload = message.payload, .was_compressed = false };
            const takeover = connection.compression_receive_context_takeover;
            const payload = if (takeover)
                connection.compression_receive.previewContextOwned(connection.allocator, message.payload, connection.limits.max_message_bytes, connection.compression_receive_max_window_bits) catch |err| return if (err == error.PreviewPending) error.InvalidFrame else @errorCast(err)
            else
                try websocket.decompressMessage(connection.allocator, message.payload, connection.limits.max_message_bytes);
            errdefer connection.allocator.free(payload);
            if (message.opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
                if (takeover) connection.compression_receive.discardContextPreview();
                return error.InvalidUtf8;
            }
            if (takeover) connection.compression_receive.commitContextPreview();
            return .{ .opcode = message.opcode, .payload = payload, .was_compressed = true };
        }

        fn restoreFrame(connection: *Connection, validation: frame_validation.Checkpoint, frame: websocket.BorrowedFrame) void {
            // The borrowed parser unmasks in place. Restore the wire payload
            // before a retry validates and decodes that same prefix again.
            if (frame.header.mask_key) |mask| websocket.applyMask(frame.payload, mask, 0);
            validation.restore(connection);
        }

        fn clearAssembler(connection: *Connection) void {
            connection.message_assembler.?.deinit();
            connection.message_assembler = null;
        }

        fn canSend(connection: *const Connection, opcode: websocket.Opcode) bool {
            return message_state.canSendOpcode(opcode, connection.close_sent.load(.acquire), connection.close_received.load(.acquire));
        }
    };
}
