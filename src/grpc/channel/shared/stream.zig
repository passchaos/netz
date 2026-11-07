//! Shared RPC capabilities; transport methods stay on the endpoint owner.
const std = @import("std");
const State = @import("state.zig").State;
const Error = @import("state.zig").Error;
const codec = @import("../../stream/codec.zig");
const reading = @import("stream/read.zig");
const writing = @import("stream/write.zig");
const types = @import("stream/call.zig");
pub const Event = types.Event;
pub const Message = types.Message;
pub const OwnedWriteMessage = types.OwnedWriteMessage;

pub const Writer = struct {
    call: *State.StreamCall,
    pub fn clone(self: Writer) Writer {
        self.call.retain();
        return self;
    }
    pub fn deinit(self: *Writer) void {
        self.call.release();
        self.* = undefined;
    }
    pub fn allocMessage(self: Writer, payload_len: usize) Error!OwnedWriteMessage {
        if (payload_len > self.call.options.requestMessageLimit()) {
            return error.GrpcMessageTooLarge;
        }
        return OwnedWriteMessage.init(self.call.parent.allocator, payload_len);
    }
    pub fn writeMessage(self: Writer, payload: []const u8) Error!void {
        return self.writeMessageWithOptions(payload, .{});
    }
    pub fn writeMessageWithOptions(self: Writer, payload: []const u8, options: codec.MessageOptions) Error!void {
        return writing.submit(self.call, .{ .payload = payload, .options = options });
    }
    pub fn writeMessageWithDeadline(self: Writer, payload: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submit(self.call, .{ .payload = payload, .deadline = deadline });
    }
    pub fn writeMessageWithOptionsAndDeadline(self: Writer, payload: []const u8, options: codec.MessageOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submit(self.call, .{ .payload = payload, .options = options, .deadline = deadline });
    }
    pub fn writeMessageWithTimeout(self: Writer, payload: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeMessageWithDeadline(payload, .fromNow(self.call.parent.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Consume `message` on success or error. It is safe to keep a deferred
    /// `message.deinit()`; consumed storage is represented by a null value.
    pub fn writeOwnedMessage(self: Writer, message: *OwnedWriteMessage) Error!void {
        return self.writeOwnedMessageWithOptions(message, .{});
    }
    pub fn writeOwnedMessageWithOptions(self: Writer, message: *OwnedWriteMessage, options: codec.MessageOptions) Error!void {
        return writing.submitOwned(self.call, message, .{ .options = options });
    }
    pub fn writeOwnedMessageWithDeadline(self: Writer, message: *OwnedWriteMessage, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submitOwned(self.call, message, .{ .deadline = deadline });
    }
    pub fn writeOwnedMessageWithOptionsAndDeadline(self: Writer, message: *OwnedWriteMessage, options: codec.MessageOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submitOwned(self.call, message, .{ .options = options, .deadline = deadline });
    }
    pub fn writeOwnedMessageWithTimeout(self: Writer, message: *OwnedWriteMessage, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) {
            message.deinit();
            return error.Timeout;
        }
        return self.writeOwnedMessageWithDeadline(message, .fromNow(self.call.parent.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn writeFinalMessage(self: Writer, payload: []const u8) Error!void {
        return writing.submit(self.call, .{ .payload = payload, .final = true });
    }
    pub fn writeFinalMessageWithOptions(self: Writer, payload: []const u8, options: codec.MessageOptions) Error!void {
        return writing.submit(self.call, .{ .payload = payload, .options = options, .final = true });
    }
    pub fn writeFinalMessageWithDeadline(self: Writer, payload: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submit(self.call, .{ .payload = payload, .final = true, .deadline = deadline });
    }
    pub fn writeFinalOwnedMessage(self: Writer, message: *OwnedWriteMessage) Error!void {
        return self.writeFinalOwnedMessageWithOptions(message, .{});
    }
    pub fn writeFinalOwnedMessageWithOptions(self: Writer, message: *OwnedWriteMessage, options: codec.MessageOptions) Error!void {
        return writing.submitOwned(self.call, message, .{ .options = options, .final = true });
    }
    pub fn writeFinalOwnedMessageWithDeadline(self: Writer, message: *OwnedWriteMessage, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submitOwned(self.call, message, .{ .final = true, .deadline = deadline });
    }
    pub fn finishRequest(self: Writer) Error!void {
        return writing.submit(self.call, .{ .finish_only = true });
    }
    pub fn finishRequestWithDeadline(self: Writer, deadline: std.Io.Clock.Timestamp) Error!void {
        return writing.submit(self.call, .{ .finish_only = true, .deadline = deadline });
    }
    pub fn finishRequestWithTimeout(self: Writer, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestWithDeadline(.fromNow(self.call.parent.io, .{ .clock = .awake, .raw = timeout }));
    }
};

pub const Reader = struct {
    call: *State.StreamCall,
    /// Whether canceling this read operation also cancels the RPC. ADS reads
    /// disable this; explicit Duplex cancellation and RPC expiry still apply.
    cancel_call_on_interrupt: bool = true,
    pub fn clone(self: Reader) Reader {
        self.call.retain();
        return self;
    }
    pub fn deinit(self: *Reader) void {
        self.call.release();
        self.* = undefined;
    }
    pub fn next(self: Reader) Error!Event {
        return reading.next(self.call, null, self.cancel_call_on_interrupt);
    }
    pub fn nextWithDeadline(self: Reader, deadline: std.Io.Clock.Timestamp) Error!Event {
        return reading.next(self.call, deadline, self.cancel_call_on_interrupt);
    }
    pub fn nextWithTimeout(self: Reader, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.nextWithDeadline(.fromNow(self.call.parent.io, .{ .clock = .awake, .raw = timeout }));
    }
};

/// This owning value requests asynchronous cancellation on destruction. Writer
/// and Reader capabilities may outlive it and observe completed cancellation.
pub const Duplex = struct {
    call: *State.StreamCall,
    pub fn writer(self: Duplex) Writer {
        self.call.retain();
        return .{ .call = self.call };
    }
    pub fn reader(self: Duplex) Reader {
        self.call.retain();
        return .{ .call = self.call };
    }
    /// Publish cancellation and wake the endpoint owner without waiting for
    /// shared state ownership or transport retirement.
    pub fn requestCancel(self: Duplex) void {
        self.call.requestCancel();
    }
    /// Compatibility join: request cancellation and wait without a deadline.
    pub fn cancel(self: Duplex) void {
        self.call.cancel();
    }
    pub fn cancelWithDeadline(self: Duplex, deadline: std.Io.Clock.Timestamp) Error!void {
        if (deadline.clock != .awake) {
            self.call.requestCancel();
            return error.Timeout;
        }
        try self.call.cancelBefore(deadline);
    }
    pub fn cancelWithTimeout(self: Duplex, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) {
            self.call.requestCancel();
            return error.Timeout;
        }
        return self.cancelWithDeadline(.fromNow(self.call.parent.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn deinit(self: *Duplex) void {
        self.call.requestCancel();
        self.call.release();
        self.* = undefined;
    }
};
