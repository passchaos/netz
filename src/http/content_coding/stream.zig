//! Bounded streaming HTTP content decoder over Vort codecs.

const std = @import("std");
const vort = @import("vort");
const pipeline = @import("pipeline.zig");

pub const Status = enum {
    need_input,
    need_output,
    done,
};

pub const Result = struct {
    input_read: usize,
    output_written: usize,
    status: Status,
};

pub const Options = struct {
    max_encoded_bytes: usize,
    max_decoded_bytes: usize,
    /// Capacity of each queue between stacked decoders. The allocation is
    /// capped at `max_decoded_bytes`; zero selects the one-byte minimum.
    intermediate_buffer_bytes: usize = 16 * 1024,
};

const Limits = struct {
    max_encoded_bytes: usize,
    max_decoded_bytes: usize,
};

pub fn Decoder(
    comptime Coding: type,
    comptime Error: type,
    comptime map_error: fn (anyerror) Error,
    comptime max_layers: usize,
) type {
    return struct {
        allocator: std.mem.Allocator,
        options: Limits,
        state: State,
        input_read: usize = 0,
        output_written: usize = 0,
        finish_started: bool = false,
        done: bool = false,
        failed: bool = false,

        const Self = @This();
        const PipelineState = pipeline.Pipeline(
            Self,
            Coding,
            Error,
            Result,
            Status,
        );

        const State = union(enum) {
            identity,
            deflate: *DeflateState,
            gzip: *GzipState,
            br: *vort.BrotliIncrementalStreamDecoder,
            zstd: *vort.ZstdNativeIncrementalFrameDecoder,
            pipeline: *PipelineState,
        };

        const DeflateState = struct {
            decoder: vort.ZlibIncrementalDecoder,
            history: [32 * 1024]u8 = undefined,
        };

        const GzipState = struct {
            decoder: vort.GzipIncrementalDecoder,
            history: [32 * 1024]u8 = undefined,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            coding: Coding,
            options: Options,
        ) Error!Self {
            const state: State = switch (coding) {
                .identity => .identity,
                .deflate => blk: {
                    const decoder = try allocator.create(DeflateState);
                    errdefer allocator.destroy(decoder);
                    decoder.decoder = vort.ZlibIncrementalDecoder.init(
                        .{ .max_output_len = options.max_decoded_bytes },
                        &decoder.history,
                    ) catch |err| return map_error(err);
                    break :blk .{ .deflate = decoder };
                },
                .gzip => blk: {
                    const decoder = try allocator.create(GzipState);
                    errdefer allocator.destroy(decoder);
                    decoder.decoder = vort.GzipIncrementalDecoder.init(
                        .{
                            .max_output_len = options.max_decoded_bytes,
                            .max_header_metadata_len = options.max_encoded_bytes,
                            .allow_concatenated = true,
                        },
                        &decoder.history,
                    ) catch |err| return map_error(err);
                    break :blk .{ .gzip = decoder };
                },
                .br => blk: {
                    const decoder = try allocator.create(
                        vort.BrotliIncrementalStreamDecoder,
                    );
                    decoder.* = vort.BrotliIncrementalStreamDecoder
                        .initWithOptions(allocator, .{
                        .max_compressed_len = options.max_encoded_bytes,
                        .max_output_len = options.max_decoded_bytes,
                    });
                    break :blk .{ .br = decoder };
                },
                .zstd => blk: {
                    const decoder = try allocator.create(
                        vort.ZstdNativeIncrementalFrameDecoder,
                    );
                    decoder.* = vort.ZstdNativeIncrementalFrameDecoder
                        .initWithOptions(allocator, .{
                        .max_compressed_buffer_len = options.max_encoded_bytes,
                        .max_decoded_buffer_len = options.max_decoded_bytes,
                        .expected_output_len = null,
                    });
                    break :blk .{ .zstd = decoder };
                },
            };
            return .{
                .allocator = allocator,
                .options = .{
                    .max_encoded_bytes = options.max_encoded_bytes,
                    .max_decoded_bytes = options.max_decoded_bytes,
                },
                .state = state,
            };
        }

        /// Initialize decoders in reverse Content-Encoding application order.
        /// Identity members are ignored. A single effective coding keeps the
        /// allocation and dispatch shape of `init`; stacked codings allocate
        /// fixed-capacity queues once and perform no per-step allocation.
        pub fn initChain(
            allocator: std.mem.Allocator,
            codings: []const Coding,
            options: Options,
        ) Error!Self {
            if (codings.len > max_layers) {
                return error.TooManyContentEncodings;
            }
            var selected: Coding = .identity;
            var count: usize = 0;
            for (codings) |coding| {
                if (coding == .identity) continue;
                selected = coding;
                count += 1;
            }
            if (count <= 1) return init(allocator, selected, options);

            const state = try allocator.create(PipelineState);
            errdefer allocator.destroy(state);
            state.* = try PipelineState.init(allocator, codings, options);
            return .{
                .allocator = allocator,
                .options = .{
                    .max_encoded_bytes = options.max_encoded_bytes,
                    .max_decoded_bytes = options.max_decoded_bytes,
                },
                .state = .{ .pipeline = state },
            };
        }

        pub fn deinit(self: *Self) void {
            switch (self.state) {
                .identity => {},
                .deflate => |decoder| self.allocator.destroy(decoder),
                .gzip => |decoder| self.allocator.destroy(decoder),
                .br => |decoder| {
                    decoder.deinit();
                    self.allocator.destroy(decoder);
                },
                .zstd => |decoder| {
                    decoder.deinit();
                    self.allocator.destroy(decoder);
                },
                .pipeline => |state| {
                    state.deinit();
                    self.allocator.destroy(state);
                },
            }
            self.* = undefined;
        }

        pub fn reset(self: *Self) void {
            switch (self.state) {
                .identity => {},
                .deflate => |decoder| decoder.decoder.reset(),
                .gzip => |decoder| decoder.decoder.reset(),
                .br => |decoder| decoder.reset(),
                .zstd => |decoder| decoder.reset(),
                .pipeline => |state| state.reset(),
            }
            self.input_read = 0;
            self.output_written = 0;
            self.finish_started = false;
            self.done = false;
            self.failed = false;
        }

        /// Consume a compressed prefix and fill a caller-owned output prefix.
        /// Successful calls report exact progress. Any returned error is
        /// terminal; call `reset` before reusing the decoder.
        pub fn step(
            self: *Self,
            input: []const u8,
            output: []u8,
        ) Error!Result {
            if (self.failed or self.finish_started) {
                return error.InvalidDecoderState;
            }
            if (self.done) {
                if (input.len != 0) return error.InvalidContentEncoding;
                return .{
                    .input_read = 0,
                    .output_written = 0,
                    .status = .done,
                };
            }
            if (input.len > self.options.max_encoded_bytes -|
                self.input_read)
            {
                return self.fail(error.EncodedBodyTooLarge);
            }

            switch (self.state) {
                .pipeline => |state| {
                    const result = state.step(input, output) catch |err|
                        return self.fail(err);
                    return self.commitResult(input.len, result);
                },
                else => {},
            }

            if (self.isIdentity()) {
                return self.commitResult(
                    input.len,
                    try self.stepIdentity(input, output),
                );
            }
            const result = switch (self.state) {
                .identity => unreachable,
                .deflate => |decoder| fromVortStep(
                    decoder.decoder.step(input, output) catch |err|
                        return self.fail(map_error(err)),
                ),
                .gzip => |decoder| fromVortStep(
                    decoder.decoder.step(input, output) catch |err|
                        return self.fail(map_error(err)),
                ),
                .br => |decoder| fromVortStep(
                    decoder.step(input, output) catch |err|
                        return self.fail(map_error(err)),
                ),
                .zstd => |decoder| fromVortStep(
                    decoder.step(input, output) catch |err|
                        return self.fail(map_error(err)),
                ),
                .pipeline => unreachable,
            };
            return self.commitResult(input.len, result);
        }

        /// Mark HTTP body EOF and drain decoder-owned output. Repeat with a
        /// fresh output slice while `need_output` is returned.
        pub fn finish(
            self: *Self,
            output: []u8,
        ) Error!Result {
            if (self.failed) return error.InvalidDecoderState;
            if (self.done) {
                return .{
                    .input_read = 0,
                    .output_written = 0,
                    .status = .done,
                };
            }
            switch (self.state) {
                .pipeline => |state| {
                    self.finish_started = true;
                    const result = state.finish(output) catch |err|
                        return self.fail(err);
                    return self.commitResult(0, result);
                },
                else => {},
            }
            if (self.isIdentity()) {
                self.finish_started = true;
                self.done = true;
                return .{
                    .input_read = 0,
                    .output_written = 0,
                    .status = .done,
                };
            }

            if (!self.finish_started) {
                const drained = self.stepCodec(&.{}, output) catch |err|
                    return self.fail(map_error(err));
                const committed = try self.commitResult(0, drained);
                if (committed.status == .done or
                    committed.status == .need_output or
                    committed.output_written != 0)
                {
                    return committed;
                }
                self.finishCodec() catch |err|
                    return self.fail(map_error(err));
                self.finish_started = true;
            }

            const drained = self.stepCodec(&.{}, output) catch |err|
                return self.fail(map_error(err));
            const result = try self.commitResult(0, drained);
            if (result.status == .need_input) {
                return self.fail(error.InvalidContentEncoding);
            }
            return result;
        }

        pub fn totalInputRead(self: Self) usize {
            return self.input_read;
        }

        pub fn totalOutputWritten(self: Self) usize {
            return self.output_written;
        }

        pub fn finished(self: Self) bool {
            return self.done;
        }

        fn isIdentity(self: Self) bool {
            return switch (self.state) {
                .identity => true,
                .pipeline => false,
                else => false,
            };
        }

        fn stepIdentity(
            self: *Self,
            input: []const u8,
            output: []u8,
        ) Error!Result {
            if (input.len > self.options.max_decoded_bytes -|
                self.output_written)
            {
                return self.fail(error.DecodedBodyTooLarge);
            }
            const count = @min(input.len, output.len);
            @memcpy(output[0..count], input[0..count]);
            return .{
                .input_read = count,
                .output_written = count,
                .status = if (count == input.len) .need_input else .need_output,
            };
        }

        fn stepCodec(
            self: *Self,
            input: []const u8,
            output: []u8,
        ) !Result {
            return switch (self.state) {
                .identity => unreachable,
                .deflate => |decoder| fromVortStep(
                    try decoder.decoder.step(input, output),
                ),
                .gzip => |decoder| fromVortStep(
                    try decoder.decoder.step(input, output),
                ),
                .br => |decoder| fromVortStep(
                    try decoder.step(input, output),
                ),
                .zstd => |decoder| fromVortStep(
                    try decoder.step(input, output),
                ),
                .pipeline => unreachable,
            };
        }

        fn finishCodec(self: *Self) !void {
            switch (self.state) {
                .identity => unreachable,
                .deflate => |decoder| try decoder.decoder.finish(),
                .gzip => |decoder| try decoder.decoder.finish(),
                .br => |decoder| try decoder.finish(),
                .zstd => |decoder| try decoder.finish(),
                .pipeline => unreachable,
            }
        }

        fn commitResult(
            self: *Self,
            offered_input_len: usize,
            result: Result,
        ) Error!Result {
            if (result.input_read > offered_input_len) {
                return self.fail(error.InvalidContentEncoding);
            }
            if (result.status == .done and
                result.input_read != offered_input_len)
            {
                return self.fail(error.InvalidContentEncoding);
            }
            self.input_read = std.math.add(
                usize,
                self.input_read,
                result.input_read,
            ) catch return self.fail(error.EncodedBodyTooLarge);
            self.output_written = std.math.add(
                usize,
                self.output_written,
                result.output_written,
            ) catch return self.fail(error.DecodedBodyTooLarge);
            if (self.input_read > self.options.max_encoded_bytes) {
                return self.fail(error.EncodedBodyTooLarge);
            }
            if (self.output_written > self.options.max_decoded_bytes) {
                return self.fail(error.DecodedBodyTooLarge);
            }
            if (result.status == .done) self.done = true;
            return result;
        }

        fn fail(self: *Self, err: Error) Error {
            self.failed = true;
            return err;
        }
    };
}

fn fromVortStep(result: vort.StepResult) Result {
    return .{
        .input_read = result.progress.input_read,
        .output_written = result.progress.output_written,
        .status = switch (result.status) {
            .need_input => .need_input,
            .need_output => .need_output,
            .done => .done,
        },
    };
}
