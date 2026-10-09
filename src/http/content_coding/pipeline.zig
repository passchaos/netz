//! Bounded backpressure plumbing for stacked HTTP content decoders.
//!
//! The codecs themselves stay in `stream.zig`. This module only connects them
//! in reverse Content-Encoding order through fixed-capacity intermediate
//! queues allocated once during initialization.

const std = @import("std");

pub fn Pipeline(
    comptime Decoder: type,
    comptime Coding: type,
    comptime Error: type,
    comptime Result: type,
    comptime Status: type,
) type {
    return struct {
        allocator: std.mem.Allocator,
        layers: []Decoder,
        queues: []Queue,
        queue_storage: []u8,
        eof: bool = false,

        const Self = @This();

        const Queue = struct {
            storage: []u8,
            start: usize = 0,
            end: usize = 0,

            fn readable(self: Queue) []const u8 {
                return self.storage[self.start..self.end];
            }

            fn writable(self: *Queue) []u8 {
                if (self.end == self.storage.len and self.start != 0) {
                    const pending = self.end - self.start;
                    std.mem.copyForwards(
                        u8,
                        self.storage[0..pending],
                        self.storage[self.start..self.end],
                    );
                    self.start = 0;
                    self.end = pending;
                }
                return self.storage[self.end..];
            }

            fn consume(self: *Queue, count: usize) void {
                std.debug.assert(count <= self.end - self.start);
                self.start += count;
                if (self.start == self.end) {
                    self.start = 0;
                    self.end = 0;
                }
            }

            fn produce(self: *Queue, count: usize) void {
                std.debug.assert(count <= self.storage.len - self.end);
                self.end += count;
            }

            fn reset(self: *Queue) void {
                self.start = 0;
                self.end = 0;
            }

            fn empty(self: Queue) bool {
                return self.start == self.end;
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            codings: []const Coding,
            options: anytype,
        ) Error!Self {
            var layer_count: usize = 0;
            for (codings) |coding| {
                layer_count += @intFromBool(coding != .identity);
            }
            std.debug.assert(layer_count > 1);

            const layers = try allocator.alloc(Decoder, layer_count);
            errdefer allocator.free(layers);
            var initialized: usize = 0;
            errdefer {
                for (layers[0..initialized]) |*layer| layer.deinit();
            }

            var source_index = codings.len;
            while (source_index != 0) {
                source_index -= 1;
                const coding = codings[source_index];
                if (coding == .identity) continue;
                var layer_options = options;
                if (initialized != 0) {
                    layer_options.max_encoded_bytes =
                        options.max_decoded_bytes;
                }
                layers[initialized] = try Decoder.init(
                    allocator,
                    coding,
                    layer_options,
                );
                initialized += 1;
            }
            std.debug.assert(initialized == layer_count);

            const queue_count = layer_count - 1;
            const queues = try allocator.alloc(Queue, queue_count);
            errdefer allocator.free(queues);
            const requested_capacity = @max(
                @as(usize, 1),
                options.intermediate_buffer_bytes,
            );
            const queue_capacity = @max(
                @as(usize, 1),
                @min(requested_capacity, options.max_decoded_bytes),
            );
            const storage_len = std.math.mul(
                usize,
                queue_count,
                queue_capacity,
            ) catch return error.OutOfMemory;
            const queue_storage = try allocator.alloc(u8, storage_len);
            errdefer allocator.free(queue_storage);
            for (queues, 0..) |*queue, index| {
                const start = index * queue_capacity;
                queue.* = .{
                    .storage = queue_storage[start..][0..queue_capacity],
                };
            }
            return .{
                .allocator = allocator,
                .layers = layers,
                .queues = queues,
                .queue_storage = queue_storage,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.layers) |*layer| layer.deinit();
            self.allocator.free(self.queue_storage);
            self.allocator.free(self.queues);
            self.allocator.free(self.layers);
            self.* = undefined;
        }

        pub fn reset(self: *Self) void {
            for (self.layers) |*layer| layer.reset();
            for (self.queues) |*queue| queue.reset();
            self.eof = false;
        }

        pub fn step(
            self: *Self,
            input: []const u8,
            output: []u8,
        ) Error!Result {
            if (self.eof) return error.InvalidDecoderState;
            return self.pump(input, output, false);
        }

        pub fn finish(self: *Self, output: []u8) Error!Result {
            self.eof = true;
            return self.pump(&.{}, output, true);
        }

        fn pump(
            self: *Self,
            input: []const u8,
            output: []u8,
            eof: bool,
        ) Error!Result {
            var input_read: usize = 0;
            var output_written: usize = 0;

            while (true) {
                var made_progress = false;
                var layer_index = self.layers.len;
                while (layer_index != 0) {
                    layer_index -= 1;
                    const layer = &self.layers[layer_index];
                    const source = if (layer_index == 0)
                        input[input_read..]
                    else
                        self.queues[layer_index - 1].readable();
                    const destination = if (layer_index + 1 ==
                        self.layers.len)
                        output[output_written..]
                    else
                        self.queues[layer_index].writable();

                    const was_finished = layer.finished();
                    const upstream_finished = if (layer_index == 0)
                        eof
                    else
                        self.layers[layer_index - 1].finished() and
                            self.queues[layer_index - 1].empty();
                    const result = if (source.len != 0)
                        try layer.step(source, destination)
                    else if (upstream_finished)
                        try layer.finish(destination)
                    else if (!was_finished)
                        try layer.step(&.{}, destination)
                    else
                        continue;

                    if (layer_index == 0) {
                        input_read += result.input_read;
                    } else {
                        self.queues[layer_index - 1]
                            .consume(result.input_read);
                    }
                    if (layer_index + 1 == self.layers.len) {
                        output_written += result.output_written;
                    } else {
                        self.queues[layer_index]
                            .produce(result.output_written);
                    }
                    made_progress = made_progress or
                        result.input_read != 0 or
                        result.output_written != 0 or
                        (!was_finished and layer.finished());
                }

                if (self.hasTrailingIntermediate()) {
                    return error.InvalidContentEncoding;
                }

                if (self.allFinished() and self.queuesEmpty()) {
                    return .{
                        .input_read = input_read,
                        .output_written = output_written,
                        .status = Status.done,
                    };
                }
                if (!made_progress) break;
            }

            if (output_written == output.len or input_read != input.len) {
                return .{
                    .input_read = input_read,
                    .output_written = output_written,
                    .status = Status.need_output,
                };
            }
            if (eof) return error.InvalidContentEncoding;
            return .{
                .input_read = input_read,
                .output_written = output_written,
                .status = Status.need_input,
            };
        }

        fn allFinished(self: Self) bool {
            for (self.layers) |layer| {
                if (!layer.finished()) return false;
            }
            return true;
        }

        fn queuesEmpty(self: Self) bool {
            for (self.queues) |queue| {
                if (!queue.empty()) return false;
            }
            return true;
        }

        fn hasTrailingIntermediate(self: Self) bool {
            for (self.queues, 1..) |queue, downstream_index| {
                if (self.layers[downstream_index].finished() and
                    !queue.empty())
                {
                    return true;
                }
            }
            return false;
        }
    };
}
