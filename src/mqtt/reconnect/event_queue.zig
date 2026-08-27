//! Owned event queue adapter for a single-owner MQTT reconnect loop.

const std = @import("std");

pub fn Queue(comptime Event: type) type {
    return struct {
        const Self = @This();

        pub const Error = std.Io.Cancelable || error{EventQueueClosed};
        pub const ReceiveTimeoutError = Error || std.Io.Timeout.Error ||
            std.Io.ConcurrentError;

        pub const OwnedEvent = struct {
            value: Event,
            allocator: std.mem.Allocator,
            owner: *Self,

            pub fn deinit(self: *OwnedEvent) void {
                self.value.deinit(self.allocator);
                const previous = self.owner.outstanding.fetchSub(1, .release);
                std.debug.assert(previous != 0);
                self.* = undefined;
            }
        };

        allocator: std.mem.Allocator,
        io: std.Io,
        storage: []OwnedEvent,
        queue: std.Io.Queue(OwnedEvent),
        outstanding: std.atomic.Value(usize) = .init(0),

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            capacity: usize,
        ) std.mem.Allocator.Error!Self {
            const storage = try allocator.alloc(OwnedEvent, capacity);
            return .{
                .allocator = allocator,
                .io = io,
                .storage = storage,
                .queue = .init(storage),
            };
        }

        /// Close the queue and destroy events that have not been received.
        /// Every event already returned to a consumer must be deinitialized
        /// first because it retains this queue for ownership accounting.
        pub fn deinit(self: *Self) void {
            self.close();
            while (true) {
                var events: [1]OwnedEvent = undefined;
                const count = self.queue.getUncancelable(
                    self.io,
                    &events,
                    0,
                ) catch break;
                if (count == 0) break;
                events[0].deinit();
            }
            // Returned events retain this queue pointer for accounting and
            // must be released before the queue's storage is destroyed.
            std.debug.assert(self.outstanding.load(.acquire) == 0);
            self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn receive(self: *Self) Error!OwnedEvent {
            return self.queue.getOne(self.io) catch |err| switch (err) {
                error.Closed => error.EventQueueClosed,
                error.Canceled => error.Canceled,
            };
        }

        pub fn tryReceive(self: *Self) Error!?OwnedEvent {
            var events: [1]OwnedEvent = undefined;
            const count = self.queue.get(self.io, &events, 0) catch |err|
                switch (err) {
                    error.Closed => return error.EventQueueClosed,
                    error.Canceled => return error.Canceled,
                };
            return if (count == 0) null else events[0];
        }

        /// Wait for one event until `timeout` elapses. If the event and timer
        /// complete concurrently, any unselected owned event is reclaimed.
        pub fn receiveTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) ReceiveTimeoutError!OwnedEvent {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            const Wake = union(enum) {
                event: (std.Io.QueueClosedError ||
                    std.Io.Cancelable)!OwnedEvent,
                timeout: std.Io.Cancelable!void,
            };
            var buffer: [2]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(self.io, &buffer);
            defer while (select.cancel()) |wake| switch (wake) {
                .event => |result| if (result) |owned_value| {
                    var owned = owned_value;
                    owned.deinit();
                } else |_| {},
                .timeout => {},
            };
            try select.concurrent(.event, receiveRaw, .{self});
            try select.concurrent(.timeout, waitForTimeout, .{ self.io, timeout });
            return switch (try select.await()) {
                .event => |result| result catch |err| switch (err) {
                    error.Closed => error.EventQueueClosed,
                    error.Canceled => error.Canceled,
                },
                .timeout => |result| {
                    try result;
                    return error.Timeout;
                },
            };
        }

        pub fn close(self: *Self) void {
            self.queue.close(self.io);
        }

        /// Transfer one event into the queue. The caller retains ownership if
        /// this returns an error and must invalidate its copy after success.
        /// `event_allocator` must be the allocator that owns the event payload;
        /// it may differ from the allocator used for queue storage.
        pub fn send(
            self: *Self,
            event: Event,
            event_allocator: std.mem.Allocator,
        ) Error!void {
            _ = self.outstanding.fetchAdd(1, .monotonic);
            errdefer {
                const previous = self.outstanding.fetchSub(1, .release);
                std.debug.assert(previous != 0);
            }
            self.queue.putOne(self.io, .{
                .value = event,
                .allocator = event_allocator,
                .owner = self,
            }) catch |err| switch (err) {
                error.Closed => return error.EventQueueClosed,
                error.Canceled => return error.Canceled,
            };
        }

        fn receiveRaw(
            self: *Self,
        ) (std.Io.QueueClosedError || std.Io.Cancelable)!OwnedEvent {
            return self.queue.getOne(self.io);
        }

        fn waitForTimeout(
            io: std.Io,
            timeout: std.Io.Duration,
        ) std.Io.Cancelable!void {
            try std.Io.sleep(io, timeout, .awake);
        }
    };
}

test "MQTT event queue transfers ownership and drains on deinit" {
    const TestEvent = struct {
        bytes: []u8,

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.bytes);
            self.* = undefined;
        }
    };
    const TestQueue = Queue(TestEvent);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try TestQueue.init(std.testing.allocator, io, 2);
    try std.testing.expect((try queue.tryReceive()) == null);

    try queue.send(
        .{ .bytes = try std.testing.allocator.dupe(u8, "first") },
        std.testing.allocator,
    );
    try queue.send(
        .{ .bytes = try std.testing.allocator.dupe(u8, "drained") },
        std.testing.allocator,
    );
    var first = try queue.receive();
    try std.testing.expectEqualStrings("first", first.value.bytes);
    first.deinit();
    queue.deinit();
}

test "MQTT event queue receive timeout returns data and timeout" {
    const TestEvent = struct {
        bytes: []u8,

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.bytes);
            self.* = undefined;
        }
    };
    const TestQueue = Queue(TestEvent);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try TestQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    try std.testing.expectError(
        error.Timeout,
        queue.receiveTimeout(.fromMilliseconds(1)),
    );
    try queue.send(
        .{ .bytes = try std.testing.allocator.dupe(u8, "ready") },
        std.testing.allocator,
    );
    var event = try queue.receiveTimeout(.fromSeconds(1));
    defer event.deinit();
    try std.testing.expectEqualStrings("ready", event.value.bytes);
}

test "MQTT event queue close wakes a blocked producer" {
    const TestEvent = struct {
        bytes: []u8,

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.bytes);
            self.* = undefined;
        }
    };
    const TestQueue = Queue(TestEvent);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try TestQueue.init(std.testing.allocator, io, 0);
    defer queue.deinit();

    const Producer = struct {
        io: std.Io,
        queue: *TestQueue,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var event = TestQueue.OwnedEvent{
                .value = .{
                    .bytes = std.testing.allocator.dupe(u8, "blocked") catch {
                        self.err = error.OutOfMemory;
                        return;
                    },
                },
                .allocator = std.testing.allocator,
                .owner = self.queue,
            };
            self.started.set(self.io);
            self.queue.send(event.value, event.allocator) catch |err| {
                event.value.deinit(event.allocator);
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var producer = Producer{ .io = io, .queue = &queue };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    queue.close();
    thread.join();
    try std.testing.expectEqual(error.EventQueueClosed, producer.err.?);
}
