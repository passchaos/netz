const std = @import("std");
const Backend = @import("../../../../runtime.zig").Backend;
const pair_mod = @import("../test_support/pair.zig");

const Spy = struct {
    inspected: usize = 0,
    maintained: usize = 0,

    fn inspect(self: *Spy, _: ?std.Io.Clock.Timestamp) error{}!void {
        self.inspected += 1;
    }

    fn maintain(self: *Spy, _: ?std.Io.Clock.Timestamp) error{}!void {
        self.maintained += 1;
    }

    fn progress(self: *Spy) Progress {
        return .{ .spy = self };
    }

    const Progress = struct {
        pub const ErrorSet = error{};
        spy: *Spy,

        pub fn inspect(self: Progress, deadline: ?std.Io.Clock.Timestamp) ErrorSet!void {
            return self.spy.inspect(deadline);
        }

        pub fn maintain(self: Progress, deadline: ?std.Io.Clock.Timestamp) ErrorSet!void {
            return self.spy.maintain(deadline);
        }
    };
};

test "HTTP/3 CONNECT DATAGRAM rejected callback send clears batch progress" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: pair_mod.Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    pair.client.callback_reader_active = true;
    defer pair.client.callback_reader_active = false;
    var committed: usize = 7;
    try std.testing.expectError(error.ConcurrentRead, pair.client.sendConnectDatagramsWithTimeout(0, &.{"data"}, &committed, .fromSeconds(1)));
    try std.testing.expectEqual(@as(usize, 0), committed);
}

test "HTTP/3 CONNECT DATAGRAM dispatcher rejection clears receive progress" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: pair_mod.Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    inline for (.{ true, false }) |client| {
        const owner = if (client) &pair.client else &pair.server;
        owner.dispatcher_bound = true;
        defer owner.dispatcher_bound = false;
        var storage: [8]u8 = @splat(0xaa);
        var outputs = [_][]u8{&storage};
        var received: usize = 7;
        try std.testing.expectError(error.InvalidDispatcherState, owner.receiveConnectDatagramsInto(0, &outputs, &received));
        try std.testing.expectEqual(@as(usize, 0), received);
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 8), &storage);
    }
}

test "HTTP/3 CONNECT DATAGRAM callback receive rejects before protocol inspection" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: pair_mod.Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    pair.client.callback_reader_active = true;
    defer pair.client.callback_reader_active = false;
    var spy = Spy{};
    try std.testing.expectError(error.ConcurrentRead, pair.client.receiveConnectDatagramWithProgress(0, null, spy.progress()));
    try std.testing.expectEqual(@as(usize, 0), spy.inspected);
    try std.testing.expectEqual(@as(usize, 0), spy.maintained);
}

test "HTTP/3 CONNECT DATAGRAM all callback receive forms reject before inspection" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: pair_mod.Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    pair.client.callback_reader_active = true;
    defer pair.client.callback_reader_active = false;
    var spy = Spy{};
    var storage: [8]u8 = @splat(0xaa);
    var outputs = [_][]u8{&storage};
    var received: usize = 7;
    try std.testing.expectError(error.ConcurrentRead, pair.client.receiveConnectDatagramIntoWithProgress(0, &storage, null, spy.progress()));
    try std.testing.expectError(error.ConcurrentRead, pair.client.receiveConnectDatagramsIntoWithProgress(0, &outputs, &received, null, spy.progress()));
    try std.testing.expectEqual(@as(usize, 0), received);
    try std.testing.expectEqual(@as(usize, 0), spy.inspected);
    try std.testing.expectEqual(@as(usize, 0), spy.maintained);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 8), &storage);
}

test "HTTP/3 CONNECT DATAGRAM invalid receive preflight never invokes protocol callbacks" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: pair_mod.Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    inline for (.{ true, false }) |client| {
        const owner = if (client) &pair.client else &pair.server;
        var spy = Spy{};
        var storage: [8]u8 = @splat(0xaa);
        var outputs = [_][]u8{&storage};
        var received: usize = 7;
        try std.testing.expectError(error.UnexpectedStream, owner.receiveConnectDatagramsIntoWithProgress(2, &outputs, &received, null, spy.progress()));
        try std.testing.expectEqual(@as(usize, 0), received);
        received = 7;
        try std.testing.expectError(error.Timeout, owner.receiveConnectDatagramsIntoWithProgress(0, &outputs, &received, .{ .clock = .awake, .raw = .zero }, spy.progress()));
        try std.testing.expectEqual(@as(usize, 0), received);
        owner.control.settings.peer.h3_datagram = false;
        try std.testing.expectError(error.DatagramsNotNegotiated, owner.receiveConnectDatagramIntoWithProgress(0, &storage, null, spy.progress()));
        owner.control.settings.peer.h3_datagram = true;
        try std.testing.expectEqual(@as(usize, 0), spy.inspected);
        try std.testing.expectEqual(@as(usize, 0), spy.maintained);
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 8), &storage);
    }
}

test "HTTP/3 CONNECT DATAGRAM fulfilled input uses nonblocking buffered inspection" {
    const BudgetSensitive = struct {
        const Parent = @This();
        inspections: usize = 0,

        const Progress = struct {
            pub const ErrorSet = error{Timeout};
            state: *Parent,

            pub fn inspect(self: @This(), until: ?std.Io.Clock.Timestamp) error{Timeout}!void {
                // A bounded inspection after the receive turn models a budget
                // that expired while parsing the fulfilled packet.
                if (until != null and self.state.inspections != 0) return error.Timeout;
                self.state.inspections += 1;
            }

            pub fn maintain(_: @This(), _: ?std.Io.Clock.Timestamp) error{Timeout}!void {}
        };
    };
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const Mode = enum { owned, into, batch };
    inline for (.{ true, false }) |client| {
        inline for (std.meta.tags(Mode)) |mode| {
            var pair: pair_mod.Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const owner = if (client) &pair.client else &pair.server;
            const peer = if (client) &pair.server else &pair.client;
            try peer.sendConnectDatagram(0, "delivered");
            var budget = BudgetSensitive{};
            const progress = BudgetSensitive.Progress{ .state = &budget };
            const until = std.Io.Clock.Timestamp.fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            var storage: [16]u8 = undefined;
            switch (mode) {
                .owned => {
                    var value = try owner.receiveConnectDatagramWithProgress(0, until, progress);
                    defer value.deinit(std.testing.allocator);
                    try std.testing.expectEqualStrings("delivered", value.payload);
                },
                .into => try std.testing.expectEqualStrings("delivered", try owner.receiveConnectDatagramIntoWithProgress(0, &storage, until, progress)),
                .batch => {
                    var outputs = [_][]u8{&storage};
                    var received: usize = 7;
                    try owner.receiveConnectDatagramsIntoWithProgress(0, &outputs, &received, until, progress);
                    try std.testing.expectEqual(@as(usize, 1), received);
                    try std.testing.expectEqualStrings("delivered", outputs[0]);
                },
            }
            try std.testing.expect(budget.inspections >= 2);
            try std.testing.expectEqual(@as(usize, 0), try owner.connect_datagrams.queuedCount(0));
        }
    }
}

test "HTTP/3 CONNECT DATAGRAM buffered inspection still propagates protocol rejection" {
    const Reject = struct {
        pub const ErrorSet = error{InvalidCapsule};
        output: []const u8,

        pub fn inspect(self: @This(), _: ?std.Io.Clock.Timestamp) ErrorSet!void {
            if (self.output[0] == 'd') return error.InvalidCapsule;
        }

        pub fn maintain(_: @This(), _: ?std.Io.Clock.Timestamp) ErrorSet!void {}
    };
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    var pair: pair_mod.Pair = undefined;
    try pair.init(backend.io());
    defer pair.deinit();
    try pair.server.sendConnectDatagram(0, "delivered");
    var storage: [16]u8 = @splat(0);
    const progress = Reject{ .output = &storage };
    try std.testing.expectError(error.InvalidCapsule, pair.client.receiveConnectDatagramIntoWithProgress(0, &storage, .fromNow(backend.io(), .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    }), progress));
    try std.testing.expectEqualStrings("delivered", storage[0..9]);
}
