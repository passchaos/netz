const std = @import("std");
const http3 = @import("../../../mod.zig");
const Error = @import("../../error.zig").Error;

const Method = union(enum) {
    get,
    head,
    post,
    put,
    delete,
    connect,
    options,
    trace,
    patch,
    custom: []u8,

    fn init(allocator: std.mem.Allocator, method: []const u8) !Method {
        inline for (.{
            .{ "GET", Method.get },
            .{ "HEAD", Method.head },
            .{ "POST", Method.post },
            .{ "PUT", Method.put },
            .{ "DELETE", Method.delete },
            .{ "CONNECT", Method.connect },
            .{ "OPTIONS", Method.options },
            .{ "TRACE", Method.trace },
            .{ "PATCH", Method.patch },
        }) |mapping| {
            if (std.mem.eql(u8, method, mapping[0])) return mapping[1];
        }
        return .{ .custom = try allocator.dupe(u8, method) };
    }

    fn deinit(self: *Method, allocator: std.mem.Allocator) void {
        if (self.* == .custom) allocator.free(self.custom);
        self.* = undefined;
    }

    fn bytes(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .head => "HEAD",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
            .connect => "CONNECT",
            .options => "OPTIONS",
            .trace => "TRACE",
            .patch => "PATCH",
            .custom => |value| value,
        };
    }
};

const Semantics = struct {
    method: Method,
    extended_connect: bool,

    fn init(
        allocator: std.mem.Allocator,
        method: []const u8,
        extended_connect: bool,
    ) !Semantics {
        return .{
            .method = try .init(allocator, method),
            .extended_connect = extended_connect,
        };
    }

    fn deinit(self: *Semantics, allocator: std.mem.Allocator) void {
        self.method.deinit(allocator);
        self.* = undefined;
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMapUnmanaged(u62, Semantics) = .empty,
    /// Highest client-initiated bidirectional stream ID allocated locally.
    /// IDs are monotonic and shared by HTTP requests and extension streams.
    /// An allocated ID absent from `entries` therefore needs no tombstone.
    highest_allocated_stream_id: ?u62 = null,
    max_streams: usize,

    pub fn init(allocator: std.mem.Allocator, max_streams: usize) Client {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    pub fn deinit(self: *Client) void {
        var iterator = self.entries.valueIterator();
        while (iterator.next()) |semantics| semantics.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn open(
        self: *Client,
        stream_id: u62,
        method: []const u8,
        extended_connect: bool,
    ) Error!void {
        if (self.entries.count() >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        if (self.entries.contains(stream_id)) return error.UnexpectedStream;
        var semantics = try Semantics.init(
            self.allocator,
            method,
            extended_connect,
        );
        var semantics_owned = true;
        errdefer if (semantics_owned) semantics.deinit(self.allocator);
        try self.entries.putNoClobber(self.allocator, stream_id, semantics);
        semantics_owned = false;
    }

    pub fn contains(self: Client, stream_id: u62) bool {
        return self.entries.count() != 0 and self.entries.contains(stream_id);
    }

    pub fn isEmpty(self: Client) bool {
        return self.entries.count() == 0;
    }

    pub fn count(self: Client) usize {
        return self.entries.count();
    }

    pub fn isFinished(self: Client, stream_id: u62) bool {
        if ((stream_id & 0x03) != 0) return false;
        const highest = self.highest_allocated_stream_id orelse return false;
        return stream_id <= highest and !self.contains(stream_id);
    }

    pub fn markAllocated(self: *Client, stream_id: u62) void {
        std.debug.assert((stream_id & 0x03) == 0);
        self.highest_allocated_stream_id =
            if (self.highest_allocated_stream_id) |highest|
                @max(highest, stream_id)
            else
                stream_id;
    }

    pub fn responseDecodeOptions(
        self: Client,
        stream_id: u62,
    ) http3.ResponseDecodeOptions {
        const value = self.entries.get(stream_id) orelse return .{};
        return .{
            .request_method = value.method.bytes(),
            .extended_connect = value.extended_connect,
        };
    }

    pub fn matchesRequest(
        self: Client,
        stream_id: u62,
        method: []const u8,
        extended_connect: bool,
    ) bool {
        const value = self.entries.get(stream_id) orelse return false;
        return value.extended_connect == extended_connect and
            std.mem.eql(u8, value.method.bytes(), method);
    }

    pub fn finish(self: *Client, stream_id: u62) Error!bool {
        return self.finishAssumeCapacity(stream_id);
    }

    pub fn prepareFinish(self: *Client) std.mem.Allocator.Error!void {
        _ = self;
    }

    pub fn finishAssumeCapacity(self: *Client, stream_id: u62) bool {
        var removed = self.entries.fetchRemove(stream_id) orelse return false;
        removed.value.deinit(self.allocator);
        return true;
    }
};

test "HTTP/3 client request lifecycle indexes outstanding streams" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 3);
    defer lifecycle.deinit();

    try std.testing.expect(lifecycle.isEmpty());
    try lifecycle.open(0, "GET", false);
    lifecycle.markAllocated(0);
    try lifecycle.open(4, "HEAD", false);
    lifecycle.markAllocated(4);
    try lifecycle.open(8, "CONNECT", true);
    lifecycle.markAllocated(8);
    try std.testing.expectEqual(@as(usize, 3), lifecycle.count());
    try std.testing.expect(lifecycle.contains(0));
    try std.testing.expect(lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expectError(
        error.ExcessiveLoad,
        lifecycle.open(12, "GET", false),
    );
    try std.testing.expectEqualStrings(
        "HEAD",
        lifecycle.responseDecodeOptions(4).request_method.?,
    );
    try std.testing.expect(lifecycle.responseDecodeOptions(8).extended_connect);

    try std.testing.expect(try lifecycle.finish(4));
    try std.testing.expect(!lifecycle.contains(4));
    try std.testing.expect(lifecycle.isFinished(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expect(try lifecycle.finish(8));
    try std.testing.expect(!lifecycle.contains(8));

    try lifecycle.open(12, "POST", false);
    lifecycle.markAllocated(12);
    try std.testing.expect(lifecycle.contains(12));
    try std.testing.expect(!try lifecycle.finish(4));
    try std.testing.expect(try lifecycle.finish(0));
    try std.testing.expect(try lifecycle.finish(12));
    try std.testing.expect(lifecycle.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.entries.count());
    try std.testing.expect(lifecycle.isFinished(0));
    try std.testing.expect(lifecycle.isFinished(4));
    try std.testing.expect(lifecycle.isFinished(8));
    try std.testing.expect(lifecycle.isFinished(12));
    try std.testing.expect(!lifecycle.isFinished(16));
    try std.testing.expect(!lifecycle.isFinished(1));

    lifecycle.markAllocated(16);
    try std.testing.expect(lifecycle.isFinished(16));
    try lifecycle.open(20, "GET", false);
    try std.testing.expect(!lifecycle.isFinished(20));
    lifecycle.markAllocated(20);
    try std.testing.expect(try lifecycle.finish(20));
    try std.testing.expect(lifecycle.isFinished(20));
}

test "HTTP/3 client request lifecycle preserves custom method identity" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 2);
    defer lifecycle.deinit();
    var method = [_]u8{ 'F', 'O', 'O' };
    try lifecycle.open(0, &method, false);
    method[0] = 'B';
    try std.testing.expect(lifecycle.matchesRequest(0, "FOO", false));
    try std.testing.expect(!lifecycle.matchesRequest(0, "BOO", false));
    try std.testing.expectEqualStrings(
        "FOO",
        lifecycle.responseDecodeOptions(0).request_method.?,
    );
}

test "HTTP/3 client request lifecycle does not mark uncommitted opens" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 2);
    defer lifecycle.deinit();

    try lifecycle.open(0, "GET", false);
    try std.testing.expect(!lifecycle.isFinished(0));
    try std.testing.expect(try lifecycle.finish(0));
    try std.testing.expect(!lifecycle.isFinished(0));

    lifecycle.markAllocated(0);
    try std.testing.expect(lifecycle.isFinished(0));
    lifecycle.markAllocated(4);
    try std.testing.expect(lifecycle.isFinished(4));
    try std.testing.expect(!lifecycle.isFinished(8));
}

test "HTTP/3 client request lifecycle finish is allocation free" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 1);
    defer lifecycle.deinit();

    try lifecycle.open(0, "GET", false);
    lifecycle.markAllocated(0);
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    lifecycle.allocator = fail.allocator();
    try std.testing.expect(try lifecycle.finish(0));
    lifecycle.allocator = allocator;
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expect(lifecycle.isFinished(0));
}

test "HTTP/3 client standard request methods need no owned string" {
    const allocator = std.testing.allocator;
    var lifecycle = Client.init(allocator, 9);
    defer lifecycle.deinit();
    try lifecycle.entries.ensureTotalCapacity(allocator, 9);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    lifecycle.allocator = no_alloc.allocator();
    inline for (.{
        "GET",     "HEAD",    "POST",  "PUT",   "DELETE",
        "CONNECT", "OPTIONS", "TRACE", "PATCH",
    }, 0..) |method, index| {
        try lifecycle.open(@intCast(index * 4), method, false);
    }
    lifecycle.allocator = allocator;
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "HTTP/3 client request lifecycle rolls back every custom method allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        openCustomMethodForTest,
        .{},
    );
}

fn openCustomMethodForTest(allocator: std.mem.Allocator) !void {
    var lifecycle = Client.init(allocator, 1);
    defer lifecycle.deinit();
    try lifecycle.open(0, "CUSTOM-METHOD", false);
    try std.testing.expect(lifecycle.matchesRequest(
        0,
        "CUSTOM-METHOD",
        false,
    ));
}
