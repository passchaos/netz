const std = @import("std");
const content_digest = @import("../../../http/digest.zig");
const http3 = @import("../../mod.zig");
const content_coding = @import("../../../http/content_coding.zig");
const quic = @import("../../../quic/mod.zig");

const net = std.Io.net;

pub const OwnedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    datagram: quic.runtime.OwnedDatagram,
    extra_datagrams: []quic.runtime.OwnedDatagram = &.{},
    bytes: []u8 = &.{},
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.datagram.deinit(allocator);
        for (self.extra_datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn contentEncoding(
        self: OwnedRequest,
    ) content_coding.Error!content_coding.Chain {
        return self.request.contentEncoding();
    }

    pub fn decodeContentAlloc(
        self: OwnedRequest,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return self.request.decodeContentAlloc(allocator, max_output_len);
    }

    pub fn decodeContentInto(
        self: OwnedRequest,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return self.request.decodeContentInto(out, scratch);
    }
};

pub const OwnedRequestBatch = struct {
    allocator: std.mem.Allocator,
    requests: []?OwnedRequest,
    errors: []?anyerror,

    pub fn init(
        allocator: std.mem.Allocator,
        count: usize,
    ) std.mem.Allocator.Error!OwnedRequestBatch {
        const requests = try allocator.alloc(?OwnedRequest, count);
        errdefer allocator.free(requests);
        @memset(requests, null);
        const errors = try allocator.alloc(?anyerror, count);
        @memset(errors, null);
        return .{
            .allocator = allocator,
            .requests = requests,
            .errors = errors,
        };
    }

    pub fn deinit(self: *OwnedRequestBatch) void {
        for (self.requests) |*request| {
            if (request.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.requests);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedRequestBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedRequestBatch) usize {
        var count: usize = 0;
        for (self.requests) |request| {
            count += @intFromBool(request != null);
        }
        return count;
    }

    pub fn successCount(self: OwnedRequestBatch) usize {
        var count: usize = 0;
        for (self.errors) |err| count += @intFromBool(err == null);
        return count;
    }
};

pub const OwnedResponse = struct {
    datagram: quic.runtime.OwnedDatagram,
    extra_datagrams: []quic.runtime.OwnedDatagram = &.{},
    bytes: []u8 = &.{},
    response: http3.DecodedResponse,

    pub fn verifyContentDigest(self: OwnedResponse, policy: content_digest.Policy) content_digest.Error!content_digest.Result {
        return self.response.verifyContentDigest(policy);
    }

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        self.datagram.deinit(allocator);
        for (self.extra_datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};
