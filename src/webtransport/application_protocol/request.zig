//! Owned request offer, retained through the CONNECT response. It does not
//! borrow client option strings after a dispatcher-driven begin returns.

const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const protocol = @import("../application_protocol.zig");

pub const Request = struct {
    header: [1]http3.Qpack.HeaderField = .{.{ .name = protocol.available_header, .value = &.{} }},
    present: bool = false,
    required: bool = false,

    pub fn init(allocator: std.mem.Allocator, policy: protocol.Policy, additional: []const http3.Qpack.HeaderField) protocol.Error!Request {
        try protocol.validateRequestPolicy(policy, additional);
        var result = Request{ .required = policy.required };
        var count: usize = 0;
        var length: usize = 0;
        for (additional) |field| {
            if (!std.ascii.eqlIgnoreCase(field.name, protocol.available_header)) continue;
            if (policy.values.len != 0) return error.InvalidApplicationProtocol;
            if (count != 0) length = std.math.add(usize, length, 2) catch return error.IntegerOverflow;
            length = std.math.add(usize, length, field.value.len) catch return error.IntegerOverflow;
            count += 1;
        }
        if (policy.values.len != 0) {
            result.header[0].value = try protocol.writeList(allocator, policy.values);
            result.present = true;
        } else if (count != 0) {
            const encoded = try allocator.alloc(u8, length);
            var cursor: usize = 0;
            var first = true;
            for (additional) |field| {
                if (!std.ascii.eqlIgnoreCase(field.name, protocol.available_header)) continue;
                if (!first) {
                    @memcpy(encoded[cursor..][0..2], ", ");
                    cursor += 2;
                }
                @memcpy(encoded[cursor..][0..field.value.len], field.value);
                cursor += field.value.len;
                first = false;
            }
            result.header[0].value = encoded;
            result.present = true;
        }
        errdefer result.deinit(allocator);
        if (policy.required) {
            const values = protocol.offered(result.fields()) orelse return error.InvalidApplicationProtocol;
            if (values.count == 0) return error.InvalidApplicationProtocol;
        }
        return result;
    }

    pub fn fields(self: *const Request) []const http3.Qpack.HeaderField {
        return self.header[0..@intFromBool(self.present)];
    }

    pub fn validateResponse(self: *const Request, response: []const http3.Qpack.HeaderField) protocol.Error!?protocol.String {
        return protocol.validateResponse(self.fields(), response, self.required);
    }

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        if (self.present) allocator.free(self.header[0].value);
        self.* = .{};
    }
};
