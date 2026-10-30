//! Own ORCA OOB request and metadata across background reconnects.
const std = @import("std");
const oob = @import("../../../orca/oob.zig");
const streaming = @import("../../../stream/runtime.zig");
const inputs = @import("../request_inputs.zig");

pub const Options = oob.ClientOptions;

pub const Config = struct {
    allocator: std.mem.Allocator,
    request: []u8,
    inputs: inputs.Inputs,
    options: oob.ClientOptions,

    pub fn init(
        allocator: std.mem.Allocator,
        source: oob.ClientOptions,
    ) oob.Error!Config {
        const request = try oob.encodeRequestAlloc(allocator, .{
            .report_interval = source.report_interval,
            .request_cost_names = source.request_cost_names,
        });
        errdefer allocator.free(request);
        const cloned = try inputs.clone(allocator, streaming.RequestOptions{
            .path = oob.path,
            .authority = source.authority,
            .scheme = source.scheme,
            .metadata = source.metadata,
            .binary_metadata = source.binary_metadata,
            .accepted_encodings = source.accepted_encodings,
            .max_message_size = source.max_message_size,
        });
        return .{
            .allocator = allocator,
            .request = request,
            .inputs = cloned.inputs,
            .options = .{
                .report_interval = source.report_interval,
                // The serialized request owns these values; reconnect does
                // not need the caller's original slices.
                .request_cost_names = &.{},
                .authority = cloned.options.authority,
                .scheme = cloned.options.scheme,
                .metadata = cloned.options.metadata,
                .binary_metadata = cloned.options.binary_metadata,
                .accepted_encodings = cloned.options.accepted_encodings,
                .max_message_size = cloned.options.max_message_size,
            },
        };
    }

    pub fn deinit(self: *Config) void {
        self.inputs.deinit();
        self.allocator.free(self.request);
        self.* = undefined;
    }
};
