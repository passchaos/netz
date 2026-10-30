//! Official grpc-cpp ORCA out-of-band interoperability server scenario.
const std = @import("std");
const netz = @import("netz");
const messages = @import("../grpc_cpp_messages.zig");

const duplex_path = "/grpc.testing.TestService/FullDuplexCall";

pub fn serve(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    var oob_stream: ?netz.grpc.ServerDuplex = null;
    defer if (oob_stream) |*stream| stream.deinit();
    var business_stream: ?netz.grpc.ServerDuplex = null;
    defer if (business_stream) |*stream| stream.deinit();
    for (0..2) |_| {
        var accepted = try connection.acceptDuplexWithTimeout(
            .fromSeconds(5),
        );
        var moved = false;
        defer if (!moved) accepted.deinit();
        if (std.mem.eql(u8, accepted.path, netz.grpc.orca_oob.path)) {
            if (oob_stream != null) return error.DuplicateOrcaOobStream;
            oob_stream = accepted;
            moved = true;
        } else if (std.mem.eql(u8, accepted.path, duplex_path)) {
            if (business_stream != null) return error.DuplicateBusinessStream;
            business_stream = accepted;
            moved = true;
        } else {
            try accepted.finish(.unimplemented, null, &.{}, &.{});
            return error.UnexpectedMethod;
        }
    }
    if (oob_stream == null or business_stream == null) {
        return error.MissingOrcaOobStream;
    }

    const raw_oob = oob_stream.?;
    oob_stream = null;
    var reports = try netz.grpc.orca_oob.accept(raw_oob);
    defer reports.deinit();
    if (reports.request.request.report_interval.nanoseconds !=
        std.Io.Duration.fromSeconds(1).nanoseconds or
        reports.request.request.request_cost_names.len != 0)
    {
        return error.UnexpectedOrcaOobRequest;
    }
    if (try reports.writeReport(.{}) != .complete) {
        return error.UnexpectedFlowControl;
    }

    var business = business_stream.?;
    business_stream = null;
    defer business.deinit();
    try business.startResponse(.{
        .request_accepted_encodings = business.accepted_encodings,
        .max_message_size = messages.max_payload_size + 64,
    });
    const expected = [_]messages.orca.Report{
        .{
            .cpu_utilization = 0.8210,
            .memory_utilization = 0.5847,
            .request_cost = &.{},
            .utilization = &.{.{ .name = "util", .value = 0.30499 }},
        },
        .{
            .cpu_utilization = 0.29309,
            .memory_utilization = 0.2,
            .request_cost = &.{},
            .utilization = &.{.{ .name = "util", .value = 0.2039 }},
        },
    };
    const response = try messages.encodeStreamingOutputCallResponseAlloc(
        allocator,
        1,
    );
    defer allocator.free(response);
    var consumer = UpdateConsumer{};
    for (expected, 0..) |wanted, index| {
        consumer.expected = wanted;
        consumer.seen = false;
        while (!consumer.seen) {
            var event = try business.readRequestEventWithTimeout(
                .fromSeconds(5),
                &consumer,
                UpdateConsumer.consume,
            );
            defer event.deinit();
            switch (event) {
                .messages => {},
                .finished => return error.MissingOrcaOobUpdate,
                .reset => return error.UnexpectedReset,
            }
        }
        if (try business.writeMessage(response) != .complete) {
            return error.UnexpectedFlowControl;
        }
        try std.Io.sleep(
            connection.connection.io,
            reports.request.request.report_interval,
            .awake,
        );
        const report: netz.grpc.orca.LoadReport = .{
            .cpu_utilization = wanted.cpu_utilization,
            .memory_utilization = wanted.memory_utilization,
            .utilization = &.{.{
                .name = wanted.utilization[0].name,
                .value = wanted.utilization[0].value,
            }},
        };
        if (try reports.writeReport(report) != .complete) {
            return error.UnexpectedFlowControl;
        }
        std.debug.print(
            "netz grpc ORCA OOB update: index={d} cpu={d} memory={d}\n",
            .{ index, wanted.cpu_utilization, wanted.memory_utilization },
        );
    }

    while (true) {
        var event = try business.readRequestEventWithTimeout(
            .fromSeconds(5),
            &consumer,
            UpdateConsumer.reject,
        );
        defer event.deinit();
        switch (event) {
            .messages => |progress| if (progress.count != 0) {
                return error.UnexpectedRequest;
            },
            .finished => |terminal| {
                if (terminal.message_count != expected.len) {
                    return error.UnexpectedRequest;
                }
                break;
            },
            .reset => return error.UnexpectedReset,
        }
    }
    try business.finishOk();
    const reset = reports.waitForPeerResetWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        error.UnexpectedEof,
        => return,
        else => return err,
    };
    if (reset.error_code != .cancel) return error.UnexpectedReset;
}

const UpdateConsumer = struct {
    expected: messages.orca.Report = undefined,
    seen: bool = false,

    fn consume(
        self: *@This(),
        message: netz.grpc.StreamingMessage,
    ) !void {
        if (self.seen or message.was_compressed) {
            return error.UnexpectedRequest;
        }
        var request_cost: [1]messages.orca.Metric = undefined;
        var utilization: [1]messages.orca.Metric = undefined;
        const actual = try messages.orca.decodeOobUpdate(
            message.payload,
            &request_cost,
            &utilization,
        );
        if (actual.cpu_utilization != self.expected.cpu_utilization or
            actual.memory_utilization != self.expected.memory_utilization or
            actual.request_cost.len != 0 or actual.utilization.len != 1 or
            !std.mem.eql(u8, actual.utilization[0].name, "util") or
            actual.utilization[0].value != self.expected.utilization[0].value)
        {
            return error.UnexpectedOrcaOobUpdate;
        }
        self.seen = true;
    }

    fn reject(_: *@This(), _: netz.grpc.StreamingMessage) !void {
        return error.UnexpectedRequest;
    }
};
