//! Owned facade fixtures and a schema-level CSDS decoder for focused tests.
const std = @import("std");
const grpc = @import("../../../../mod.zig");
const managed = @import("../../managed.zig");
const fixture = @import("../testing.zig");
const bootstrap = @import("../../../bootstrap.zig");
const csds = @import("../../../csds.zig");
const pb = @import("../../../../protobuf.zig");
pub const names = fixture;
pub const gpa = std.testing.allocator;
pub const lds = @import("../../../lds.zig");
pub const rds = @import("../../../rds.zig");
pub const cds = @import("../../../cds.zig");
pub const eds = @import("../../../eds.zig");
pub const lds_fixture = @import("../../../lds/testing.zig");
pub const rds_fixture = @import("../../../rds/testing.zig");
pub const cds_fixture = @import("../../../cds/testing.zig");

pub fn Harness(comptime mode: managed.Mode) type {
    return struct {
        const Self = @This();
        io: std.Io,
        config: *bootstrap.Bootstrap,
        data: grpc.SharedChannel,
        facade: *managed.Managed(mode),
        fn configure(options: *@import("../../options.zig").Options) void {
            options.disable_automatic_lrs = true;
        }
        pub fn init(io: std.Io) !Self {
            return initWithDataErrors(io, false);
        }
        pub fn initWithDataErrors(io: std.Io, fail_on_data_errors: bool) !Self {
            const config = try fixture.configuration(1, 2);
            errdefer config.deinit();
            config.authority("A").?.servers[0].resource_timer_is_transient_error = true;
            config.authority("A").?.servers[0].fail_on_data_errors = fail_on_data_errors;
            var data = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
            errdefer data.deinit();
            const facade = try managed.Managed(mode).createForTarget(gpa, io, config, data, "xds://A/frontend", .{ .resolver = .{ .default_authority = "backend.test" }, .configure = configure });
            errdefer facade.deinit();
            _ = try facade.startWithDeadline(fixture.deadline(io));
            return .{ .io = io, .config = config, .data = data, .facade = facade };
        }
        pub fn deinit(self: *Self) void {
            self.facade.deinit();
            self.data.deinit();
            self.config.deinit();
        }
        pub fn event(self: *Self, step: fixture.Step) !managed.Managed(mode).Event {
            return fixture.offline(mode, self.facade, step);
        }
        pub fn accept(self: *Self, step: fixture.Step) !void {
            var update = try self.event(step);
            defer update.deinit();
            try std.testing.expectError(error.AdsNotConnected, self.facade.applyWithDeadline(&update, fixture.deadline(self.io)));
        }
        pub fn routes(self: *Self) !void {
            const listener = try lds_fixture.encode(gpa, .{ .name = fixture.listener, .route_name = fixture.routes });
            defer gpa.free(listener);
            try self.accept(.{ .url = lds.type_url, .name = fixture.listener, .version = "l1", .bytes = listener });
            const routes_wire = try rds_fixture.encode(gpa, fixture.routes, &.{"backend.test"}, &.{
                .{ .exact = "/demo.Service/Alpha", .cluster = fixture.cluster_a },
                .{ .prefix = "/", .cluster = fixture.cluster_b },
            }, null);
            defer gpa.free(routes_wire);
            try self.accept(.{ .url = rds.type_url, .name = fixture.routes, .version = "r1", .bytes = routes_wire });
        }
        pub fn graph(self: *Self) !void {
            try self.routes();
            inline for (.{
                .{ fixture.cluster_a, fixture.endpoint_a, "ca1", "ea1" },
                .{ fixture.cluster_b, fixture.endpoint_b, "cb1", "eb1" },
            }) |pair| {
                const cluster = try cds_fixture.cluster(gpa, pair[0], pair[1], "");
                defer gpa.free(cluster);
                try self.accept(.{ .url = cds.type_url, .name = pair[0], .version = pair[2], .bytes = cluster });
                const assignment = try cds_fixture.assignment(gpa, pair[1], "127.0.0.1", 1001);
                defer gpa.free(assignment);
                try self.accept(.{ .url = eds.type_url, .name = pair[1], .version = pair[3], .bytes = assignment });
            }
        }
        pub fn snapshot(self: *Self, request: []const u8) ![]u8 {
            return self.facade.fetchClientStatus(gpa, request, .{});
        }
    };
}

pub const Dump = struct {
    resources: []csds.Resource,
    node: []const u8 = "",
    scope: []const u8 = "",
    pub fn deinit(self: Dump) void {
        gpa.free(self.resources);
    }
    pub fn find(self: Dump, url: []const u8, name: []const u8) ?csds.Resource {
        for (self.resources) |resource| if (std.mem.eql(u8, resource.type_url, url) and std.mem.eql(u8, resource.name, name)) return resource;
        return null;
    }
};
fn timestamp(bytes: []const u8) !csds.Timestamp {
    var reader = pb.Reader{ .bytes = bytes };
    var value: csds.Timestamp = .{};
    while (try reader.next()) |field| switch (field.number) {
        1 => value.seconds = @bitCast(try reader.varint()),
        2 => value.nanos = @intCast(try reader.varint()),
        else => try reader.skip(field),
    };
    return value;
}
fn failure(bytes: []const u8) !csds.UpdateFailureState {
    var reader = pb.Reader{ .bytes = bytes };
    var value: csds.UpdateFailureState = .{};
    while (try reader.next()) |field| switch (field.number) {
        2 => value.last_update_attempt = try timestamp(try reader.bytesValue()),
        3 => value.details = try reader.bytesValue(),
        4 => value.version_info = try reader.bytesValue(),
        else => try reader.skip(field),
    };
    return value;
}
fn parseResource(bytes: []const u8) !csds.Resource {
    var reader = pb.Reader{ .bytes = bytes };
    var value: csds.Resource = .{ .type_url = "", .name = "", .status = .unknown };
    while (try reader.next()) |field| switch (field.number) {
        1 => value.type_url = try reader.bytesValue(),
        2 => value.name = try reader.bytesValue(),
        3 => value.version = try reader.bytesValue(),
        4 => {
            var any_reader = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try any_reader.next()) |any_field| {
                if (any_field.number == 2) value.wire = try any_reader.bytesValue() else try any_reader.skip(any_field);
            }
        },
        5 => {
            const time = try timestamp(try reader.bytesValue());
            value.last_updated_seconds = time.seconds;
            value.last_updated_nanos = time.nanos;
        },
        7 => value.status = @enumFromInt(try reader.varint()),
        8 => value.error_state = try failure(try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return value;
}
pub fn decode(bytes: []const u8) !Dump {
    var reader = pb.Reader{ .bytes = bytes };
    var result = Dump{ .resources = &.{} };
    var values: std.ArrayList(csds.Resource) = .empty;
    errdefer values.deinit(gpa);
    var clients: usize = 0;
    while (try reader.next()) |field| {
        if (field.number != 1) {
            try reader.skip(field);
            continue;
        }
        clients += 1;
        var client = pb.Reader{ .bytes = try reader.bytesValue() };
        while (try client.next()) |item| switch (item.number) {
            1 => result.node = try client.bytesValue(),
            3 => try values.append(gpa, try parseResource(try client.bytesValue())),
            4 => result.scope = try client.bytesValue(),
            else => try client.skip(item),
        };
    }
    try std.testing.expectEqual(@as(usize, 1), clients);
    result.resources = try values.toOwnedSlice(gpa);
    return result;
}
