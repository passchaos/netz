//! Finite outbound bridge used by the two-Mosquitto process gate.

const std = @import("std");
const netz = @import("netz");

const session_expiry = [_]netz.mqtt.Property{.{ .four_byte = .{
    .id = .session_expiry_interval,
    .value = 60,
} }};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 8 and args.len != 10) return error.InvalidArguments;
    const source_port = try parsePort(args[1]);
    const target_port = try parsePort(args[2]);
    const control_port = try parsePort(args[3]);
    const source_protocol = try parseProtocol(args[4]);
    const target_protocol = try parseProtocol(args[5]);
    const qos = try parseQos(args[6]);
    const case_id = args[7];
    if (case_id.len == 0) return error.InvalidArguments;
    if ((qos == .exactly_once) != (args.len == 10)) {
        return error.InvalidArguments;
    }

    const allocator = init.gpa;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const coordinator_dir: ?std.Io.Dir = if (args.len == 10)
        try std.Io.Dir.openDirAbsolute(io, args[8], .{})
    else
        null;
    defer if (coordinator_dir) |dir| dir.close(io);
    const coordinator_mode: netz.mqtt.bridge.outbound.CoordinatorMode =
        if (args.len == 10)
            try parseCoordinatorMode(args[9])
        else
            .create;
    var bridge_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(case_id, &bridge_digest, .{});

    const source_client_id = try std.fmt.allocPrint(
        allocator,
        "netz-outbound-source-{s}",
        .{case_id},
    );
    defer allocator.free(source_client_id);
    const target_client_id = try std.fmt.allocPrint(
        allocator,
        "netz-outbound-target-{s}",
        .{case_id},
    );
    defer allocator.free(target_client_id);

    var shutdown: std.Io.Event = .unset;
    var bridge = try netz.mqtt.bridge.OutboundBridge.init(
        allocator,
        io,
        try std.Io.net.IpAddress.parse("127.0.0.1", source_port),
        try std.Io.net.IpAddress.parse("127.0.0.1", target_port),
        .{
            .source_connect = .{
                .protocol = source_protocol,
                .client_id = source_client_id,
                .clean_start = false,
                .keep_alive_seconds = 2,
                .properties = propertiesFor(source_protocol),
            },
            .target_connect = .{
                .protocol = target_protocol,
                .client_id = target_client_id,
                .clean_start = false,
                .keep_alive_seconds = 2,
                .properties = propertiesFor(target_protocol),
            },
            .source_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(10),
                .max_delay = .fromMilliseconds(100),
            },
            .target_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(10),
                .max_delay = .fromMilliseconds(100),
            },
            .rule = .{
                .filter = "sensors/#",
                .qos = qos,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
            .coordinator = if (coordinator_dir) |dir| .{
                .bridge_id = bridge_digest[0..16].*,
                .dir = dir,
                .sub_path = "outbound-qos2.log",
                .mode = coordinator_mode,
            } else null,
        },
        &shutdown,
    );
    defer bridge.deinit();

    var control = try std.Io.net.IpAddress.listen(
        &.{ .ip4 = .loopback(control_port) },
        io,
        .{ .reuse_address = true },
    );
    defer control.deinit(io);
    var stop = io.async(waitForStop, .{ io, &control, &shutdown });
    defer stop.cancel(io) catch {};

    const connected = try bridge.connect();
    const expect_resume = coordinator_dir != null and
        coordinator_mode == .restore;
    if (connected.source_session_present != expect_resume or
        connected.target_session_present != expect_resume)
    {
        return error.UnexpectedSessionResume;
    }
    std.debug.print(
        "netz MQTT outbound bridge ready source={s} target={s} qos={d} " ++
            "client_io=zio-std-io brokers=mosquitto\n",
        .{
            @tagName(source_protocol),
            @tagName(target_protocol),
            @intFromEnum(qos),
        },
    );

    try bridge.run(.{
        .timeout = .fromMilliseconds(250),
        .cancellation_check_interval = .fromMilliseconds(10),
    });
    try stop.await(io);
    try bridge.disconnect(0);
}

fn waitForStop(
    io: std.Io,
    server: *std.Io.net.Server,
    shutdown: *std.Io.Event,
) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var read_buffer: [1]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var signal: [1]u8 = undefined;
    if (try reader.interface.readSliceShort(&signal) != 1 or
        signal[0] != 1)
    {
        return error.InvalidStopSignal;
    }
    shutdown.set(io);
}

fn parsePort(value: []const u8) !u16 {
    const port = try std.fmt.parseInt(u16, value, 10);
    if (port == 0) return error.InvalidArguments;
    return port;
}

fn parseProtocol(value: []const u8) !netz.mqtt.ProtocolVersion {
    if (std.mem.eql(u8, value, "v311")) return .v3_1_1;
    if (std.mem.eql(u8, value, "v5")) return .v5;
    return error.InvalidArguments;
}

fn parseQos(value: []const u8) !netz.mqtt.QoS {
    if (std.mem.eql(u8, value, "0")) return .at_most_once;
    if (std.mem.eql(u8, value, "1")) return .at_least_once;
    if (std.mem.eql(u8, value, "2")) return .exactly_once;
    return error.InvalidArguments;
}

fn parseCoordinatorMode(
    value: []const u8,
) !netz.mqtt.bridge.outbound.CoordinatorMode {
    if (std.mem.eql(u8, value, "create")) return .create;
    if (std.mem.eql(u8, value, "restore")) return .restore;
    return error.InvalidArguments;
}

fn propertiesFor(
    protocol: netz.mqtt.ProtocolVersion,
) []const netz.mqtt.Property {
    return if (protocol == .v5) &session_expiry else &.{};
}
