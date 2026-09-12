const std = @import("std");
const netz = @import("netz");

const batch_size: usize = 54;
const payload_size: usize = 1152;
const default_iterations: usize = 1_000;
const default_warmup_iterations: usize = 100;

const Mode = enum { all, gro, gro_service, plain, service, visitor };
const FrameShape = enum { padding, stream, stream_gap };

const Options = struct {
    mode: Mode = .all,
    iterations: usize = default_iterations,
    warmup_iterations: usize = default_warmup_iterations,
    frame: FrameShape = .padding,
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const keys = netz.quic.protection.deriveAes128Keys([_]u8{0xb7} ** netz.quic.protection.secret_len);
    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };

    if (options.mode != .all) {
        _ = try measureMode(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            options.mode,
            options.frame,
            options.warmup_iterations,
        );
        const elapsed = try measureMode(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            options.mode,
            options.frame,
            options.iterations,
        );
        const total_packets = options.iterations * batch_size;
        std.debug.print(
            "QUIC 1-RTT receive benchmark: mode={s} frame={s} warmup={d} iterations={d} " ++
                "packets={d} ns/packet={d}\n",
            .{
                @tagName(options.mode),
                @tagName(options.frame),
                options.warmup_iterations,
                options.iterations,
                total_packets,
                elapsed / total_packets,
            },
        );
        return;
    }

    if (options.warmup_iterations != 0) {
        _ = measureMode(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            .gro,
            options.frame,
            options.warmup_iterations,
        ) catch |err| switch (err) {
            error.GroUnavailable => 0,
            else => |other| return other,
        };
        _ = measureMode(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            .gro_service,
            options.frame,
            options.warmup_iterations,
        ) catch |err| switch (err) {
            error.GroUnavailable => 0,
            else => |other| return other,
        };
        inline for (.{ Mode.plain, Mode.service, Mode.visitor }) |mode| {
            _ = try measureMode(
                allocator,
                io,
                keys,
                client_cid,
                server_cid,
                mode,
                options.frame,
                options.warmup_iterations,
            );
        }
    }

    const gro_ns = measure(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        true,
        false,
        options.frame,
        options.iterations,
    ) catch |err| switch (err) {
        error.GroUnavailable => null,
        else => |e| return e,
    };
    const plain_ns = try measure(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        false,
        false,
        options.frame,
        options.iterations,
    );
    const gro_service_ns = measure(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        true,
        true,
        options.frame,
        options.iterations,
    ) catch |err| switch (err) {
        error.GroUnavailable => null,
        else => |e| return e,
    };
    const service_ns = try measure(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        false,
        true,
        options.frame,
        options.iterations,
    );
    const visitor_ns = try measureVisitor(
        allocator,
        io,
        keys,
        client_cid,
        server_cid,
        options.frame,
        options.iterations,
    );
    const total_packets = options.iterations * batch_size;
    if (gro_ns != null and gro_service_ns != null) {
        const gro = gro_ns.?;
        const gro_service = gro_service_ns.?;
        const ratio_x100 = ratioTimes100(plain_ns, gro);
        const service_ratio_x100 = ratioTimes100(gro, gro_service);
        std.debug.print(
            \\QUIC 1-RTT receive benchmark
            \\  frame: {s}, iterations: {d}, packets/batch: {d}, payload bytes/packet: {d}
            \\  GRO batch:    {d} ns/batch, {d} ns/packet
            \\  GRO state service: {d} ns/batch, {d} ns/packet
            \\  plain packet: {d} ns/batch, {d} ns/packet
            \\  in-place service: {d} ns/batch, {d} ns/packet
            \\  borrowed visitor: {d} ns/batch, {d} ns/packet
            \\  GRO relative packet throughput: {d}.{d:0>2}x
            \\  state-only vs owning GRO throughput: {d}.{d:0>2}x
            \\  total packets/path: {d}
            \\
        , .{
            @tagName(options.frame),
            options.iterations,
            batch_size,
            payload_size,
            gro / options.iterations,
            gro / total_packets,
            gro_service / options.iterations,
            gro_service / total_packets,
            plain_ns / options.iterations,
            plain_ns / total_packets,
            service_ns / options.iterations,
            service_ns / total_packets,
            visitor_ns / options.iterations,
            visitor_ns / total_packets,
            ratio_x100 / 100,
            ratio_x100 % 100,
            service_ratio_x100 / 100,
            service_ratio_x100 % 100,
            total_packets,
        });
    } else {
        std.debug.print(
            \\QUIC 1-RTT receive benchmark
            \\  frame: {s}, iterations: {d}, packets/batch: {d}, payload bytes/packet: {d}
            \\  GRO batch:    unavailable on this endpoint
            \\  GRO state service: unavailable on this endpoint
            \\  plain packet: {d} ns/batch, {d} ns/packet
            \\  in-place service: {d} ns/batch, {d} ns/packet
            \\  borrowed visitor: {d} ns/batch, {d} ns/packet
            \\  total packets/path: {d}
            \\
        , .{
            @tagName(options.frame),
            options.iterations,
            batch_size,
            payload_size,
            plain_ns / options.iterations,
            plain_ns / total_packets,
            service_ns / options.iterations,
            service_ns / total_packets,
            visitor_ns / options.iterations,
            visitor_ns / total_packets,
            total_packets,
        });
    }
}

fn measureVisitor(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: netz.quic.protection.PacketProtectionKeys,
    client_cid: [4]u8,
    server_cid: [4]u8,
    frame_shape: FrameShape,
    iteration_count: usize,
) !u64 {
    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer client_endpoint.deinit();
    var server = try netz.quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    var payload_storage: [batch_size][payload_size]u8 = undefined;
    var packet_storage: [batch_size * 1400]u8 = undefined;
    var datagrams: [batch_size][]const u8 = undefined;
    var total_ns: u64 = 0;
    var first_packet_number: u64 = 0;
    var stream_offset: u64 = 0;
    var observed_frames: usize = 0;
    var observed_stream_bytes: usize = 0;
    for (0..iteration_count) |_| {
        _ = try sealPacketBatch(
            &packet_storage,
            &payload_storage,
            &datagrams,
            keys,
            &server_cid,
            first_packet_number,
            frame_shape,
            &stream_offset,
        );
        reorderStreamGapDatagrams(frame_shape, &datagrams);
        try client_endpoint.sendManyBytes(server_endpoint.address(), &datagrams);

        const started = nowNs(io);
        for (0..batch_size) |_| {
            var context = VisitContext{
                .connection = &server,
                .frame_shape = frame_shape,
                .observed_frames = &observed_frames,
                .observed_stream_bytes = &observed_stream_bytes,
            };
            try server.visitPacketAt(
                started,
                &context,
                observePacket,
            );
        }
        total_ns +|= nowNs(io) -| started;
        first_packet_number += batch_size;
    }
    if (observed_frames != iteration_count * batch_size) {
        return error.UnexpectedPacketCount;
    }
    if (isStreamFrame(frame_shape) and
        observed_stream_bytes != stream_offset)
    {
        return error.UnexpectedPacketCount;
    }
    return total_ns;
}

fn measureMode(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: netz.quic.protection.PacketProtectionKeys,
    client_cid: [4]u8,
    server_cid: [4]u8,
    mode: Mode,
    frame_shape: FrameShape,
    iteration_count: usize,
) !u64 {
    return switch (mode) {
        .gro => measure(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            true,
            false,
            frame_shape,
            iteration_count,
        ),
        .gro_service => measure(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            true,
            true,
            frame_shape,
            iteration_count,
        ),
        .plain => measure(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            false,
            false,
            frame_shape,
            iteration_count,
        ),
        .service => measure(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            false,
            true,
            frame_shape,
            iteration_count,
        ),
        .visitor => measureVisitor(
            allocator,
            io,
            keys,
            client_cid,
            server_cid,
            frame_shape,
            iteration_count,
        ),
        .all => error.InvalidArgument,
    };
}

const VisitContext = struct {
    connection: *netz.quic.one_rtt.Connection,
    frame_shape: FrameShape,
    observed_frames: *usize,
    observed_stream_bytes: *usize,
};

fn observePacket(
    context: *VisitContext,
    packet: netz.quic.one_rtt.ReceivedPacketView,
) !void {
    context.observed_frames.* += @intFromBool(packet.frames.len != 0);
    if (isStreamFrame(context.frame_shape)) {
        context.observed_stream_bytes.* += try drainStream(context.connection);
    }
}

fn measure(
    allocator: std.mem.Allocator,
    io: std.Io,
    keys: netz.quic.protection.PacketProtectionKeys,
    client_cid: [4]u8,
    server_cid: [4]u8,
    enable_gro: bool,
    service_in_place: bool,
    frame_shape: FrameShape,
    iteration_count: usize,
) !u64 {
    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 1400,
            .enable_gro_receive = enable_gro,
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer client_endpoint.deinit();
    if (enable_gro and !server_endpoint.groReceiveEnabled()) return error.GroUnavailable;

    var server = try netz.quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    var payload_storage: [batch_size][payload_size]u8 = undefined;
    var packet_storage: [batch_size * 1400]u8 = undefined;
    var datagrams: [batch_size][]const u8 = undefined;
    var total_ns: u64 = 0;
    var first_packet_number: u64 = 0;
    var stream_offset: u64 = 0;
    var observed_stream_bytes: usize = 0;
    for (0..iteration_count) |_| {
        const written = try sealPacketBatch(
            &packet_storage,
            &payload_storage,
            &datagrams,
            keys,
            &server_cid,
            first_packet_number,
            frame_shape,
            &stream_offset,
        );
        _ = written;
        reorderStreamGapDatagrams(frame_shape, &datagrams);
        try client_endpoint.sendManyBytes(server_endpoint.address(), &datagrams);

        const started = nowNs(io);
        if (enable_gro and service_in_place) {
            if (try server.servicePacketBatchAt(started) != batch_size) {
                return error.UnexpectedPacketCount;
            }
            if (isStreamFrame(frame_shape)) {
                observed_stream_bytes += try drainStream(&server);
            }
        } else if (enable_gro) {
            var received = try server.receivePacketBatchAt(started);
            defer received.deinit();
            var consumed: usize = 0;
            while (received.takeNext()) |packet_value| {
                var packet = packet_value;
                packet.deinit(allocator);
                consumed += 1;
            }
            if (consumed != batch_size) {
                return error.UnexpectedPacketCount;
            }
            if (isStreamFrame(frame_shape)) {
                observed_stream_bytes += try drainStream(&server);
            }
        } else if (service_in_place) {
            for (0..batch_size) |_| {
                try server.servicePacketAt(started);
                if (isStreamFrame(frame_shape)) {
                    observed_stream_bytes += try drainStream(&server);
                }
            }
        } else {
            for (0..batch_size) |_| {
                var received = try server.receivePacketAt(started);
                defer received.deinit(allocator);
                if (isStreamFrame(frame_shape)) {
                    observed_stream_bytes += try drainStream(&server);
                }
            }
        }
        total_ns +|= nowNs(io) -| started;
        first_packet_number += batch_size;
    }
    if (isStreamFrame(frame_shape) and
        observed_stream_bytes != stream_offset)
    {
        return error.UnexpectedPacketCount;
    }
    return total_ns;
}

fn parseOptions(init: std.process.Init, allocator: std.mem.Allocator) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--mode=")) {
            options.mode = std.meta.stringToEnum(
                Mode,
                arg["--mode=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup_iterations = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--frame=")) {
            options.frame = std.meta.stringToEnum(
                FrameShape,
                arg["--frame=".len..],
            ) orelse return error.InvalidArgument;
        } else {
            return error.InvalidArgument;
        }
    }
    if (options.iterations == 0) return error.InvalidArgument;
    return options;
}

fn sealPacketBatch(
    storage: []u8,
    payload_storage: *[batch_size][payload_size]u8,
    datagrams: *[batch_size][]const u8,
    keys: netz.quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    first_packet_number: u64,
    frame_shape: FrameShape,
    stream_offset: *u64,
) !usize {
    const first_payload = try fillPayload(
        &payload_storage[0],
        frame_shape,
        stream_offset,
    );
    const packet_len = try netz.quic.protection.shortPacketLen(.{
        .destination_connection_id = destination_connection_id,
        .packet_number = first_packet_number,
        .packet_number_len = 4,
        .payload = first_payload,
    });
    var offset: usize = 0;
    for (datagrams, 0..) |*datagram, index| {
        const payload = if (index == 0)
            first_payload
        else
            try fillPayload(
                &payload_storage[index],
                frame_shape,
                stream_offset,
            );
        const packet_number = first_packet_number + index;
        datagram.* = try netz.quic.protection.sealShortPacketInto(
            storage[offset..][0..packet_len],
            keys,
            .{
                .destination_connection_id = destination_connection_id,
                .packet_number = packet_number,
                .packet_number_len = 4,
                .payload = payload,
            },
        );
        offset += packet_len;
    }
    return offset;
}

fn fillPayload(
    out: *[payload_size]u8,
    frame_shape: FrameShape,
    stream_offset: *u64,
) ![]const u8 {
    if (frame_shape == .padding) {
        out[0] = @intFromEnum(netz.quic.FrameType.ping);
        @memset(out[1..], @intFromEnum(netz.quic.FrameType.padding));
        return out;
    }

    const stream_data = [_]u8{0x5a} ** payload_size;
    var data_len = payload_size - 8;
    while (true) {
        const frame = netz.quic.Frame{ .stream = .{
            .stream_id = 0,
            .offset = stream_offset.*,
            .data = stream_data[0..data_len],
        } };
        const frame_len = try frame.wireLen();
        if (frame_len == payload_size) {
            var fixed = std.heap.FixedBufferAllocator.init(out);
            var encoded = try std.ArrayList(u8).initCapacity(
                fixed.allocator(),
                payload_size,
            );
            try frame.write(&encoded, fixed.allocator());
            stream_offset.* += data_len;
            return encoded.items;
        }
        if (frame_len > payload_size) {
            data_len -= frame_len - payload_size;
        } else {
            data_len += payload_size - frame_len;
        }
    }
}

fn isStreamFrame(frame_shape: FrameShape) bool {
    return frame_shape == .stream or frame_shape == .stream_gap;
}

fn reorderStreamGapDatagrams(
    frame_shape: FrameShape,
    datagrams: *[batch_size][]const u8,
) void {
    if (frame_shape != .stream_gap) return;
    for (0..batch_size / 2) |pair| {
        std.mem.swap(
            []const u8,
            &datagrams[pair * 2],
            &datagrams[pair * 2 + 1],
        );
    }
}

fn drainStream(connection: *netz.quic.one_rtt.Connection) !usize {
    var buffer: [payload_size]u8 = undefined;
    var total: usize = 0;
    while (try connection.pollStreamId(0, &buffer)) |event| switch (event) {
        .data => |data| total += data.bytes,
        .reset => return error.UnexpectedPacketCount,
    };
    return total;
}

fn ratioTimes100(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return 0;
    return (numerator *| 100) / denominator;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
