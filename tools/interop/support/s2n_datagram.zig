const std = @import("std");
const netz = @import("netz");

pub const Role = enum { client, server };

pub const Result = struct {
    boundary_bytes: usize,
};

const start = "NZDGRAM1";
const ready = "NZDGRRD1";
const drain = "NZDGRGO1";
const received = "NZDGRRX1";
const done = "NZDGRDN1";
const ack = "NZDGRAK1";
const sibling_payload = "world";
const local_small = [_][]const u8{ "netz-alpha", "netz-beta" };
const peer_small = [_][]const u8{ "s2n-alpha", "s2n-beta" };
const peer_boundary_bytes = 62;
const max_payload_storage = 8192;

pub fn run(
    connection: *netz.quic.one_rtt.Connection,
    role: Role,
) !Result {
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{
        .clock = .awake,
        .raw = .fromSeconds(20),
    });
    if (!connection.datagramsEnabled()) return error.DatagramsNotNegotiated;

    var control_offset: u64 = 0;
    switch (role) {
        .client => {
            const stream_id = try connection.openStreamWithDeadline(deadline);
            if (stream_id != 0) return error.UnexpectedStreamId;
            try sendExact(
                connection,
                stream_id,
                &control_offset,
                start,
                false,
                deadline,
            );
        },
        .server => try expectMarker(connection, start, false, deadline),
    }

    const boundary_bytes = connection.maxDatagramPayloadSize() orelse
        return error.DatagramsNotNegotiated;
    if (boundary_bytes < peer_boundary_bytes or
        boundary_bytes + 1 > max_payload_storage)
    {
        return error.UnexpectedDatagramBoundary;
    }

    for (local_small) |payload| {
        try connection.sendDatagramWithDeadline(payload, deadline);
    }
    var boundary_storage: [max_payload_storage]u8 = undefined;
    fillBoundary(boundary_storage[0..boundary_bytes], .netz);
    try connection.sendDatagramWithDeadline(
        boundary_storage[0..boundary_bytes],
        deadline,
    );
    fillBoundary(boundary_storage[0 .. boundary_bytes + 1], .netz);
    if (connection.sendDatagram(boundary_storage[0 .. boundary_bytes + 1])) |_| {
        return error.OversizedDatagramAccepted;
    } else |err| switch (err) {
        error.DatagramTooLarge => {},
        else => return err,
    }

    switch (role) {
        .client => {
            try expectMarker(connection, ready, false, deadline);
            try sendExact(connection, 0, &control_offset, ready, false, deadline);
            try expectMarker(connection, drain, false, deadline);
        },
        .server => {
            try sendExact(connection, 0, &control_offset, ready, false, deadline);
            try expectMarker(connection, ready, false, deadline);
            try sendExact(connection, 0, &control_offset, drain, false, deadline);
        },
    }

    try receivePeerDatagrams(connection, deadline);
    switch (role) {
        .client => {
            try sendExact(
                connection,
                0,
                &control_offset,
                received,
                false,
                deadline,
            );
            try expectMarker(connection, received, false, deadline);
        },
        .server => {
            try expectMarker(connection, received, false, deadline);
            try sendExact(
                connection,
                0,
                &control_offset,
                received,
                false,
                deadline,
            );
        },
    }

    switch (role) {
        .client => {
            const sibling_id = try connection.openStreamWithDeadline(deadline);
            if (sibling_id != 4) return error.UnexpectedStreamId;
            var sibling_offset: u64 = 0;
            try sendExact(
                connection,
                sibling_id,
                &sibling_offset,
                sibling_payload,
                true,
                deadline,
            );
            try expectStream(
                connection,
                @intCast(sibling_id),
                sibling_payload,
                true,
                deadline,
            );
            try sendExact(connection, 0, &control_offset, done, true, deadline);
            try expectMarker(connection, ack, true, deadline);
        },
        .server => {
            try expectStream(connection, 4, sibling_payload, true, deadline);
            var sibling_offset: u64 = 0;
            try sendExact(
                connection,
                4,
                &sibling_offset,
                sibling_payload,
                true,
                deadline,
            );
            try expectMarker(connection, done, true, deadline);
            try sendExact(connection, 0, &control_offset, ack, true, deadline);
        },
    }

    return .{ .boundary_bytes = boundary_bytes };
}

const BoundarySource = enum { netz, s2n };

fn fillBoundary(out: []u8, source: BoundarySource) void {
    const multiplier: usize = switch (source) {
        .netz => 29,
        .s2n => 31,
    };
    const increment: usize = switch (source) {
        .netz => 7,
        .s2n => 11,
    };
    for (out, 0..) |*byte, index| {
        byte.* = @truncate(index *% multiplier +% increment);
    }
}

fn receivePeerDatagrams(
    connection: *netz.quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var seen = [_]bool{false} ** 3;
    var received_count: usize = 0;
    var storage: [max_payload_storage]u8 = undefined;
    while (received_count < seen.len) {
        const payload = try connection.popDatagram(&storage) orelse {
            try connection.servicePacketServicingTimersDeadline(deadline);
            continue;
        };
        const index: usize = if (std.mem.eql(u8, payload, peer_small[0]))
            0
        else if (std.mem.eql(u8, payload, peer_small[1]))
            1
        else if (payload.len == peer_boundary_bytes and
            boundaryMatches(payload, .s2n))
            2
        else
            return error.UnexpectedDatagramPayload;
        if (seen[index]) return error.DuplicateDatagramPayload;
        seen[index] = true;
        received_count += 1;
    }
}

fn boundaryMatches(payload: []const u8, source: BoundarySource) bool {
    var expected: [max_payload_storage]u8 = undefined;
    fillBoundary(expected[0..payload.len], source);
    return std.mem.eql(u8, payload, expected[0..payload.len]);
}

fn expectMarker(
    connection: *netz.quic.one_rtt.Connection,
    marker: []const u8,
    expect_fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    return expectStream(connection, 0, marker, expect_fin, deadline);
}

fn expectStream(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u62,
    expected: []const u8,
    expect_fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var received_bytes: usize = 0;
    var fin = false;
    var storage: [64]u8 = undefined;
    while (received_bytes < expected.len or expect_fin and !fin) {
        const target = if (received_bytes < expected.len)
            storage[0 .. expected.len - received_bytes]
        else
            storage[0..1];
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            target,
            deadline,
        );
        const data = switch (event) {
            .reset => return error.UnexpectedReset,
            .data => |value| value,
        };
        if (data.stream_id != stream_id or
            received_bytes + data.bytes > expected.len or
            !std.mem.eql(
                u8,
                storage[0..data.bytes],
                expected[received_bytes..][0..data.bytes],
            ))
        {
            return error.InvalidDatagramControl;
        }
        received_bytes += data.bytes;
        fin = fin or data.fin;
    }
    if (fin != expect_fin) return error.InvalidDatagramControl;
}

fn sendExact(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: *u64,
    bytes: []const u8,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var committed: usize = 0;
    try connection.sendStreamWithDeadline(
        stream_id,
        offset.*,
        bytes,
        fin,
        &committed,
        deadline,
    );
    if (committed != bytes.len) return error.IncompleteDatagramControlSend;
    offset.* += committed;
}
