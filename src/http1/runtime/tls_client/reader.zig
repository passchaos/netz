//! Standard TLS network reads retain the cause of local interruptions.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const stream_io = @import("../../../internal/stream_io.zig");
const net = std.Io.net;

pub const vtable: std.Io.Reader.VTable = .{
    .stream = tlsClientReaderStream,
    .readVec = tlsClientReaderReadVec,
};

fn tlsClientReaderStream(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    const destination = limit.slice(try writer.writableSliceGreedy(1));
    var data: [1][]u8 = .{destination};
    const count = try tlsClientReaderReadVec(reader, &data);
    writer.advance(count);
    return count;
}

fn tlsClientReaderReadVec(
    reader: *std.Io.Reader,
    data: [][]u8,
) std.Io.Reader.Error!usize {
    const net_reader: *net.Stream.Reader = @alignCast(
        @fieldParentPtr("interface", reader),
    );
    const connection: *runtime.TlsClientConnection = @alignCast(
        @fieldParentPtr("net_reader", net_reader),
    );
    var vectors: [8][]u8 = undefined;
    const vector_count, const direct_bytes = try reader.writableVector(
        &vectors,
        data,
    );
    const destinations = vectors[0..vector_count];
    std.debug.assert(destinations.len != 0 and destinations[0].len != 0);

    const count = if (connection.timed_read_deadline) |deadline|
        readTlsClientTransportWithDeadline(
            connection,
            destinations,
            deadline,
        ) catch |err| {
            connection.timed_read_error = mapTimedReadError(err);
            return error.ReadFailed;
        }
    else
        stream_io.readVec(
            connection.io,
            connection.stream,
            destinations,
        ) catch |err| {
            net_reader.err = err;
            return error.ReadFailed;
        };
    if (count == 0) return error.EndOfStream;
    if (count > direct_bytes) {
        reader.end += count - direct_bytes;
        return direct_bytes;
    }
    return count;
}

fn mapTimedReadError(err: stream_io.TimedReadError) runtime.Error {
    // std.Io.Reader erases transport errors into ReadFailed. The connection
    // retains this cause separately from net.Stream.Reader.Error, which cannot
    // represent executor admission failure. Keep the existing file/socket
    // normalization for other transport errors.
    return switch (err) {
        error.AccessDenied => error.AccessDenied,
        error.Canceled => error.Canceled,
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.NetworkDown => error.NetworkDown,
        error.SocketUnconnected => error.SocketUnconnected,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => error.SystemResources,
        error.Timeout => error.Timeout,
        else => error.Unexpected,
    };
}

fn readTlsClientTransportWithDeadline(
    connection: *runtime.TlsClientConnection,
    destinations: [][]u8,
    deadline: std.Io.Clock.Timestamp,
) stream_io.TimedReadError!usize {
    var total: usize = 0;
    for (destinations) |destination| {
        if (destination.len == 0) continue;
        const count = try stream_io.readSomeWithDeadline(
            connection.io,
            connection.stream,
            destination,
            deadline,
        );
        total += count;
        // One read is enough to preserve ordinary stream short-read behavior.
        // Continue only when it completely filled this vector so a following
        // TLS-owned buffer can receive bytes already available in the socket.
        if (count != destination.len) break;
    }
    return total;
}
