//! Official max-concurrent-streams connection-scaling server scenario.
const std = @import("std");
const netz = @import("netz");
const messages = @import("../grpc_cpp_messages.zig");
const finishConnection = @import("connection_finish.zig").finish;

const duplex_service_path = "/grpc.testing.TestService/FullDuplexCall";

pub fn serve(
    allocator: std.mem.Allocator,
    tls_enabled: bool,
    clear_server: *netz.grpc.runtime.Server,
    tls_server: *netz.grpc.runtime.TlsServer,
) !void {
    var connection_a = try acceptConnection(
        tls_enabled,
        clear_server,
        tls_server,
    );
    defer connection_a.deinit();
    const peer_a = connection_a.peerAddress().?;
    const peer_a_text = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{peer_a},
    );
    defer allocator.free(peer_a_text);

    var first = try acceptAndRespond(
        allocator,
        &connection_a,
        peer_a_text,
    );
    defer first.deinit();
    var second = try acceptAndRespond(
        allocator,
        &connection_a,
        peer_a_text,
    );
    defer second.deinit();

    var connection_b = try acceptConnection(
        tls_enabled,
        clear_server,
        tls_server,
    );
    defer connection_b.deinit();
    const peer_b = connection_b.peerAddress().?;
    if (peer_a.eql(&peer_b)) return error.ExpectedDistinctPeerAddress;
    const peer_b_text = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{peer_b},
    );
    defer allocator.free(peer_b_text);
    var third = try acceptAndRespond(
        allocator,
        &connection_b,
        peer_b_text,
    );
    defer third.deinit();

    try finishAfterClientHalfClose(&first);
    try finishAfterClientHalfClose(&second);
    try finishAfterClientHalfClose(&third);
    try finishConnection(&connection_a.connection);
    try finishConnection(&connection_b.connection);
    std.debug.print(
        "netz grpc connection scaling: streams=2+1 connections=2 " ++
            "peer_a={s} peer_b={s}\n",
        .{ peer_a_text, peer_b_text },
    );
}

fn acceptConnection(
    tls_enabled: bool,
    clear_server: *netz.grpc.runtime.Server,
    tls_server: *netz.grpc.runtime.TlsServer,
) !netz.grpc.runtime.ServerConnection {
    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    errdefer connection.deinit();
    if (tls_enabled and
        !std.mem.eql(u8, connection.negotiatedAlpn() orelse "", "h2"))
    {
        return error.InvalidAlpn;
    }
    return connection;
}

fn acceptAndRespond(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
    peer_socket_address: []const u8,
) !netz.grpc.ServerDuplex {
    var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
    errdefer stream.deinit();
    if (!std.mem.eql(u8, stream.path, duplex_service_path)) {
        try stream.finish(.unimplemented, null, &.{}, &.{});
        return error.UnexpectedMethod;
    }

    var request_seen = false;
    const Consumer = struct {
        seen: *bool,

        fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
            if (self.seen.*) return error.UnexpectedRequest;
            try messages.decodePeerSocketAddressRequest(message.payload);
            self.seen.* = true;
        }
    };
    var consumer = Consumer{ .seen = &request_seen };
    while (!request_seen) {
        var event = try stream.readRequestEventWithTimeout(
            .fromSeconds(5),
            &consumer,
            Consumer.consume,
        );
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => return error.MissingRequest,
            .reset => return error.UnexpectedReset,
        }
    }

    const response = try messages.encodePeerSocketAddressResponseAlloc(
        allocator,
        peer_socket_address,
    );
    defer allocator.free(response);
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
        .max_message_size = messages.max_payload_size + 64,
    });
    if (try stream.writeMessage(response) != .complete) {
        return error.UnexpectedFlowControl;
    }
    return stream;
}

fn finishAfterClientHalfClose(stream: *netz.grpc.ServerDuplex) !void {
    const Consumer = struct {
        fn consume(_: *@This(), _: netz.grpc.StreamingMessage) !void {
            return error.UnexpectedRequest;
        }
    };
    var consumer: Consumer = .{};
    while (true) {
        var event = try stream.readRequestEventWithTimeout(
            .fromSeconds(5),
            &consumer,
            Consumer.consume,
        );
        defer event.deinit();
        switch (event) {
            .messages => |progress| {
                if (progress.count != 0) return error.UnexpectedRequest;
            },
            .finished => {
                try stream.finishOk();
                return;
            },
            .reset => return error.UnexpectedReset,
        }
    }
}
