//! Certificate-verified HTTP/3 client for process-boundary interoperability
//! with the quic-go fixture maintained in the audited local quicz checkout.

const std = @import("std");
const netz = @import("netz");

const cancellation_response_size = 128 * 1024;
const stream_receive_window = 8 * 1024;
const connection_receive_window = 24 * 1024;
const read_before_cancel = 12 * 1024;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };

    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var local_transport_parameters = netz.quic.practical_transport_parameters;
    local_transport_parameters.initial_max_data = connection_receive_window;
    local_transport_parameters.initial_max_stream_data_bidi_local =
        stream_receive_window;
    local_transport_parameters.initial_max_stream_data_bidi_remote =
        stream_receive_window;
    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .server_auth = verifier.clientVerifier(),
                .max_crypto_buffer = 64 * 1024,
                .local_transport_parameters = local_transport_parameters,
                .initial_one_rtt_config = .{
                    // Keep auto-tuning from hiding whether cancellation can
                    // unblock a response larger than the negotiated window.
                    .receive_window = connection_receive_window,
                    .max_receive_window = connection_receive_window,
                    .stream_receive_window = stream_receive_window,
                    .max_stream_receive_window = stream_receive_window,
                    .max_datagram_size = 4096,
                },
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer client.deinit();

    const canceled_stream_id = try client.startRequest(.{
        .method = "GET",
        .path = "/cancel?from=netz",
        .scheme = "https",
        .authority = "localhost",
    }, 0);

    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/interop?from=netz",
        .scheme = "https",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-request",
            .value = "request-header",
        }},
    }, "netz-request".len);
    try client.sendRequestBodyPaced(stream_id, "netz-", false);
    try client.sendRequestBodyPaced(stream_id, "request", false);
    try client.finishRequestTrailersPaced(stream_id, &.{.{
        .name = "x-netz-trailer",
        .value = "request-trailer",
    }});

    var canceled_bytes: usize = 0;
    var cancellation_sent = false;
    var sibling_head = false;
    var sibling_trailer = false;
    var sibling_finished = false;
    var sibling_body: std.ArrayList(u8) = .empty;
    defer sibling_body.deinit(allocator);
    var read_buffer: [2048]u8 = undefined;
    while (!sibling_finished) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.UnexpectedResponseReset,
            .message => |message| {
                if (message.stream_id != canceled_stream_id and
                    message.stream_id != stream_id)
                {
                    return error.UnexpectedStream;
                }
                switch (message.value) {
                    .head => |head| {
                        if (head != .response) return error.InvalidResponse;
                        if (message.stream_id == canceled_stream_id) {
                            if (head.response.status != 200 or
                                head.response.content_length !=
                                    cancellation_response_size or
                                !headerEquals(
                                    head.response.headers,
                                    "x-quic-go-cancel",
                                    "large-response-started",
                                ))
                            {
                                return error.InvalidResponse;
                            }
                        } else {
                            if (head.response.status != 201 or
                                !headerEquals(
                                    head.response.headers,
                                    "x-quic-go-response",
                                    "response-header",
                                ))
                            {
                                return error.InvalidResponse;
                            }
                            sibling_head = true;
                        }
                    },
                    .data_available => {
                        const read = try client.readResponseData(
                            message.stream_id,
                            &read_buffer,
                        );
                        if (message.stream_id == canceled_stream_id) {
                            for (read_buffer[0..read]) |byte| {
                                if (byte != 'q') {
                                    return error.InvalidResponse;
                                }
                            }
                            canceled_bytes += read;
                            if (canceled_bytes >= read_before_cancel) {
                                try client.cancelRequest(
                                    canceled_stream_id,
                                    netz.http3.ApplicationErrorCode
                                        .request_cancelled,
                                );
                                cancellation_sent = true;
                            }
                        } else {
                            try sibling_body.appendSlice(
                                allocator,
                                read_buffer[0..read],
                            );
                        }
                    },
                    .trailers => |trailers| {
                        if (message.stream_id != stream_id or
                            !headerEquals(
                                trailers.fields,
                                "x-quic-go-trailer",
                                "response-trailer",
                            ))
                        {
                            return error.InvalidResponse;
                        }
                        sibling_trailer = true;
                    },
                    .finished => {
                        if (message.stream_id != stream_id) {
                            return error.InvalidResponse;
                        }
                        sibling_finished = true;
                    },
                    .push_promise => return error.InvalidResponse,
                }
            },
        }
    }
    if (!cancellation_sent or canceled_bytes < read_before_cancel or
        !sibling_head or !sibling_trailer or
        !std.mem.eql(u8, sibling_body.items, "quic-go-response"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/3 client interoperated with quic-go: cancel=H3_REQUEST_CANCELLED concurrent_sibling=true stream_window={d} read_before_cancel>={d} large_response={d} request_body=12 request_trailers=1 response_body=16 response_trailers=1\n",
        .{ stream_receive_window, read_before_cancel, cancellation_response_size },
    );
}

fn headerEquals(
    headers: []const netz.http3.Qpack.HeaderField,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) {
            return std.mem.eql(u8, header.value, value);
        }
    }
    return false;
}
