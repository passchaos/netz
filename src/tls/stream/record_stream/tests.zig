const std = @import("std");
const record_stream_root = @import("../record_stream.zig");

const record_io = @import("../record_io.zig");
const vail = @import("vail");

const Stream = record_stream_root.Stream;
const handshake_type_key_update = record_stream_root.handshake_type_key_update;
const handshake_type_new_session_ticket = record_stream_root.handshake_type_new_session_ticket;
const max_consecutive_peer_key_updates = record_stream_root.max_consecutive_peer_key_updates;
const testingNetworkStreams = record_stream_root.testingNetworkStreams;
const testingRecordStream = record_stream_root.testingRecordStream;
const tls_record = record_stream_root.tls_record;

test "TLS record stream exposes authenticated close notify as EOF" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    try sender.writeAll(io, streams[0], "body");
    try sender.sendCloseNotify(io, streams[0]);
    var buffer: [8]u8 = undefined;
    const body_len = try receiver.read(io, streams[1], &buffer);
    try std.testing.expectEqualStrings("body", buffer[0..body_len]);
    try std.testing.expectEqual(
        @as(usize, 0),
        try receiver.read(io, streams[1], &buffer),
    );
    try std.testing.expect(receiver.receivedCloseNotify());
    try std.testing.expectError(
        error.ConnectionClosed,
        sender.writeAll(io, streams[0], "late"),
    );

    // Receiving close_notify closes only the peer's write direction. The
    // receiver may still finish its own application data before replying.
    try receiver.writeAll(io, streams[1], "reply");
    try receiver.sendCloseNotify(io, streams[1]);
    const reply_len = try sender.read(io, streams[0], &buffer);
    try std.testing.expectEqualStrings("reply", buffer[0..reply_len]);
    try std.testing.expectEqual(
        @as(usize, 0),
        try sender.read(io, streams[0], &buffer),
    );
}

test "TLS record stream finishes retained ciphertext without re-encrypting" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();
    sender.beginPendingWrite(
        tls_record.content_type_application_data,
        "retained",
    ) catch |err| return err;
    sender.pending_write_offset = 3;
    try record_io.writeAll(
        io,
        streams[0],
        sender.pending_write[0..sender.pending_write_offset],
    );

    var committed: usize = 99;
    try sender.finishPendingWrite(io, streams[0], &committed);
    try std.testing.expectEqual(@as(usize, "retained".len), committed);
    try std.testing.expectEqual(@as(usize, 0), sender.pending_write_len);
    try std.testing.expectEqual(@as(u64, 1), sender.write_sequence);

    var plaintext: [16]u8 = undefined;
    const count = try receiver.read(io, streams[1], &plaintext);
    try std.testing.expectEqualStrings("retained", plaintext[0..count]);
}

test "TLS record stream reusable boundary distinguishes plaintext from ciphertext" {
    var records = try testingRecordStream(0x22, 0x11);
    defer records.deinit();
    try std.testing.expect(records.isReusableBoundary());

    // Ciphertext and post-handshake fragments have not yet been authenticated
    // as application data and must not be treated as an unsolicited response.
    records.record_reader.encoded_len = 1;
    records.post_handshake_len = 1;
    try std.testing.expect(records.isReusableBoundary());

    records.buffered_end = 1;
    try std.testing.expect(!records.isReusableBoundary());
    records.buffered_end = 0;
    records.failed = true;
    try std.testing.expect(!records.isReusableBoundary());
}

test "TLS record stream rejects fatal and malformed alerts" {
    const cases = [_]struct {
        alert: [2]u8,
        expected: anyerror,
    }{
        .{ .alert = .{ 2, 40 }, .expected = error.PeerTlsAlert },
        .{ .alert = .{ 1, 40 }, .expected = error.InvalidTlsAlert },
    };
    for (cases) |case| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const streams = try testingNetworkStreams(io);
        defer streams[0].close(io);
        defer streams[1].close(io);
        var sender = try testingRecordStream(0x22, 0x11);
        defer sender.deinit();
        var receiver = try testingRecordStream(0x11, 0x22);
        defer receiver.deinit();

        try sender.writeRecord(
            io,
            streams[0],
            tls_record.content_type_alert,
            &case.alert,
        );
        var byte: [1]u8 = undefined;
        try std.testing.expectError(
            case.expected,
            receiver.read(io, streams[1], &byte),
        );
        try std.testing.expect(!receiver.receivedCloseNotify());
        try std.testing.expectError(
            error.ConnectionClosed,
            receiver.read(io, streams[1], &byte),
        );
    }
}

test "TLS record stream accepts user canceled followed by close notify" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    try sender.writeRecord(
        io,
        streams[0],
        tls_record.content_type_alert,
        &.{ 1, 90 },
    );
    try sender.writeRecord(
        io,
        streams[0],
        tls_record.content_type_alert,
        &.{ 1, 0 },
    );
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        try receiver.read(io, streams[1], &byte),
    );
    try std.testing.expect(receiver.receivedCloseNotify());
}

test "TLS record stream distinguishes socket EOF from record truncation" {
    const cuts = [_]?usize{ null, 1, 4, 5, 10 };
    for (cuts) |cut| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const streams = try testingNetworkStreams(io);
        var sender_open = true;
        defer if (sender_open) streams[0].close(io);
        defer streams[1].close(io);
        var sender = try testingRecordStream(0x22, 0x11);
        defer sender.deinit();
        var receiver = try testingRecordStream(0x11, 0x22);
        defer receiver.deinit();

        if (cut) |count| {
            var encoded: [record_io.max_record_len]u8 = undefined;
            const len = try sender.write_keys.seal(
                sender.write_sequence,
                tls_record.content_type_application_data,
                "truncated",
                &encoded,
            );
            try std.testing.expect(count < len);
            try record_io.writeAll(io, streams[0], encoded[0..count]);
        }
        streams[0].close(io);
        sender_open = false;

        var byte: [1]u8 = undefined;
        try std.testing.expectError(
            if (cut == null) error.UnexpectedEof else error.TruncatedRecord,
            receiver.read(io, streams[1], &byte),
        );
        try std.testing.expect(!receiver.receivedCloseNotify());
        if (cut == null) {
            try std.testing.expect(receiver.shouldSendCloseNotify());
            try std.testing.expectError(
                error.UnexpectedEof,
                receiver.read(io, streams[1], &byte),
            );
        } else {
            try std.testing.expect(!receiver.shouldSendCloseNotify());
            try std.testing.expectError(
                error.ConnectionClosed,
                receiver.read(io, streams[1], &byte),
            );
        }
    }
}

test "TLS record stream delivers authenticated data before later truncation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    var sender_open = true;
    defer if (sender_open) streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    try sender.writeAll(io, streams[0], "complete");
    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try sender.write_keys.seal(
        sender.write_sequence,
        tls_record.content_type_application_data,
        "truncated",
        &encoded,
    );
    try std.testing.expect(len > 8);
    try record_io.writeAll(io, streams[0], encoded[0..8]);
    streams[0].close(io);
    sender_open = false;

    var buffer: [16]u8 = undefined;
    const count = try receiver.read(io, streams[1], &buffer);
    try std.testing.expectEqualStrings("complete", buffer[0..count]);
    try std.testing.expectError(
        error.TruncatedRecord,
        receiver.read(io, streams[1], &buffer),
    );
}

test "TLS record stream resumes a partial record after read timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try sender.write_keys.seal(
        sender.write_sequence,
        tls_record.content_type_application_data,
        "resumed-record",
        &encoded,
    );
    try record_io.writeAll(io, streams[0], encoded[0..1]);

    var plaintext: [32]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        receiver.readWithDeadline(
            io,
            streams[1],
            &plaintext,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), receiver.record_reader.encoded_len);

    try record_io.writeAll(io, streams[0], encoded[1..len]);
    const count = try receiver.read(io, streams[1], &plaintext);
    try std.testing.expectEqualStrings(
        "resumed-record",
        plaintext[0..count],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        receiver.record_reader.encoded_len,
    );
}

test "TLS record stream resumes a partial record after task cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testingNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var sender = try testingRecordStream(0x22, 0x11);
    defer sender.deinit();
    var receiver = try testingRecordStream(0x11, 0x22);
    defer receiver.deinit();

    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try sender.write_keys.seal(
        sender.write_sequence,
        tls_record.content_type_application_data,
        "canceled-record",
        &encoded,
    );
    try record_io.writeAll(io, streams[0], encoded[0..1]);

    var plaintext: [32]u8 = undefined;
    var read_future = try io.concurrent(
        Stream.read,
        .{ &receiver, io, streams[1], &plaintext },
    );
    try std.Io.sleep(
        io,
        .fromMilliseconds(20),
        .awake,
    );
    try std.testing.expectError(error.Canceled, read_future.cancel(io));
    try std.testing.expectEqual(
        @as(usize, 1),
        receiver.record_reader.encoded_len,
    );

    try record_io.writeAll(io, streams[0], encoded[1..len]);
    const count = try receiver.read(io, streams[1], &plaintext);
    try std.testing.expectEqualStrings(
        "canceled-record",
        plaintext[0..count],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        receiver.record_reader.encoded_len,
    );
}

test "TLS record stream reassembles and bounds peer KeyUpdate messages" {
    const suite = vail.tls.cipher_suite.Suite.aes_256_gcm_sha384;
    var read_secret = try vail.tls.secret.Secret.init(
        suite.hash(),
        &([_]u8{0x41} ** 48),
    );
    defer read_secret.deinit();
    var write_secret = try vail.tls.secret.Secret.init(
        suite.hash(),
        &([_]u8{0x52} ** 48),
    );
    defer write_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, read_secret),
        try tls_record.Keys.derive(suite, write_secret),
        read_secret,
        write_secret,
    );
    defer records.deinit();

    // Fragmentation may cross arbitrary record boundaries. No socket is used
    // because update_not_requested must not emit a reciprocal record.
    try records.consumePostHandshake(
        undefined,
        undefined,
        &.{ handshake_type_key_update, 0 },
    );
    try std.testing.expectEqual(@as(u64, 0), records.keyUpdateCounts().received);
    try records.consumePostHandshake(undefined, undefined, &.{ 0, 1, 0 });
    try std.testing.expectEqual(@as(u64, 1), records.keyUpdateCounts().received);
    try std.testing.expectEqual(@as(u64, 0), records.read_sequence);
    try std.testing.expectEqual(@as(usize, 0), records.post_handshake_len);

    const update = [_]u8{ handshake_type_key_update, 0, 0, 1, 0 };
    for (1..max_consecutive_peer_key_updates) |_| {
        try records.consumePostHandshake(undefined, undefined, &update);
    }
    try std.testing.expectError(
        error.KeyUpdateLimitExceeded,
        records.consumePostHandshake(undefined, undefined, &update),
    );
}

test "TLS record stream rejects malformed KeyUpdate framing" {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    const bytes = [_]u8{0x63} ** 32;
    var traffic_secret = try vail.tls.secret.Secret.init(suite.hash(), &bytes);
    defer traffic_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer records.deinit();

    try std.testing.expectError(
        error.InvalidKeyUpdate,
        records.consumePostHandshake(
            undefined,
            undefined,
            &.{ handshake_type_key_update, 0, 0, 2, 0 },
        ),
    );
}

test "TLS record stream client discards bounded fragmented NewSessionTicket" {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    const bytes = [_]u8{0x64} ** 32;
    var traffic_secret = try vail.tls.secret.Secret.init(suite.hash(), &bytes);
    defer traffic_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer records.deinit();
    records.allowNewSessionTickets();

    // Minimal structurally sized ticket body split across record boundaries,
    // immediately followed by a KeyUpdate in the same handshake fragment.
    const ticket_and_update = [_]u8{
        handshake_type_new_session_ticket, 0, 0, 14,
        0, 0, 0, 1, // lifetime
        0, 0, 0, 2, // age_add
        0, // nonce length
        0, 1, 0xaa, // one-byte ticket
        0,                         0, // extensions
        handshake_type_key_update, 0,
        0,                         1,
        0,
    };
    try records.consumePostHandshake(undefined, undefined, ticket_and_update[0..9]);
    try std.testing.expectEqual(@as(u64, 0), records.discardedSessionTicketCount());
    try records.consumePostHandshake(undefined, undefined, ticket_and_update[9..]);
    try std.testing.expectEqual(@as(u64, 1), records.discardedSessionTicketCount());
    try std.testing.expectEqual(@as(u64, 1), records.keyUpdateCounts().received);

    var server_records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer server_records.deinit();
    try std.testing.expectError(
        error.InvalidNewSessionTicket,
        server_records.consumePostHandshake(undefined, undefined, ticket_and_update[0..18]),
    );
}

test "TLS record stream retains the newest complete NewSessionTicket" {
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    const bytes = [_]u8{0x65} ** 32;
    var traffic_secret = try vail.tls.secret.Secret.init(suite.hash(), &bytes);
    defer traffic_secret.deinit();
    var records = Stream.init(
        try tls_record.Keys.derive(suite, traffic_secret),
        try tls_record.Keys.derive(suite, traffic_secret),
        traffic_secret,
        traffic_secret,
    );
    defer records.deinit();
    records.retainNewSessionTickets(std.testing.allocator);

    const ticket_and_update = [_]u8{
        handshake_type_new_session_ticket, 0, 0, 14,
        0, 0, 0, 1, // lifetime
        0, 0, 0, 2, // age_add
        0, // nonce length
        0, 1, 0xaa, // one-byte ticket
        0,                         0, // extensions
        handshake_type_key_update, 0,
        0,                         1,
        0,
    };
    try records.consumePostHandshake(
        undefined,
        undefined,
        ticket_and_update[0..9],
    );
    try std.testing.expect(records.takeNewSessionTicketMessage() == null);
    try records.consumePostHandshake(
        undefined,
        undefined,
        ticket_and_update[9..],
    );
    var retained = records.takeNewSessionTicketMessage() orelse
        return error.MissingSessionTicket;
    defer retained.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        ticket_and_update[0..18],
        retained.items,
    );
    try std.testing.expect(records.takeNewSessionTicketMessage() == null);
    try std.testing.expectEqual(@as(u64, 0), records.discardedSessionTicketCount());
    try std.testing.expectEqual(@as(u64, 1), records.keyUpdateCounts().received);
}
