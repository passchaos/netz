//! TLS 1.3 resumption-PSK helpers for QUIC PSK-DHE handshakes.
//!
//! The caller builds an otherwise complete ClientHello, then this module
//! appends `psk_key_exchange_modes` and the mandatory-last `pre_shared_key`
//! extension while computing the binder over the correctly truncated message.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const ext_pre_shared_key: u16 = 0x0029;
pub const ext_psk_key_exchange_modes: u16 = 0x002d;
pub const psk_dhe_ke: u8 = 1;
pub const selected_identity_first: u16 = 0;

pub const Error = std.mem.Allocator.Error || error{
    InvalidClientHello,
    InvalidServerHello,
    MissingPskOffer,
    InvalidPskIdentity,
    InvalidPskBinder,
    InvalidPskAge,
    ExpiredPsk,
    UnsupportedPskKeyExchangeMode,
    PskExtensionNotLast,
};

pub const Offer = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
    binder: [Sha256.digest_length]u8,
    binder_truncated_len: usize,
};

pub const TicketAgePolicy = struct {
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    now_ms: u64,
    tolerance_ms: u32 = 10_000,
};

pub fn appendClientOffer(
    client_hello: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    identity: []const u8,
    obfuscated_ticket_age: u32,
    psk: [Sha256.digest_length]u8,
) Error!void {
    if (identity.len == 0 or identity.len > std.math.maxInt(u16)) {
        return error.InvalidPskIdentity;
    }
    const original_len = client_hello.items.len;
    errdefer client_hello.items.len = original_len;
    const offsets = try clientHelloOffsets(client_hello.items);
    try rejectExistingPskExtensions(
        client_hello.items,
        offsets.extensions_offset,
        offsets.extensions_len,
    );

    var mode_extension: [6]u8 = undefined;
    std.mem.writeInt(u16, mode_extension[0..2], ext_psk_key_exchange_modes, .big);
    std.mem.writeInt(u16, mode_extension[2..4], 2, .big);
    mode_extension[4] = 1;
    mode_extension[5] = psk_dhe_ke;
    try client_hello.appendSlice(allocator, &mode_extension);

    const identity_entry_len = 2 + identity.len + 4;
    const identities_len = identity_entry_len;
    const binders_len = 1 + Sha256.digest_length;
    const psk_payload_len = 2 + identities_len + 2 + binders_len;
    if (psk_payload_len > std.math.maxInt(u16)) {
        return error.InvalidPskIdentity;
    }
    var header: [8]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], ext_pre_shared_key, .big);
    std.mem.writeInt(u16, header[2..4], @intCast(psk_payload_len), .big);
    std.mem.writeInt(u16, header[4..6], @intCast(identities_len), .big);
    std.mem.writeInt(u16, header[6..8], @intCast(identity.len), .big);
    try client_hello.appendSlice(allocator, &header);
    try client_hello.appendSlice(allocator, identity);
    var age: [4]u8 = undefined;
    std.mem.writeInt(u32, &age, obfuscated_ticket_age, .big);
    try client_hello.appendSlice(allocator, &age);
    var binder_header: [3]u8 = undefined;
    std.mem.writeInt(u16, binder_header[0..2], @intCast(binders_len), .big);
    binder_header[2] = Sha256.digest_length;
    try client_hello.appendSlice(allocator, &binder_header);
    const binder_offset = client_hello.items.len;
    try client_hello.appendNTimes(allocator, 0, Sha256.digest_length);

    const added = client_hello.items.len - offsets.message_len;
    const new_extensions_len = std.math.add(
        usize,
        offsets.extensions_len,
        added,
    ) catch return error.InvalidClientHello;
    const new_body_len = std.math.add(
        usize,
        offsets.body_len,
        added,
    ) catch return error.InvalidClientHello;
    if (new_extensions_len > std.math.maxInt(u16) or
        new_body_len > std.math.maxInt(u24))
    {
        return error.InvalidClientHello;
    }
    std.mem.writeInt(
        u16,
        client_hello.items[offsets.extensions_len_offset..][0..2],
        @intCast(new_extensions_len),
        .big,
    );
    writeU24(client_hello.items[1..4], @intCast(new_body_len));

    // RFC 8446 §4.2.11.2: transcript ends immediately before the binders
    // vector's uint16 length field.
    const binder_truncated_len = binder_offset - 3;
    const binder = computeBinder(
        psk,
        transcriptHash(client_hello.items[0..binder_truncated_len]),
    );
    @memcpy(
        client_hello.items[binder_offset..][0..Sha256.digest_length],
        &binder,
    );
}

fn rejectExistingPskExtensions(
    client_hello: []const u8,
    extensions_offset: usize,
    extensions_len: usize,
) Error!void {
    var pos = extensions_offset;
    const extensions_end = extensions_offset + extensions_len;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) return error.InvalidClientHello;
        const typ = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
        const len = std.mem.readInt(
            u16,
            client_hello[pos + 2 ..][0..2],
            .big,
        );
        const payload_start = pos + 4;
        const payload_end = std.math.add(
            usize,
            payload_start,
            len,
        ) catch return error.InvalidClientHello;
        if (payload_end > extensions_end) return error.InvalidClientHello;
        if (typ == ext_psk_key_exchange_modes or typ == ext_pre_shared_key) {
            return error.InvalidClientHello;
        }
        pos = payload_end;
    }
}

pub fn parseClientOffer(client_hello: []const u8) Error!Offer {
    const offsets = try clientHelloOffsets(client_hello);
    var pos = offsets.extensions_offset;
    const extensions_end = offsets.extensions_offset + offsets.extensions_len;
    var saw_mode = false;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) return error.InvalidClientHello;
        const typ = std.mem.readInt(u16, client_hello[pos..][0..2], .big);
        const len = std.mem.readInt(u16, client_hello[pos + 2 ..][0..2], .big);
        const payload_start = pos + 4;
        const payload_end = std.math.add(
            usize,
            payload_start,
            len,
        ) catch return error.InvalidClientHello;
        if (payload_end > extensions_end) return error.InvalidClientHello;
        if (typ == ext_psk_key_exchange_modes) {
            if (saw_mode) return error.InvalidClientHello;
            if (len != 2 or client_hello[payload_start] != 1 or
                client_hello[payload_start + 1] != psk_dhe_ke)
            {
                return error.UnsupportedPskKeyExchangeMode;
            }
            saw_mode = true;
        } else if (typ == ext_pre_shared_key) {
            if (payload_end != extensions_end) {
                return error.PskExtensionNotLast;
            }
            if (!saw_mode) return error.UnsupportedPskKeyExchangeMode;
            return parseOfferPayload(
                client_hello,
                payload_start,
                payload_end,
            );
        }
        pos = payload_end;
    }
    return error.MissingPskOffer;
}

pub fn verifyClientOffer(
    client_hello: []const u8,
    offer: Offer,
    expected_identity: []const u8,
    psk: [Sha256.digest_length]u8,
) Error!void {
    if (!std.mem.eql(u8, offer.identity, expected_identity)) {
        return error.InvalidPskIdentity;
    }
    const expected = computeBinder(
        psk,
        transcriptHash(client_hello[0..offer.binder_truncated_len]),
    );
    if (!std.crypto.timing_safe.eql(
        [Sha256.digest_length]u8,
        offer.binder,
        expected,
    )) {
        return error.InvalidPskBinder;
    }
}

pub fn validateTicketAge(
    offer: Offer,
    policy: TicketAgePolicy,
) Error!void {
    if (policy.lifetime_seconds == 0 or policy.now_ms < policy.issued_at_ms) {
        return error.ExpiredPsk;
    }
    const actual_age = policy.now_ms - policy.issued_at_ms;
    const lifetime_ms = @as(u64, policy.lifetime_seconds) *
        std.time.ms_per_s;
    if (actual_age > lifetime_ms or actual_age > std.math.maxInt(u32)) {
        return error.ExpiredPsk;
    }
    const offered_age = offer.obfuscated_ticket_age -% policy.age_add;
    const actual_age_u32: u32 = @intCast(actual_age);
    const skew = if (offered_age > actual_age_u32)
        offered_age - actual_age_u32
    else
        actual_age_u32 - offered_age;
    if (skew > policy.tolerance_ms) return error.InvalidPskAge;
}

pub fn appendServerSelection(
    extensions: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error!void {
    var extension: [6]u8 = undefined;
    std.mem.writeInt(u16, extension[0..2], ext_pre_shared_key, .big);
    std.mem.writeInt(u16, extension[2..4], 2, .big);
    std.mem.writeInt(u16, extension[4..6], selected_identity_first, .big);
    try extensions.appendSlice(allocator, &extension);
}

pub fn parseServerSelection(payload: []const u8) Error!u16 {
    if (payload.len != 2) return error.InvalidServerHello;
    const selected = std.mem.readInt(u16, payload[0..2], .big);
    if (selected != selected_identity_first) return error.InvalidServerHello;
    return selected;
}

pub fn computeBinder(
    psk: [Sha256.digest_length]u8,
    truncated_client_hello_hash: [Sha256.digest_length]u8,
) [Sha256.digest_length]u8 {
    const zero = [_]u8{0} ** Sha256.digest_length;
    const early_secret = HkdfSha256.extract(&zero, &psk);
    const empty_hash = std.crypto.tls.emptyHash(Sha256);
    const binder_key = std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        early_secret,
        "res binder",
        &empty_hash,
        Sha256.digest_length,
    );
    const finished_key = std.crypto.tls.hkdfExpandLabel(
        HkdfSha256,
        binder_key,
        "finished",
        "",
        Sha256.digest_length,
    );
    var binder: [Sha256.digest_length]u8 = undefined;
    HmacSha256.create(
        &binder,
        &truncated_client_hello_hash,
        &finished_key,
    );
    return binder;
}

pub fn earlySecret(
    psk: ?[Sha256.digest_length]u8,
) [Sha256.digest_length]u8 {
    const zero = [_]u8{0} ** Sha256.digest_length;
    // RFC 8446 §7.1 defines an absent PSK as Hash.length zero octets, not an
    // empty input. Keeping that distinction here makes the ordinary and
    // resumed key schedules interoperable with independent TLS 1.3 stacks.
    return HkdfSha256.extract(&zero, if (psk) |value| &value else &zero);
}

fn parseOfferPayload(
    client_hello: []const u8,
    payload_start: usize,
    payload_end: usize,
) Error!Offer {
    var pos = payload_start;
    if (payload_end - pos < 2) return error.InvalidClientHello;
    const identities_len =
        std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    pos += 2;
    const identities_end = std.math.add(
        usize,
        pos,
        identities_len,
    ) catch return error.InvalidPskIdentity;
    if (identities_end > payload_end or identities_end - pos < 6) {
        return error.InvalidPskIdentity;
    }
    const identity_len =
        std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    pos += 2;
    const identity_end = std.math.add(
        usize,
        pos,
        identity_len,
    ) catch return error.InvalidPskIdentity;
    const age_end = std.math.add(
        usize,
        identity_end,
        @sizeOf(u32),
    ) catch return error.InvalidPskIdentity;
    if (identity_len == 0 or age_end > identities_end) {
        return error.InvalidPskIdentity;
    }
    const identity = client_hello[pos..identity_end];
    pos = identity_end;
    const age = std.mem.readInt(u32, client_hello[pos..][0..4], .big);
    pos += 4;
    // This compact implementation offers exactly one identity.
    if (pos != identities_end) return error.InvalidPskIdentity;
    if (payload_end - pos < 3) return error.InvalidPskBinder;
    const binders_len =
        std.mem.readInt(u16, client_hello[pos..][0..2], .big);
    const binder_truncated_len = pos;
    pos += 2;
    if (binders_len != 1 + Sha256.digest_length or
        payload_end - pos != binders_len or
        client_hello[pos] != Sha256.digest_length)
    {
        return error.InvalidPskBinder;
    }
    pos += 1;
    const binder = client_hello[pos..][0..Sha256.digest_length].*;
    return .{
        .identity = identity,
        .obfuscated_ticket_age = age,
        .binder = binder,
        .binder_truncated_len = binder_truncated_len,
    };
}

const ClientHelloOffsets = struct {
    message_len: usize,
    body_len: usize,
    extensions_len_offset: usize,
    extensions_offset: usize,
    extensions_len: usize,
};

fn clientHelloOffsets(bytes: []const u8) Error!ClientHelloOffsets {
    if (bytes.len < 4 or bytes[0] != 1) return error.InvalidClientHello;
    const body_len = readU24(bytes[1..4]);
    if (body_len + 4 != bytes.len) return error.InvalidClientHello;
    var pos: usize = 4 + 2 + 32;
    if (pos >= bytes.len) return error.InvalidClientHello;
    const session_id_len = bytes[pos];
    pos = std.math.add(
        usize,
        pos + 1,
        session_id_len,
    ) catch return error.InvalidClientHello;
    if (pos + 2 > bytes.len) return error.InvalidClientHello;
    const cipher_suites_len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
    pos = std.math.add(
        usize,
        pos + 2,
        cipher_suites_len,
    ) catch return error.InvalidClientHello;
    if (pos >= bytes.len) return error.InvalidClientHello;
    const compression_len = bytes[pos];
    pos = std.math.add(
        usize,
        pos + 1,
        compression_len,
    ) catch return error.InvalidClientHello;
    if (pos + 2 > bytes.len) return error.InvalidClientHello;
    const extensions_len_offset = pos;
    const extensions_len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
    pos += 2;
    if (pos + extensions_len != bytes.len) return error.InvalidClientHello;
    return .{
        .message_len = bytes.len,
        .body_len = body_len,
        .extensions_len_offset = extensions_len_offset,
        .extensions_offset = pos,
        .extensions_len = extensions_len,
    };
}

fn transcriptHash(bytes: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}

test "TLS PSK appends and verifies a mandatory-last binder" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0x42} ** Sha256.digest_length;
    try appendClientOffer(
        &hello,
        allocator,
        "ticket-id",
        0x01020304,
        psk,
    );

    const offer = try parseClientOffer(hello.items);
    try std.testing.expectEqualStrings("ticket-id", offer.identity);
    try std.testing.expectEqual(@as(u32, 0x01020304), offer.obfuscated_ticket_age);
    try verifyClientOffer(hello.items, offer, "ticket-id", psk);

    var tampered = try hello.clone(allocator);
    defer tampered.deinit(allocator);
    tampered.items[offer.binder_truncated_len - 1] ^= 1;
    const tampered_offer = try parseClientOffer(tampered.items);
    try std.testing.expectError(
        error.InvalidPskBinder,
        verifyClientOffer(
            tampered.items,
            tampered_offer,
            "ticket-id",
            psk,
        ),
    );
    try std.testing.expectError(
        error.InvalidPskIdentity,
        verifyClientOffer(hello.items, offer, "other", psk),
    );
}

test "TLS PSK rejects malformed modes and non-last selection" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    try appendClientOffer(
        &hello,
        allocator,
        "ticket",
        0,
        [_]u8{0x33} ** Sha256.digest_length,
    );
    const offsets = try clientHelloOffsets(hello.items);
    // Locate psk_key_exchange_modes and replace psk_dhe_ke with psk_ke.
    var pos = offsets.extensions_offset;
    while (pos < hello.items.len) {
        const typ = std.mem.readInt(u16, hello.items[pos..][0..2], .big);
        const len = std.mem.readInt(u16, hello.items[pos + 2 ..][0..2], .big);
        if (typ == ext_psk_key_exchange_modes) {
            hello.items[pos + 5] = 0;
            break;
        }
        pos += 4 + len;
    }
    try std.testing.expectError(
        error.UnsupportedPskKeyExchangeMode,
        parseClientOffer(hello.items),
    );

    var server_extensions: std.ArrayList(u8) = .empty;
    defer server_extensions.deinit(allocator);
    try appendServerSelection(&server_extensions, allocator);
    try std.testing.expectEqual(
        selected_identity_first,
        try parseServerSelection(server_extensions.items[4..]),
    );
    try std.testing.expectError(
        error.InvalidServerHello,
        parseServerSelection(&.{ 0, 1 }),
    );
}

test "TLS PSK rejects duplicate offer extensions" {
    const allocator = std.testing.allocator;
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    const psk = [_]u8{0x35} ** Sha256.digest_length;
    try appendClientOffer(&hello, allocator, "ticket", 0, psk);
    try std.testing.expectError(
        error.InvalidClientHello,
        appendClientOffer(&hello, allocator, "ticket", 0, psk),
    );
    _ = try parseClientOffer(hello.items);

    // Turning the mode extension into a duplicate pre_shared_key extension
    // must fail before the payload can be interpreted as an identity vector.
    const offsets = try clientHelloOffsets(hello.items);
    std.mem.writeInt(
        u16,
        hello.items[offsets.extensions_offset..][0..2],
        ext_pre_shared_key,
        .big,
    );
    try std.testing.expectError(
        error.PskExtensionNotLast,
        parseClientOffer(hello.items),
    );
}

test "TLS PSK changes handshake key schedule" {
    const psk = [_]u8{0x55} ** Sha256.digest_length;
    const with_psk = earlySecret(psk);
    const without_psk = earlySecret(null);
    const zero = [_]u8{0} ** Sha256.digest_length;
    try std.testing.expect(!std.mem.eql(u8, &with_psk, &without_psk));
    try std.testing.expectEqualSlices(u8, &with_psk, &earlySecret(psk));
    try std.testing.expectEqualSlices(
        u8,
        &HkdfSha256.extract(&zero, &zero),
        &without_psk,
    );
}

test "TLS PSK validates ticket age, lifetime, and skew" {
    var hello = try baseClientHello(std.testing.allocator);
    defer hello.deinit(std.testing.allocator);
    try appendClientOffer(
        &hello,
        std.testing.allocator,
        "ticket",
        500 +% 17,
        [_]u8{0x44} ** Sha256.digest_length,
    );
    const offer = try parseClientOffer(hello.items);
    try validateTicketAge(offer, .{
        .age_add = 17,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
        .now_ms = 1500,
        .tolerance_ms = 0,
    });
    try std.testing.expectError(
        error.InvalidPskAge,
        validateTicketAge(offer, .{
            .age_add = 17,
            .issued_at_ms = 1000,
            .lifetime_seconds = 10,
            .now_ms = 1600,
            .tolerance_ms = 10,
        }),
    );
    try std.testing.expectError(
        error.ExpiredPsk,
        validateTicketAge(offer, .{
            .age_add = 17,
            .issued_at_ms = 1000,
            .lifetime_seconds = 1,
            .now_ms = 2001,
        }),
    );
}

fn checkAppendClientOfferAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var hello = try baseClientHello(allocator);
    defer hello.deinit(allocator);
    try appendClientOffer(
        &hello,
        allocator,
        "ticket",
        1,
        [_]u8{0x77} ** Sha256.digest_length,
    );
    const offer = try parseClientOffer(hello.items);
    try verifyClientOffer(
        hello.items,
        offer,
        "ticket",
        [_]u8{0x77} ** Sha256.digest_length,
    );
}

test "TLS PSK ClientHello append is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAppendClientOfferAllocationFailure,
        .{},
    );
}

fn baseClientHello(allocator: std.mem.Allocator) !std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    // legacy_version + random + empty session ID + one cipher + null
    // compression + empty extension vector.
    try body.appendSlice(allocator, &.{ 0x03, 0x03 });
    try body.appendNTimes(allocator, 0x11, 32);
    try body.append(allocator, 0);
    try body.appendSlice(allocator, &.{ 0, 2, 0x13, 0x01, 1, 0 });
    try body.appendSlice(allocator, &.{ 0, 0 });

    var hello: std.ArrayList(u8) = .empty;
    errdefer hello.deinit(allocator);
    try hello.append(allocator, 1);
    var len_bytes: [3]u8 = undefined;
    writeU24(&len_bytes, @intCast(body.items.len));
    try hello.appendSlice(allocator, &len_bytes);
    try hello.appendSlice(allocator, body.items);
    body.deinit(allocator);
    return hello;
}
