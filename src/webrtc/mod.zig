const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const runtime = @import("runtime.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidStunMessage,
    InvalidStunAttribute,
    MissingStunAttribute,
    BadMessageIntegrity,
    BadFingerprint,
    InvalidIceCandidate,
    MissingFingerprint,
    InvalidFingerprint,
    MissingIceUfrag,
    MissingIcePwd,
    InvalidSdp,
    InvalidDtlsRecord,
    InvalidRtpPacket,
    InvalidRtcpPacket,
    InvalidSrtpPacket,
    BadSrtpAuthTag,
    SrtpReplay,
    InvalidSctpPacket,
    BadSctpChecksum,
    UnknownIceCandidateType,
    UnsupportedAddressFamily,
    IntegerOverflow,
} || std.mem.Allocator.Error;

pub const stun = struct {
    pub const magic_cookie: u32 = 0x2112A442;

    pub const Class = enum(u2) {
        request = 0,
        indication = 1,
        success_response = 2,
        error_response = 3,
    };

    pub const Method = enum(u12) {
        binding = 0x001,
        _,
    };

    pub const AttributeType = enum(u16) {
        mapped_address = 0x0001,
        username = 0x0006,
        message_integrity = 0x0008,
        error_code = 0x0009,
        unknown_attributes = 0x000a,
        realm = 0x0014,
        nonce = 0x0015,
        xor_mapped_address = 0x0020,
        software = 0x8022,
        alternate_server = 0x8023,
        fingerprint = 0x8028,
        ice_controlled = 0x8029,
        ice_controlling = 0x802a,
        priority = 0x0024,
        use_candidate = 0x0025,
        _,
    };

    pub const Attribute = struct {
        attr_type: AttributeType,
        value: []const u8,
    };

    pub const message_integrity_len: usize = 20;
    pub const fingerprint_len: usize = 4;

    pub const XorMappedAddress = struct {
        family: AddressFamily,
        port: u16,
        address: [16]u8,
        address_len: u8,

        pub fn bytes(self: XorMappedAddress) []const u8 {
            return self.address[0..self.address_len];
        }
    };

    pub const AddressFamily = enum { ipv4, ipv6 };

    pub const ErrorCodeAttribute = struct {
        code: u16,
        reason: []const u8,
    };

    pub const error_code_role_conflict: u16 = 487;
    pub const role_conflict_reason = "Role Conflict";
    pub const error_code_reason_max_len: usize = 763;

    pub const Message = struct {
        class: Class,
        method: Method,
        transaction_id: [12]u8,
        attributes: []Attribute,

        pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
            allocator.free(self.attributes);
            self.* = undefined;
        }
    };

    pub fn encodeType(method: Method, class: Class) u16 {
        const m: u16 = @intFromEnum(method);
        const c: u16 = @intFromEnum(class);
        return (m & 0x000f) |
            ((m & 0x0070) << 1) |
            ((m & 0x0f80) << 2) |
            ((c & 0x01) << 4) |
            ((c & 0x02) << 7);
    }

    pub fn decodeType(value: u16) struct { method: Method, class: Class } {
        const method_value: u12 = @truncate((value & 0x000f) | ((value & 0x00e0) >> 1) | ((value & 0x3e00) >> 2));
        const class_value: u2 = @truncate(((value >> 4) & 0x01) | ((value >> 7) & 0x02));
        return .{ .method = @enumFromInt(method_value), .class = @enumFromInt(class_value) };
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!Message {
        var cursor = wire.Cursor.init(bytes);
        const typ = try cursor.readInt(u16, .big);
        if ((typ & 0xc000) != 0) return error.InvalidStunMessage;
        const len = try cursor.readInt(u16, .big);
        const cookie = try cursor.readInt(u32, .big);
        if (cookie != @This().magic_cookie) return error.InvalidStunMessage;
        const transaction_id = (try cursor.readSlice(12))[0..12].*;
        if ((len % 4) != 0) return error.InvalidStunMessage;
        const message_end = 20 + @as(usize, len);
        if (bytes.len < message_end) return error.BufferTooShort;
        if (bytes.len != message_end) return error.InvalidStunMessage;
        const decoded_type = decodeType(typ);
        var attr_cursor = wire.Cursor.init(bytes[20..message_end]);
        var attrs: std.ArrayList(Attribute) = .empty;
        errdefer attrs.deinit(allocator);
        var seen_integrity = false;
        var seen_fingerprint = false;
        while (!attr_cursor.eof()) {
            const attr_type: AttributeType = @enumFromInt(try attr_cursor.readInt(u16, .big));
            const attr_len = try attr_cursor.readInt(u16, .big);
            const value = try attr_cursor.readSlice(attr_len);
            const padding = (@as(usize, 4) - (attr_len % 4)) % 4;
            try attr_cursor.skip(padding);
            if (seen_fingerprint) return error.InvalidStunAttribute;
            if (seen_integrity and attr_type != .fingerprint) return error.InvalidStunAttribute;
            try attrs.append(allocator, .{ .attr_type = attr_type, .value = value });
            if (attr_type == .message_integrity) seen_integrity = true;
            if (attr_type == .fingerprint) seen_fingerprint = true;
        }
        return .{
            .class = decoded_type.class,
            .method = decoded_type.method,
            .transaction_id = transaction_id,
            .attributes = try attrs.toOwnedSlice(allocator),
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        class: Class,
        method: Method,
        transaction_id: [12]u8,
        attrs: []const Attribute,
    ) !void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        var seen_integrity = false;
        var seen_fingerprint = false;
        for (attrs) |attr| {
            if (seen_fingerprint) return error.InvalidStunAttribute;
            if (seen_integrity and attr.attr_type != .fingerprint) return error.InvalidStunAttribute;
            if (seen_fingerprint and attr.attr_type == .message_integrity) return error.InvalidStunAttribute;
            if (attr.value.len > std.math.maxInt(u16)) return error.InvalidStunAttribute;
            try wire.appendInt(&payload, allocator, u16, @intFromEnum(attr.attr_type), .big);
            try wire.appendInt(&payload, allocator, u16, @intCast(attr.value.len), .big);
            try payload.appendSlice(allocator, attr.value);
            const padding = (4 - (attr.value.len % 4)) % 4;
            try payload.appendNTimes(allocator, 0, padding);
            if (attr.attr_type == .message_integrity) seen_integrity = true;
            if (attr.attr_type == .fingerprint) seen_fingerprint = true;
        }
        try wire.appendInt(list, allocator, u16, encodeType(method, class), .big);
        try wire.appendInt(list, allocator, u16, @intCast(payload.items.len), .big);
        try wire.appendInt(list, allocator, u32, @This().magic_cookie, .big);
        try list.appendSlice(allocator, &transaction_id);
        try list.appendSlice(allocator, payload.items);
    }

    pub const IceRole = enum {
        controlling,
        controlled,
    };

    pub const ValidatedIceBindingRequest = struct {
        username: []const u8,
        priority: u32,
        role: IceRole,
        tie_breaker: u64,
        use_candidate: bool,
    };

    pub const IceRoleConflictDecision = enum {
        no_conflict,
        switch_role,
        reject_role_conflict,
    };

    pub const BindingRequestOptions = struct {
        transaction_id: [12]u8,
        username: []const u8,
        password: []const u8,
        priority: u32,
        role: IceRole,
        tie_breaker: u64,
        use_candidate: bool = false,
    };

    pub fn iceUsernameLocalUfrag(username: []const u8) []const u8 {
        // ICE USERNAME is "local-ufrag:remote-ufrag".  Pion's UDP/TCP muxes
        // route inbound STUN packets by taking the text before ':'; expose the
        // same small helper so netz runtimes can demux without duplicating
        // string-splitting edge cases.
        if (std.mem.indexOfScalar(u8, username, ':')) |colon| return username[0..colon];
        return username;
    }

    pub fn iceUsernameRemoteUfrag(username: []const u8) ?[]const u8 {
        const colon = std.mem.indexOfScalar(u8, username, ':') orelse return null;
        return username[colon + 1 ..];
    }

    pub fn writeIceBindingRequest(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: BindingRequestOptions) Error!void {
        var priority_value: [4]u8 = undefined;
        std.mem.writeInt(u32, &priority_value, options.priority, .big);
        var tie_breaker_value: [8]u8 = undefined;
        std.mem.writeInt(u64, &tie_breaker_value, options.tie_breaker, .big);

        var attrs_buf: [4]Attribute = undefined;
        var attr_count: usize = 0;
        attrs_buf[attr_count] = .{ .attr_type = .username, .value = options.username };
        attr_count += 1;
        attrs_buf[attr_count] = .{ .attr_type = .priority, .value = &priority_value };
        attr_count += 1;
        if (options.use_candidate) {
            attrs_buf[attr_count] = .{ .attr_type = .use_candidate, .value = &.{} };
            attr_count += 1;
        }
        attrs_buf[attr_count] = .{
            .attr_type = switch (options.role) {
                .controlling => .ice_controlling,
                .controlled => .ice_controlled,
            },
            .value = &tie_breaker_value,
        };
        attr_count += 1;

        try writeAuthenticated(list, allocator, .request, .binding, options.transaction_id, attrs_buf[0..attr_count], options.password);
    }

    pub fn writeAuthenticatedBindingSuccess(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        transaction_id: [12]u8,
        xor_mapped_value: []const u8,
        password: []const u8,
    ) Error!void {
        const attrs = [_]Attribute{.{ .attr_type = .xor_mapped_address, .value = xor_mapped_value }};
        try writeAuthenticated(list, allocator, .success_response, .binding, transaction_id, &attrs, password);
    }

    pub fn writeAuthenticatedBindingError(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        transaction_id: [12]u8,
        code: u16,
        reason: []const u8,
        password: []const u8,
    ) Error!void {
        var error_value: std.ArrayList(u8) = .empty;
        defer error_value.deinit(allocator);
        try writeErrorCodeValue(&error_value, allocator, code, reason);
        const attrs = [_]Attribute{.{ .attr_type = .error_code, .value = error_value.items }};
        try writeAuthenticated(list, allocator, .error_response, .binding, transaction_id, &attrs, password);
    }

    pub fn writeIceRoleConflictError(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        transaction_id: [12]u8,
        password: []const u8,
    ) Error!void {
        try writeAuthenticatedBindingError(list, allocator, transaction_id, error_code_role_conflict, role_conflict_reason, password);
    }

    pub fn validateIceBindingRequest(
        bytes: []const u8,
        message: Message,
        expected_username: []const u8,
        password: []const u8,
    ) Error!ValidatedIceBindingRequest {
        if (message.class != .request or message.method != .binding) return error.InvalidStunMessage;
        const username = attrValue(message, .username) orelse return error.MissingStunAttribute;
        if (!std.mem.eql(u8, username, expected_username)) return error.InvalidStunAttribute;

        // Pion's ICE agent rejects inbound Binding Requests before pair
        // handling when USERNAME or MESSAGE-INTEGRITY do not match local ICE
        // credentials. Validate the same invariant at the codec boundary so
        // callers that use netz's lightweight runtime cannot accidentally reply
        // to unauthenticated connectivity checks.
        try validateMessageIntegrity(bytes, password);
        if (attrValue(message, .fingerprint) != null) try validateFingerprint(bytes);

        const priority_value = try attrU32(message, .priority);
        const controlling = attrValue(message, .ice_controlling);
        const controlled = attrValue(message, .ice_controlled);
        if (controlling != null and controlled != null) return error.InvalidStunAttribute;
        if (controlling == null and controlled == null) return error.MissingStunAttribute;
        const role: IceRole = if (controlling != null) .controlling else .controlled;
        const tie_breaker = try attrU64(message, if (role == .controlling) .ice_controlling else .ice_controlled);

        if (attrValue(message, .use_candidate)) |value| {
            if (value.len != 0) return error.InvalidStunAttribute;
        }
        return .{
            .username = username,
            .priority = priority_value,
            .role = role,
            .tie_breaker = tie_breaker,
            .use_candidate = attrValue(message, .use_candidate) != null,
        };
    }

    pub fn resolveRoleConflict(local_role: IceRole, local_tie_breaker: u64, remote: ValidatedIceBindingRequest) IceRoleConflictDecision {
        if (local_role != remote.role) return .no_conflict;
        const local_is_greater_or_equal = local_tie_breaker >= remote.tie_breaker;

        // RFC 8445 section 7.3.1.1 / Pion ICE:
        // * controlling + local >= remote ICE-CONTROLLING => reject with 487
        // * controlled   + local <  remote ICE-CONTROLLED   => reject with 487
        // Otherwise the local agent switches role and continues processing the
        // connectivity check.  Exposing the pure decision here lets lightweight
        // runtimes share the same tiebreaker behavior without embedding a full
        // ICE agent state machine in the STUN codec.
        return switch (local_role) {
            .controlling => if (local_is_greater_or_equal) .reject_role_conflict else .switch_role,
            .controlled => if (!local_is_greater_or_equal) .reject_role_conflict else .switch_role,
        };
    }

    pub fn writeErrorCodeValue(list: *std.ArrayList(u8), allocator: std.mem.Allocator, code: u16, reason: []const u8) Error!void {
        if (reason.len > error_code_reason_max_len) return error.InvalidStunAttribute;
        const class = code / 100;
        const number = code % 100;
        // Follow pion/stun's ERROR-CODE wire layout: two reserved zero bytes,
        // one class byte, one modulo-100 number byte, then the reason phrase.
        if (class > std.math.maxInt(u8)) return error.InvalidStunAttribute;
        try list.appendSlice(allocator, &.{ 0, 0, @intCast(class), @intCast(number) });
        try list.appendSlice(allocator, reason);
    }

    pub fn parseErrorCodeAttribute(value: []const u8) Error!ErrorCodeAttribute {
        if (value.len < 4) return error.InvalidStunAttribute;
        const code = @as(u16, value[2]) * 100 + value[3];
        return .{ .code = code, .reason = value[4..] };
    }

    pub fn writeUnknownAttributesValue(list: *std.ArrayList(u8), allocator: std.mem.Allocator, attrs: []const AttributeType) Error!void {
        for (attrs) |attr| try wire.appendInt(list, allocator, u16, @intFromEnum(attr), .big);
    }

    pub fn parseUnknownAttributesValue(allocator: std.mem.Allocator, value: []const u8) Error![]AttributeType {
        if ((value.len % 2) != 0) return error.InvalidStunAttribute;
        const attrs = try allocator.alloc(AttributeType, value.len / 2);
        errdefer allocator.free(attrs);
        var cursor = wire.Cursor.init(value);
        for (attrs) |*attr| attr.* = @enumFromInt(try cursor.readInt(u16, .big));
        return attrs;
    }

    pub fn validateFingerprint(bytes: []const u8) Error!void {
        const located = (try findAttributeBytes(bytes, .fingerprint)) orelse return error.MissingStunAttribute;
        if (located.value.len != fingerprint_len) return error.InvalidStunAttribute;
        if (located.value_start + fingerprint_len != try stunMessageEnd(bytes)) return error.InvalidStunAttribute;
        const expected = fingerprint(bytes[0..located.attribute_start]);
        const actual = std.mem.readInt(u32, located.value[0..4], .big);
        if (actual != expected) return error.BadFingerprint;
    }

    pub fn validateMessageIntegrity(bytes: []const u8, password: []const u8) Error!void {
        const located = (try findAttributeBytes(bytes, .message_integrity)) orelse return error.MissingStunAttribute;
        if (located.value.len != message_integrity_len) return error.InvalidStunAttribute;

        const integrity_end = located.value_start + message_integrity_len;
        const length_with_integrity = std.math.cast(u16, integrity_end - 20) orelse return error.InvalidStunMessage;
        var length_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_bytes, length_with_integrity, .big);

        var expected: [message_integrity_len]u8 = undefined;
        var hmac = std.crypto.auth.hmac.HmacSha1.init(password);
        hmac.update(bytes[0..2]);
        hmac.update(&length_bytes);
        hmac.update(bytes[4..located.value_start]);
        hmac.final(&expected);
        if (!std.crypto.timing_safe.eql([message_integrity_len]u8, expected, located.value[0..message_integrity_len].*)) {
            return error.BadMessageIntegrity;
        }
    }

    pub fn attrValue(message: Message, attr_type: AttributeType) ?[]const u8 {
        for (message.attributes) |attr| {
            if (attr.attr_type == attr_type) return attr.value;
        }
        return null;
    }

    pub fn attrU32(message: Message, attr_type: AttributeType) Error!u32 {
        const value = attrValue(message, attr_type) orelse return error.MissingStunAttribute;
        if (value.len != 4) return error.InvalidStunAttribute;
        return std.mem.readInt(u32, value[0..4], .big);
    }

    pub fn attrU64(message: Message, attr_type: AttributeType) Error!u64 {
        const value = attrValue(message, attr_type) orelse return error.MissingStunAttribute;
        if (value.len != 8) return error.InvalidStunAttribute;
        return std.mem.readInt(u64, value[0..8], .big);
    }

    pub fn fingerprint(bytes: []const u8) u32 {
        return std.hash.Crc32.hash(bytes) ^ 0x5354554e;
    }

    pub fn priority(type_preference: u8, local_preference: u16, component_id: u8) u32 {
        return (@as(u32, type_preference) << 24) |
            (@as(u32, local_preference) << 8) |
            (@as(u32, 256) - component_id);
    }

    pub const DecodedPriority = struct {
        type_preference: u8,
        local_preference: u16,
        component_id: u8,
    };

    pub fn decodePriority(value: u32) Error!DecodedPriority {
        const component_delta = value & 0xff;
        if (component_delta == 0) return error.InvalidStunAttribute;
        return .{
            .type_preference = @truncate(value >> 24),
            .local_preference = @truncate((value >> 8) & 0xffff),
            .component_id = @intCast(256 - component_delta),
        };
    }

    pub fn parseXorMappedAddress(value: []const u8, transaction_id: [12]u8) Error!XorMappedAddress {
        if (value.len < 4 or value[0] != 0) return error.InvalidStunAttribute;
        const family = value[1];
        const port = std.mem.readInt(u16, value[2..4], .big) ^ @as(u16, @truncate(@This().magic_cookie >> 16));
        switch (family) {
            0x01 => {
                if (value.len != 8) return error.InvalidStunAttribute;
                var decoded: [16]u8 = undefined;
                @memset(&decoded, 0);
                @memcpy(decoded[0..4], value[4..8]);
                var cookie_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &cookie_bytes, @This().magic_cookie, .big);
                for (decoded[0..4], cookie_bytes) |*byte, key| byte.* ^= key;
                return .{ .family = .ipv4, .port = port, .address = decoded, .address_len = 4 };
            },
            0x02 => {
                if (value.len != 20) return error.InvalidStunAttribute;
                var decoded: [16]u8 = value[4..20].*;
                var key: [16]u8 = undefined;
                std.mem.writeInt(u32, key[0..4], @This().magic_cookie, .big);
                @memcpy(key[4..], &transaction_id);
                for (&decoded, key) |*byte, k| byte.* ^= k;
                return .{ .family = .ipv6, .port = port, .address = decoded, .address_len = 16 };
            },
            else => return error.UnsupportedAddressFamily,
        }
    }

    pub fn writeXorMappedAddress(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        family: AddressFamily,
        port: u16,
        address: []const u8,
        transaction_id: [12]u8,
    ) Error!void {
        try list.append(allocator, 0);
        try list.append(allocator, switch (family) {
            .ipv4 => 0x01,
            .ipv6 => 0x02,
        });
        try wire.appendInt(list, allocator, u16, port ^ @as(u16, @truncate(@This().magic_cookie >> 16)), .big);
        switch (family) {
            .ipv4 => {
                if (address.len != 4) return error.UnsupportedAddressFamily;
                var cookie_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &cookie_bytes, @This().magic_cookie, .big);
                for (address, cookie_bytes) |byte, key| try list.append(allocator, byte ^ key);
            },
            .ipv6 => {
                if (address.len != 16) return error.UnsupportedAddressFamily;
                var key: [16]u8 = undefined;
                std.mem.writeInt(u32, key[0..4], @This().magic_cookie, .big);
                @memcpy(key[4..], &transaction_id);
                for (address, key) |byte, k| try list.append(allocator, byte ^ k);
            },
        }
    }

    fn writeAuthenticated(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        class: Class,
        method: Method,
        transaction_id: [12]u8,
        attrs: []const Attribute,
        password: []const u8,
    ) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        for (attrs) |attr| try appendAttribute(&payload, allocator, attr);

        const integrity_payload_len = payload.items.len + 4 + message_integrity_len;
        var integrity_input: std.ArrayList(u8) = .empty;
        defer integrity_input.deinit(allocator);
        try writeHeaderAndPayload(&integrity_input, allocator, class, method, transaction_id, integrity_payload_len, payload.items);
        try wire.appendInt(&integrity_input, allocator, u16, @intFromEnum(AttributeType.message_integrity), .big);
        try wire.appendInt(&integrity_input, allocator, u16, message_integrity_len, .big);

        var integrity: [message_integrity_len]u8 = undefined;
        std.crypto.auth.hmac.HmacSha1.create(&integrity, integrity_input.items, password);
        try appendAttribute(&payload, allocator, .{ .attr_type = .message_integrity, .value = &integrity });

        const fingerprint_payload_len = payload.items.len + 4 + fingerprint_len;
        var fingerprint_input: std.ArrayList(u8) = .empty;
        defer fingerprint_input.deinit(allocator);
        try writeHeaderAndPayload(&fingerprint_input, allocator, class, method, transaction_id, fingerprint_payload_len, payload.items);
        const fingerprint_value = fingerprint(fingerprint_input.items);
        var fingerprint_bytes: [fingerprint_len]u8 = undefined;
        std.mem.writeInt(u32, &fingerprint_bytes, fingerprint_value, .big);
        try appendAttribute(&payload, allocator, .{ .attr_type = .fingerprint, .value = &fingerprint_bytes });

        try writeHeaderAndPayload(list, allocator, class, method, transaction_id, payload.items.len, payload.items);
    }

    fn writeHeaderAndPayload(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        class: Class,
        method: Method,
        transaction_id: [12]u8,
        payload_len: usize,
        payload: []const u8,
    ) Error!void {
        if (payload_len > std.math.maxInt(u16)) return error.InvalidStunMessage;
        try wire.appendInt(list, allocator, u16, encodeType(method, class), .big);
        try wire.appendInt(list, allocator, u16, @intCast(payload_len), .big);
        try wire.appendInt(list, allocator, u32, @This().magic_cookie, .big);
        try list.appendSlice(allocator, &transaction_id);
        try list.appendSlice(allocator, payload);
    }

    fn appendAttribute(list: *std.ArrayList(u8), allocator: std.mem.Allocator, attr: Attribute) Error!void {
        if (attr.value.len > std.math.maxInt(u16)) return error.InvalidStunAttribute;
        try wire.appendInt(list, allocator, u16, @intFromEnum(attr.attr_type), .big);
        try wire.appendInt(list, allocator, u16, @intCast(attr.value.len), .big);
        try list.appendSlice(allocator, attr.value);
        try list.appendNTimes(allocator, 0, (4 - (attr.value.len % 4)) % 4);
    }

    const LocatedAttribute = struct {
        attribute_start: usize,
        value_start: usize,
        value: []const u8,
    };

    fn findAttributeBytes(bytes: []const u8, wanted: AttributeType) Error!?LocatedAttribute {
        if (bytes.len < 20) return error.BufferTooShort;
        const payload_len = std.mem.readInt(u16, bytes[2..4], .big);
        if (bytes.len < 20 + @as(usize, payload_len)) return error.BufferTooShort;
        var pos: usize = 20;
        const end = 20 + @as(usize, payload_len);
        while (pos < end) {
            if (end - pos < 4) return error.InvalidStunAttribute;
            const attribute_start = pos;
            const attr_type: AttributeType = @enumFromInt(std.mem.readInt(u16, bytes[pos..][0..2], .big));
            const attr_len = std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big);
            pos += 4;
            if (pos + attr_len > end) return error.InvalidStunAttribute;
            const value_start = pos;
            const value = bytes[pos .. pos + attr_len];
            pos += attr_len;
            pos += (@as(usize, 4) - (attr_len % 4)) % 4;
            if (pos > end) return error.InvalidStunAttribute;
            if (attr_type == wanted) return .{
                .attribute_start = attribute_start,
                .value_start = value_start,
                .value = value,
            };
        }
        return null;
    }

    fn stunMessageEnd(bytes: []const u8) Error!usize {
        if (bytes.len < 20) return error.BufferTooShort;
        const payload_len = std.mem.readInt(u16, bytes[2..4], .big);
        if ((payload_len % 4) != 0) return error.InvalidStunMessage;
        const end = 20 + @as(usize, payload_len);
        if (bytes.len < end) return error.BufferTooShort;
        if (bytes.len != end) return error.InvalidStunMessage;
        return end;
    }
};

pub const ice = struct {
    pub const CandidateType = enum {
        host,
        srflx,
        prflx,
        relay,

        pub fn string(self: CandidateType) []const u8 {
            return @tagName(self);
        }

        pub fn preference(self: CandidateType) u8 {
            return candidateTypePreference(self);
        }
    };

    pub const Transport = enum {
        udp,
        tcp,

        pub fn string(self: Transport) []const u8 {
            return @tagName(self);
        }
    };

    pub fn transportFromString(value: []const u8) ?Transport {
        if (std.ascii.eqlIgnoreCase(value, "udp")) return .udp;
        if (std.ascii.eqlIgnoreCase(value, "tcp")) return .tcp;
        return null;
    }

    pub const TcpType = enum {
        active,
        passive,
        so,

        pub fn string(self: TcpType) []const u8 {
            return @tagName(self);
        }
    };

    pub const RelayProtocol = enum {
        udp,
        tcp,
        dtls,
        tls,

        pub fn string(self: RelayProtocol) []const u8 {
            return @tagName(self);
        }
    };

    pub fn relayProtocolFromString(value: []const u8) ?RelayProtocol {
        if (std.mem.eql(u8, value, "udp")) return .udp;
        if (std.mem.eql(u8, value, "tcp")) return .tcp;
        if (std.mem.eql(u8, value, "dtls")) return .dtls;
        if (std.mem.eql(u8, value, "tls")) return .tls;
        return null;
    }

    pub const Component = enum(u8) {
        unknown = 0,
        rtp = 1,
        rtcp = 2,

        pub fn id(self: Component) u8 {
            return @intFromEnum(self);
        }

        pub fn string(self: Component) []const u8 {
            return switch (self) {
                .rtp => "rtp",
                .rtcp => "rtcp",
                .unknown => "unknown",
            };
        }
    };

    pub fn componentFromString(value: []const u8) Component {
        if (std.mem.eql(u8, value, "rtp")) return .rtp;
        if (std.mem.eql(u8, value, "rtcp")) return .rtcp;
        return .unknown;
    }

    pub fn componentFromId(id: u8) Component {
        return switch (id) {
            1 => .rtp,
            2 => .rtcp,
            else => .unknown,
        };
    }

    pub const NetworkType = enum {
        unknown,
        udp4,
        udp6,
        tcp4,
        tcp6,

        pub fn string(self: NetworkType) []const u8 {
            return switch (self) {
                .udp4 => "udp4",
                .udp6 => "udp6",
                .tcp4 => "tcp4",
                .tcp6 => "tcp6",
                .unknown => "unknown",
            };
        }

        pub fn protocol(self: NetworkType) ?Transport {
            return switch (self) {
                .udp4, .udp6 => .udp,
                .tcp4, .tcp6 => .tcp,
                .unknown => null,
            };
        }
    };

    pub const supported_network_types: []const NetworkType = &.{ .udp4, .udp6 };

    pub fn networkTypeFromString(value: []const u8) NetworkType {
        if (std.mem.eql(u8, value, "udp4")) return .udp4;
        if (std.mem.eql(u8, value, "udp6")) return .udp6;
        if (std.mem.eql(u8, value, "tcp4")) return .tcp4;
        if (std.mem.eql(u8, value, "tcp6")) return .tcp6;
        return .unknown;
    }

    pub const default_local_preference: u16 = 65_535;
    pub const default_tcp_priority_offset: u8 = 27;
    pub const max_tcp_direction_preference: u3 = 7;
    pub const max_tcp_other_preference: u13 = 8_191;

    pub const CandidatePriorityOptions = struct {
        transport: Transport = .udp,
        tcp_type: ?TcpType = null,
        tcp_priority_offset: u8 = default_tcp_priority_offset,
        relay_protocol: RelayProtocol = .udp,
        local_preference: ?u16 = null,
        tcp_other_preference: u13 = max_tcp_other_preference,
    };

    pub const CandidateExtension = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const Candidate = struct {
        foundation: []const u8,
        component: u16,
        transport: Transport,
        priority: u32,
        address: []const u8,
        port: u16,
        candidate_type: CandidateType,
        related_address: ?[]const u8 = null,
        related_port: ?u16 = null,
        tcp_type: ?[]const u8 = null,
        extensions: []CandidateExtension = &.{},

        pub fn parse(line: []const u8) Error!Candidate {
            return parseInternal(null, line);
        }

        pub fn parseOwned(allocator: std.mem.Allocator, line: []const u8) Error!Candidate {
            return parseInternal(allocator, line);
        }

        fn parseInternal(allocator: ?std.mem.Allocator, line: []const u8) Error!Candidate {
            const prefix = "candidate:";
            const body = if (std.mem.startsWith(u8, line, "a=")) line[2..] else line;
            const candidate_body = if (std.mem.startsWith(u8, body, prefix)) body[prefix.len..] else body;
            var it = std.mem.splitScalar(u8, candidate_body, ' ');
            const foundation = it.next() orelse return error.InvalidIceCandidate;
            try validateIceFoundation(foundation);
            const component_s = it.next() orelse return error.InvalidIceCandidate;
            try validateDecimalToken(component_s, 5);
            const transport_s = it.next() orelse return error.InvalidIceCandidate;
            const priority_s = it.next() orelse return error.InvalidIceCandidate;
            try validateDecimalToken(priority_s, 10);
            const address_token = it.next() orelse return error.InvalidIceCandidate;
            const address = stripIpv6ZoneId(address_token);
            try validateCandidateAddress(address);
            const port_s = it.next() orelse return error.InvalidIceCandidate;
            try validateDecimalToken(port_s, 5);
            const typ_label = it.next() orelse return error.InvalidIceCandidate;
            if (!std.mem.eql(u8, typ_label, "typ")) return error.InvalidIceCandidate;
            const typ_s = it.next() orelse return error.InvalidIceCandidate;
            const extension_raw = it.rest();

            var extensions: std.ArrayList(CandidateExtension) = .empty;
            errdefer if (allocator) |a| extensions.deinit(a);
            var candidate: Candidate = .{
                .foundation = foundation,
                .component = std.fmt.parseInt(u16, component_s, 10) catch return error.InvalidIceCandidate,
                .transport = transportFromString(transport_s) orelse return error.InvalidIceCandidate,
                .priority = std.fmt.parseInt(u32, priority_s, 10) catch return error.InvalidIceCandidate,
                .address = address,
                .port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidIceCandidate,
                .candidate_type = candidateTypeFromString(typ_s) orelse return error.UnknownIceCandidateType,
            };

            var ext_pos: usize = 0;
            while (try nextCandidateExtensionToken(extension_raw, &ext_pos)) |key| {
                const value = try nextCandidateExtensionValue(extension_raw, &ext_pos);
                if (std.mem.eql(u8, key, "raddr")) {
                    if (candidate.related_address != null or candidate.related_port != null) return error.InvalidIceCandidate;
                    const related_address = stripIpv6ZoneId(value);
                    try validateCandidateAddress(related_address);
                    candidate.related_address = related_address;
                    const rport_key = (try nextCandidateExtensionToken(extension_raw, &ext_pos)) orelse return error.InvalidIceCandidate;
                    if (!std.mem.eql(u8, rport_key, "rport")) return error.InvalidIceCandidate;
                    const rport_value = try nextCandidateExtensionValue(extension_raw, &ext_pos);
                    try validateDecimalToken(rport_value, 5);
                    candidate.related_port = std.fmt.parseInt(u16, rport_value, 10) catch return error.InvalidIceCandidate;
                } else if (std.mem.eql(u8, key, "rport")) {
                    return error.InvalidIceCandidate;
                } else if (std.mem.eql(u8, key, "tcptype")) {
                    if (!validTcpType(value)) return error.InvalidIceCandidate;
                    candidate.tcp_type = value;
                } else if (allocator) |a| {
                    // Pion preserves candidate extension attributes such as
                    // generation/network-id/network-cost and writes them back in
                    // insertion order.  The zero-allocation parse path keeps its
                    // previous lightweight behavior, while parseOwned exposes the
                    // full extension list for SDP round-tripping.
                    try extensions.append(a, .{ .key = key, .value = value });
                }
            }
            if (allocator) |a| candidate.extensions = try extensions.toOwnedSlice(a);
            return candidate;
        }

        pub fn deinit(self: *Candidate, allocator: std.mem.Allocator) void {
            allocator.free(self.extensions);
            self.* = undefined;
        }

        pub fn parsedTcpType(self: Candidate) Error!?TcpType {
            const value = self.tcp_type orelse return null;
            return tcpTypeFromString(value) orelse error.InvalidIceCandidate;
        }

        pub fn extensionValue(self: Candidate, key: []const u8) ?[]const u8 {
            if (std.ascii.eqlIgnoreCase(key, "tcptype")) {
                if (self.tcp_type) |value| return value;
            }
            for (self.extensions) |extension| {
                if (std.ascii.eqlIgnoreCase(extension.key, key)) return extension.value;
            }
            return null;
        }

        pub fn exportedExtensions(self: Candidate, allocator: std.mem.Allocator) Error![]CandidateExtension {
            const tcp_count: usize = if (self.tcp_type != null) 1 else 0;
            const out = try allocator.alloc(CandidateExtension, tcp_count + self.extensions.len);
            if (self.tcp_type) |tcp| {
                out[0] = .{ .key = "tcptype", .value = tcp };
            }
            @memcpy(out[tcp_count..], self.extensions);
            return out;
        }

        pub fn addExtension(self: *Candidate, allocator: std.mem.Allocator, extension: CandidateExtension) Error!void {
            try validateCandidateByteString(extension.key);
            try validateCandidateExtensionByteString(extension.value);
            if (std.mem.eql(u8, extension.key, "tcptype")) {
                if (!validTcpType(extension.value)) return error.InvalidIceCandidate;
                self.tcp_type = extension.value;
                return;
            }
            for (self.extensions) |*existing| {
                if (std.mem.eql(u8, existing.key, extension.key)) {
                    existing.* = extension;
                    return;
                }
            }
            if (self.extensions.len == 0) {
                self.extensions = try allocator.alloc(CandidateExtension, 1);
                self.extensions[0] = extension;
                return;
            }
            self.extensions = try allocator.realloc(self.extensions, self.extensions.len + 1);
            self.extensions[self.extensions.len - 1] = extension;
        }

        pub fn removeExtension(self: *Candidate, allocator: std.mem.Allocator, key: []const u8) Error!bool {
            var removed = false;
            if (std.mem.eql(u8, key, "tcptype") and self.tcp_type != null) {
                self.tcp_type = null;
                removed = true;
            }
            for (self.extensions, 0..) |extension, index| {
                if (!std.mem.eql(u8, extension.key, key)) continue;
                std.mem.copyForwards(CandidateExtension, self.extensions[index .. self.extensions.len - 1], self.extensions[index + 1 ..]);
                self.extensions = try allocator.realloc(self.extensions, self.extensions.len - 1);
                return true;
            }
            return removed;
        }

        pub fn computedPriority(self: Candidate, options: CandidatePriorityOptions) Error!u32 {
            if (self.component == 0 or self.component > std.math.maxInt(u8)) return error.InvalidIceCandidate;
            var effective = options;
            effective.transport = self.transport;
            if (effective.tcp_type == null) effective.tcp_type = try self.parsedTcpType();
            return candidatePriority(self.candidate_type, @intCast(self.component), effective);
        }

        pub fn write(self: Candidate, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
            try self.validateForWrite();
            try list.appendSlice(allocator, "candidate:");
            try list.appendSlice(allocator, self.foundation);
            try appendFmt(list, allocator, " {} {s} {} {s} {} typ {s}", .{
                self.component,
                @tagName(self.transport),
                self.priority,
                self.address,
                self.port,
                @tagName(self.candidate_type),
            });
            if (self.related_address) |addr| {
                try appendFmt(list, allocator, " raddr {s}", .{addr});
            }
            if (self.related_port) |port| {
                try appendFmt(list, allocator, " rport {}", .{port});
            }
            if (self.tcp_type) |tcp| {
                try appendFmt(list, allocator, " tcptype {s}", .{tcp});
            }
            for (self.extensions) |extension| {
                try appendFmt(list, allocator, " {s} {s}", .{ extension.key, extension.value });
            }
        }

        fn validateForWrite(self: Candidate) Error!void {
            try validateIceFoundation(self.foundation);
            try validateCandidateAddress(self.address);
            if (self.related_address) |addr| try validateCandidateAddress(addr);
            if (self.related_port != null and self.related_address == null) return error.InvalidIceCandidate;
            if (self.tcp_type) |tcp| {
                if (!validTcpType(tcp)) return error.InvalidIceCandidate;
            }
            for (self.extensions) |extension| {
                try validateCandidateByteString(extension.key);
                try validateCandidateExtensionByteString(extension.value);
                if (std.mem.eql(u8, extension.key, "raddr") or
                    std.mem.eql(u8, extension.key, "rport") or
                    std.mem.eql(u8, extension.key, "tcptype")) return error.InvalidIceCandidate;
            }
        }
    };

    pub fn candidateTypePreference(candidate_type: CandidateType) u8 {
        // RFC 5245/8445 recommended type preferences, mirrored by Pion ICE:
        // host candidates win over peer-reflexive, then server-reflexive, while
        // relayed candidates use local preference to rank relay transports.
        return switch (candidate_type) {
            .host => 126,
            .prflx => 110,
            .srflx => 100,
            .relay => 0,
        };
    }

    pub fn typePreference(candidate_type: CandidateType, options: CandidatePriorityOptions) u8 {
        const base = candidateTypePreference(candidate_type);
        if (base == 0 or options.transport != .tcp) return base;
        return if (options.tcp_priority_offset >= base) 0 else base - options.tcp_priority_offset;
    }

    pub fn relayLocalPreference(protocol: RelayProtocol) u16 {
        return switch (protocol) {
            .tls => 0,
            .tcp => 1,
            .dtls => 2,
            .udp => 3,
        };
    }

    pub fn tcpLocalPreference(candidate_type: CandidateType, tcp_type: ?TcpType, other_preference: u13) u16 {
        const direction_preference: u16 = switch (candidate_type) {
            .host, .relay => switch (tcp_type orelse return @as(u16, other_preference)) {
                .active => 6,
                .passive => 4,
                .so => 2,
            },
            .prflx, .srflx => switch (tcp_type orelse return @as(u16, other_preference)) {
                .so => 6,
                .active => 4,
                .passive => 2,
            },
        };
        // RFC 6544 folds TCP direction preference into the ICE local
        // preference.  Keep other-pref explicit so multi-homed callers can
        // provide stable per-interface ordering instead of relying on SDP order.
        return (@as(u16, 1) << 13) * direction_preference + @as(u16, other_preference);
    }

    pub fn localPreference(candidate_type: CandidateType, options: CandidatePriorityOptions) u16 {
        if (options.local_preference) |preference| return preference;
        if (candidate_type == .relay) return relayLocalPreference(options.relay_protocol);
        if (options.transport == .tcp) return tcpLocalPreference(candidate_type, options.tcp_type, options.tcp_other_preference);
        return default_local_preference;
    }

    pub fn candidatePriority(candidate_type: CandidateType, component_id: u8, options: CandidatePriorityOptions) Error!u32 {
        if (component_id == 0) return error.InvalidIceCandidate;
        return stun.priority(typePreference(candidate_type, options), localPreference(candidate_type, options), component_id);
    }

    pub fn pairPriority(controlling_priority: u32, controlled_priority: u32) u64 {
        const min_priority = @as(u64, @min(controlling_priority, controlled_priority));
        const max_priority = @as(u64, @max(controlling_priority, controlled_priority));
        const tie_breaker: u64 = if (controlling_priority > controlled_priority) 1 else 0;
        // RFC 5245 section 5.7.2 defines pair priority in terms of the
        // controlling (G) and controlled (D) candidate priorities.  Pion uses
        // 2^32-1 as the multiplier so the maxUint32/maxUint32 case remains in
        // range for u64 while preserving the ordering semantics.
        return (((@as(u64, 1) << 32) - 1) * min_priority) + (2 * max_priority) + tie_breaker;
    }

    pub fn pairPriorityForRole(local_priority: u32, remote_priority: u32, local_role: stun.IceRole) u64 {
        return switch (local_role) {
            .controlling => pairPriority(local_priority, remote_priority),
            .controlled => pairPriority(remote_priority, local_priority),
        };
    }

    pub fn candidateTypeFromString(value: []const u8) ?CandidateType {
        inline for (std.meta.fields(CandidateType)) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn tcpTypeFromString(value: []const u8) ?TcpType {
        inline for (std.meta.fields(TcpType)) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    fn validateIceFoundation(value: []const u8) Error!void {
        // RFC 8445 keeps the foundation to 1*32 ice-char.  Pion's ICE parser
        // applies the same bound before candidate construction so malformed SDP
        // cannot sneak control bytes or path-like tokens into later ICE state.
        if (value.len == 0 or value.len > 32) return error.InvalidIceCandidate;
        for (value) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '+' and byte != '/') return error.InvalidIceCandidate;
        }
    }

    fn validateDecimalToken(value: []const u8, max_len: usize) Error!void {
        if (value.len == 0 or value.len > max_len) return error.InvalidIceCandidate;
        for (value) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidIceCandidate;
        }
    }

    fn validateCandidateByteString(value: []const u8) Error!void {
        if (value.len == 0) return error.InvalidIceCandidate;
        for (value) |byte| {
            // RFC 4566 byte-string excludes NUL, CR, and LF.  This catches SDP
            // line injection in extension attributes while preserving mDNS
            // hostnames and IPv6 literals that are common in WebRTC candidates.
            if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidIceCandidate;
        }
    }

    fn validateCandidateExtensionByteString(value: []const u8) Error!void {
        for (value) |byte| {
            if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidIceCandidate;
        }
    }

    fn nextCandidateExtensionToken(raw: []const u8, pos: *usize) Error!?[]const u8 {
        if (pos.* >= raw.len) return null;
        const start = pos.*;
        var end = start;
        while (end < raw.len and raw[end] != ' ') : (end += 1) {}
        const token = raw[start..end];
        if (token.len == 0) return error.InvalidIceCandidate;
        try validateCandidateByteString(token);
        pos.* = if (end < raw.len) end + 1 else end;
        return token;
    }

    fn nextCandidateExtensionValue(raw: []const u8, pos: *usize) Error![]const u8 {
        if (pos.* >= raw.len) return "";
        const start = pos.*;
        var end = start;
        while (end < raw.len and raw[end] != ' ') : (end += 1) {}
        const value = raw[start..end];
        try validateCandidateExtensionByteString(value);
        pos.* = if (end < raw.len) end + 1 else end;
        return value;
    }

    fn validateCandidateAddress(value: []const u8) Error!void {
        try validateCandidateByteString(value);
        if (std.Io.net.IpAddress.parse(value, 0)) |_| {
            return;
        } else |_| {}
        try validateHostname(value);
    }

    fn stripIpv6ZoneId(value: []const u8) []const u8 {
        // Pion/ICE normalizes candidates such as "fe80::1%eth0" by dropping
        // the local-interface zone before comparing or serializing.  SDP
        // candidates are exchanged between peers, so local zone identifiers are
        // not meaningful on the remote endpoint.
        if (std.mem.indexOfScalar(u8, value, ':') == null) return value;
        if (std.mem.indexOfScalar(u8, value, '%')) |zone| return value[0..zone];
        return value;
    }

    fn validateHostname(value: []const u8) Error!void {
        if (value.len == 0 or value.len > 253) return error.InvalidIceCandidate;
        var labels = std.mem.splitScalar(u8, value, '.');
        var saw_label = false;
        while (labels.next()) |label| {
            if (label.len == 0 or label.len > 63) return error.InvalidIceCandidate;
            saw_label = true;
            for (label) |byte| {
                if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.InvalidIceCandidate;
            }
        }
        if (!saw_label) return error.InvalidIceCandidate;
    }

    fn validTcpType(value: []const u8) bool {
        return tcpTypeFromString(value) != null;
    }
};

pub const sdp = struct {
    pub const Attribute = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn formatAttributeLine(allocator: std.mem.Allocator, attr: Attribute) Error![]u8 {
        try validateSdpToken(attr.name);
        if (attr.value.len == 0) {
            return std.fmt.allocPrint(allocator, "a={s}\r\n", .{attr.name});
        }
        try validateSdpAttributeValue(attr.value);
        return std.fmt.allocPrint(allocator, "a={s}:{s}\r\n", .{ attr.name, attr.value });
    }

    pub fn appendAttributeLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, attr: Attribute) Error!void {
        const line = try formatAttributeLine(allocator, attr);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub const Media = struct {
        kind: []const u8,
        port: u16,
        port_range: ?u16 = null,
        protocol: []const u8,
        formats: []const u8,
        title: ?[]const u8 = null,
        connection: ?Connection = null,
        bandwidth: []Bandwidth = &.{},
        encryption_key: ?[]const u8 = null,
        attributes: []Attribute,
    };

    const MediaHeader = struct {
        kind: []const u8,
        port: u16,
        port_range: ?u16 = null,
        protocol: []const u8,
        formats: []const u8,
    };

    pub const Connection = struct {
        network_type: []const u8,
        address_type: []const u8,
        address: []const u8,
    };

    pub const ConnectionAddress = struct {
        address: []const u8,
        ttl: ?u16 = null,
        range: ?u16 = null,
    };

    pub const unspecified_ipv4_connection: Connection = .{
        .network_type = "IN",
        .address_type = "IP4",
        .address = "0.0.0.0",
    };

    pub const RtcpAddress = struct {
        port: u16,
        connection: ?Connection = null,
    };

    pub const Bandwidth = struct {
        typ: []const u8,
        bandwidth: u64,
        experimental: bool = false,
    };

    pub const Origin = struct {
        username: []const u8,
        session_id: u64,
        session_version: u64,
        network_type: []const u8,
        address_type: []const u8,
        unicast_address: []const u8,
    };

    pub const Timing = struct {
        start_time: u64,
        stop_time: u64,
    };

    pub const RepeatTime = struct {
        interval: i64,
        duration: i64,
        offsets: []const i64 = &.{},
    };

    pub const TimeZone = struct {
        adjustment_time: u64,
        offset: i64,
    };

    pub const Session = struct {
        version: []const u8 = "0",
        origin: []const u8 = "- 0 0 IN IP4 127.0.0.1",
        name: []const u8 = "-",
        information: ?[]const u8 = null,
        uri: ?[]const u8 = null,
        email: ?[]const u8 = null,
        phone: ?[]const u8 = null,
        connection: ?Connection = null,
        bandwidth: []Bandwidth = &.{},
        timing: []const u8 = "0 0",
        repeat_times: []const []const u8 = &.{},
        time_zones: ?[]const u8 = null,
        encryption_key: ?[]const u8 = null,
        attributes: []Attribute,
        media: []Media,

        pub fn deinit(self: *Session, allocator: std.mem.Allocator) void {
            allocator.free(self.bandwidth);
            allocator.free(self.repeat_times);
            allocator.free(self.attributes);
            for (self.media) |media| {
                allocator.free(media.bandwidth);
                allocator.free(media.attributes);
            }
            allocator.free(self.media);
            self.* = undefined;
        }
    };

    pub const Fingerprint = struct {
        algorithm: []const u8,
        value: []const u8,
    };

    pub const IceCredentials = struct {
        ufrag: []const u8,
        password: []const u8,
    };

    pub const ice_option_trickle = "trickle";
    pub const ice_option_renomination = "renomination";

    pub const IceCandidate = struct {
        candidate: ice.Candidate,
        sdp_mid: ?[]const u8 = null,
        sdp_mline_index: u16 = 0,

        pub fn deinit(self: *IceCandidate, allocator: std.mem.Allocator) void {
            var candidate = self.candidate;
            candidate.deinit(allocator);
            self.* = undefined;
        }
    };

    pub const IceDetails = struct {
        credentials: IceCredentials,
        candidates: []IceCandidate,
        end_of_candidates: bool = false,

        pub fn deinit(self: *IceDetails, allocator: std.mem.Allocator) void {
            for (self.candidates) |*candidate| candidate.deinit(allocator);
            allocator.free(self.candidates);
            self.* = undefined;
        }
    };

    pub const TransportAttributes = struct {
        ice_lite: bool = false,
        rtcp_mux: bool = false,
        rtcp_rsize: bool = false,
    };

    pub const SdpType = enum {
        unknown,
        offer,
        pranswer,
        answer,
        rollback,

        pub fn string(self: SdpType) []const u8 {
            return switch (self) {
                .offer => "offer",
                .pranswer => "pranswer",
                .answer => "answer",
                .rollback => "rollback",
                .unknown => "unknown",
            };
        }
    };

    pub fn parseSdpType(raw: []const u8) SdpType {
        if (std.mem.eql(u8, raw, "offer")) return .offer;
        if (std.mem.eql(u8, raw, "pranswer")) return .pranswer;
        if (std.mem.eql(u8, raw, "answer")) return .answer;
        if (std.mem.eql(u8, raw, "rollback")) return .rollback;
        return .unknown;
    }

    pub fn parseSdpTypeIgnoreCase(raw: []const u8) SdpType {
        if (std.ascii.eqlIgnoreCase(raw, "offer")) return .offer;
        if (std.ascii.eqlIgnoreCase(raw, "pranswer")) return .pranswer;
        if (std.ascii.eqlIgnoreCase(raw, "answer")) return .answer;
        if (std.ascii.eqlIgnoreCase(raw, "rollback")) return .rollback;
        return .unknown;
    }

    pub const RtpCodecType = enum {
        unknown,
        audio,
        video,

        pub fn mediaKind(self: RtpCodecType) []const u8 {
            return switch (self) {
                .audio => "audio",
                .video => "video",
                .unknown => "unknown",
            };
        }
    };

    pub fn rtpCodecTypeForMediaKind(kind: []const u8) RtpCodecType {
        if (std.ascii.eqlIgnoreCase(kind, "audio")) return .audio;
        if (std.ascii.eqlIgnoreCase(kind, "video")) return .video;
        return .unknown;
    }

    pub const MediaDirection = enum {
        sendrecv,
        sendonly,
        recvonly,
        inactive,

        pub fn attribute(self: MediaDirection) []const u8 {
            return switch (self) {
                .sendrecv => "sendrecv",
                .sendonly => "sendonly",
                .recvonly => "recvonly",
                .inactive => "inactive",
            };
        }
    };

    pub fn parseMediaDirection(value: []const u8) ?MediaDirection {
        inline for (std.meta.fields(MediaDirection)) |field| {
            if (std.ascii.eqlIgnoreCase(value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn mediaDirection(media: Media) ?MediaDirection {
        for (media.attributes) |attr| {
            if (attr.value.len != 0) continue;
            if (parseMediaDirection(attr.name)) |direction| return direction;
        }
        return null;
    }

    pub fn reverseMediaDirection(direction: MediaDirection) MediaDirection {
        return switch (direction) {
            .sendonly => .recvonly,
            .recvonly => .sendonly,
            else => direction,
        };
    }

    pub fn mediaDirectionIntersects(haystack: []const MediaDirection, needle: []const MediaDirection) bool {
        for (needle) |candidate| {
            for (haystack) |existing| {
                if (existing == candidate) return true;
            }
        }
        return false;
    }

    pub fn preferredLocalDirectionsForRemote(remote: MediaDirection) []const MediaDirection {
        return switch (remote) {
            .sendrecv => &.{ .recvonly, .sendrecv, .sendonly },
            .sendonly => &.{.recvonly},
            .recvonly => &.{ .sendonly, .sendrecv },
            .inactive => &.{},
        };
    }

    pub fn formatMediaDirectionLine(allocator: std.mem.Allocator, direction: MediaDirection) Error![]u8 {
        return std.fmt.allocPrint(allocator, "a={s}\r\n", .{direction.attribute()});
    }

    pub fn appendMediaDirectionLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, direction: MediaDirection) Error!void {
        const line = try formatMediaDirectionLine(allocator, direction);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub const TransportLineOptions = struct {
        ice_credentials: ?IceCredentials = null,
        fingerprint: ?Fingerprint = null,
        dtls_role: ?DtlsRole = null,
        transport_attributes: TransportAttributes = .{},
        extmap_allow_mixed: bool = false,
    };

    pub const DtlsRole = enum {
        auto,
        client,
        server,

        pub fn setupAttribute(self: DtlsRole) []const u8 {
            return switch (self) {
                .auto => "actpass",
                .client => "active",
                .server => "passive",
            };
        }
    };

    pub fn formatIceUfragLine(allocator: std.mem.Allocator, credentials: IceCredentials) Error![]u8 {
        try validateIceCredentialToken(credentials.ufrag);
        return std.fmt.allocPrint(allocator, "a=ice-ufrag:{s}\r\n", .{credentials.ufrag});
    }

    pub fn formatIcePwdLine(allocator: std.mem.Allocator, credentials: IceCredentials) Error![]u8 {
        try validateIceCredentialToken(credentials.password);
        return std.fmt.allocPrint(allocator, "a=ice-pwd:{s}\r\n", .{credentials.password});
    }

    pub fn formatIceOptionsAttribute(allocator: std.mem.Allocator, options: []const []const u8) Error![]u8 {
        if (options.len == 0) return error.InvalidSdp;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (options, 0..) |option, index| {
            try validateSdpToken(option);
            if (iceOptionSliceHasToken(options[0..index], option)) continue;
            if (out.items.len != 0) try out.append(allocator, ' ');
            try out.appendSlice(allocator, option);
        }
        if (out.items.len == 0) return error.InvalidSdp;
        return out.toOwnedSlice(allocator);
    }

    pub fn formatIceOptionsLine(allocator: std.mem.Allocator, options: []const []const u8) Error![]u8 {
        const attr = try formatIceOptionsAttribute(allocator, options);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "a=ice-options:{s}\r\n", .{attr});
    }

    pub fn appendIceOptionsLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: []const []const u8) Error!void {
        const line = try formatIceOptionsLine(allocator, options);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatIceLiteLine(allocator: std.mem.Allocator) Error![]u8 {
        return allocator.dupe(u8, "a=ice-lite\r\n");
    }

    pub fn appendIceLiteLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try list.appendSlice(allocator, "a=ice-lite\r\n");
    }

    pub fn formatFingerprintLine(allocator: std.mem.Allocator, fingerprint: Fingerprint) Error![]u8 {
        const digest_len = fingerprintDigestLen(fingerprint.algorithm) orelse return error.InvalidFingerprint;
        try validateColonHexFingerprint(fingerprint.value, digest_len);
        return std.fmt.allocPrint(allocator, "a=fingerprint:{s} {s}\r\n", .{ fingerprint.algorithm, fingerprint.value });
    }

    pub fn formatDtlsSetupLine(allocator: std.mem.Allocator, role: DtlsRole) Error![]u8 {
        return std.fmt.allocPrint(allocator, "a=setup:{s}\r\n", .{role.setupAttribute()});
    }

    pub fn appendTransportAttributeLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: TransportLineOptions) Error!void {
        if (options.transport_attributes.ice_lite) try appendIceLiteLine(list, allocator);
        if (options.dtls_role) |role| {
            const line = try formatDtlsSetupLine(allocator, role);
            defer allocator.free(line);
            try list.appendSlice(allocator, line);
        }
        if (options.fingerprint) |fingerprint| {
            const line = try formatFingerprintLine(allocator, fingerprint);
            defer allocator.free(line);
            try list.appendSlice(allocator, line);
        }
        if (options.ice_credentials) |credentials| {
            const ufrag = try formatIceUfragLine(allocator, credentials);
            defer allocator.free(ufrag);
            try list.appendSlice(allocator, ufrag);
            const pwd = try formatIcePwdLine(allocator, credentials);
            defer allocator.free(pwd);
            try list.appendSlice(allocator, pwd);
        }
        if (options.transport_attributes.rtcp_mux) try list.appendSlice(allocator, "a=rtcp-mux\r\n");
        if (options.transport_attributes.rtcp_rsize) try list.appendSlice(allocator, "a=rtcp-rsize\r\n");
        if (options.extmap_allow_mixed) try list.appendSlice(allocator, "a=extmap-allow-mixed\r\n");
    }

    pub fn formatMidLine(allocator: std.mem.Allocator, mid: []const u8) Error![]u8 {
        try validateSdpToken(mid);
        return std.fmt.allocPrint(allocator, "a=mid:{s}\r\n", .{mid});
    }

    pub fn appendMidLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, mid: []const u8) Error!void {
        const line = try formatMidLine(allocator, mid);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatBundleGroupAttribute(allocator: std.mem.Allocator, mids: []const []const u8) Error![]u8 {
        if (mids.len == 0) return error.InvalidSdp;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "BUNDLE");
        for (mids) |mid| {
            try validateSdpToken(mid);
            try out.append(allocator, ' ');
            try out.appendSlice(allocator, mid);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn formatBundleGroupLine(allocator: std.mem.Allocator, mids: []const []const u8) Error![]u8 {
        const attr = try formatBundleGroupAttribute(allocator, mids);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "a=group:{s}\r\n", .{attr});
    }

    pub fn appendBundleGroupLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, mids: []const []const u8) Error!void {
        const line = try formatBundleGroupLine(allocator, mids);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseBundleGroupAttribute(allocator: std.mem.Allocator, value: []const u8) Error![]const []const u8 {
        var parts = std.mem.tokenizeAny(u8, value, " \t");
        const semantic = parts.next() orelse return error.InvalidSdp;
        if (!std.mem.eql(u8, semantic, "BUNDLE")) return error.InvalidSdp;
        var mids: std.ArrayList([]const u8) = .empty;
        errdefer mids.deinit(allocator);
        while (parts.next()) |mid| {
            try validateSdpToken(mid);
            try mids.append(allocator, mid);
        }
        if (mids.items.len == 0) return error.InvalidSdp;
        return mids.toOwnedSlice(allocator);
    }

    pub fn extractBundleMids(allocator: std.mem.Allocator, session: Session) Error![]const []const u8 {
        for (session.attributes) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "group")) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const semantic = parts.next() orelse continue;
            if (!std.mem.eql(u8, semantic, "BUNDLE")) continue;
            return parseBundleGroupAttribute(allocator, attr.value);
        }
        return allocator.alloc([]const u8, 0);
    }

    pub fn freeBundleMids(allocator: std.mem.Allocator, mids: []const []const u8) void {
        allocator.free(mids);
    }

    pub fn bundleMatchesMid(session: Session, mid: []const u8) bool {
        for (session.attributes) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "group")) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const semantic = parts.next() orelse continue;
            if (!std.mem.eql(u8, semantic, "BUNDLE")) continue;
            while (parts.next()) |bundle_mid| {
                if (std.mem.eql(u8, bundle_mid, mid)) return true;
            }
            return false;
        }
        return true;
    }

    fn validateSdpToken(value: []const u8) Error!void {
        if (value.len == 0) return error.InvalidSdp;
        for (value) |byte| {
            if (byte == 0 or byte == '\r' or byte == '\n' or byte == ' ' or byte == '\t') return error.InvalidSdp;
        }
    }

    fn validateSdpNetworkType(value: []const u8) Error!void {
        try validateSdpToken(value);
        if (!std.mem.eql(u8, value, "IN")) return error.InvalidSdp;
    }

    fn validateSdpAddressType(value: []const u8) Error!void {
        try validateSdpToken(value);
        if (!std.mem.eql(u8, value, "IP4") and !std.mem.eql(u8, value, "IP6")) return error.InvalidSdp;
    }

    fn validateBandwidthType(value: []const u8) Error!void {
        try validateSdpToken(value);
        if (std.mem.eql(u8, value, "CT") or
            std.mem.eql(u8, value, "AS") or
            std.mem.eql(u8, value, "TIAS") or
            std.mem.eql(u8, value, "RS") or
            std.mem.eql(u8, value, "RR")) return;
        return error.InvalidSdp;
    }

    fn validateSdpAttributeValue(value: []const u8) Error!void {
        if (value.len == 0) return error.InvalidSdp;
        for (value) |byte| {
            if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidSdp;
        }
    }

    pub fn formatSsrcLine(allocator: std.mem.Allocator, ssrc: u32, attribute: []const u8, value: []const u8) Error![]u8 {
        try validateSdpToken(attribute);
        try validateSdpAttributeValue(value);
        return std.fmt.allocPrint(allocator, "a=ssrc:{d} {s}:{s}\r\n", .{ ssrc, attribute, value });
    }

    pub fn appendSsrcLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, ssrc: u32, attribute: []const u8, value: []const u8) Error!void {
        const line = try formatSsrcLine(allocator, ssrc, attribute, value);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatSsrcGroupLine(allocator: std.mem.Allocator, semantics: []const u8, ssrcs: []const u32) Error![]u8 {
        try validateSdpToken(semantics);
        if (ssrcs.len < 2) return error.InvalidSdp;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "a=ssrc-group:");
        try out.appendSlice(allocator, semantics);
        for (ssrcs) |ssrc| {
            const item = try std.fmt.allocPrint(allocator, " {d}", .{ssrc});
            defer allocator.free(item);
            try out.appendSlice(allocator, item);
        }
        try out.appendSlice(allocator, "\r\n");
        return out.toOwnedSlice(allocator);
    }

    pub fn appendSsrcGroupLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, semantics: []const u8, ssrcs: []const u32) Error!void {
        const line = try formatSsrcGroupLine(allocator, semantics, ssrcs);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatMsidLine(allocator: std.mem.Allocator, stream_id: []const u8, track_id: []const u8) Error![]u8 {
        try validateSdpToken(stream_id);
        try validateSdpToken(track_id);
        return std.fmt.allocPrint(allocator, "a=msid:{s} {s}\r\n", .{ stream_id, track_id });
    }

    pub fn appendMsidLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_id: []const u8, track_id: []const u8) Error!void {
        const line = try formatMsidLine(allocator, stream_id, track_id);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub const msid_semantic_wms = "WMS";

    pub fn formatMsidSemanticAttribute(allocator: std.mem.Allocator, semantic: []const u8, stream_ids: []const []const u8) Error![]u8 {
        try validateSdpToken(semantic);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, semantic);
        for (stream_ids) |stream_id| {
            try validateSdpToken(stream_id);
            try out.append(allocator, ' ');
            try out.appendSlice(allocator, stream_id);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn formatMsidSemanticTokensLine(allocator: std.mem.Allocator, semantic: []const u8, stream_ids: []const []const u8) Error![]u8 {
        const attr = try formatMsidSemanticAttribute(allocator, semantic, stream_ids);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "a=msid-semantic:{s}\r\n", .{attr});
    }

    pub fn appendMsidSemanticTokensLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, semantic: []const u8, stream_ids: []const []const u8) Error!void {
        const line = try formatMsidSemanticTokensLine(allocator, semantic, stream_ids);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatWildcardMsidSemanticLine(allocator: std.mem.Allocator) Error![]u8 {
        return formatMsidSemanticTokensLine(allocator, msid_semantic_wms, &.{"*"});
    }

    pub fn formatMsidSemanticLine(allocator: std.mem.Allocator, value: []const u8) Error![]u8 {
        try validateSdpAttributeValue(value);
        return std.fmt.allocPrint(allocator, "a=msid-semantic:{s}\r\n", .{value});
    }

    pub fn appendMsidSemanticLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) Error!void {
        const line = try formatMsidSemanticLine(allocator, value);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatRangedMediaLine(allocator: std.mem.Allocator, kind: []const u8, port: u16, port_range: ?u16, protocol: []const u8, formats: []const u8) Error![]u8 {
        try validateSdpToken(kind);
        try validateSdpToken(protocol);
        try validateSdpAttributeValue(formats);
        if (port_range) |range| {
            return std.fmt.allocPrint(allocator, "m={s} {d}/{d} {s} {s}\r\n", .{ kind, port, range, protocol, formats });
        }
        return std.fmt.allocPrint(allocator, "m={s} {d} {s} {s}\r\n", .{ kind, port, protocol, formats });
    }

    pub fn formatMediaLine(allocator: std.mem.Allocator, kind: []const u8, port: u16, protocol: []const u8, formats: []const u8) Error![]u8 {
        return formatRangedMediaLine(allocator, kind, port, null, protocol, formats);
    }

    pub fn appendRangedMediaLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, kind: []const u8, port: u16, port_range: ?u16, protocol: []const u8, formats: []const u8) Error!void {
        const line = try formatRangedMediaLine(allocator, kind, port, port_range, protocol, formats);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn appendMediaLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, kind: []const u8, port: u16, protocol: []const u8, formats: []const u8) Error!void {
        try appendRangedMediaLine(list, allocator, kind, port, null, protocol, formats);
    }

    pub fn formatConnectionLine(allocator: std.mem.Allocator, network_type: []const u8, address_type: []const u8, address: []const u8) Error![]u8 {
        try validateSdpNetworkType(network_type);
        try validateSdpAddressType(address_type);
        try validateSdpToken(address);
        return std.fmt.allocPrint(allocator, "c={s} {s} {s}\r\n", .{ network_type, address_type, address });
    }

    pub fn appendConnectionLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, network_type: []const u8, address_type: []const u8, address: []const u8) Error!void {
        const line = try formatConnectionLine(allocator, network_type, address_type, address);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatConnectionAddress(allocator: std.mem.Allocator, connection_address: ConnectionAddress) Error![]u8 {
        try validateSdpToken(connection_address.address);
        if (connection_address.ttl) |ttl| {
            if (connection_address.range) |range| {
                return std.fmt.allocPrint(allocator, "{s}/{d}/{d}", .{ connection_address.address, ttl, range });
            }
            return std.fmt.allocPrint(allocator, "{s}/{d}", .{ connection_address.address, ttl });
        }
        if (connection_address.range != null) return error.InvalidSdp;
        return allocator.dupe(u8, connection_address.address);
    }

    pub fn formatStructuredConnectionLine(allocator: std.mem.Allocator, network_type: []const u8, address_type: []const u8, connection_address: ConnectionAddress) Error![]u8 {
        const address = try formatConnectionAddress(allocator, connection_address);
        defer allocator.free(address);
        return formatConnectionLine(allocator, network_type, address_type, address);
    }

    pub fn appendStructuredConnectionLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, network_type: []const u8, address_type: []const u8, connection_address: ConnectionAddress) Error!void {
        const line = try formatStructuredConnectionLine(allocator, network_type, address_type, connection_address);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseConnectionAddress(value: []const u8) Error!ConnectionAddress {
        var parts = std.mem.splitScalar(u8, value, '/');
        const address = parts.next() orelse return error.InvalidSdp;
        try validateSdpToken(address);
        const ttl_s = parts.next();
        const range_s = parts.next();
        if (parts.next() != null) return error.InvalidSdp;
        return .{
            .address = address,
            .ttl = if (ttl_s) |ttl| std.fmt.parseInt(u16, ttl, 10) catch return error.InvalidSdp else null,
            .range = if (range_s) |range| std.fmt.parseInt(u16, range, 10) catch return error.InvalidSdp else null,
        };
    }

    pub fn formatInformationLine(allocator: std.mem.Allocator, information: []const u8) Error![]u8 {
        try validateSdpAttributeValue(information);
        return std.fmt.allocPrint(allocator, "i={s}\r\n", .{information});
    }

    pub fn appendInformationLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, information: []const u8) Error!void {
        const line = try formatInformationLine(allocator, information);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatUriLine(allocator: std.mem.Allocator, uri: []const u8) Error![]u8 {
        try validateSdpAttributeValue(uri);
        return std.fmt.allocPrint(allocator, "u={s}\r\n", .{uri});
    }

    pub fn appendUriLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, uri: []const u8) Error!void {
        const line = try formatUriLine(allocator, uri);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatEmailLine(allocator: std.mem.Allocator, email: []const u8) Error![]u8 {
        try validateSdpAttributeValue(email);
        return std.fmt.allocPrint(allocator, "e={s}\r\n", .{email});
    }

    pub fn appendEmailLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, email: []const u8) Error!void {
        const line = try formatEmailLine(allocator, email);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatPhoneLine(allocator: std.mem.Allocator, phone: []const u8) Error![]u8 {
        try validateSdpAttributeValue(phone);
        return std.fmt.allocPrint(allocator, "p={s}\r\n", .{phone});
    }

    pub fn appendPhoneLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, phone: []const u8) Error!void {
        const line = try formatPhoneLine(allocator, phone);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatEncryptionKeyLine(allocator: std.mem.Allocator, encryption_key: []const u8) Error![]u8 {
        try validateSdpAttributeValue(encryption_key);
        return std.fmt.allocPrint(allocator, "k={s}\r\n", .{encryption_key});
    }

    pub fn appendEncryptionKeyLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, encryption_key: []const u8) Error!void {
        const line = try formatEncryptionKeyLine(allocator, encryption_key);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatRepeatTimeLine(allocator: std.mem.Allocator, repeat_time: []const u8) Error![]u8 {
        try validateSdpAttributeValue(repeat_time);
        return std.fmt.allocPrint(allocator, "r={s}\r\n", .{repeat_time});
    }

    pub fn appendRepeatTimeLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, repeat_time: []const u8) Error!void {
        const line = try formatRepeatTimeLine(allocator, repeat_time);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatTimeZonesLine(allocator: std.mem.Allocator, time_zones: []const u8) Error![]u8 {
        try validateSdpAttributeValue(time_zones);
        return std.fmt.allocPrint(allocator, "z={s}\r\n", .{time_zones});
    }

    pub fn appendTimeZonesLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, time_zones: []const u8) Error!void {
        const line = try formatTimeZonesLine(allocator, time_zones);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatSessionNameLine(allocator: std.mem.Allocator, name: []const u8) Error![]u8 {
        try validateSdpAttributeValue(name);
        return std.fmt.allocPrint(allocator, "s={s}\r\n", .{name});
    }

    pub fn appendSessionNameLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8) Error!void {
        const line = try formatSessionNameLine(allocator, name);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatOriginAttribute(allocator: std.mem.Allocator, origin: Origin) Error![]u8 {
        try validateSdpToken(origin.username);
        try validateSdpNetworkType(origin.network_type);
        try validateSdpAddressType(origin.address_type);
        try validateSdpToken(origin.unicast_address);
        return std.fmt.allocPrint(allocator, "{s} {d} {d} {s} {s} {s}", .{
            origin.username,
            origin.session_id,
            origin.session_version,
            origin.network_type,
            origin.address_type,
            origin.unicast_address,
        });
    }

    pub fn formatOriginLine(allocator: std.mem.Allocator, origin: Origin) Error![]u8 {
        const attr = try formatOriginAttribute(allocator, origin);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "o={s}\r\n", .{attr});
    }

    pub fn appendOriginLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, origin: Origin) Error!void {
        const line = try formatOriginLine(allocator, origin);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseOriginAttribute(raw: []const u8) Error!Origin {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const username = parts.next() orelse return error.InvalidSdp;
        const session_id_s = parts.next() orelse return error.InvalidSdp;
        const session_version_s = parts.next() orelse return error.InvalidSdp;
        const network_type = parts.next() orelse return error.InvalidSdp;
        const address_type = parts.next() orelse "IP4";
        const unicast_address = parts.next() orelse if (std.mem.eql(u8, address_type, "IP6")) "::" else "0.0.0.0";
        if (parts.next() != null) return error.InvalidSdp;
        try validateSdpToken(username);
        try validateSdpNetworkType(network_type);
        try validateSdpAddressType(address_type);
        try validateSdpToken(unicast_address);
        return .{
            .username = username,
            .session_id = std.fmt.parseInt(u64, session_id_s, 10) catch return error.InvalidSdp,
            .session_version = std.fmt.parseInt(u64, session_version_s, 10) catch return error.InvalidSdp,
            .network_type = network_type,
            .address_type = address_type,
            .unicast_address = unicast_address,
        };
    }

    pub fn formatTimingAttribute(allocator: std.mem.Allocator, timing: Timing) Error![]u8 {
        return std.fmt.allocPrint(allocator, "{d} {d}", .{ timing.start_time, timing.stop_time });
    }

    pub fn formatTimingLine(allocator: std.mem.Allocator, timing: Timing) Error![]u8 {
        const attr = try formatTimingAttribute(allocator, timing);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "t={s}\r\n", .{attr});
    }

    pub fn appendTimingLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, timing: Timing) Error!void {
        const line = try formatTimingLine(allocator, timing);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseTimingAttribute(raw: []const u8) Error!Timing {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const start_s = parts.next() orelse return error.InvalidSdp;
        const stop_s = parts.next() orelse return error.InvalidSdp;
        if (parts.next() != null) return error.InvalidSdp;
        return .{
            .start_time = std.fmt.parseInt(u64, start_s, 10) catch return error.InvalidSdp,
            .stop_time = std.fmt.parseInt(u64, stop_s, 10) catch return error.InvalidSdp,
        };
    }

    fn parseTimeUnits(value: []const u8) Error!i64 {
        if (value.len == 0) return error.InvalidSdp;
        const suffix = value[value.len - 1];
        const multiplier: i64 = switch (suffix) {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            else => 0,
        };
        const numeric = if (multiplier == 0) value else value[0 .. value.len - 1];
        if (numeric.len == 0) return error.InvalidSdp;
        const parsed = std.fmt.parseInt(i64, numeric, 10) catch return error.InvalidSdp;
        return std.math.mul(i64, parsed, if (multiplier == 0) 1 else multiplier) catch return error.InvalidSdp;
    }

    pub fn formatRepeatTimeAttribute(allocator: std.mem.Allocator, repeat_time: RepeatTime) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        const header = try std.fmt.allocPrint(allocator, "{d} {d}", .{ repeat_time.interval, repeat_time.duration });
        defer allocator.free(header);
        try out.appendSlice(allocator, header);
        for (repeat_time.offsets) |offset| {
            const item = try std.fmt.allocPrint(allocator, " {d}", .{offset});
            defer allocator.free(item);
            try out.appendSlice(allocator, item);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn parseRepeatTimeAttribute(allocator: std.mem.Allocator, raw: []const u8) Error!RepeatTime {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const interval_s = parts.next() orelse return error.InvalidSdp;
        const duration_s = parts.next() orelse return error.InvalidSdp;
        var offsets: std.ArrayList(i64) = .empty;
        errdefer offsets.deinit(allocator);
        while (parts.next()) |offset_s| try offsets.append(allocator, try parseTimeUnits(offset_s));
        return .{
            .interval = try parseTimeUnits(interval_s),
            .duration = try parseTimeUnits(duration_s),
            .offsets = try offsets.toOwnedSlice(allocator),
        };
    }

    pub fn formatTimeZonesAttribute(allocator: std.mem.Allocator, time_zones: []const TimeZone) Error![]u8 {
        if (time_zones.len == 0) return error.InvalidSdp;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (time_zones, 0..) |time_zone, index| {
            const item = try std.fmt.allocPrint(allocator, "{s}{d} {d}", .{ if (index == 0) "" else " ", time_zone.adjustment_time, time_zone.offset });
            defer allocator.free(item);
            try out.appendSlice(allocator, item);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn parseTimeZonesAttribute(allocator: std.mem.Allocator, raw: []const u8) Error![]TimeZone {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        var out: std.ArrayList(TimeZone) = .empty;
        errdefer out.deinit(allocator);
        while (parts.next()) |adjustment_s| {
            const offset_s = parts.next() orelse return error.InvalidSdp;
            try out.append(allocator, .{
                .adjustment_time = std.fmt.parseInt(u64, adjustment_s, 10) catch return error.InvalidSdp,
                .offset = try parseTimeUnits(offset_s),
            });
        }
        if (out.items.len == 0) return error.InvalidSdp;
        return out.toOwnedSlice(allocator);
    }

    pub fn formatRtcpAttribute(allocator: std.mem.Allocator, rtcp_address: RtcpAddress) Error![]u8 {
        if (rtcp_address.connection) |connection| {
            try validateSdpNetworkType(connection.network_type);
            try validateSdpAddressType(connection.address_type);
            try validateSdpToken(connection.address);
            return std.fmt.allocPrint(allocator, "{d} {s} {s} {s}", .{ rtcp_address.port, connection.network_type, connection.address_type, connection.address });
        }
        return std.fmt.allocPrint(allocator, "{d}", .{rtcp_address.port});
    }

    pub fn formatRtcpLine(allocator: std.mem.Allocator, rtcp_address: RtcpAddress) Error![]u8 {
        const attr = try formatRtcpAttribute(allocator, rtcp_address);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "a=rtcp:{s}\r\n", .{attr});
    }

    pub fn appendRtcpLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, rtcp_address: RtcpAddress) Error!void {
        const line = try formatRtcpLine(allocator, rtcp_address);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseRtcpAttribute(raw: []const u8) Error!RtcpAddress {
        var it = std.mem.splitScalar(u8, raw, ' ');
        const port_s = it.next() orelse return error.InvalidSdp;
        try validateSdpToken(port_s);
        const port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidSdp;
        const network_type = it.next() orelse return .{ .port = port };
        const address_type = it.next() orelse return error.InvalidSdp;
        const address = it.next() orelse return error.InvalidSdp;
        if (it.next() != null) return error.InvalidSdp;
        try validateSdpNetworkType(network_type);
        try validateSdpAddressType(address_type);
        try validateSdpToken(address);
        return .{
            .port = port,
            .connection = .{
                .network_type = network_type,
                .address_type = address_type,
                .address = address,
            },
        };
    }

    pub fn extractRtcpAddress(media: Media) Error!?RtcpAddress {
        const raw = findAttr(media.attributes, "rtcp") orelse return null;
        return try parseRtcpAttribute(raw);
    }

    pub fn formatBandwidthAttribute(allocator: std.mem.Allocator, bandwidth: Bandwidth) Error![]u8 {
        if (bandwidth.experimental) {
            try validateSdpToken(bandwidth.typ);
            return std.fmt.allocPrint(allocator, "X-{s}:{d}", .{ bandwidth.typ, bandwidth.bandwidth });
        }
        try validateBandwidthType(bandwidth.typ);
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ bandwidth.typ, bandwidth.bandwidth });
    }

    pub fn formatBandwidthLine(allocator: std.mem.Allocator, bandwidth: Bandwidth) Error![]u8 {
        const attr = try formatBandwidthAttribute(allocator, bandwidth);
        defer allocator.free(attr);
        return std.fmt.allocPrint(allocator, "b={s}\r\n", .{attr});
    }

    pub fn appendBandwidthLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, bandwidth: Bandwidth) Error!void {
        const line = try formatBandwidthLine(allocator, bandwidth);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseBandwidthLine(value: []const u8) Error!Bandwidth {
        const colon = std.mem.indexOfScalar(u8, value, ':') orelse return error.InvalidSdp;
        var typ = value[0..colon];
        if (typ.len == 0) return error.InvalidSdp;
        var experimental = false;
        if (std.mem.startsWith(u8, typ, "X-")) {
            experimental = true;
            typ = typ["X-".len..];
            if (typ.len == 0) return error.InvalidSdp;
        }
        if (experimental) {
            try validateSdpToken(typ);
        } else {
            try validateBandwidthType(typ);
        }
        const raw_bandwidth = value[colon + 1 ..];
        if (raw_bandwidth.len == 0) return error.InvalidSdp;
        return .{
            .typ = typ,
            .bandwidth = std.fmt.parseInt(u64, raw_bandwidth, 10) catch return error.InvalidSdp,
            .experimental = experimental,
        };
    }

    pub fn appendSessionHeaderLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, session: Session) Error!void {
        try validateSdpToken(session.version);
        try validateSdpAttributeValue(session.origin);
        try validateSdpAttributeValue(session.name);
        if (session.information) |information| try validateSdpAttributeValue(information);
        if (session.uri) |uri| try validateSdpAttributeValue(uri);
        if (session.email) |email| try validateSdpAttributeValue(email);
        if (session.phone) |phone| try validateSdpAttributeValue(phone);
        if (session.encryption_key) |encryption_key| try validateSdpAttributeValue(encryption_key);
        for (session.repeat_times) |repeat_time| try validateSdpAttributeValue(repeat_time);
        if (session.time_zones) |time_zones| try validateSdpAttributeValue(time_zones);
        try validateSdpAttributeValue(session.timing);
        const version_line = try std.fmt.allocPrint(allocator, "v={s}\r\n", .{session.version});
        defer allocator.free(version_line);
        try list.appendSlice(allocator, version_line);
        const origin_line = try std.fmt.allocPrint(allocator, "o={s}\r\n", .{session.origin});
        defer allocator.free(origin_line);
        try list.appendSlice(allocator, origin_line);
        try appendSessionNameLine(list, allocator, session.name);
        if (session.information) |information| try appendInformationLine(list, allocator, information);
        if (session.uri) |uri| try appendUriLine(list, allocator, uri);
        if (session.email) |email| try appendEmailLine(list, allocator, email);
        if (session.phone) |phone| try appendPhoneLine(list, allocator, phone);
        // WebRTC implementations such as Pion serialize connection
        // information for every generated m-section (including rejected
        // tracks) because older SIPCC/Firefox SDP parsers require a c= line
        // at media level.  Session-level c= is still valid SDP, so preserve it
        // when parsing remote descriptions and place it before t= as required
        // by RFC 4566's session field order.
        if (session.connection) |connection| try appendConnectionLine(list, allocator, connection.network_type, connection.address_type, connection.address);
        for (session.bandwidth) |bandwidth| try appendBandwidthLine(list, allocator, bandwidth);
        const timing_line = try std.fmt.allocPrint(allocator, "t={s}\r\n", .{session.timing});
        defer allocator.free(timing_line);
        try list.appendSlice(allocator, timing_line);
        for (session.repeat_times) |repeat_time| try appendRepeatTimeLine(list, allocator, repeat_time);
        if (session.time_zones) |time_zones| try appendTimeZonesLine(list, allocator, time_zones);
        if (session.encryption_key) |encryption_key| try appendEncryptionKeyLine(list, allocator, encryption_key);
    }

    pub fn formatSessionHeaderLines(allocator: std.mem.Allocator, session: Session) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try appendSessionHeaderLines(&out, allocator, session);
        return out.toOwnedSlice(allocator);
    }

    pub fn appendSessionLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, session: Session) Error!void {
        try appendSessionHeaderLines(list, allocator, session);
        for (session.attributes) |attr| try appendAttributeLine(list, allocator, attr);
        for (session.media) |media| {
            try appendRangedMediaLine(list, allocator, media.kind, media.port, media.port_range, media.protocol, media.formats);
            if (media.title) |title| try appendInformationLine(list, allocator, title);
            if (media.connection) |connection| try appendConnectionLine(list, allocator, connection.network_type, connection.address_type, connection.address);
            for (media.bandwidth) |bandwidth| try appendBandwidthLine(list, allocator, bandwidth);
            if (media.encryption_key) |encryption_key| try appendEncryptionKeyLine(list, allocator, encryption_key);
            for (media.attributes) |attr| try appendAttributeLine(list, allocator, attr);
        }
    }

    pub fn formatSessionLines(allocator: std.mem.Allocator, session: Session) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try appendSessionLines(&out, allocator, session);
        return out.toOwnedSlice(allocator);
    }

    pub fn formatCandidateAttribute(allocator: std.mem.Allocator, candidate: ice.Candidate) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try candidate.write(&out, allocator);
        return out.toOwnedSlice(allocator);
    }

    pub fn formatCandidateLine(allocator: std.mem.Allocator, candidate: ice.Candidate) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.append(allocator, 'a');
        try out.append(allocator, '=');
        try candidate.write(&out, allocator);
        try out.appendSlice(allocator, "\r\n");
        return out.toOwnedSlice(allocator);
    }

    pub fn appendCandidateLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, candidate: ice.Candidate) Error!void {
        const line = try formatCandidateLine(allocator, candidate);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn appendEndOfCandidatesLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try list.appendSlice(allocator, "a=end-of-candidates\r\n");
    }

    pub const RtcpFeedback = struct {
        typ: []const u8,
        parameter: []const u8 = "",

        pub fn isType(self: RtcpFeedback, typ: []const u8) bool {
            return std.mem.eql(u8, self.typ, typ);
        }
    };

    pub const rtcp_feedback_transport_cc = "transport-cc";
    pub const rtcp_feedback_goog_remb = "goog-remb";
    pub const rtcp_feedback_ack = "ack";
    pub const rtcp_feedback_ccm = "ccm";
    pub const rtcp_feedback_nack = "nack";
    pub const rtcp_feedback_parameter_fir = "fir";
    pub const rtcp_feedback_parameter_pli = "pli";

    pub fn rtcpFeedbackEquivalent(a: RtcpFeedback, b: RtcpFeedback) bool {
        return std.mem.eql(u8, a.typ, b.typ) and std.mem.eql(u8, a.parameter, b.parameter);
    }

    pub fn rtcpFeedbackContains(feedback: []const RtcpFeedback, needle: RtcpFeedback) bool {
        for (feedback) |candidate| {
            if (rtcpFeedbackEquivalent(candidate, needle)) return true;
        }
        return false;
    }

    pub fn rtcpFeedbackEquivalentIgnoreCase(a: RtcpFeedback, b: RtcpFeedback) bool {
        return std.ascii.eqlIgnoreCase(a.typ, b.typ) and std.ascii.eqlIgnoreCase(a.parameter, b.parameter);
    }

    pub fn rtcpFeedbackContainsIgnoreCase(feedback: []const RtcpFeedback, needle: RtcpFeedback) bool {
        for (feedback) |candidate| {
            if (rtcpFeedbackEquivalentIgnoreCase(candidate, needle)) return true;
        }
        return false;
    }

    pub fn rtcpFeedbackDeduplicate(allocator: std.mem.Allocator, feedback: []const RtcpFeedback) Error![]RtcpFeedback {
        var out: std.ArrayList(RtcpFeedback) = .empty;
        errdefer out.deinit(allocator);
        for (feedback) |candidate| {
            if (!rtcpFeedbackContainsIgnoreCase(out.items, candidate)) try out.append(allocator, candidate);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn formatRtcpFeedbackAttribute(allocator: std.mem.Allocator, payload_type: ?u8, feedback: RtcpFeedback) Error![]u8 {
        if (payload_type) |payload| {
            if (feedback.parameter.len == 0) {
                return std.fmt.allocPrint(allocator, "{d} {s}", .{ payload, feedback.typ });
            }
            return std.fmt.allocPrint(allocator, "{d} {s} {s}", .{ payload, feedback.typ, feedback.parameter });
        }
        if (feedback.parameter.len == 0) {
            return std.fmt.allocPrint(allocator, "* {s}", .{feedback.typ});
        }
        return std.fmt.allocPrint(allocator, "* {s} {s}", .{ feedback.typ, feedback.parameter });
    }

    pub fn formatRtcpFeedbackLine(allocator: std.mem.Allocator, payload_type: ?u8, feedback: RtcpFeedback) Error![]u8 {
        if (payload_type) |payload| {
            if (feedback.parameter.len == 0) {
                return std.fmt.allocPrint(allocator, "a=rtcp-fb:{d} {s}\r\n", .{ payload, feedback.typ });
            }
            return std.fmt.allocPrint(allocator, "a=rtcp-fb:{d} {s} {s}\r\n", .{ payload, feedback.typ, feedback.parameter });
        }
        if (feedback.parameter.len == 0) {
            return std.fmt.allocPrint(allocator, "a=rtcp-fb:* {s}\r\n", .{feedback.typ});
        }
        return std.fmt.allocPrint(allocator, "a=rtcp-fb:* {s} {s}\r\n", .{ feedback.typ, feedback.parameter });
    }

    pub fn appendRtcpFeedbackLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, payload_type: ?u8, feedback: []const RtcpFeedback) Error!void {
        for (feedback) |entry| {
            const line = try formatRtcpFeedbackLine(allocator, payload_type, entry);
            defer allocator.free(line);
            try list.appendSlice(allocator, line);
        }
    }

    pub fn formatFmtpAttribute(allocator: std.mem.Allocator, payload_type: u8, fmtp: []const u8) Error![]u8 {
        if (fmtp.len == 0) return error.InvalidSdp;
        return std.fmt.allocPrint(allocator, "{d} {s}", .{ payload_type, fmtp });
    }

    pub fn formatFmtpLine(allocator: std.mem.Allocator, payload_type: u8, fmtp: []const u8) Error![]u8 {
        if (fmtp.len == 0) return error.InvalidSdp;
        return std.fmt.allocPrint(allocator, "a=fmtp:{d} {s}\r\n", .{ payload_type, fmtp });
    }

    pub fn appendFmtpLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, payload_type: u8, fmtp: []const u8) Error!void {
        if (fmtp.len == 0) return;
        const line = try formatFmtpLine(allocator, payload_type, fmtp);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatRtpMapAttribute(allocator: std.mem.Allocator, payload_type: u8, codec_name: []const u8, clock_rate: u32, channels: u16) Error![]u8 {
        if (codec_name.len == 0 or clock_rate == 0) return error.InvalidSdp;
        if (channels == 0) {
            return std.fmt.allocPrint(allocator, "{d} {s}/{d}", .{ payload_type, codec_name, clock_rate });
        }
        return std.fmt.allocPrint(allocator, "{d} {s}/{d}/{d}", .{ payload_type, codec_name, clock_rate, channels });
    }

    pub fn formatRtpMapLine(allocator: std.mem.Allocator, payload_type: u8, codec_name: []const u8, clock_rate: u32, channels: u16) Error![]u8 {
        if (codec_name.len == 0 or clock_rate == 0) return error.InvalidSdp;
        if (channels == 0) {
            return std.fmt.allocPrint(allocator, "a=rtpmap:{d} {s}/{d}\r\n", .{ payload_type, codec_name, clock_rate });
        }
        return std.fmt.allocPrint(allocator, "a=rtpmap:{d} {s}/{d}/{d}\r\n", .{ payload_type, codec_name, clock_rate, channels });
    }

    pub fn appendRtpMapLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, payload_type: u8, codec_name: []const u8, clock_rate: u32, channels: u16) Error!void {
        const line = try formatRtpMapLine(allocator, payload_type, codec_name, clock_rate, channels);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn rtcpFeedbackIntersection(allocator: std.mem.Allocator, local: []const RtcpFeedback, remote: []const RtcpFeedback) Error![]RtcpFeedback {
        var out: std.ArrayList(RtcpFeedback) = .empty;
        errdefer out.deinit(allocator);
        for (local) |local_feedback| {
            if (rtcpFeedbackContains(remote, local_feedback)) try out.append(allocator, local_feedback);
        }
        return out.toOwnedSlice(allocator);
    }

    pub const RtpCodec = struct {
        payload_type: u8,
        mime_type: []const u8,
        codec_name: []const u8,
        clock_rate: u32,
        channels: u16 = 0,
        fmtp: []const u8 = "",
        apt: ?u8 = null,
        rtcp_feedback: []RtcpFeedback = &.{},

        pub fn deinit(self: *RtpCodec, allocator: std.mem.Allocator) void {
            allocator.free(self.rtcp_feedback);
            self.* = undefined;
        }
    };

    pub fn appendRtpCodecLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, codec: RtpCodec) Error!void {
        try appendRtpMapLine(list, allocator, codec.payload_type, codec.codec_name, codec.clock_rate, codec.channels);
        try appendFmtpLine(list, allocator, codec.payload_type, codec.fmtp);
        try appendRtcpFeedbackLines(list, allocator, codec.payload_type, codec.rtcp_feedback);
    }

    pub const FmtpParameter = struct {
        key: []const u8,
        value: []const u8 = "",
    };

    pub const Rid = struct {
        id: []const u8,
        direction: []const u8,
        parameters: []const u8 = "",
        paused: bool = false,
    };

    pub fn formatRidLine(allocator: std.mem.Allocator, rid: Rid) Error![]u8 {
        try validateSdpToken(rid.id);
        try validateSdpToken(rid.direction);
        if (rid.parameters.len == 0) {
            return std.fmt.allocPrint(allocator, "a=rid:{s} {s}\r\n", .{ rid.id, rid.direction });
        }
        try validateSdpAttributeValue(rid.parameters);
        return std.fmt.allocPrint(allocator, "a=rid:{s} {s} {s}\r\n", .{ rid.id, rid.direction, rid.parameters });
    }

    pub fn appendRidLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, rid: Rid) Error!void {
        const line = try formatRidLine(allocator, rid);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn formatSimulcastLine(allocator: std.mem.Allocator, direction: []const u8, rids: []const Rid) Error![]u8 {
        try validateSdpToken(direction);
        if (rids.len == 0) return error.InvalidSdp;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "a=simulcast:");
        try out.appendSlice(allocator, direction);
        try out.append(allocator, ' ');
        for (rids, 0..) |rid, index| {
            try validateSdpToken(rid.id);
            if (index != 0) try out.append(allocator, ';');
            if (rid.paused) try out.append(allocator, '~');
            try out.appendSlice(allocator, rid.id);
        }
        try out.appendSlice(allocator, "\r\n");
        return out.toOwnedSlice(allocator);
    }

    pub fn appendSimulcastLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, direction: []const u8, rids: []const Rid) Error!void {
        const line = try formatSimulcastLine(allocator, direction, rids);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub const TrackDetails = struct {
        mid: []const u8,
        kind: []const u8,
        stream_id: []const u8 = "",
        track_id: []const u8 = "",
        ssrc: ?u32 = null,
        rtx_ssrc: ?u32 = null,
        fec_ssrc: ?u32 = null,
        rids: []Rid = &.{},

        pub fn deinit(self: *TrackDetails, allocator: std.mem.Allocator) void {
            allocator.free(self.rids);
            self.* = undefined;
        }
    };

    pub const DtlsSetupRole = enum {
        actpass,
        active,
        passive,
        holdconn,

        pub fn dtlsRole(self: DtlsSetupRole) DtlsRole {
            return switch (self) {
                .active => .client,
                .passive => .server,
                // actpass is negotiated from the answer and holdconn means no
                // connection is currently established; both leave the concrete
                // DTLS endpoint role unresolved at SDP-parse time.
                .actpass, .holdconn => .auto,
            };
        }
    };

    pub const sctp_data_channel_protocol = "webrtc-datachannel";

    pub const SctpParameters = struct {
        port: u16,
        max_message_size: u32 = sctp_max_message_size_unset,
        max_channels: ?u16 = null,
        protocol: []const u8 = sctp_data_channel_protocol,
    };

    pub const sctp_max_message_size_unset: u32 = std.math.maxInt(u16);

    pub fn formatSctpPortLine(allocator: std.mem.Allocator, port: u16) Error![]u8 {
        if (port == 0) return error.InvalidSdp;
        return std.fmt.allocPrint(allocator, "a=sctp-port:{d}\r\n", .{port});
    }

    pub fn formatMaxMessageSizeLine(allocator: std.mem.Allocator, max_message_size: u32) Error![]u8 {
        return std.fmt.allocPrint(allocator, "a=max-message-size:{d}\r\n", .{max_message_size});
    }

    pub fn formatSctpMapLine(allocator: std.mem.Allocator, port: u16, max_channels: ?u16) Error![]u8 {
        if (port == 0) return error.InvalidSdp;
        if (max_channels) |channels| {
            return std.fmt.allocPrint(allocator, "a=sctpmap:{d} " ++ sctp_data_channel_protocol ++ " {d}\r\n", .{ port, channels });
        }
        return std.fmt.allocPrint(allocator, "a=sctpmap:{d} " ++ sctp_data_channel_protocol ++ "\r\n", .{port});
    }

    pub fn appendSctpDataChannelLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, params: SctpParameters, legacy_sctpmap: bool) Error!void {
        if (!std.ascii.eqlIgnoreCase(params.protocol, sctp_data_channel_protocol)) return error.InvalidSdp;
        if (legacy_sctpmap) {
            const line = try formatSctpMapLine(allocator, params.port, params.max_channels);
            defer allocator.free(line);
            try list.appendSlice(allocator, line);
        } else {
            const line = try formatSctpPortLine(allocator, params.port);
            defer allocator.free(line);
            try list.appendSlice(allocator, line);
        }
        if (params.max_message_size != sctp_max_message_size_unset) {
            const max_line = try formatMaxMessageSizeLine(allocator, params.max_message_size);
            defer allocator.free(max_line);
            try list.appendSlice(allocator, max_line);
        }
    }

    pub const abs_send_time_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
    pub const transport_cc_uri = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
    pub const sdes_mid_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";
    pub const sdes_rtp_stream_id_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
    pub const sdes_repaired_rtp_stream_id_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";
    pub const audio_level_uri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
    pub const video_orientation_uri = "urn:3gpp:video-orientation";

    pub const ExtMapDirection = enum {
        sendrecv,
        sendonly,
        recvonly,
        inactive,

        pub fn suffix(self: ExtMapDirection) []const u8 {
            return switch (self) {
                .sendrecv => "",
                .sendonly => "/sendonly",
                .recvonly => "/recvonly",
                .inactive => "/inactive",
            };
        }
    };

    pub const max_extmap_id: u16 = 246;

    pub const ExtMap = struct {
        id: u16,
        direction: ExtMapDirection = .sendrecv,
        uri: []const u8,
        extension_attributes: []const u8 = &.{},

        pub fn rtpId(self: ExtMap) Error!u8 {
            if (self.id == 0 or self.id > max_extmap_id) return error.InvalidSdp;
            return @intCast(self.id);
        }
    };

    pub const RtpExtensionMap = struct {
        uri: []const u8,
        id: u8,
    };

    pub fn formatExtMapAttribute(allocator: std.mem.Allocator, extmap: ExtMap) Error![]u8 {
        _ = try extmap.rtpId();
        if (extmap.uri.len == 0) return error.InvalidSdp;
        if (extmap.extension_attributes.len == 0) {
            return std.fmt.allocPrint(allocator, "{d}{s} {s}", .{ extmap.id, extmap.direction.suffix(), extmap.uri });
        }
        return std.fmt.allocPrint(allocator, "{d}{s} {s} {s}", .{ extmap.id, extmap.direction.suffix(), extmap.uri, extmap.extension_attributes });
    }

    pub fn formatExtMapLine(allocator: std.mem.Allocator, extmap: ExtMap) Error![]u8 {
        _ = try extmap.rtpId();
        if (extmap.uri.len == 0) return error.InvalidSdp;
        if (extmap.extension_attributes.len == 0) {
            return std.fmt.allocPrint(allocator, "a=extmap:{d}{s} {s}\r\n", .{ extmap.id, extmap.direction.suffix(), extmap.uri });
        }
        return std.fmt.allocPrint(allocator, "a=extmap:{d}{s} {s} {s}\r\n", .{ extmap.id, extmap.direction.suffix(), extmap.uri, extmap.extension_attributes });
    }

    pub fn appendExtMapLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, extmap: ExtMap) Error!void {
        const line = try formatExtMapLine(allocator, extmap);
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }

    pub fn parseExtMapAttribute(raw: []const u8) Error!ExtMap {
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (trimmed.len == 0) return error.InvalidSdp;

        const first_end = std.mem.indexOfAny(u8, trimmed, " \t") orelse return error.InvalidSdp;
        const id_and_direction = trimmed[0..first_end];
        var rest = std.mem.trim(u8, trimmed[first_end..], " \t");
        if (rest.len == 0) return error.InvalidSdp;

        var direction: ExtMapDirection = .sendrecv;
        const id_part = if (std.mem.indexOfScalar(u8, id_and_direction, '/')) |slash| blk: {
            const dir = id_and_direction[slash + 1 ..];
            if (dir.len == 0) return error.InvalidSdp;
            direction = parseExtMapDirection(dir) orelse return error.InvalidSdp;
            break :blk id_and_direction[0..slash];
        } else id_and_direction;
        const id = std.fmt.parseInt(u16, id_part, 10) catch return error.InvalidSdp;
        if (id == 0 or id > max_extmap_id) return error.InvalidSdp;

        const uri_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
        const uri = rest[0..uri_end];
        if (uri.len == 0) return error.InvalidSdp;
        rest = std.mem.trim(u8, rest[uri_end..], " \t");

        return .{ .id = id, .direction = direction, .uri = uri, .extension_attributes = rest };
    }

    pub fn collectExtMaps(allocator: std.mem.Allocator, attrs: []const Attribute) Error![]ExtMap {
        var out: std.ArrayList(ExtMap) = .empty;
        errdefer out.deinit(allocator);
        for (attrs) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, "extmap")) {
                try out.append(allocator, try parseExtMapAttribute(attr.value));
            }
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn findExtMap(attrs: []const Attribute, uri: []const u8) Error!?ExtMap {
        for (attrs) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "extmap")) continue;
            const extmap = try parseExtMapAttribute(attr.value);
            if (std.mem.eql(u8, extmap.uri, uri)) return extmap;
        }
        return null;
    }

    pub fn findExtMapInSession(session: Session, uri: []const u8) Error!?ExtMap {
        if (candidateMedia(session)) |media| {
            if (try findExtMap(media.attributes, uri)) |extmap| return extmap;
        }
        return findExtMap(session.attributes, uri);
    }

    pub fn extMapAllowMixed(session: Session) bool {
        if (findAttr(session.attributes, "extmap-allow-mixed") != null) return true;
        if (candidateMedia(session)) |media| return findAttr(media.attributes, "extmap-allow-mixed") != null;
        return false;
    }

    pub fn supportsIceTrickle(session: Session) bool {
        if (iceOptionsAttributesHaveToken(session.attributes, ice_option_trickle)) return true;
        for (session.media) |media| {
            if (iceOptionsAttributesHaveToken(media.attributes, ice_option_trickle)) return true;
        }
        return false;
    }

    pub fn supportsIceRenomination(session: Session) bool {
        if (iceOptionsAttributesHaveToken(session.attributes, ice_option_renomination)) return true;
        for (session.media) |media| {
            if (iceOptionsAttributesHaveToken(media.attributes, ice_option_renomination)) return true;
        }
        return false;
    }

    pub fn extractExtMaps(allocator: std.mem.Allocator, session: Session) Error![]ExtMap {
        var out: std.ArrayList(ExtMap) = .empty;
        errdefer out.deinit(allocator);
        for (session.attributes) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, "extmap")) try out.append(allocator, try parseExtMapAttribute(attr.value));
        }
        if (candidateMedia(session)) |media| {
            for (media.attributes) |attr| {
                if (std.ascii.eqlIgnoreCase(attr.name, "extmap")) try out.append(allocator, try parseExtMapAttribute(attr.value));
            }
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn freeExtMaps(allocator: std.mem.Allocator, extmaps: []ExtMap) void {
        allocator.free(extmaps);
    }

    pub fn rtpExtensionsFromMedia(allocator: std.mem.Allocator, media: Media) Error![]RtpExtensionMap {
        var out: std.ArrayList(RtpExtensionMap) = .empty;
        errdefer out.deinit(allocator);
        for (media.attributes) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "extmap")) continue;
            const extmap = try parseExtMapAttribute(attr.value);
            try out.append(allocator, .{ .uri = extmap.uri, .id = try extmap.rtpId() });
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn freeRtpExtensionMap(allocator: std.mem.Allocator, extensions: []RtpExtensionMap) void {
        allocator.free(extensions);
    }

    fn parseExtMapDirection(value: []const u8) ?ExtMapDirection {
        if (std.ascii.eqlIgnoreCase(value, "sendrecv")) return .sendrecv;
        if (std.ascii.eqlIgnoreCase(value, "sendonly")) return .sendonly;
        if (std.ascii.eqlIgnoreCase(value, "recvonly")) return .recvonly;
        if (std.ascii.eqlIgnoreCase(value, "inactive")) return .inactive;
        return null;
    }

    pub fn parse(allocator: std.mem.Allocator, text: []const u8) Error!Session {
        var session_attrs: std.ArrayList(Attribute) = .empty;
        errdefer session_attrs.deinit(allocator);
        var media_items: std.ArrayList(Media) = .empty;
        errdefer {
            for (media_items.items) |media| {
                allocator.free(media.bandwidth);
                allocator.free(media.attributes);
            }
            media_items.deinit(allocator);
        }
        var current_attrs: std.ArrayList(Attribute) = .empty;
        defer current_attrs.deinit(allocator);
        var current_bandwidth: std.ArrayList(Bandwidth) = .empty;
        defer current_bandwidth.deinit(allocator);
        var current_media: ?MediaHeader = null;
        var current_title: ?[]const u8 = null;
        var current_connection: ?Connection = null;
        var current_encryption_key: ?[]const u8 = null;
        var version: []const u8 = "0";
        var origin: []const u8 = "- 0 0 IN IP4 127.0.0.1";
        var name: []const u8 = "-";
        var session_information: ?[]const u8 = null;
        var session_uri: ?[]const u8 = null;
        var session_email: ?[]const u8 = null;
        var session_phone: ?[]const u8 = null;
        var session_connection: ?Connection = null;
        var session_bandwidth: std.ArrayList(Bandwidth) = .empty;
        errdefer session_bandwidth.deinit(allocator);
        var timing: []const u8 = "0 0";
        var session_repeat_times: std.ArrayList([]const u8) = .empty;
        errdefer session_repeat_times.deinit(allocator);
        var session_time_zones: ?[]const u8 = null;
        var session_encryption_key: ?[]const u8 = null;

        var lines = std.mem.splitSequence(u8, text, "\n");
        while (lines.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            if (line.len == 0) continue;
            if (line.len < 2 or line[1] != '=') return error.InvalidSdp;
            const value = line[2..];
            switch (line[0]) {
                'v' => version = value,
                'o' => origin = value,
                's' => name = value,
                'i' => {
                    try validateSdpAttributeValue(value);
                    if (current_media != null) {
                        current_title = value;
                    } else {
                        session_information = value;
                    }
                },
                'u' => {
                    try validateSdpAttributeValue(value);
                    session_uri = value;
                },
                'e' => {
                    try validateSdpAttributeValue(value);
                    session_email = value;
                },
                'p' => {
                    try validateSdpAttributeValue(value);
                    session_phone = value;
                },
                't' => timing = value,
                'r' => {
                    try validateSdpAttributeValue(value);
                    try session_repeat_times.append(allocator, value);
                },
                'z' => {
                    try validateSdpAttributeValue(value);
                    session_time_zones = value;
                },
                'c' => {
                    const connection = try parseConnectionLine(value);
                    if (current_media != null) {
                        current_connection = connection;
                    } else {
                        session_connection = connection;
                    }
                },
                'b' => {
                    const bandwidth = try parseBandwidthLine(value);
                    if (current_media != null) {
                        try current_bandwidth.append(allocator, bandwidth);
                    } else {
                        try session_bandwidth.append(allocator, bandwidth);
                    }
                },
                'k' => {
                    try validateSdpAttributeValue(value);
                    if (current_media != null) {
                        current_encryption_key = value;
                    } else {
                        session_encryption_key = value;
                    }
                },
                'a' => {
                    const attr = parseAttribute(value);
                    if (current_media != null) {
                        try current_attrs.append(allocator, attr);
                    } else {
                        try session_attrs.append(allocator, attr);
                    }
                },
                'm' => {
                    if (current_media) |media_header| {
                        try media_items.append(allocator, .{
                            .kind = media_header.kind,
                            .port = media_header.port,
                            .port_range = media_header.port_range,
                            .protocol = media_header.protocol,
                            .formats = media_header.formats,
                            .title = current_title,
                            .connection = current_connection,
                            .bandwidth = try current_bandwidth.toOwnedSlice(allocator),
                            .encryption_key = current_encryption_key,
                            .attributes = try current_attrs.toOwnedSlice(allocator),
                        });
                        current_attrs = .empty;
                        current_bandwidth = .empty;
                        current_title = null;
                        current_connection = null;
                        current_encryption_key = null;
                    }
                    current_media = try parseMediaLine(value);
                },
                else => {},
            }
        }
        if (current_media) |media_header| {
            try media_items.append(allocator, .{
                .kind = media_header.kind,
                .port = media_header.port,
                .port_range = media_header.port_range,
                .protocol = media_header.protocol,
                .formats = media_header.formats,
                .title = current_title,
                .connection = current_connection,
                .bandwidth = try current_bandwidth.toOwnedSlice(allocator),
                .encryption_key = current_encryption_key,
                .attributes = try current_attrs.toOwnedSlice(allocator),
            });
            current_attrs = .empty;
            current_bandwidth = .empty;
        }

        return .{
            .version = version,
            .origin = origin,
            .name = name,
            .information = session_information,
            .uri = session_uri,
            .email = session_email,
            .phone = session_phone,
            .connection = session_connection,
            .bandwidth = try session_bandwidth.toOwnedSlice(allocator),
            .timing = timing,
            .repeat_times = try session_repeat_times.toOwnedSlice(allocator),
            .time_zones = session_time_zones,
            .encryption_key = session_encryption_key,
            .attributes = try session_attrs.toOwnedSlice(allocator),
            .media = try media_items.toOwnedSlice(allocator),
        };
    }

    fn parseAttribute(value: []const u8) Attribute {
        if (std.mem.indexOfScalar(u8, value, ':')) |colon| return .{ .name = value[0..colon], .value = value[colon + 1 ..] };
        return .{ .name = value, .value = "" };
    }

    fn parseConnectionLine(value: []const u8) Error!Connection {
        var it = std.mem.splitScalar(u8, value, ' ');
        const network_type = it.next() orelse return error.InvalidSdp;
        const address_type = it.next() orelse return error.InvalidSdp;
        const address = it.next() orelse return error.InvalidSdp;
        if (it.next() != null) return error.InvalidSdp;
        try validateSdpNetworkType(network_type);
        try validateSdpAddressType(address_type);
        try validateSdpToken(address);
        return .{
            .network_type = network_type,
            .address_type = address_type,
            .address = address,
        };
    }

    fn parseMediaPort(value: []const u8) Error!struct { u16, ?u16 } {
        if (std.mem.indexOfScalar(u8, value, '/')) |slash| {
            const port = std.fmt.parseInt(u16, value[0..slash], 10) catch return error.InvalidSdp;
            const range = std.fmt.parseInt(u16, value[slash + 1 ..], 10) catch return error.InvalidSdp;
            return .{ port, range };
        }
        return .{ std.fmt.parseInt(u16, value, 10) catch return error.InvalidSdp, null };
    }

    fn parseMediaLine(value: []const u8) Error!MediaHeader {
        var it = std.mem.splitScalar(u8, value, ' ');
        const kind = it.next() orelse return error.InvalidSdp;
        const port_s = it.next() orelse return error.InvalidSdp;
        const protocol = it.next() orelse return error.InvalidSdp;
        const formats = it.rest();
        const parsed_port = try parseMediaPort(port_s);
        return .{ .kind = kind, .port = parsed_port[0], .port_range = parsed_port[1], .protocol = protocol, .formats = formats };
    }

    pub fn extractFingerprint(session: Session) Error!Fingerprint {
        if (findAttr(session.attributes, "fingerprint")) |fingerprint| return parseFingerprint(fingerprint);

        if (bundleId(session)) |bundle_id| {
            for (session.media) |media| {
                if (findAttr(media.attributes, "mid")) |mid| {
                    if (std.mem.eql(u8, mid, bundle_id)) {
                        if (findAttr(media.attributes, "fingerprint")) |fingerprint| return parseFingerprint(fingerprint);
                    }
                }
            }
        } else {
            for (session.media) |media| {
                if (findAttr(media.attributes, "fingerprint")) |fingerprint| return parseFingerprint(fingerprint);
            }
        }

        return error.MissingFingerprint;
    }

    pub fn extractIceCredentials(session: Session) Error!IceCredentials {
        const session_ufrag = try optionalIceCredential(session.attributes, "ice-ufrag");
        const session_password = try optionalIceCredential(session.attributes, "ice-pwd");
        if (session_ufrag != null or session_password != null) {
            // Pion treats session-level ICE credentials as an atomic override.
            // Mixing a session ufrag with a media password (or vice versa)
            // could authenticate checks against credentials that never appeared
            // together in SDP, so report the missing session half instead.
            return .{
                .ufrag = session_ufrag orelse return error.MissingIceUfrag,
                .password = session_password orelse return error.MissingIcePwd,
            };
        }

        if (candidateMedia(session)) |selected| {
            return .{
                .ufrag = try requiredIceCredential(selected.attributes, "ice-ufrag", error.MissingIceUfrag),
                .password = try requiredIceCredential(selected.attributes, "ice-pwd", error.MissingIcePwd),
            };
        }

        return error.MissingIceUfrag;
    }

    fn optionalIceCredential(attrs: []const Attribute, name: []const u8) Error!?[]const u8 {
        const value = findAttr(attrs, name) orelse return null;
        try validateIceCredentialToken(value);
        return value;
    }

    fn requiredIceCredential(attrs: []const Attribute, name: []const u8, missing: Error) Error![]const u8 {
        const value = findAttr(attrs, name) orelse return missing;
        try validateIceCredentialToken(value);
        return value;
    }

    fn validateIceCredentialToken(value: []const u8) Error!void {
        // ICE credentials are SDP attribute payloads, but semantically they are
        // single tokens used to build STUN USERNAME/MESSAGE-INTEGRITY inputs.
        // Reject whitespace/control characters at the SDP boundary so generated
        // and parsed descriptions cannot inject extra lines or authenticate
        // checks with credentials that browsers/Pion would not use verbatim.
        try validateSdpToken(value);
    }

    pub fn extractIceCandidates(allocator: std.mem.Allocator, session: Session) Error![]IceCandidate {
        const media = selectCandidateMedia(session) orelse return allocator.alloc(IceCandidate, 0);
        var candidates: std.ArrayList(IceCandidate) = .empty;
        errdefer {
            for (candidates.items) |*candidate| candidate.deinit(allocator);
            candidates.deinit(allocator);
        }
        var last_error: ?Error = null;
        for (media.media.attributes) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "candidate")) continue;
            var candidate = ice.Candidate.parseOwned(allocator, attr.value) catch |err| switch (err) {
                error.UnknownIceCandidateType => continue,
                error.InvalidIceCandidate => {
                    last_error = err;
                    continue;
                },
                else => |e| return e,
            };
            errdefer candidate.deinit(allocator);
            try candidates.append(allocator, .{
                .candidate = candidate,
                .sdp_mid = findAttr(media.media.attributes, "mid"),
                .sdp_mline_index = media.index,
            });
            candidate.extensions = &.{};
        }
        if (candidates.items.len == 0) {
            if (last_error) |err| return err;
        }
        return candidates.toOwnedSlice(allocator);
    }

    pub fn iceEndOfCandidates(session: Session) bool {
        const media = candidateMedia(session) orelse return findAttr(session.attributes, "end-of-candidates") != null;
        return findAttr(media.attributes, "end-of-candidates") != null or findAttr(session.attributes, "end-of-candidates") != null;
    }

    pub fn descriptionContainsUfrag(session: Session, match_ufrag: []const u8) bool {
        if (findAttr(session.attributes, "ice-ufrag")) |ufrag| {
            if (std.mem.eql(u8, ufrag, match_ufrag)) return true;
        }
        for (session.media) |media| {
            if (findAttr(media.attributes, "ice-ufrag")) |ufrag| {
                if (std.mem.eql(u8, ufrag, match_ufrag)) return true;
            }
        }
        return false;
    }

    pub fn candidateUfrag(candidate: ice.Candidate) ?[]const u8 {
        return candidate.extensionValue("ufrag");
    }

    pub fn candidateMatchesDescriptionUfrag(session: Session, candidate: ice.Candidate) bool {
        const ufrag = candidateUfrag(candidate) orelse return true;
        // Pion drops trickle candidates from old ICE generations when the
        // candidate-level ufrag is not present in the currently applied remote
        // description.  Keep the predicate separate from extraction so callers
        // can decide whether to log, ignore, or surface the mismatch.
        return descriptionContainsUfrag(session, ufrag);
    }

    pub fn extractIceDetails(allocator: std.mem.Allocator, session: Session) Error!IceDetails {
        const credentials = try extractIceCredentials(session);
        const candidates = try extractIceCandidates(allocator, session);
        errdefer {
            for (candidates) |*candidate| candidate.deinit(allocator);
            allocator.free(candidates);
        }
        return .{
            .credentials = credentials,
            .candidates = candidates,
            .end_of_candidates = iceEndOfCandidates(session),
        };
    }

    pub fn extractDtlsRole(session: Session) Error!DtlsRole {
        if (candidateMedia(session)) |media| {
            if (findAttr(media.attributes, "setup")) |setup| return (try parseDtlsSetupAttribute(setup)).dtlsRole();
        }
        if (findAttr(session.attributes, "setup")) |setup| return (try parseDtlsSetupAttribute(setup)).dtlsRole();
        for (session.media) |media| {
            if (findAttr(media.attributes, "setup")) |setup| return (try parseDtlsSetupAttribute(setup)).dtlsRole();
        }
        return .auto;
    }

    pub fn extractTransportAttributes(session: Session) TransportAttributes {
        const media = candidateMedia(session);
        return .{
            .ice_lite = findAttr(session.attributes, "ice-lite") != null,
            .rtcp_mux = if (media) |selected| findAttr(selected.attributes, "rtcp-mux") != null else false,
            .rtcp_rsize = if (media) |selected| findAttr(selected.attributes, "rtcp-rsize") != null else false,
        };
    }

    pub fn extractSctpParameters(session: Session) Error!SctpParameters {
        const media = dataChannelMedia(session) orelse return error.InvalidSdp;
        var port: ?u16 = null;
        var protocol: ?[]const u8 = null;
        var max_channels: ?u16 = null;

        if (findAttr(media.attributes, "sctp-port")) |raw_port| {
            port = parseSctpPort(raw_port);
        }
        if (findAttr(media.attributes, "sctpmap")) |raw_map| {
            const mapped = try parseSctpMapAttribute(raw_map);
            if (port) |existing| {
                if (existing != mapped.port) return error.InvalidSdp;
            } else {
                port = mapped.port;
            }
            protocol = mapped.protocol;
            max_channels = mapped.max_channels;
        }
        if (port == null) {
            // Older WebRTC stacks used `m=application ... DTLS/SCTP 5000`
            // plus `a=sctpmap:5000 webrtc-datachannel 256` instead of the
            // RFC 8841 `a=sctp-port:5000` form.  Pion still accepts these
            // offers for interop; preserve that behavior here so generated or
            // archived SDP from old browsers remains usable.
            port = parseSctpPort(firstFormatToken(media.formats) orelse return error.InvalidSdp);
        }
        const format_protocol = try dataChannelProtocolFromFormats(media.formats);
        if (protocol == null) protocol = format_protocol;

        return .{
            .port = port orelse return error.InvalidSdp,
            .max_message_size = try parseMaxMessageSize(findAttr(media.attributes, "max-message-size")),
            .max_channels = max_channels,
            .protocol = protocol orelse sctp_data_channel_protocol,
        };
    }

    pub fn extractSctpInit(allocator: std.mem.Allocator, session: Session) Error!?[]u8 {
        const media = dataChannelMedia(session) orelse return null;
        const raw = findAttr(media.attributes, "sctp-init") orelse return null;
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(raw) catch return error.InvalidSdp;
        const decoded = try allocator.alloc(u8, decoded_len);
        errdefer allocator.free(decoded);
        std.base64.standard.Decoder.decode(decoded, raw) catch return error.InvalidSdp;
        return decoded;
    }

    pub fn extractRtpCodecs(allocator: std.mem.Allocator, media: Media) Error![]RtpCodec {
        var codecs: std.ArrayList(RtpCodec) = .empty;
        errdefer {
            for (codecs.items) |*codec| codec.deinit(allocator);
            codecs.deinit(allocator);
        }

        var payloads = std.mem.tokenizeAny(u8, media.formats, " \t");
        while (payloads.next()) |payload_token| {
            const payload_type = try parsePayloadType(payload_token);
            var codec = if (findPayloadAttribute(media.attributes, "rtpmap", payload_type)) |rtpmap|
                try parseRtpMap(payload_type, media.kind, rtpmap)
            else
                staticRtpCodec(payload_type) orelse return error.InvalidSdp;
            errdefer codec.deinit(allocator);
            if (findPayloadAttribute(media.attributes, "fmtp", payload_type)) |fmtp| {
                codec.fmtp = fmtp;
                codec.apt = if (fmtpParameter(fmtp, "apt")) |apt| parsePayloadType(apt) catch null else null;
            }
            codec.rtcp_feedback = try collectRtcpFeedback(allocator, media.attributes, payload_type);
            try codecs.append(allocator, codec);
            codec.rtcp_feedback = &.{};
        }
        return codecs.toOwnedSlice(allocator);
    }

    pub fn freeRtpCodecs(allocator: std.mem.Allocator, codecs: []RtpCodec) void {
        for (codecs) |*codec| codec.deinit(allocator);
        allocator.free(codecs);
    }

    pub fn rtpCodecCompatible(local: RtpCodec, remote: RtpCodec) bool {
        if (!std.ascii.eqlIgnoreCase(local.mime_type, remote.mime_type)) return false;
        if (!codecClockRateEqual(local.mime_type, local.clock_rate, remote.clock_rate)) return false;
        if (!codecChannelsEqual(local.mime_type, local.channels, remote.channels)) return false;

        if (std.ascii.eqlIgnoreCase(local.mime_type, "video/H264")) return h264FmtpCompatible(local.fmtp, remote.fmtp);
        if (std.ascii.eqlIgnoreCase(local.mime_type, "video/VP9")) return vp9FmtpCompatible(local.fmtp, remote.fmtp);
        if (std.ascii.eqlIgnoreCase(local.mime_type, "video/AV1")) return av1FmtpCompatible(local.fmtp, remote.fmtp);
        return genericFmtpCompatible(local.fmtp, remote.fmtp);
    }

    pub fn findCodecByPayloadType(codecs: []const RtpCodec, payload_type: u8) ?RtpCodec {
        for (codecs) |codec| {
            if (codec.payload_type == payload_type) return codec;
        }
        return null;
    }

    pub fn rtxAssociatedCodec(codecs: []const RtpCodec, rtx: RtpCodec) ?RtpCodec {
        if (!std.ascii.eqlIgnoreCase(rtx.mime_type, "video/rtx")) return null;
        const apt = rtx.apt orelse return null;
        return findCodecByPayloadType(codecs, apt);
    }

    pub fn rtxPayloadTypeForPrimary(codecs: []const RtpCodec, primary_payload_type: u8) ?u8 {
        for (codecs) |codec| {
            if (!std.ascii.eqlIgnoreCase(codec.mime_type, "video/rtx")) continue;
            if (codec.apt != null and codec.apt.? == primary_payload_type) return codec.payload_type;
        }
        return null;
    }

    pub fn rtxPrimaryPayloadExists(codecs: []const RtpCodec, rtx: RtpCodec) bool {
        return rtxAssociatedCodec(codecs, rtx) != null;
    }

    pub fn fecPayloadType(codecs: []const RtpCodec) ?u8 {
        for (codecs) |codec| {
            if (std.ascii.indexOfIgnoreCase(codec.mime_type, "flexfec") != null) return codec.payload_type;
        }
        return null;
    }

    pub fn extractRids(allocator: std.mem.Allocator, media: Media) Error![]Rid {
        var rids: std.ArrayList(Rid) = .empty;
        errdefer rids.deinit(allocator);
        var simulcast: ?[]const u8 = null;
        for (media.attributes) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, "rid")) {
                try rids.append(allocator, try parseRidAttribute(attr.value));
            } else if (std.ascii.eqlIgnoreCase(attr.name, "simulcast")) {
                simulcast = attr.value;
            }
        }
        if (simulcast) |value| markPausedRids(rids.items, value);
        return rids.toOwnedSlice(allocator);
    }

    pub fn extractTrackDetails(allocator: std.mem.Allocator, session: Session) Error![]TrackDetails {
        var tracks: std.ArrayList(TrackDetails) = .empty;
        errdefer {
            for (tracks.items) |*track| track.deinit(allocator);
            tracks.deinit(allocator);
        }

        for (session.media) |media| {
            var media_tracks: std.ArrayList(TrackDetails) = .empty;
            errdefer {
                for (media_tracks.items) |*track| track.deinit(allocator);
                media_tracks.deinit(allocator);
            }

            if (findAttr(media.attributes, "recvonly") != null or findAttr(media.attributes, "inactive") != null) continue;
            if (!std.ascii.eqlIgnoreCase(media.kind, "audio") and !std.ascii.eqlIgnoreCase(media.kind, "video")) continue;
            const mid = findAttr(media.attributes, "mid") orelse continue;
            var stream_id: []const u8 = "";
            var track_id: []const u8 = "";
            if (findAttr(media.attributes, "msid")) |msid| {
                parseMsid(msid, &stream_id, &track_id);
            }
            if (stream_id.len == 0 or track_id.len == 0) {
                inferMsidFromSsrc(media.attributes, &stream_id, &track_id);
            }

            var rtx_pairs: [16]SsrcPair = undefined;
            var rtx_len: usize = 0;
            var fec_pairs: [16]SsrcPair = undefined;
            var fec_len: usize = 0;
            collectSsrcGroups(media.attributes, &rtx_pairs, &rtx_len, &fec_pairs, &fec_len);

            const rids = try extractRids(allocator, media);
            errdefer allocator.free(rids);
            if (rids.len != 0 and stream_id.len != 0 and track_id.len != 0) {
                try media_tracks.append(allocator, .{
                    .mid = mid,
                    .kind = media.kind,
                    .stream_id = stream_id,
                    .track_id = track_id,
                    .rids = rids,
                });
                try tracks.appendSlice(allocator, media_tracks.items);
                media_tracks.deinit(allocator);
                media_tracks = .empty;
                continue;
            }
            allocator.free(rids);

            for (media.attributes) |attr| {
                if (!std.ascii.eqlIgnoreCase(attr.name, "ssrc")) continue;
                var local_stream = stream_id;
                var local_track = track_id;
                const ssrc = parseSsrcAttribute(attr.value, &local_stream, &local_track) orelse continue;
                if (repairBase(&rtx_pairs, rtx_len, ssrc) != null or repairBase(&fec_pairs, fec_len, ssrc) != null) continue;
                const existing = findTrackBySsrc(media_tracks.items, ssrc);
                if (existing) |track| {
                    track.stream_id = local_stream;
                    track.track_id = local_track;
                    continue;
                }
                try media_tracks.append(allocator, .{
                    .mid = mid,
                    .kind = media.kind,
                    .stream_id = local_stream,
                    .track_id = local_track,
                    .ssrc = ssrc,
                    .rtx_ssrc = repairForBase(&rtx_pairs, rtx_len, ssrc),
                    .fec_ssrc = repairForBase(&fec_pairs, fec_len, ssrc),
                });
            }
            try tracks.appendSlice(allocator, media_tracks.items);
            media_tracks.deinit(allocator);
            media_tracks = .empty;
        }
        return tracks.toOwnedSlice(allocator);
    }

    pub fn freeTrackDetails(allocator: std.mem.Allocator, tracks: []TrackDetails) void {
        for (tracks) |*track| track.deinit(allocator);
        allocator.free(tracks);
    }

    pub fn trackDetailsForSsrc(tracks: []const TrackDetails, ssrc: u32) ?*const TrackDetails {
        for (tracks, 0..) |track, index| {
            // Match Pion's trackDetailsForSSRC behavior: only primary media
            // SSRCs identify tracks here. RTX/FEC repair SSRCs are kept as
            // metadata on the base track and must not independently demux to a
            // remote track identity.
            if (track.ssrc != null and track.ssrc.? == ssrc) return &tracks[index];
        }
        return null;
    }

    pub fn trackDetailsForRid(tracks: []const TrackDetails, mid: []const u8, rid: []const u8) ?*const TrackDetails {
        for (tracks, 0..) |track, index| {
            if (!std.mem.eql(u8, track.mid, mid)) continue;
            for (track.rids) |track_rid| {
                if (std.mem.eql(u8, track_rid.id, rid)) return &tracks[index];
            }
        }
        return null;
    }

    pub fn trackDetailsForMid(tracks: []const TrackDetails, mid: []const u8) ?*const TrackDetails {
        for (tracks, 0..) |track, index| {
            if (std.mem.eql(u8, track.mid, mid)) return &tracks[index];
        }
        return null;
    }

    pub fn tracksContainRepeatedMid(tracks: []const TrackDetails) bool {
        for (tracks, 0..) |track, index| {
            for (tracks[0..index]) |prior| {
                if (std.mem.eql(u8, prior.mid, track.mid)) return true;
            }
        }
        return false;
    }

    pub fn sessionPossiblyPlanB(session: Session) bool {
        for (session.media) |media| {
            const mid = findAttr(media.attributes, "mid") orelse continue;
            if (std.ascii.eqlIgnoreCase(mid, "audio") or
                std.ascii.eqlIgnoreCase(mid, "video") or
                std.ascii.eqlIgnoreCase(mid, "data")) return true;
        }
        return false;
    }

    pub fn applicationMedia(session: Session) ?Media {
        for (session.media) |media| {
            if (std.mem.eql(u8, media.kind, "application")) return media;
        }
        return null;
    }

    pub fn hasApplicationMedia(session: Session) bool {
        return applicationMedia(session) != null;
    }

    pub fn hasDataChannelMedia(session: Session) bool {
        return dataChannelMedia(session) != null;
    }

    pub fn findAttr(attrs: []const Attribute, name: []const u8) ?[]const u8 {
        for (attrs) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, name)) return attr.value;
        }
        return null;
    }

    pub fn collectAttrValues(allocator: std.mem.Allocator, attrs: []const Attribute, name: []const u8) Error![]const []const u8 {
        var values: std.ArrayList([]const u8) = .empty;
        errdefer values.deinit(allocator);
        for (attrs) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, name)) try values.append(allocator, attr.value);
        }
        return values.toOwnedSlice(allocator);
    }

    pub fn freeAttrValues(allocator: std.mem.Allocator, values: []const []const u8) void {
        allocator.free(values);
    }

    fn iceOptionsHasToken(value: []const u8, token: []const u8) bool {
        var parts = std.mem.tokenizeAny(u8, value, " \t");
        while (parts.next()) |part| {
            if (std.ascii.eqlIgnoreCase(part, token)) return true;
        }
        return false;
    }

    fn iceOptionSliceHasToken(options: []const []const u8, token: []const u8) bool {
        for (options) |option| {
            if (std.ascii.eqlIgnoreCase(option, token)) return true;
        }
        return false;
    }

    fn iceOptionsAttributesHaveToken(attrs: []const Attribute, token: []const u8) bool {
        for (attrs) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, "ice-options") and iceOptionsHasToken(attr.value, token)) return true;
        }
        return false;
    }

    pub fn parseDtlsSetupAttribute(raw: []const u8) Error!DtlsSetupRole {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const value = parts.next() orelse return error.InvalidSdp;
        if (parts.next() != null) return error.InvalidSdp;
        if (std.ascii.eqlIgnoreCase(value, "actpass")) return .actpass;
        if (std.ascii.eqlIgnoreCase(value, "active")) return .active;
        if (std.ascii.eqlIgnoreCase(value, "passive")) return .passive;
        if (std.ascii.eqlIgnoreCase(value, "holdconn")) return .holdconn;
        return error.InvalidSdp;
    }

    const SctpMap = struct {
        port: u16,
        protocol: []const u8,
        max_channels: ?u16 = null,
    };

    fn parseSctpMapAttribute(raw: []const u8) Error!SctpMap {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const port_s = parts.next() orelse return error.InvalidSdp;
        const protocol = parts.next() orelse return error.InvalidSdp;
        try validateSctpDataChannelProtocol(protocol);
        const max_channels_s = parts.next();
        if (parts.next() != null) return error.InvalidSdp;
        return .{
            .port = parseSctpPort(port_s) orelse return error.InvalidSdp,
            .protocol = sctp_data_channel_protocol,
            .max_channels = if (max_channels_s) |value| std.fmt.parseInt(u16, value, 10) catch return error.InvalidSdp else null,
        };
    }

    fn validateSctpDataChannelProtocol(protocol: []const u8) Error!void {
        if (!std.ascii.eqlIgnoreCase(protocol, sctp_data_channel_protocol)) return error.InvalidSdp;
    }

    fn parseSctpPort(value: []const u8) ?u16 {
        if (value.len == 0) return null;
        const port = std.fmt.parseInt(u16, value, 10) catch return null;
        if (port == 0) return null;
        return port;
    }

    fn parseRtpMap(payload_type: u8, media_kind: []const u8, raw: []const u8) Error!RtpCodec {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const encoding = parts.next() orelse return error.InvalidSdp;
        if (parts.next() != null) return error.InvalidSdp;

        var encoding_parts = std.mem.splitScalar(u8, encoding, '/');
        const codec_name = encoding_parts.next() orelse return error.InvalidSdp;
        const clock_s = encoding_parts.next() orelse return error.InvalidSdp;
        const channels_s = encoding_parts.next();
        if (encoding_parts.next() != null or codec_name.len == 0 or clock_s.len == 0) return error.InvalidSdp;

        return .{
            .payload_type = payload_type,
            .mime_type = fullMimeType(media_kind, codec_name),
            .codec_name = codec_name,
            .clock_rate = std.fmt.parseInt(u32, clock_s, 10) catch return error.InvalidSdp,
            .channels = if (channels_s) |channels| std.fmt.parseInt(u16, channels, 10) catch return error.InvalidSdp else 0,
        };
    }

    fn fullMimeType(media_kind: []const u8, codec_name: []const u8) []const u8 {
        if (std.ascii.eqlIgnoreCase(media_kind, "audio")) {
            if (std.ascii.eqlIgnoreCase(codec_name, "opus")) return "audio/opus";
            if (std.ascii.eqlIgnoreCase(codec_name, "PCMU")) return "audio/PCMU";
            if (std.ascii.eqlIgnoreCase(codec_name, "PCMA")) return "audio/PCMA";
            if (std.ascii.eqlIgnoreCase(codec_name, "G722")) return "audio/G722";
        } else if (std.ascii.eqlIgnoreCase(media_kind, "video")) {
            if (std.ascii.eqlIgnoreCase(codec_name, "VP8")) return "video/VP8";
            if (std.ascii.eqlIgnoreCase(codec_name, "VP9")) return "video/VP9";
            if (std.ascii.eqlIgnoreCase(codec_name, "AV1")) return "video/AV1";
            if (std.ascii.eqlIgnoreCase(codec_name, "H264")) return "video/H264";
            if (std.ascii.eqlIgnoreCase(codec_name, "H265")) return "video/H265";
            if (std.ascii.eqlIgnoreCase(codec_name, "rtx")) return "video/rtx";
            if (std.ascii.eqlIgnoreCase(codec_name, "flexfec")) return "video/flexfec";
            if (std.ascii.eqlIgnoreCase(codec_name, "flexfec-03")) return "video/flexfec-03";
            if (std.ascii.eqlIgnoreCase(codec_name, "ulpfec")) return "video/ulpfec";
        }
        return codec_name;
    }

    fn parsePayloadType(value: []const u8) Error!u8 {
        const payload = std.fmt.parseInt(u8, value, 10) catch return error.InvalidSdp;
        if (payload > 127) return error.InvalidSdp;
        return payload;
    }

    fn staticRtpCodec(payload_type: u8) ?RtpCodec {
        // Pion/sdp handles the RTP/AVP static payload types without an rtpmap
        // attribute.  These appear in legacy offers and browser interop tests.
        return switch (payload_type) {
            0 => .{ .payload_type = 0, .mime_type = "audio/PCMU", .codec_name = "PCMU", .clock_rate = 8000, .channels = 0 },
            8 => .{ .payload_type = 8, .mime_type = "audio/PCMA", .codec_name = "PCMA", .clock_rate = 8000, .channels = 0 },
            9 => .{ .payload_type = 9, .mime_type = "audio/G722", .codec_name = "G722", .clock_rate = 8000, .channels = 0 },
            else => null,
        };
    }

    fn findPayloadAttribute(attrs: []const Attribute, name: []const u8, payload_type: u8) ?[]const u8 {
        for (attrs) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, name)) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const payload_s = parts.next() orelse continue;
            const payload = parsePayloadType(payload_s) catch continue;
            if (payload != payload_type) continue;
            const value_start = payload_s.len;
            return std.mem.trim(u8, attr.value[value_start..], " \t");
        }
        return null;
    }

    fn collectRtcpFeedback(allocator: std.mem.Allocator, attrs: []const Attribute, payload_type: u8) Error![]RtcpFeedback {
        var feedback: std.ArrayList(RtcpFeedback) = .empty;
        errdefer feedback.deinit(allocator);
        for (attrs) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "rtcp-fb")) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const payload_s = parts.next() orelse return error.InvalidSdp;
            if (!std.mem.eql(u8, payload_s, "*")) {
                const payload = try parsePayloadType(payload_s);
                if (payload != payload_type) continue;
            }
            const typ = parts.next() orelse return error.InvalidSdp;
            const parameter = parts.rest();
            const entry = RtcpFeedback{ .typ = typ, .parameter = std.mem.trim(u8, parameter, " \t") };
            if (!rtcpFeedbackContainsIgnoreCase(feedback.items, entry)) try feedback.append(allocator, entry);
        }
        return feedback.toOwnedSlice(allocator);
    }

    pub fn parseFmtpParameters(allocator: std.mem.Allocator, fmtp: []const u8) Error![]FmtpParameter {
        var parameters: std.ArrayList(FmtpParameter) = .empty;
        errdefer parameters.deinit(allocator);
        var parts = std.mem.splitScalar(u8, fmtp, ';');
        while (parts.next()) |raw_param| {
            const param = std.mem.trim(u8, raw_param, " \t");
            if (param.len == 0) continue;
            if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
                try parameters.append(allocator, .{
                    .key = std.mem.trim(u8, param[0..eq], " \t"),
                    .value = std.mem.trim(u8, param[eq + 1 ..], " \t"),
                });
            } else {
                try parameters.append(allocator, .{ .key = param, .value = "" });
            }
        }
        return parameters.toOwnedSlice(allocator);
    }

    pub fn freeFmtpParameters(allocator: std.mem.Allocator, parameters: []FmtpParameter) void {
        allocator.free(parameters);
    }

    pub fn fmtpParameter(fmtp: []const u8, key: []const u8) ?[]const u8 {
        var params = std.mem.splitScalar(u8, fmtp, ';');
        while (params.next()) |raw_param| {
            const param = std.mem.trim(u8, raw_param, " \t");
            if (param.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, param, '=') orelse {
                if (std.ascii.eqlIgnoreCase(param, key)) return "";
                continue;
            };
            const param_key = std.mem.trim(u8, param[0..eq], " \t");
            if (std.ascii.eqlIgnoreCase(param_key, key)) return std.mem.trim(u8, param[eq + 1 ..], " \t");
        }
        return null;
    }

    pub fn h264FmtpCompatible(local_fmtp: []const u8, remote_fmtp: []const u8) bool {
        const local_packetization = fmtpParameter(local_fmtp, "packetization-mode") orelse return false;
        const remote_packetization = fmtpParameter(remote_fmtp, "packetization-mode") orelse return false;
        if (!std.mem.eql(u8, local_packetization, remote_packetization)) return false;

        const local_profile = fmtpParameter(local_fmtp, "profile-level-id") orelse return false;
        const remote_profile = fmtpParameter(remote_fmtp, "profile-level-id") orelse return false;
        return h264ProfileLevelIdMatches(local_profile, remote_profile);
    }

    pub fn h264ProfileLevelIdMatches(a: []const u8, b: []const u8) bool {
        if (a.len < 4 or b.len < 4) return false;
        const a0 = std.fmt.parseInt(u8, a[0..2], 16) catch return false;
        const a1 = std.fmt.parseInt(u8, a[2..4], 16) catch return false;
        const b0 = std.fmt.parseInt(u8, b[0..2], 16) catch return false;
        const b1 = std.fmt.parseInt(u8, b[2..4], 16) catch return false;
        return a0 == b0 and a1 == b1;
    }

    pub fn vp9FmtpCompatible(local_fmtp: []const u8, remote_fmtp: []const u8) bool {
        const local_profile = fmtpParameter(local_fmtp, "profile-id") orelse "0";
        const remote_profile = fmtpParameter(remote_fmtp, "profile-id") orelse "0";
        return std.mem.eql(u8, local_profile, remote_profile);
    }

    pub fn av1FmtpCompatible(local_fmtp: []const u8, remote_fmtp: []const u8) bool {
        const local_profile = fmtpParameter(local_fmtp, "profile") orelse "0";
        const remote_profile = fmtpParameter(remote_fmtp, "profile") orelse "0";
        return std.mem.eql(u8, local_profile, remote_profile);
    }

    fn genericFmtpCompatible(local_fmtp: []const u8, remote_fmtp: []const u8) bool {
        return fmtpSharedParamsEqual(local_fmtp, remote_fmtp) and fmtpSharedParamsEqual(remote_fmtp, local_fmtp);
    }

    fn fmtpSharedParamsEqual(a: []const u8, b: []const u8) bool {
        var params = std.mem.splitScalar(u8, a, ';');
        while (params.next()) |raw_param| {
            const param = std.mem.trim(u8, raw_param, " \t");
            if (param.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, param, '=') orelse {
                continue;
            };
            const key = std.mem.trim(u8, param[0..eq], " \t");
            const value = std.mem.trim(u8, param[eq + 1 ..], " \t");
            const other = fmtpParameter(b, key) orelse continue;
            if (!std.ascii.eqlIgnoreCase(value, other)) return false;
        }
        return true;
    }

    fn codecClockRateEqual(mime_type: []const u8, a: u32, b: u32) bool {
        const left = if (a == 0) defaultClockRate(mime_type) else a;
        const right = if (b == 0) defaultClockRate(mime_type) else b;
        return left == right;
    }

    fn codecChannelsEqual(mime_type: []const u8, a: u16, b: u16) bool {
        var left = if (a == 0) defaultChannels(mime_type) else a;
        var right = if (b == 0) defaultChannels(mime_type) else b;
        if (left == 0) left = 1;
        if (right == 0) right = 1;
        return left == right;
    }

    fn defaultClockRate(mime_type: []const u8) u32 {
        if (std.ascii.eqlIgnoreCase(mime_type, "audio/opus")) return 48000;
        if (std.ascii.eqlIgnoreCase(mime_type, "audio/PCMU")) return 8000;
        if (std.ascii.eqlIgnoreCase(mime_type, "audio/PCMA")) return 8000;
        if (std.ascii.startsWithIgnoreCase(mime_type, "video/")) return 90000;
        // Pion's fmtp defaultClockRate falls back to 90 kHz for custom and
        // otherwise unknown codecs when one side omits the clock rate.  This
        // keeps capability matching permissive for application/private codecs
        // without relaxing explicit mismatches.
        return 90000;
    }

    fn defaultChannels(mime_type: []const u8) u16 {
        if (std.ascii.eqlIgnoreCase(mime_type, "audio/opus")) return 2;
        if (std.ascii.startsWithIgnoreCase(mime_type, "audio/")) return 1;
        return 0;
    }

    fn parseRidAttribute(raw: []const u8) Error!Rid {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const id = parts.next() orelse return error.InvalidSdp;
        const direction = parts.next() orelse return error.InvalidSdp;
        const rest = parts.rest();
        if (id.len == 0 or direction.len == 0) return error.InvalidSdp;
        return .{ .id = id, .direction = direction, .parameters = std.mem.trim(u8, rest, " \t") };
    }

    fn markPausedRids(rids: []Rid, raw_simulcast: []const u8) void {
        var value = raw_simulcast;
        if (std.mem.indexOfAny(u8, value, " \t")) |space| {
            value = std.mem.trim(u8, value[space + 1 ..], " \t");
        } else {
            return;
        }
        var alternatives = std.mem.splitScalar(u8, value, ';');
        while (alternatives.next()) |alternative_raw| {
            var alternative = std.mem.trim(u8, alternative_raw, " \t");
            if (alternative.len == 0) continue;
            var paused = false;
            if (alternative[0] == '~') {
                paused = true;
                alternative = alternative[1..];
            }
            if (!paused or alternative.len == 0) continue;
            var ids = std.mem.splitScalar(u8, alternative, ',');
            while (ids.next()) |id_raw| {
                const id = std.mem.trim(u8, id_raw, " \t");
                for (rids) |*rid| {
                    if (std.mem.eql(u8, rid.id, id)) rid.paused = true;
                }
            }
        }
    }

    fn parseMsid(value: []const u8, stream_id: *[]const u8, track_id: *[]const u8) void {
        var parts = std.mem.tokenizeAny(u8, value, " \t");
        const stream = parts.next() orelse return;
        const track = parts.next() orelse return;
        stream_id.* = stream;
        track_id.* = track;
    }

    fn parseSsrcAttribute(value: []const u8, stream_id: *[]const u8, track_id: *[]const u8) ?u32 {
        var parts = std.mem.tokenizeAny(u8, value, " \t");
        const ssrc_s = parts.next() orelse return null;
        const ssrc = std.fmt.parseInt(u32, ssrc_s, 10) catch return null;
        const maybe_msid = parts.next() orelse return ssrc;
        if (std.mem.startsWith(u8, maybe_msid, "msid:")) {
            if (parts.next()) |track| {
                // Pion/webrtc-go only treats `a=ssrc:<ssrc> msid:<stream> <track>`
                // as an MSID-bearing SSRC when it has exactly three fields.
                // Ignoring malformed extras avoids binding a track to
                // accidentally concatenated SDP attributes or vendor garbage.
                if (parts.next() != null) return ssrc;
                stream_id.* = maybe_msid["msid:".len..];
                track_id.* = track;
            }
        }
        return ssrc;
    }

    fn inferMsidFromSsrc(attrs: []const Attribute, stream_id: *[]const u8, track_id: *[]const u8) void {
        for (attrs) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "ssrc")) continue;
            var local_stream = stream_id.*;
            var local_track = track_id.*;
            _ = parseSsrcAttribute(attr.value, &local_stream, &local_track) orelse continue;
            if (local_stream.len != 0 and local_track.len != 0) {
                stream_id.* = local_stream;
                track_id.* = local_track;
                return;
            }
        }
    }

    fn collectSsrcGroups(
        attrs: []const Attribute,
        rtx_pairs: *[16]SsrcPair,
        rtx_len: *usize,
        fec_pairs: *[16]SsrcPair,
        fec_len: *usize,
    ) void {
        for (attrs) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "ssrc-group")) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const semantic = parts.next() orelse continue;
            const base = std.fmt.parseInt(u32, parts.next() orelse continue, 10) catch continue;
            const repair = std.fmt.parseInt(u32, parts.next() orelse continue, 10) catch continue;
            if (std.mem.eql(u8, semantic, "FID")) {
                if (rtx_len.* < rtx_pairs.len) {
                    rtx_pairs[rtx_len.*] = .{ .base = base, .repair = repair };
                    rtx_len.* += 1;
                }
            } else if (std.mem.eql(u8, semantic, "FEC-FR")) {
                if (fec_len.* < fec_pairs.len) {
                    fec_pairs[fec_len.*] = .{ .base = base, .repair = repair };
                    fec_len.* += 1;
                }
            }
        }
    }

    const SsrcPair = struct { base: u32, repair: u32 };

    fn repairForBase(pairs: []const SsrcPair, len: usize, base: u32) ?u32 {
        for (pairs[0..len]) |pair| {
            if (pair.base == base) return pair.repair;
        }
        return null;
    }

    fn repairBase(pairs: []const SsrcPair, len: usize, repair: u32) ?u32 {
        for (pairs[0..len]) |pair| {
            if (pair.repair == repair) return pair.base;
        }
        return null;
    }

    fn findTrackBySsrc(tracks: []TrackDetails, ssrc: u32) ?*TrackDetails {
        for (tracks) |*track| {
            if (track.ssrc != null and track.ssrc.? == ssrc) return track;
        }
        return null;
    }

    fn parseMaxMessageSize(value: ?[]const u8) Error!u32 {
        // Pion reports an absent a=max-message-size as the SCTP unset value
        // (65535), while an explicit "0" remains the RFC 8841 unlimited
        // sentinel.  Preserve that distinction for capability negotiation.
        const raw = value orelse return sctp_max_message_size_unset;
        if (raw.len == 0) return error.InvalidSdp;
        return std.fmt.parseInt(u32, raw, 10) catch return error.InvalidSdp;
    }

    pub fn dataChannelMedia(session: Session) ?Media {
        if (candidateMedia(session)) |media| {
            if (mediaLooksLikeDataChannel(media)) return media;
        }
        for (session.media) |media| {
            if (mediaLooksLikeDataChannel(media)) return media;
        }
        return null;
    }

    pub fn mediaLooksLikeDataChannel(media: Media) bool {
        if (!std.ascii.eqlIgnoreCase(media.kind, "application")) return false;
        if (findAttr(media.attributes, "sctp-port") != null or findAttr(media.attributes, "sctpmap") != null) return true;
        if (std.ascii.indexOfIgnoreCase(media.protocol, "SCTP") != null) return true;
        if (formatContains(media.formats, "webrtc-datachannel")) return true;
        return false;
    }

    fn firstFormatToken(formats: []const u8) ?[]const u8 {
        var tokens = std.mem.tokenizeAny(u8, formats, " \t");
        return tokens.next();
    }

    fn dataChannelProtocolFromFormats(formats: []const u8) Error!?[]const u8 {
        var protocol: ?[]const u8 = null;
        var tokens = std.mem.tokenizeAny(u8, formats, " \t");
        while (tokens.next()) |token| {
            _ = std.fmt.parseInt(u16, token, 10) catch {
                // RFC 8841 and Pion-generated SDP use a single application
                // format token, "webrtc-datachannel", to identify SCTP Data
                // Channels.  Treat any other non-numeric token as malformed
                // SDP instead of silently negotiating an unsupported SCTP
                // application protocol.
                try validateSctpDataChannelProtocol(token);
                protocol = sctp_data_channel_protocol;
                continue;
            };
        }
        return protocol;
    }

    fn formatContains(formats: []const u8, needle: []const u8) bool {
        var tokens = std.mem.tokenizeAny(u8, formats, " \t");
        while (tokens.next()) |token| {
            if (std.ascii.eqlIgnoreCase(token, needle)) return true;
        }
        return false;
    }

    fn parseFingerprint(raw: []const u8) Error!Fingerprint {
        var parts = std.mem.tokenizeAny(u8, raw, " \t");
        const algorithm = parts.next() orelse return error.InvalidFingerprint;
        const value = parts.next() orelse return error.InvalidFingerprint;
        if (parts.next() != null) return error.InvalidFingerprint;
        const digest_len = fingerprintDigestLen(algorithm) orelse return error.InvalidFingerprint;
        try validateColonHexFingerprint(value, digest_len);
        return .{ .algorithm = algorithm, .value = value };
    }

    fn fingerprintDigestLen(algorithm: []const u8) ?usize {
        // Pion/webrtc-go emits SHA-256 fingerprints and validates received
        // fingerprints through pion/dtls' hash registry.  Keep the SDP parser
        // strict about the IANA hash textual names that are useful for DTLS
        // fingerprints instead of accepting arbitrary labels that would later
        // make certificate pinning silently impossible.
        if (std.ascii.eqlIgnoreCase(algorithm, "sha-1")) return 20;
        if (std.ascii.eqlIgnoreCase(algorithm, "sha-224")) return 28;
        if (std.ascii.eqlIgnoreCase(algorithm, "sha-256")) return 32;
        if (std.ascii.eqlIgnoreCase(algorithm, "sha-384")) return 48;
        if (std.ascii.eqlIgnoreCase(algorithm, "sha-512")) return 64;
        return null;
    }

    fn validateColonHexFingerprint(value: []const u8, digest_len: usize) Error!void {
        if (digest_len == 0) return error.InvalidFingerprint;
        const expected_len = std.math.sub(usize, std.math.mul(usize, digest_len, 3) catch return error.InvalidFingerprint, 1) catch return error.InvalidFingerprint;
        if (value.len != expected_len) return error.InvalidFingerprint;
        for (0..digest_len) |index| {
            const offset = index * 3;
            if (!std.ascii.isHex(value[offset]) or !std.ascii.isHex(value[offset + 1])) return error.InvalidFingerprint;
            if (index + 1 != digest_len and value[offset + 2] != ':') return error.InvalidFingerprint;
        }
    }

    fn bundleId(session: Session) ?[]const u8 {
        for (session.attributes) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, "group")) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const semantic = parts.next() orelse continue;
            if (!std.mem.eql(u8, semantic, "BUNDLE")) continue;
            return parts.next();
        }
        return null;
    }

    fn candidateMedia(session: Session) ?Media {
        if (selectCandidateMedia(session)) |indexed| return indexed.media;
        return null;
    }

    pub const IndexedMedia = struct {
        media: Media,
        index: u16,
    };

    pub fn mediaByMid(session: Session, search_mid: []const u8) ?IndexedMedia {
        for (session.media, 0..) |media, index| {
            if (findAttr(media.attributes, "mid")) |mid| {
                if (std.mem.eql(u8, mid, search_mid)) return .{ .media = media, .index = @intCast(index) };
            }
        }
        return null;
    }

    pub fn selectCandidateMedia(session: Session) ?IndexedMedia {
        if (bundleId(session)) |bundle_id| {
            return mediaByMid(session, bundle_id);
        }
        return if (session.media.len > 0) .{ .media = session.media[0], .index = 0 } else null;
    }
};

pub const dtls = struct {
    pub const ContentType = enum(u8) {
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,
        _,
    };

    pub const Record = struct {
        content_type: ContentType,
        version: u16,
        epoch: u16,
        sequence_number: u48,
        fragment: []const u8,

        pub fn parse(bytes: []const u8) Error!Record {
            var cursor = wire.Cursor.init(bytes);
            const content_type: ContentType = @enumFromInt(try cursor.readByte());
            const version = try cursor.readInt(u16, .big);
            try validateRecordHeader(content_type, version);
            const epoch = try cursor.readInt(u16, .big);
            const seq_hi = try cursor.readInt(u16, .big);
            const seq_lo = try cursor.readInt(u32, .big);
            const len = try cursor.readInt(u16, .big);
            const fragment = try cursor.readSlice(len);
            return .{ .content_type = content_type, .version = version, .epoch = epoch, .sequence_number = (@as(u48, seq_hi) << 32) | seq_lo, .fragment = fragment };
        }
    };

    pub const WriteOptions = struct {
        content_type: ContentType,
        version: u16 = 0xfefd,
        epoch: u16,
        sequence_number: u48,
    };

    pub const RecordToWrite = struct {
        options: WriteOptions,
        fragment: []const u8,
    };

    pub fn writeRecord(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: WriteOptions, fragment: []const u8) Error!void {
        if (fragment.len > std.math.maxInt(u16)) return error.InvalidDtlsRecord;
        try list.append(allocator, @intFromEnum(options.content_type));
        try wire.appendInt(list, allocator, u16, options.version, .big);
        try wire.appendInt(list, allocator, u16, options.epoch, .big);
        try wire.appendInt(list, allocator, u16, @intCast(options.sequence_number >> 32), .big);
        try wire.appendInt(list, allocator, u32, @truncate(options.sequence_number), .big);
        try wire.appendInt(list, allocator, u16, @intCast(fragment.len), .big);
        try list.appendSlice(allocator, fragment);
    }

    pub fn writeRecords(list: *std.ArrayList(u8), allocator: std.mem.Allocator, records: []const RecordToWrite) Error!void {
        if (records.len == 0) return error.InvalidDtlsRecord;
        for (records) |record| try writeRecord(list, allocator, record.options, record.fragment);
    }

    pub fn parseRecords(allocator: std.mem.Allocator, bytes: []const u8) Error![]Record {
        var records: std.ArrayList(Record) = .empty;
        errdefer records.deinit(allocator);

        var cursor = wire.Cursor.init(bytes);
        while (!cursor.eof()) {
            const content_type: ContentType = @enumFromInt(try cursor.readByte());
            const version = try cursor.readInt(u16, .big);
            try validateRecordHeader(content_type, version);
            const epoch = try cursor.readInt(u16, .big);
            const seq_hi = try cursor.readInt(u16, .big);
            const seq_lo = try cursor.readInt(u32, .big);
            const len = try cursor.readInt(u16, .big);
            const fragment = try cursor.readSlice(len);
            try records.append(allocator, .{
                .content_type = content_type,
                .version = version,
                .epoch = epoch,
                .sequence_number = (@as(u48, seq_hi) << 32) | seq_lo,
                .fragment = fragment,
            });
        }
        if (records.items.len == 0) return error.InvalidDtlsRecord;
        return records.toOwnedSlice(allocator);
    }

    pub fn freeRecords(allocator: std.mem.Allocator, records: []Record) void {
        allocator.free(records);
    }

    fn validateRecordHeader(content_type: ContentType, version: u16) Error!void {
        switch (content_type) {
            .change_cipher_spec, .alert, .handshake, .application_data => {},
            _ => return error.InvalidDtlsRecord,
        }
        // Pion's record layer accepts DTLS 1.0 (FEFF) and DTLS 1.2 (FEFD).
        if (version != 0xfeff and version != 0xfefd) return error.InvalidDtlsRecord;
    }
};

pub const rtp = struct {
    pub const one_byte_header_extension_profile: u16 = 0xbede;
    pub const two_byte_header_extension_profile: u16 = 0x1000;
    pub const cryptex_one_byte_header_extension_profile: u16 = 0xc0de;
    pub const cryptex_two_byte_header_extension_profile: u16 = 0xc2de;

    pub const Extension = struct {
        profile: u16,
        data: []const u8,
    };

    pub const HeaderExtensionElement = struct {
        id: u8,
        data: []const u8,
    };

    pub const UnknownRtpDemuxDetails = struct {
        mid: []const u8 = "",
        rid: []const u8 = "",
        repaired_rid: []const u8 = "",
        padding_only: bool = false,
    };

    pub const AudioLevelExtension = struct {
        level: u7,
        voice: bool = false,
    };

    pub const PlayoutDelayExtension = struct {
        min_delay: u12,
        max_delay: u12,
    };

    pub const VideoRotation = enum(u2) {
        rotate_0 = 0,
        rotate_90 = 1,
        rotate_180 = 2,
        rotate_270 = 3,
    };

    pub const VideoOrientationExtension = struct {
        rotation: VideoRotation = .rotate_0,
        flip: bool = false,
        camera: bool = false,
    };

    pub const AbsCaptureTimeExtension = struct {
        timestamp: u64,
        estimated_capture_clock_offset: ?i64 = null,

        pub fn captureUnixNanos(self: AbsCaptureTimeExtension) u64 {
            return unixNanosFromNtpTime(self.timestamp);
        }

        pub fn estimatedCaptureClockOffsetNanos(self: AbsCaptureTimeExtension) ?i64 {
            const raw = self.estimated_capture_clock_offset orelse return null;
            return captureClockOffsetNanos(raw);
        }
    };

    pub const VideoLayerAllocation = struct {
        rtp_stream_id: u2,
        rtp_stream_count: u3,
        active_spatial_layers: []const SpatialLayer,
        has_resolution_and_framerate: bool = false,
    };

    pub const SpatialLayer = struct {
        rtp_stream_id: u2,
        spatial_id: u2,
        target_bitrates_kbps: []const u32,
        width: u16 = 0,
        height: u16 = 0,
        framerate: u8 = 0,
    };

    pub const HeaderExtensionFormat = enum {
        one_byte,
        two_byte,
        raw,
    };

    pub fn headerExtensionFormat(profile: u16) ?HeaderExtensionFormat {
        if (profile == one_byte_header_extension_profile or profile == cryptex_one_byte_header_extension_profile) return .one_byte;
        if ((profile & 0xfff0) == two_byte_header_extension_profile or profile == cryptex_two_byte_header_extension_profile) return .two_byte;
        return .raw;
    }

    pub fn parseHeaderExtensionElements(allocator: std.mem.Allocator, extension: Extension) Error![]HeaderExtensionElement {
        return switch (headerExtensionFormat(extension.profile) orelse return error.InvalidRtpPacket) {
            .one_byte => parseOneByteHeaderExtensions(allocator, extension.data),
            .two_byte => parseTwoByteHeaderExtensions(allocator, extension.data),
            .raw => parseRawHeaderExtensions(allocator, extension.data),
        };
    }

    pub fn parseHeaderExtensionElementsLenient(allocator: std.mem.Allocator, extension: Extension) Error![]HeaderExtensionElement {
        return switch (headerExtensionFormat(extension.profile) orelse return error.InvalidRtpPacket) {
            .one_byte => parseOneByteHeaderExtensionsLenient(allocator, extension.data),
            .two_byte => parseTwoByteHeaderExtensions(allocator, extension.data),
            .raw => parseRawHeaderExtensions(allocator, extension.data),
        };
    }

    pub fn freeHeaderExtensionElements(allocator: std.mem.Allocator, elements: []HeaderExtensionElement) void {
        allocator.free(elements);
    }

    pub fn findHeaderExtension(elements: []const HeaderExtensionElement, id: u8) ?[]const u8 {
        for (elements) |element| {
            if (element.id == id) return element.data;
        }
        return null;
    }

    pub fn headerExtensionIds(allocator: std.mem.Allocator, elements: []const HeaderExtensionElement) Error![]u8 {
        const ids = try allocator.alloc(u8, elements.len);
        for (elements, ids) |element, *id| id.* = element.id;
        return ids;
    }

    pub fn setHeaderExtension(
        allocator: std.mem.Allocator,
        elements: *[]HeaderExtensionElement,
        id: u8,
        data: []const u8,
    ) Error!void {
        if (id == 0) return error.InvalidRtpPacket;
        for (elements.*) |*element| {
            if (element.id == id) {
                element.data = data;
                return;
            }
        }
        if (elements.*.len == 0) {
            elements.* = try allocator.alloc(HeaderExtensionElement, 1);
            elements.*[0] = .{ .id = id, .data = data };
            return;
        }
        elements.* = try allocator.realloc(elements.*, elements.*.len + 1);
        elements.*[elements.*.len - 1] = .{ .id = id, .data = data };
    }

    pub fn setHeaderExtensionForProfile(
        allocator: std.mem.Allocator,
        elements: *[]HeaderExtensionElement,
        profile: u16,
        id: u8,
        data: []const u8,
    ) Error!void {
        switch (headerExtensionFormat(profile) orelse return error.InvalidRtpPacket) {
            .one_byte => {
                if (id == 0 or id >= 15 or data.len > 16) return error.InvalidRtpPacket;
                try setHeaderExtension(allocator, elements, id, data);
            },
            .two_byte => {
                if (id == 0 or data.len > std.math.maxInt(u8)) return error.InvalidRtpPacket;
                try setHeaderExtension(allocator, elements, id, data);
            },
            .raw => {
                if (id != 0) return error.InvalidRtpPacket;
                try setRawHeaderExtension(allocator, elements, data);
            },
        }
    }

    pub fn deleteHeaderExtension(allocator: std.mem.Allocator, elements: *[]HeaderExtensionElement, id: u8) Error!bool {
        for (elements.*, 0..) |element, index| {
            if (element.id != id) continue;
            std.mem.copyForwards(HeaderExtensionElement, elements.*[index .. elements.*.len - 1], elements.*[index + 1 ..]);
            elements.* = try allocator.realloc(elements.*, elements.*.len - 1);
            return true;
        }
        return false;
    }

    pub fn setRawHeaderExtension(allocator: std.mem.Allocator, elements: *[]HeaderExtensionElement, data: []const u8) Error!void {
        for (elements.*) |*element| {
            if (element.id == 0) {
                element.data = data;
                return;
            }
        }
        if (elements.*.len == 0) {
            elements.* = try allocator.alloc(HeaderExtensionElement, 1);
            elements.*[0] = .{ .id = 0, .data = data };
            return;
        }
        elements.* = try allocator.realloc(elements.*, elements.*.len + 1);
        elements.*[elements.*.len - 1] = .{ .id = 0, .data = data };
    }

    pub fn clearHeaderExtensions(allocator: std.mem.Allocator, elements: *[]HeaderExtensionElement) void {
        allocator.free(elements.*);
        elements.* = &.{};
    }

    pub fn mid(elements: []const HeaderExtensionElement, id: u8) ?[]const u8 {
        return findHeaderExtension(elements, id);
    }

    pub fn rtpStreamId(elements: []const HeaderExtensionElement, id: u8) ?[]const u8 {
        return findHeaderExtension(elements, id);
    }

    pub fn repairedRtpStreamId(elements: []const HeaderExtensionElement, id: u8) ?[]const u8 {
        return findHeaderExtension(elements, id);
    }

    pub fn unknownRtpDemuxDetails(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        mid_extension_id: u8,
        stream_id_extension_id: u8,
        repair_stream_id_extension_id: u8,
    ) Error!UnknownRtpDemuxDetails {
        var packet = try Packet.parse(allocator, bytes);
        defer packet.deinit(allocator);

        var details = UnknownRtpDemuxDetails{
            .padding_only = packet.header.padding and packet.payload.len == 0,
        };
        const extension = packet.extension orelse return details;
        const elements = try parseHeaderExtensionElementsLenient(allocator, extension);
        defer freeHeaderExtensionElements(allocator, elements);

        // This mirrors Pion's handleUnknownRTPPacket helper used during
        // simulcast/late-SSRC demux: MID, RID and repaired RID are optional
        // raw UTF-8-ish byte strings carried in RTP header extensions.  The
        // helper intentionally returns borrowed packet slices so callers can
        // make a demux decision without allocating per packet.
        details.mid = mid(elements, mid_extension_id) orelse "";
        details.rid = rtpStreamId(elements, stream_id_extension_id) orelse "";
        details.repaired_rid = repairedRtpStreamId(elements, repair_stream_id_extension_id) orelse "";
        return details;
    }

    pub fn parseOneByteHeaderExtensions(allocator: std.mem.Allocator, data: []const u8) Error![]HeaderExtensionElement {
        var elements: std.ArrayList(HeaderExtensionElement) = .empty;
        errdefer elements.deinit(allocator);

        var pos: usize = 0;
        while (pos < data.len) {
            const header = data[pos];
            pos += 1;
            if (header == 0) continue; // 0 bytes are padding in both RFC5285 forms.
            const id = header >> 4;
            if (id == 15) return error.InvalidRtpPacket; // Reserved by RFC 5285.
            if (id == 0) return error.InvalidRtpPacket; // Non-zero padding length is invalid in RFC 5285.
            const len = @as(usize, header & 0x0f) + 1;
            if (pos + len > data.len) return error.InvalidRtpPacket;
            try elements.append(allocator, .{ .id = id, .data = data[pos .. pos + len] });
            pos += len;
        }
        return elements.toOwnedSlice(allocator);
    }

    pub fn parseOneByteHeaderExtensionsLenient(allocator: std.mem.Allocator, data: []const u8) Error![]HeaderExtensionElement {
        var elements: std.ArrayList(HeaderExtensionElement) = .empty;
        errdefer elements.deinit(allocator);

        var pos: usize = 0;
        while (pos < data.len) {
            const header = data[pos];
            pos += 1;
            if (header == 0) continue;
            const id = header >> 4;
            if (id == 15 or id == 0) break;
            const len = @as(usize, header & 0x0f) + 1;
            if (pos + len > data.len) break;
            try elements.append(allocator, .{ .id = id, .data = data[pos .. pos + len] });
            pos += len;
        }
        return elements.toOwnedSlice(allocator);
    }

    pub fn parseTwoByteHeaderExtensions(allocator: std.mem.Allocator, data: []const u8) Error![]HeaderExtensionElement {
        var elements: std.ArrayList(HeaderExtensionElement) = .empty;
        errdefer elements.deinit(allocator);

        var pos: usize = 0;
        while (pos < data.len) {
            const id = data[pos];
            pos += 1;
            if (id == 0) continue; // Single-byte padding.
            if (pos >= data.len) return error.InvalidRtpPacket;
            const len = data[pos];
            pos += 1;
            if (pos + len > data.len) return error.InvalidRtpPacket;
            try elements.append(allocator, .{ .id = id, .data = data[pos .. pos + len] });
            pos += len;
        }
        return elements.toOwnedSlice(allocator);
    }

    pub fn parseRawHeaderExtensions(allocator: std.mem.Allocator, data: []const u8) Error![]HeaderExtensionElement {
        const elements = try allocator.alloc(HeaderExtensionElement, 1);
        elements[0] = .{ .id = 0, .data = data };
        return elements;
    }

    pub fn writeOneByteHeaderExtensions(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        elements: []const HeaderExtensionElement,
    ) Error!void {
        const start = list.items.len;
        for (elements) |element| {
            if (element.id == 0 or element.id >= 15 or element.data.len == 0 or element.data.len > 16) {
                return error.InvalidRtpPacket;
            }
            try list.append(allocator, (@as(u8, element.id) << 4) | @as(u8, @intCast(element.data.len - 1)));
            try list.appendSlice(allocator, element.data);
        }
        try padHeaderExtensionData(list, allocator, start);
    }

    pub fn writeTwoByteHeaderExtensions(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        elements: []const HeaderExtensionElement,
    ) Error!void {
        const start = list.items.len;
        for (elements) |element| {
            if (element.id == 0 or element.data.len > std.math.maxInt(u8)) return error.InvalidRtpPacket;
            try list.append(allocator, element.id);
            try list.append(allocator, @intCast(element.data.len));
            try list.appendSlice(allocator, element.data);
        }
        try padHeaderExtensionData(list, allocator, start);
    }

    pub fn transportWideSequenceNumber(elements: []const HeaderExtensionElement, id: u8) Error!?u16 {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len < 2) return error.InvalidRtpPacket;
        return std.mem.readInt(u16, value[0..2], .big);
    }

    pub fn transportWideSequenceNumberPayload(sequence_number: u16) [2]u8 {
        var out: [2]u8 = undefined;
        std.mem.writeInt(u16, &out, sequence_number, .big);
        return out;
    }

    pub fn absoluteSendTime24(elements: []const HeaderExtensionElement, id: u8) Error!?u24 {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len < 3) return error.InvalidRtpPacket;
        return (@as(u24, value[0]) << 16) | (@as(u24, value[1]) << 8) | value[2];
    }

    pub fn absoluteSendTimePayload(timestamp: u24) [3]u8 {
        return .{
            @truncate(timestamp >> 16),
            @truncate(timestamp >> 8),
            @truncate(timestamp),
        };
    }

    pub fn absoluteSendTimeFromUnixNanos(unix_time_ns: u64) u24 {
        return @truncate(ntpTimeFromUnixNanos(unix_time_ns) >> 14);
    }

    pub fn estimateAbsoluteSendTimeUnixNanos(timestamp: u24, receive_unix_time_ns: u64) u64 {
        const receive_ntp = ntpTimeFromUnixNanos(receive_unix_time_ns);
        var ntp = (receive_ntp & 0xffff_ffc0_0000_0000) | (@as(u64, timestamp) << 14);
        if (receive_ntp < ntp) ntp -%= @as(u64, 0x1_000000) << 14;
        return unixNanosFromNtpTime(ntp);
    }

    pub fn ntpTimeFromUnixNanos(unix_time_ns: u64) u64 {
        const ntp_epoch_offset_seconds: u64 = 2_208_988_800;
        const seconds = unix_time_ns / std.time.ns_per_s + ntp_epoch_offset_seconds;
        const fractional_ns = unix_time_ns % std.time.ns_per_s;
        const fraction = (fractional_ns << 32) / std.time.ns_per_s;
        return (seconds << 32) | fraction;
    }

    pub fn unixNanosFromNtpTime(ntp_time: u64) u64 {
        const ntp_epoch_offset_seconds: u64 = 2_208_988_800;
        const seconds = (ntp_time >> 32) - ntp_epoch_offset_seconds;
        const fraction = ntp_time & 0xffff_ffff;
        const fractional_ns = (fraction * std.time.ns_per_s) >> 32;
        return seconds * std.time.ns_per_s + fractional_ns;
    }

    pub fn audioLevel(elements: []const HeaderExtensionElement, id: u8) Error!?AudioLevelExtension {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len < 1) return error.InvalidRtpPacket;
        return .{
            .level = @truncate(value[0] & 0x7f),
            .voice = (value[0] & 0x80) != 0,
        };
    }

    pub fn audioLevelPayload(level: u8, voice: bool) Error![1]u8 {
        if (level > 127) return error.InvalidRtpPacket;
        return .{(if (voice) @as(u8, 0x80) else 0) | level};
    }

    pub fn playoutDelay(elements: []const HeaderExtensionElement, id: u8) Error!?PlayoutDelayExtension {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len < 3) return error.InvalidRtpPacket;
        return .{
            .min_delay = @truncate(std.mem.readInt(u16, value[0..2], .big) >> 4),
            .max_delay = @truncate(std.mem.readInt(u16, value[1..3], .big) & 0x0fff),
        };
    }

    pub fn playoutDelayPayload(min_delay: u16, max_delay: u16) Error![3]u8 {
        if (min_delay > 0x0fff or max_delay > 0x0fff) return error.InvalidRtpPacket;
        return .{
            @truncate(min_delay >> 4),
            @as(u8, @truncate(min_delay << 4)) | @as(u8, @truncate(max_delay >> 8)),
            @truncate(max_delay),
        };
    }

    pub fn videoOrientation(elements: []const HeaderExtensionElement, id: u8) Error!?VideoOrientationExtension {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len != 1 or (value[0] & 0xf0) != 0) return error.InvalidRtpPacket;
        return .{
            .rotation = @enumFromInt(value[0] & 0x03),
            .flip = (value[0] & 0x04) != 0,
            .camera = (value[0] & 0x08) != 0,
        };
    }

    pub fn videoOrientationPayload(orientation: VideoOrientationExtension) [1]u8 {
        return .{
            @intFromEnum(orientation.rotation) |
                (if (orientation.flip) @as(u8, 0x04) else 0) |
                (if (orientation.camera) @as(u8, 0x08) else 0),
        };
    }

    pub fn absCaptureTime(elements: []const HeaderExtensionElement, id: u8) Error!?AbsCaptureTimeExtension {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len < 8) return error.InvalidRtpPacket;
        return .{
            .timestamp = std.mem.readInt(u64, value[0..8], .big),
            .estimated_capture_clock_offset = if (value.len >= 16) std.mem.readInt(i64, value[8..16], .big) else null,
        };
    }

    pub fn absCaptureTimePayload(timestamp: u64, offset: ?i64) [16]u8 {
        var out: [16]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], timestamp, .big);
        if (offset) |value| {
            std.mem.writeInt(i64, out[8..16], value, .big);
        } else {
            @memset(out[8..16], 0);
        }
        return out;
    }

    pub fn absCaptureTimePayloadLen(offset: ?i64) usize {
        return if (offset == null) 8 else 16;
    }

    pub fn absCaptureTimeFromUnixNanos(unix_time_ns: u64) u64 {
        return ntpTimeFromUnixNanos(unix_time_ns);
    }

    pub fn captureClockOffsetFromNanos(offset_ns: i64) i64 {
        const negative = offset_ns < 0;
        const magnitude: u64 = @intCast(if (negative) -@as(i128, offset_ns) else @as(i128, offset_ns));
        const seconds = magnitude / std.time.ns_per_s;
        const fractional_ns = magnitude % std.time.ns_per_s;
        const raw_u = (seconds << 32) | ((fractional_ns << 32) / std.time.ns_per_s);
        const raw: i64 = @intCast(raw_u);
        return if (negative) -raw else raw;
    }

    pub fn captureClockOffsetNanos(raw_offset: i64) i64 {
        const negative = raw_offset < 0;
        const magnitude: u64 = @intCast(if (negative) -@as(i128, raw_offset) else @as(i128, raw_offset));
        const seconds = magnitude >> 32;
        const fraction = magnitude & 0xffff_ffff;
        const nanos = seconds * std.time.ns_per_s + ((fraction * std.time.ns_per_s) >> 32);
        const signed: i64 = @intCast(nanos);
        return if (negative) -signed else signed;
    }

    pub fn writeVideoLayerAllocationPayload(list: *std.ArrayList(u8), allocator: std.mem.Allocator, vla: VideoLayerAllocation) Error!void {
        if (vla.rtp_stream_count == 0 or vla.rtp_stream_count > 4 or vla.rtp_stream_id >= vla.rtp_stream_count) return error.InvalidRtpPacket;
        var sl_bms = [_]u4{ 0, 0, 0, 0 };
        var indices: [4][4]?usize = .{
            .{ null, null, null, null },
            .{ null, null, null, null },
            .{ null, null, null, null },
            .{ null, null, null, null },
        };
        for (vla.active_spatial_layers, 0..) |layer, index| {
            if (layer.rtp_stream_id >= vla.rtp_stream_count or layer.target_bitrates_kbps.len == 0 or layer.target_bitrates_kbps.len > 4) return error.InvalidRtpPacket;
            if (indices[layer.rtp_stream_id][layer.spatial_id] != null) return error.InvalidRtpPacket;
            sl_bms[layer.rtp_stream_id] |= @as(u4, 1) << layer.spatial_id;
            indices[layer.rtp_stream_id][layer.spatial_id] = index;
            if (vla.has_resolution_and_framerate and (layer.width == 0 or layer.height == 0)) return error.InvalidRtpPacket;
        }

        const common_sl_bm = commonSpatialLayerBitmask(sl_bms[0..vla.rtp_stream_count]);
        try list.append(allocator, (@as(u8, vla.rtp_stream_id) << 6) | ((@as(u8, vla.rtp_stream_count) - 1) << 4) | common_sl_bm);
        if (common_sl_bm == 0) {
            var packed_bm = [_]u8{0} ** 2;
            for (0..vla.rtp_stream_count) |stream_id| {
                if ((stream_id % 2) == 0) {
                    packed_bm[stream_id / 2] |= @as(u8, sl_bms[stream_id]) << 4;
                } else {
                    packed_bm[stream_id / 2] |= @as(u8, sl_bms[stream_id]);
                }
            }
            try list.appendSlice(allocator, packed_bm[0 .. (vla.rtp_stream_count - 1) / 2 + 1]);
        }

        const tl_start = list.items.len;
        try list.appendNTimes(allocator, 0, vlaTemporalLayerControlLen(vla.active_spatial_layers.len));
        var temporal_layer_index: usize = 0;
        for (0..vla.rtp_stream_count) |stream_id| {
            for (0..4) |spatial_id| {
                const index = indices[stream_id][spatial_id] orelse continue;
                const shift: u3 = @intCast(2 * (3 - (temporal_layer_index % 4)));
                list.items[tl_start + temporal_layer_index / 4] |= @as(u8, @intCast(vla.active_spatial_layers[index].target_bitrates_kbps.len - 1)) << shift;
                temporal_layer_index += 1;
            }
        }

        for (0..vla.rtp_stream_count) |stream_id| {
            for (0..4) |spatial_id| {
                const index = indices[stream_id][spatial_id] orelse continue;
                for (vla.active_spatial_layers[index].target_bitrates_kbps) |kbps| try appendLeb128(list, allocator, kbps);
            }
        }

        if (vla.has_resolution_and_framerate) {
            for (vla.active_spatial_layers) |layer| {
                try wire.appendInt(list, allocator, u16, layer.width - 1, .big);
                try wire.appendInt(list, allocator, u16, layer.height - 1, .big);
                try list.append(allocator, layer.framerate);
            }
        }
    }

    pub fn videoLayerAllocationPayloadLen(vla: VideoLayerAllocation) Error!usize {
        if (vla.rtp_stream_count == 0 or vla.rtp_stream_count > 4 or vla.rtp_stream_id >= vla.rtp_stream_count) return error.InvalidRtpPacket;
        var sl_bms = [_]u4{ 0, 0, 0, 0 };
        var seen: [4][4]bool = .{
            .{ false, false, false, false },
            .{ false, false, false, false },
            .{ false, false, false, false },
            .{ false, false, false, false },
        };
        var bitrate_len: usize = 0;
        for (vla.active_spatial_layers) |layer| {
            if (layer.rtp_stream_id >= vla.rtp_stream_count or layer.target_bitrates_kbps.len == 0 or layer.target_bitrates_kbps.len > 4) return error.InvalidRtpPacket;
            if (seen[layer.rtp_stream_id][layer.spatial_id]) return error.InvalidRtpPacket;
            seen[layer.rtp_stream_id][layer.spatial_id] = true;
            sl_bms[layer.rtp_stream_id] |= @as(u4, 1) << layer.spatial_id;
            if (vla.has_resolution_and_framerate and (layer.width == 0 or layer.height == 0)) return error.InvalidRtpPacket;
            for (layer.target_bitrates_kbps) |kbps| bitrate_len += leb128Size(kbps);
        }

        var total: usize = 1; // RID/NS/sl_bm byte.
        if (commonSpatialLayerBitmask(sl_bms[0..vla.rtp_stream_count]) == 0) {
            total += (vla.rtp_stream_count - 1) / 2 + 1;
        }
        total += vlaTemporalLayerControlLen(vla.active_spatial_layers.len);
        total += bitrate_len;
        if (vla.has_resolution_and_framerate) total += vla.active_spatial_layers.len * 5;
        return total;
    }

    pub fn parseVideoLayerAllocationPayload(allocator: std.mem.Allocator, payload: []const u8) Error!VideoLayerAllocation {
        if (payload.len == 0) return error.InvalidRtpPacket;
        var offset: usize = 0;
        const first = payload[offset];
        offset += 1;
        const rtp_stream_id: u2 = @truncate(first >> 6);
        const rtp_stream_count: u3 = @as(u3, @truncate((first >> 4) & 0x03)) + 1;
        const common_sl_bm: u4 = @truncate(first & 0x0f);
        if (rtp_stream_id >= rtp_stream_count) return error.InvalidRtpPacket;

        var sl_bms = [_]u4{ 0, 0, 0, 0 };
        if (common_sl_bm != 0) {
            for (0..rtp_stream_count) |stream_id| sl_bms[stream_id] = common_sl_bm;
        } else {
            const slbm_len = (rtp_stream_count - 1) / 2 + 1;
            if (payload.len < offset + slbm_len) return error.InvalidRtpPacket;
            for (0..rtp_stream_count) |stream_id| {
                const packed_bm = payload[offset + stream_id / 2];
                sl_bms[stream_id] = @truncate(if ((stream_id % 2) == 0) (packed_bm >> 4) & 0x0f else packed_bm & 0x0f);
            }
            offset += slbm_len;
        }

        if (payload.len <= offset) return error.InvalidRtpPacket;
        var layer_count: usize = 0;
        for (0..rtp_stream_count) |stream_id| layer_count += @popCount(sl_bms[stream_id]);
        const layers = try allocator.alloc(SpatialLayer, layer_count);
        var initialized_layers: usize = 0;
        errdefer {
            for (layers[0..initialized_layers]) |layer| allocator.free(@constCast(layer.target_bitrates_kbps));
            allocator.free(layers);
        }

        var temporal_layer_index: usize = 0;
        for (0..rtp_stream_count) |stream_id| {
            for (0..4) |spatial_id| {
                if ((sl_bms[stream_id] & (@as(u4, 1) << @intCast(spatial_id))) == 0) continue;
                if (payload.len <= offset + temporal_layer_index / 4) return error.InvalidRtpPacket;
                const shift: u3 = @intCast(2 * (3 - (temporal_layer_index % 4)));
                const temporal_count = @as(usize, ((payload[offset + temporal_layer_index / 4] >> shift) & 0x03)) + 1;
                const bitrates = try allocator.alloc(u32, temporal_count);
                errdefer allocator.free(bitrates);
                layers[initialized_layers] = .{
                    .rtp_stream_id = @intCast(stream_id),
                    .spatial_id = @intCast(spatial_id),
                    .target_bitrates_kbps = bitrates,
                };
                initialized_layers += 1;
                temporal_layer_index += 1;
            }
        }
        offset += if (layer_count == 0) 1 else (layer_count - 1) / 4 + 1;

        for (layers) |*layer| {
            for (@constCast(layer.target_bitrates_kbps)) |*kbps| {
                const decoded = try readLeb128(payload[offset..]);
                kbps.* = decoded.value;
                offset += decoded.consumed;
            }
        }

        const remaining = payload.len - offset;
        var has_resolution = false;
        if (remaining != 0) {
            if (remaining < layers.len * 5) return error.InvalidRtpPacket;
            has_resolution = true;
            for (layers) |*layer| {
                layer.width = std.mem.readInt(u16, payload[offset..][0..2], .big) + 1;
                layer.height = std.mem.readInt(u16, payload[offset + 2 ..][0..2], .big) + 1;
                layer.framerate = payload[offset + 4];
                offset += 5;
            }
        }

        return .{
            .rtp_stream_id = rtp_stream_id,
            .rtp_stream_count = rtp_stream_count,
            .active_spatial_layers = layers,
            .has_resolution_and_framerate = has_resolution,
        };
    }

    pub fn videoLayerAllocation(allocator: std.mem.Allocator, elements: []const HeaderExtensionElement, id: u8) Error!?VideoLayerAllocation {
        const value = findHeaderExtension(elements, id) orelse return null;
        return try parseVideoLayerAllocationPayload(allocator, value);
    }

    pub fn freeVideoLayerAllocation(allocator: std.mem.Allocator, vla: VideoLayerAllocation) void {
        for (vla.active_spatial_layers) |layer| allocator.free(@constCast(layer.target_bitrates_kbps));
        allocator.free(@constCast(vla.active_spatial_layers));
    }

    fn commonSpatialLayerBitmask(bitmasks: []const u4) u4 {
        var common: u4 = 0;
        for (bitmasks) |bitmask| {
            if (bitmask == 0) continue;
            if (common == 0) {
                common = bitmask;
                continue;
            }
            if (common != bitmask) return 0;
        }
        return common;
    }

    fn appendLeb128(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) Error!void {
        var remaining = value;
        while (true) {
            var byte: u8 = @truncate(remaining & 0x7f);
            remaining >>= 7;
            if (remaining == 0) {
                try list.append(allocator, byte);
                return;
            }
            byte |= 0x80;
            try list.append(allocator, byte);
        }
    }

    fn leb128Size(value: u32) usize {
        var remaining = value >> 7;
        var size: usize = 1;
        while (remaining != 0) : (remaining >>= 7) size += 1;
        return size;
    }

    fn vlaTemporalLayerControlLen(layer_count: usize) usize {
        return if (layer_count == 0) 1 else (layer_count - 1) / 4 + 1;
    }

    fn readLeb128(bytes: []const u8) Error!struct { value: u32, consumed: usize } {
        var value: u32 = 0;
        var shift: u5 = 0;
        for (bytes, 0..) |byte, index| {
            if (shift >= 32) return error.InvalidRtpPacket;
            value |= @as(u32, byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) return .{ .value = value, .consumed = index + 1 };
            shift += 7;
        }
        return error.InvalidRtpPacket;
    }

    pub const Header = struct {
        version: u2,
        padding: bool,
        extension: bool,
        csrc_count: u4,
        marker: bool,
        payload_type: u7,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        csrcs: []const u32,
        payload_offset: usize,

        pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!Header {
            if (bytes.len < 12) return error.BufferTooShort;
            const b0 = bytes[0];
            const csrc_count: u4 = @truncate(b0 & 0x0f);
            const header_len = 12 + @as(usize, csrc_count) * 4;
            if (bytes.len < header_len) return error.BufferTooShort;
            const csrcs = try allocator.alloc(u32, csrc_count);
            errdefer allocator.free(csrcs);
            var pos: usize = 12;
            for (csrcs) |*csrc| {
                csrc.* = std.mem.readInt(u32, bytes[pos..][0..4], .big);
                pos += 4;
            }
            return .{
                .version = @truncate(b0 >> 6),
                .padding = (b0 & 0x20) != 0,
                .extension = (b0 & 0x10) != 0,
                .csrc_count = csrc_count,
                .marker = (bytes[1] & 0x80) != 0,
                .payload_type = @truncate(bytes[1] & 0x7f),
                .sequence_number = std.mem.readInt(u16, bytes[2..][0..2], .big),
                .timestamp = std.mem.readInt(u32, bytes[4..][0..4], .big),
                .ssrc = std.mem.readInt(u32, bytes[8..][0..4], .big),
                .csrcs = csrcs,
                .payload_offset = pos,
            };
        }

        pub fn deinit(self: *Header, allocator: std.mem.Allocator) void {
            allocator.free(self.csrcs);
            self.* = undefined;
        }
    };

    pub const Packet = struct {
        header: Header,
        extension: ?Extension,
        payload: []const u8,
        padding_len: u8,

        pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!Packet {
            var header = try Header.parse(allocator, bytes);
            errdefer header.deinit(allocator);
            if (header.version != 2) return error.InvalidRtpPacket;

            var pos = header.payload_offset;
            var extension: ?Extension = null;
            if (header.extension) {
                if (bytes.len < pos + 4) return error.BufferTooShort;
                const profile = std.mem.readInt(u16, bytes[pos..][0..2], .big);
                const words = std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big);
                pos += 4;
                const ext_len = std.math.mul(usize, words, 4) catch return error.IntegerOverflow;
                if (bytes.len < pos + ext_len) return error.BufferTooShort;
                extension = .{ .profile = profile, .data = bytes[pos .. pos + ext_len] };
                pos += ext_len;
            }

            var payload_end = bytes.len;
            var padding_len: u8 = 0;
            if (header.padding) {
                if (bytes.len == pos) return error.InvalidRtpPacket;
                padding_len = bytes[bytes.len - 1];
                if (padding_len == 0 or padding_len > bytes.len - pos) return error.InvalidRtpPacket;
                payload_end -= padding_len;
            }

            return .{
                .header = header,
                .extension = extension,
                .payload = bytes[pos..payload_end],
                .padding_len = padding_len,
            };
        }

        pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
            self.header.deinit(allocator);
            self.* = undefined;
        }
    };

    pub const WriteOptions = struct {
        marker: bool = false,
        payload_type: u7,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        csrcs: []const u32 = &.{},
        extension: ?Extension = null,
        padding_len: u8 = 0,
    };

    pub fn writePacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: WriteOptions, payload: []const u8) Error!void {
        if (options.csrcs.len > 15) return error.InvalidRtpPacket;
        const has_padding = options.padding_len > 0;
        const has_extension = options.extension != null;
        const b0: u8 = 0x80 |
            (if (has_padding) @as(u8, 0x20) else 0) |
            (if (has_extension) @as(u8, 0x10) else 0) |
            @as(u8, @intCast(options.csrcs.len));
        const b1: u8 = (if (options.marker) @as(u8, 0x80) else 0) | @as(u8, options.payload_type);
        try list.append(allocator, b0);
        try list.append(allocator, b1);
        try wire.appendInt(list, allocator, u16, options.sequence_number, .big);
        try wire.appendInt(list, allocator, u32, options.timestamp, .big);
        try wire.appendInt(list, allocator, u32, options.ssrc, .big);
        for (options.csrcs) |csrc| try wire.appendInt(list, allocator, u32, csrc, .big);
        if (options.extension) |extension| {
            if (extension.data.len % 4 != 0) return error.InvalidRtpPacket;
            const extension_words = extension.data.len / 4;
            if (extension_words > std.math.maxInt(u16)) return error.InvalidRtpPacket;
            try wire.appendInt(list, allocator, u16, extension.profile, .big);
            try wire.appendInt(list, allocator, u16, @intCast(extension_words), .big);
            try list.appendSlice(allocator, extension.data);
        }
        try list.appendSlice(allocator, payload);
        if (options.padding_len > 0) {
            try list.appendNTimes(allocator, 0, options.padding_len - 1);
            try list.append(allocator, options.padding_len);
        }
    }

    fn padHeaderExtensionData(list: *std.ArrayList(u8), allocator: std.mem.Allocator, start: usize) Error!void {
        const len = list.items.len - start;
        try list.appendNTimes(allocator, 0, (4 - (len % 4)) % 4);
    }
};

pub const srtp = struct {
    pub const auth_tag_len_80: usize = 10;
    pub const hmac_sha1_len: usize = 20;
    pub const default_replay_window_size: u7 = 64;

    pub const ProtectionProfile = enum {
        /// RFC 3711 NULL cipher with HMAC-SHA1-80 authentication.  This is not
        /// the default profile browsers negotiate today, but it is the smallest
        /// useful SRTP building block: RTP stays parseable while authentication,
        /// ROC handling, and replay protection are exercised exactly like a real
        /// SRTP session.  AEAD profiles can layer on the same context/replay
        /// model once AES-GCM record protection is added.
        null_hmac_sha1_80,
    };

    pub const KeyingMaterial = struct {
        auth_key: []const u8,
        salt: []const u8 = &.{},
    };

    pub const RolloverCounter = struct {
        roc: u32 = 0,
        highest_seq: ?u16 = null,

        pub fn estimate(self: RolloverCounter, sequence_number: u16) u32 {
            const highest = self.highest_seq orelse return self.roc;
            if (highest < 0x8000) {
                if (sequence_number > highest and sequence_number - highest > 0x8000) {
                    return if (self.roc == 0) 0 else self.roc - 1;
                }
                return self.roc;
            }
            if (highest > sequence_number and highest - sequence_number > 0x8000) return self.roc +% 1;
            return self.roc;
        }

        pub fn update(self: *RolloverCounter, sequence_number: u16, estimated_roc: u32) void {
            const highest = self.highest_seq orelse {
                self.highest_seq = sequence_number;
                self.roc = estimated_roc;
                return;
            };
            if (estimated_roc > self.roc) {
                self.roc = estimated_roc;
                self.highest_seq = sequence_number;
                return;
            }
            if (estimated_roc == self.roc and rtpSeqNewer(sequence_number, highest)) {
                self.highest_seq = sequence_number;
            }
        }
    };

    pub const ReplayWindow = struct {
        max_index: ?u64 = null,
        bitmap: u64 = 0,
        window_size: u7 = default_replay_window_size,

        pub fn accept(self: *ReplayWindow, packet_index: u64) Error!void {
            // RFC 3711 replay protection is a sliding packet-index window.  A
            // u64 bitmap keeps this allocation-free for the common WebRTC
            // windows (Pion/webrtc-go defaults are also small fixed windows);
            // clamp oversized caller input so shift counts always stay valid.
            const window_size = @min(@as(u7, 64), @max(@as(u7, 1), self.window_size));
            const max_index = self.max_index orelse {
                self.max_index = packet_index;
                self.bitmap = 1;
                return;
            };
            if (packet_index > max_index) {
                const shift = @min(packet_index - max_index, 64);
                self.bitmap = if (shift >= 64) 0 else self.bitmap << @intCast(shift);
                self.bitmap |= 1;
                self.max_index = packet_index;
                return;
            }

            const delta = max_index - packet_index;
            if (delta >= window_size) return error.SrtpReplay;
            const mask = @as(u64, 1) << @intCast(delta);
            if ((self.bitmap & mask) != 0) return error.SrtpReplay;
            self.bitmap |= mask;
        }
    };

    pub const Context = struct {
        profile: ProtectionProfile = .null_hmac_sha1_80,
        keys: KeyingMaterial,
        rollover: RolloverCounter = .{},
        replay: ReplayWindow = .{},
        srtcp_send_index: u31 = 0,
        srtcp_replay: ReplayWindow = .{},

        pub fn protectRtp(self: *Context, list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet: []const u8) Error!void {
            const sequence_number = try rtpSequenceNumber(packet);
            const roc = self.rollover.estimate(sequence_number);
            try list.appendSlice(allocator, packet);
            try appendAuthTag(list, allocator, self.keys.auth_key, packet, roc);
            self.rollover.update(sequence_number, roc);
        }

        pub fn protectRtpPacket(self: *Context, list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: rtp.WriteOptions, payload: []const u8) Error!void {
            var packet: std.ArrayList(u8) = .empty;
            defer packet.deinit(allocator);
            try rtp.writePacket(&packet, allocator, options, payload);
            try self.protectRtp(list, allocator, packet.items);
        }

        pub fn verifyRtp(self: *Context, protected_packet: []const u8) Error!VerifiedRtp {
            if (protected_packet.len <= auth_tag_len_80) return error.InvalidSrtpPacket;
            const packet = protected_packet[0 .. protected_packet.len - auth_tag_len_80];
            const tag = protected_packet[protected_packet.len - auth_tag_len_80 ..];
            const sequence_number = try rtpSequenceNumber(packet);
            const roc = self.rollover.estimate(sequence_number);
            var expected: [auth_tag_len_80]u8 = undefined;
            authTag(&expected, self.keys.auth_key, packet, roc);
            if (!std.crypto.timing_safe.eql([auth_tag_len_80]u8, expected, tag[0..auth_tag_len_80].*)) return error.BadSrtpAuthTag;
            const index = packetIndex(roc, sequence_number);
            try self.replay.accept(index);
            self.rollover.update(sequence_number, roc);
            return .{ .packet = packet, .roc = roc, .packet_index = index };
        }

        pub fn unprotectRtp(self: *Context, allocator: std.mem.Allocator, protected_packet: []const u8) Error!AuthenticatedRtp {
            const verified = try self.verifyRtp(protected_packet);
            var packet = try rtp.Packet.parse(allocator, verified.packet);
            errdefer packet.deinit(allocator);
            return .{ .verified = verified, .rtp = packet };
        }

        pub fn protectRtcp(self: *Context, list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet: []const u8) Error!void {
            if (packet.len < 8 or (packet[0] & 0xc0) != 0x80) return error.InvalidSrtpPacket;
            try list.appendSlice(allocator, packet);
            const index = self.srtcp_send_index;
            self.srtcp_send_index +%= 1;
            try wire.appendInt(list, allocator, u32, index, .big);
            try appendRtcpAuthTag(list, allocator, self.keys.auth_key, packet, index);
        }

        pub fn protectRtcpPacket(self: *Context, list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet: rtcp.Packet) Error!void {
            var raw: std.ArrayList(u8) = .empty;
            defer raw.deinit(allocator);
            try rtcp.writePacket(&raw, allocator, packet);
            try self.protectRtcp(list, allocator, raw.items);
        }

        pub fn protectRtcpCompound(self: *Context, list: *std.ArrayList(u8), allocator: std.mem.Allocator, packets: []const rtcp.Packet) Error!void {
            var raw: std.ArrayList(u8) = .empty;
            defer raw.deinit(allocator);
            try rtcp.writeCompound(&raw, allocator, packets);
            try self.protectRtcp(list, allocator, raw.items);
        }

        pub fn protectRtcpPackets(self: *Context, list: *std.ArrayList(u8), allocator: std.mem.Allocator, packets: []const rtcp.Packet) Error!void {
            var raw: std.ArrayList(u8) = .empty;
            defer raw.deinit(allocator);
            try rtcp.writePackets(&raw, allocator, packets);
            try self.protectRtcp(list, allocator, raw.items);
        }

        pub fn verifyRtcp(self: *Context, protected_packet: []const u8) Error!VerifiedRtcp {
            if (protected_packet.len <= 4 + auth_tag_len_80) return error.InvalidSrtpPacket;
            const auth_start = protected_packet.len - auth_tag_len_80;
            const index_start = auth_start - 4;
            const packet = protected_packet[0..index_start];
            const raw_index = std.mem.readInt(u32, protected_packet[index_start..auth_start][0..4], .big);
            const encrypted = (raw_index & 0x8000_0000) != 0;
            if (encrypted) return error.InvalidSrtpPacket;
            const index: u31 = @truncate(raw_index & 0x7fff_ffff);
            var expected: [auth_tag_len_80]u8 = undefined;
            rtcpAuthTag(&expected, self.keys.auth_key, packet, index);
            if (!std.crypto.timing_safe.eql([auth_tag_len_80]u8, expected, protected_packet[auth_start..][0..auth_tag_len_80].*)) return error.BadSrtpAuthTag;
            try self.srtcp_replay.accept(index);
            return .{ .packet = packet, .index = index, .encrypted = encrypted };
        }

        pub fn unprotectRtcp(self: *Context, allocator: std.mem.Allocator, protected_packet: []const u8) Error!AuthenticatedRtcp {
            const verified = try self.verifyRtcp(protected_packet);
            var parsed = try rtcp.parsePacket(allocator, verified.packet);
            errdefer parsed.deinit(allocator);
            return .{ .verified = verified, .rtcp = parsed.packet };
        }

        pub fn unprotectRtcpCompound(self: *Context, allocator: std.mem.Allocator, protected_packet: []const u8) Error!AuthenticatedRtcpCompound {
            const verified = try self.verifyRtcp(protected_packet);
            const packets = try rtcp.parseCompound(allocator, verified.packet);
            errdefer rtcp.freeCompound(allocator, packets);
            return .{ .verified = verified, .rtcp = packets };
        }

        pub fn unprotectRtcpPackets(self: *Context, allocator: std.mem.Allocator, protected_packet: []const u8) Error!AuthenticatedRtcpPackets {
            const verified = try self.verifyRtcp(protected_packet);
            const packets = try rtcp.parsePackets(allocator, verified.packet);
            errdefer rtcp.freePackets(allocator, packets);
            return .{ .verified = verified, .rtcp = packets };
        }
    };

    pub const VerifiedRtp = struct {
        packet: []const u8,
        roc: u32,
        packet_index: u64,
    };

    pub const AuthenticatedRtp = struct {
        verified: VerifiedRtp,
        rtp: rtp.Packet,

        pub fn deinit(self: *AuthenticatedRtp, allocator: std.mem.Allocator) void {
            self.rtp.deinit(allocator);
            self.* = undefined;
        }
    };

    pub const VerifiedRtcp = struct {
        packet: []const u8,
        index: u31,
        encrypted: bool = false,
    };

    pub const AuthenticatedRtcp = struct {
        verified: VerifiedRtcp,
        rtcp: rtcp.Packet,

        pub fn deinit(self: *AuthenticatedRtcp, allocator: std.mem.Allocator) void {
            self.rtcp.deinit(allocator);
            self.* = undefined;
        }
    };

    pub const AuthenticatedRtcpCompound = struct {
        verified: VerifiedRtcp,
        rtcp: []rtcp.Packet,

        pub fn deinit(self: *AuthenticatedRtcpCompound, allocator: std.mem.Allocator) void {
            rtcp.freeCompound(allocator, self.rtcp);
            self.* = undefined;
        }
    };

    pub const AuthenticatedRtcpPackets = struct {
        verified: VerifiedRtcp,
        rtcp: []rtcp.Packet,

        pub fn deinit(self: *AuthenticatedRtcpPackets, allocator: std.mem.Allocator) void {
            rtcp.freePackets(allocator, self.rtcp);
            self.* = undefined;
        }
    };

    pub fn packetIndex(roc: u32, sequence_number: u16) u64 {
        return (@as(u64, roc) << 16) | sequence_number;
    }

    pub fn authTag(out: *[auth_tag_len_80]u8, auth_key: []const u8, packet: []const u8, roc: u32) void {
        var roc_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &roc_bytes, roc, .big);
        var full: [hmac_sha1_len]u8 = undefined;
        var hmac = std.crypto.auth.hmac.HmacSha1.init(auth_key);
        hmac.update(packet);
        hmac.update(&roc_bytes);
        hmac.final(&full);
        @memcpy(out[0..], full[0..auth_tag_len_80]);
    }

    pub fn rtcpAuthTag(out: *[auth_tag_len_80]u8, auth_key: []const u8, packet: []const u8, index: u31) void {
        var index_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &index_bytes, index, .big);
        var full: [hmac_sha1_len]u8 = undefined;
        var hmac = std.crypto.auth.hmac.HmacSha1.init(auth_key);
        hmac.update(packet);
        hmac.update(&index_bytes);
        hmac.final(&full);
        @memcpy(out[0..], full[0..auth_tag_len_80]);
    }

    fn appendAuthTag(list: *std.ArrayList(u8), allocator: std.mem.Allocator, auth_key: []const u8, packet: []const u8, roc: u32) Error!void {
        var tag: [auth_tag_len_80]u8 = undefined;
        authTag(&tag, auth_key, packet, roc);
        try list.appendSlice(allocator, &tag);
    }

    fn appendRtcpAuthTag(list: *std.ArrayList(u8), allocator: std.mem.Allocator, auth_key: []const u8, packet: []const u8, index: u31) Error!void {
        var tag: [auth_tag_len_80]u8 = undefined;
        rtcpAuthTag(&tag, auth_key, packet, index);
        try list.appendSlice(allocator, &tag);
    }

    fn rtpSequenceNumber(packet: []const u8) Error!u16 {
        if (packet.len < 12 or (packet[0] & 0xc0) != 0x80) return error.InvalidSrtpPacket;
        return std.mem.readInt(u16, packet[2..4], .big);
    }

    fn rtpSeqNewer(a: u16, b: u16) bool {
        return a != b and ((a -% b) < 0x8000);
    }
};

pub const rtcp = struct {
    pub const PacketType = enum(u8) {
        sender_report = 200,
        receiver_report = 201,
        source_description = 202,
        goodbye = 203,
        application_defined = 204,
        transport_feedback = 205,
        payload_feedback = 206,
        extended_report = 207,
        _,
    };

    pub const transport_feedback_nack: u5 = 1;
    pub const transport_feedback_sli: u5 = 2;
    pub const transport_feedback_rrr: u5 = 5;
    pub const transport_feedback_ccfb: u5 = 11;
    pub const transport_feedback_twcc: u5 = 15;
    pub const payload_feedback_pli: u5 = 1;
    pub const payload_feedback_sli: u5 = 2;
    pub const payload_feedback_fir: u5 = 4;
    pub const payload_feedback_remb: u5 = 15;
    pub const compact_ntp_units_per_second: u64 = 65_536;
    const max_rtcp_payload_len: usize = @as(usize, std.math.maxInt(u16)) * 4;

    pub const Header = struct {
        version: u2,
        padding: bool,
        count_or_format: u5,
        packet_type: PacketType,
        length_words_minus_one: u16,

        pub fn parse(bytes: []const u8) Error!Header {
            if (bytes.len < 4) return error.BufferTooShort;
            const first = bytes[0];
            const version: u2 = @truncate(first >> 6);
            if (version != 2) return error.InvalidRtcpPacket;
            return .{
                .version = version,
                .padding = (first & 0x20) != 0,
                .count_or_format = @truncate(first & 0x1f),
                .packet_type = @enumFromInt(bytes[1]),
                .length_words_minus_one = std.mem.readInt(u16, bytes[2..4], .big),
            };
        }

        pub fn packetLen(self: Header) usize {
            return (@as(usize, self.length_words_minus_one) + 1) * 4;
        }
    };

    pub const ReportBlock = struct {
        ssrc: u32,
        fraction_lost: u8 = 0,
        cumulative_lost: u24 = 0,
        highest_sequence_number: u32 = 0,
        interarrival_jitter: u32 = 0,
        last_sender_report: u32 = 0,
        delay_since_last_sender_report: u32 = 0,

        pub fn roundTripDelay65536(self: ReportBlock, now_compact_ntp: u32) ?u32 {
            return roundTripDelayFromCompact(self.last_sender_report, self.delay_since_last_sender_report, now_compact_ntp);
        }

        pub fn roundTripDelayNanos(self: ReportBlock, now_compact_ntp: u32) ?u64 {
            const delay = self.roundTripDelay65536(now_compact_ntp) orelse return null;
            return compactNtpDelayToNanos(delay);
        }

        pub fn cumulativeLostSigned(self: ReportBlock) i32 {
            return decodeCumulativeLost(self.cumulative_lost);
        }

        pub fn setCumulativeLostSigned(self: *ReportBlock, lost: i32) Error!void {
            self.cumulative_lost = try encodeCumulativeLost(lost);
        }

        pub fn wireLen(_: ReportBlock) usize {
            return 24;
        }
    };

    pub const SenderReport = struct {
        sender_ssrc: u32,
        ntp_timestamp_msw: u32,
        ntp_timestamp_lsw: u32,
        rtp_timestamp: u32,
        sender_packet_count: u32,
        sender_octet_count: u32,
        report_blocks: []ReportBlock = &.{},
        profile_extensions: []const u8 = &.{},

        pub fn wireLen(self: SenderReport) usize {
            return 4 + 24 + self.report_blocks.len * 24 + std.mem.alignForward(usize, self.profile_extensions.len, 4);
        }
    };

    pub const ReceiverReport = struct {
        sender_ssrc: u32,
        report_blocks: []ReportBlock = &.{},
        profile_extensions: []const u8 = &.{},

        pub fn wireLen(self: ReceiverReport) usize {
            return 4 + 4 + self.report_blocks.len * 24 + std.mem.alignForward(usize, self.profile_extensions.len, 4);
        }
    };

    pub const ReceiverEstimatedMaximumBitrate = struct {
        sender_ssrc: u32,
        bitrate: u64,
        ssrcs: []const u32 = &.{},

        pub fn wireLen(self: ReceiverEstimatedMaximumBitrate) usize {
            return 20 + self.ssrcs.len * 4;
        }

        pub fn deinit(self: *ReceiverEstimatedMaximumBitrate, allocator: std.mem.Allocator) void {
            allocator.free(@constCast(self.ssrcs));
            self.* = undefined;
        }
    };

    pub const ApplicationDefined = struct {
        subtype: u5 = 0,
        ssrc: u32,
        name: [4]u8,
        data: []const u8 = &.{},

        pub fn wireLen(self: ApplicationDefined) usize {
            return 12 + std.mem.alignForward(usize, self.data.len, 4);
        }

        pub fn deinit(self: *ApplicationDefined, allocator: std.mem.Allocator) void {
            allocator.free(@constCast(self.data));
            self.* = undefined;
        }
    };

    pub const Goodbye = struct {
        sources: []u32 = &.{},
        reason: []const u8 = &.{},

        pub fn wireLen(self: Goodbye) usize {
            const reason_len = if (self.reason.len == 0) 0 else 1 + self.reason.len;
            return std.mem.alignForward(usize, 4 + self.sources.len * 4 + reason_len, 4);
        }

        pub fn deinit(self: *Goodbye, allocator: std.mem.Allocator) void {
            allocator.free(self.sources);
            self.* = undefined;
        }
    };

    pub const SdesItemType = enum(u8) {
        end = 0,
        cname = 1,
        name = 2,
        email = 3,
        phone = 4,
        location = 5,
        tool = 6,
        note = 7,
        private = 8,
        _,
    };

    pub const SdesItem = struct {
        item_type: SdesItemType,
        value: []const u8,

        pub fn wireLen(self: SdesItem) usize {
            return if (self.item_type == .end) 1 else 2 + self.value.len;
        }
    };

    pub const SdesChunk = struct {
        ssrc: u32,
        items: []SdesItem,

        pub fn wireLen(self: SdesChunk) usize {
            var len: usize = 4;
            for (self.items) |item| len += item.wireLen();
            len += 1; // END item.
            return std.mem.alignForward(usize, len, 4);
        }
    };

    pub const SourceDescription = struct {
        chunks: []SdesChunk,

        pub fn wireLen(self: SourceDescription) usize {
            var len: usize = 4;
            for (self.chunks) |chunk| len += chunk.wireLen();
            return len;
        }

        pub fn deinit(self: *SourceDescription, allocator: std.mem.Allocator) void {
            for (self.chunks) |chunk| allocator.free(chunk.items);
            allocator.free(self.chunks);
            self.* = undefined;
        }

        pub fn cname(self: SourceDescription, ssrc: u32) ?[]const u8 {
            for (self.chunks) |chunk| {
                if (chunk.ssrc != ssrc) continue;
                for (chunk.items) |item| {
                    if (item.item_type == .cname) return item.value;
                }
            }
            return null;
        }
    };

    pub const PictureLossIndication = struct {
        sender_ssrc: u32,
        media_ssrc: u32,

        pub fn wireLen(_: PictureLossIndication) usize {
            return 12;
        }
    };

    pub const SliEntry = struct {
        first: u16,
        number: u16,
        picture: u8,
    };

    pub const SliceLossIndication = struct {
        sender_ssrc: u32,
        media_ssrc: u32,
        entries: []SliEntry,

        pub fn wireLen(self: SliceLossIndication) usize {
            return 12 + self.entries.len * 4;
        }

        pub fn deinit(self: *SliceLossIndication, allocator: std.mem.Allocator) void {
            allocator.free(self.entries);
            self.* = undefined;
        }
    };

    pub const FirEntry = struct {
        ssrc: u32,
        sequence_number: u8,
    };

    pub const FullIntraRequest = struct {
        sender_ssrc: u32,
        media_ssrc: u32 = 0,
        entries: []FirEntry,

        pub fn wireLen(self: FullIntraRequest) usize {
            return 12 + self.entries.len * 8;
        }

        pub fn deinit(self: *FullIntraRequest, allocator: std.mem.Allocator) void {
            allocator.free(self.entries);
            self.* = undefined;
        }
    };

    pub const RapidResynchronizationRequest = struct {
        sender_ssrc: u32,
        media_ssrc: u32,

        pub fn wireLen(_: RapidResynchronizationRequest) usize {
            return 12;
        }
    };

    pub const Ecn = enum(u2) {
        non_ect = 0,
        ect1 = 1,
        ect0 = 2,
        ce = 3,
    };

    pub const CcFeedbackMetricBlock = struct {
        received: bool = false,
        ecn: Ecn = .non_ect,
        /// Offset in 1/1024-second units before the report timestamp.
        arrival_time_offset: u16 = 0,

        pub fn arrivalOffsetMicros(self: CcFeedbackMetricBlock) ?u64 {
            if (!self.received) return null;
            return ccFeedbackArrivalOffsetToMicros(self.arrival_time_offset);
        }

        pub fn arrivalTimeMicros(self: CcFeedbackMetricBlock, report_timestamp: u32) ?u64 {
            const offset_micros = self.arrivalOffsetMicros() orelse return null;
            return ccFeedbackReportTimestampToMicros(report_timestamp) -| offset_micros;
        }
    };

    pub const CcFeedbackReportBlock = struct {
        media_ssrc: u32,
        begin_sequence: u16 = 0,
        metric_blocks: []CcFeedbackMetricBlock = &.{},

        pub fn metricForSequence(self: CcFeedbackReportBlock, sequence_number: u16) ?CcFeedbackMetricBlock {
            const delta = sequence_number -% self.begin_sequence;
            if (delta >= self.metric_blocks.len) return null;
            return self.metric_blocks[delta];
        }

        pub fn arrivalOffsetMicrosForSequence(self: CcFeedbackReportBlock, sequence_number: u16) ?u64 {
            const metric = self.metricForSequence(sequence_number) orelse return null;
            return metric.arrivalOffsetMicros();
        }

        pub fn arrivalTimeMicrosForSequence(self: CcFeedbackReportBlock, report_timestamp: u32, sequence_number: u16) ?u64 {
            const metric = self.metricForSequence(sequence_number) orelse return null;
            return metric.arrivalTimeMicros(report_timestamp);
        }

        pub fn wireLen(self: CcFeedbackReportBlock) usize {
            return 8 + std.mem.alignForward(usize, self.metric_blocks.len * 2, 4);
        }

        pub fn deinit(self: *CcFeedbackReportBlock, allocator: std.mem.Allocator) void {
            allocator.free(self.metric_blocks);
            self.* = undefined;
        }
    };

    pub const CongestionControlFeedback = struct {
        sender_ssrc: u32,
        report_blocks: []CcFeedbackReportBlock = &.{},
        report_timestamp: u32,

        pub fn deinit(self: *CongestionControlFeedback, allocator: std.mem.Allocator) void {
            for (self.report_blocks) |*block| block.deinit(allocator);
            allocator.free(self.report_blocks);
            self.* = undefined;
        }

        pub fn metricForMediaSequence(self: CongestionControlFeedback, media_ssrc: u32, sequence_number: u16) ?CcFeedbackMetricBlock {
            for (self.report_blocks) |block| {
                if (block.media_ssrc == media_ssrc) return block.metricForSequence(sequence_number);
            }
            return null;
        }

        pub fn arrivalOffsetMicrosForMediaSequence(self: CongestionControlFeedback, media_ssrc: u32, sequence_number: u16) ?u64 {
            const metric = self.metricForMediaSequence(media_ssrc, sequence_number) orelse return null;
            return metric.arrivalOffsetMicros();
        }

        pub fn reportTimestampMicros(self: CongestionControlFeedback) u64 {
            return ccFeedbackReportTimestampToMicros(self.report_timestamp);
        }

        pub fn arrivalTimeMicrosForMediaSequence(self: CongestionControlFeedback, media_ssrc: u32, sequence_number: u16) ?u64 {
            const metric = self.metricForMediaSequence(media_ssrc, sequence_number) orelse return null;
            return metric.arrivalTimeMicros(self.report_timestamp);
        }

        pub fn wirePayloadLen(self: CongestionControlFeedback) usize {
            var len: usize = 4 + 4; // Sender SSRC + trailing Report Timestamp.
            for (self.report_blocks) |block| len += block.wireLen();
            return len;
        }
    };

    pub const cc_feedback_arrival_offset_units_per_second: u64 = 1024;

    pub fn ccFeedbackArrivalOffsetToMicros(offset: u16) u64 {
        return (@as(u64, offset & 0x1fff) * std.time.us_per_s) / cc_feedback_arrival_offset_units_per_second;
    }

    pub fn ccFeedbackReportTimestampToMicros(report_timestamp: u32) u64 {
        return (@as(u64, report_timestamp) * std.time.us_per_s) / cc_feedback_arrival_offset_units_per_second;
    }

    pub const XrBlockType = enum(u8) {
        loss_rle = 1,
        duplicate_rle = 2,
        packet_receipt_times = 3,
        receiver_reference_time = 4,
        dlrr = 5,
        statistics_summary = 6,
        voip_metrics = 7,
        _,
    };

    pub const XrHeader = struct {
        block_type: XrBlockType,
        type_specific: u8 = 0,
        block_length_words: u16 = 0,
    };

    pub const XrChunk = u16;

    pub const XrChunkType = enum {
        run_length,
        bit_vector,
        terminating_null,
    };

    pub fn xrChunkType(chunk: XrChunk) XrChunkType {
        if (chunk == 0) return .terminating_null;
        return if ((chunk & 0x8000) == 0) .run_length else .bit_vector;
    }

    pub fn xrChunkRunType(chunk: XrChunk) Error!u1 {
        if (xrChunkType(chunk) != .run_length) return error.InvalidRtcpPacket;
        return @truncate((chunk >> 14) & 0x01);
    }

    pub fn xrChunkValue(chunk: XrChunk) u15 {
        return switch (xrChunkType(chunk)) {
            .run_length => @truncate(chunk & 0x3fff),
            .bit_vector => @truncate(chunk & 0x7fff),
            .terminating_null => 0,
        };
    }

    pub fn xrRunLengthChunk(run_type: u1, length: u14) XrChunk {
        return (@as(u16, run_type) << 14) | length;
    }

    pub fn xrBitVectorChunk(bits: u15) XrChunk {
        return 0x8000 | @as(u16, bits);
    }

    pub fn xrTerminatingNullChunk() XrChunk {
        return 0;
    }

    pub const RleReportBlock = struct {
        thinning: u4 = 0,
        ssrc: u32,
        begin_sequence: u16,
        end_sequence: u16,
        chunks: []XrChunk = &.{},

        pub fn wireLen(self: RleReportBlock) usize {
            return 4 + 8 + self.chunks.len * 2;
        }

        pub fn deinit(self: *RleReportBlock, allocator: std.mem.Allocator) void {
            allocator.free(self.chunks);
            self.* = undefined;
        }
    };

    pub const PacketReceiptTimesReportBlock = struct {
        thinning: u4 = 0,
        ssrc: u32,
        begin_sequence: u16,
        end_sequence: u16,
        receipt_times: []u32 = &.{},

        pub fn wireLen(self: PacketReceiptTimesReportBlock) usize {
            return 4 + 8 + self.receipt_times.len * 4;
        }

        pub fn deinit(self: *PacketReceiptTimesReportBlock, allocator: std.mem.Allocator) void {
            allocator.free(self.receipt_times);
            self.* = undefined;
        }
    };

    pub const TtlOrHopLimit = enum(u2) {
        missing = 0,
        ipv4 = 1,
        ipv6 = 2,
        reserved = 3,
    };

    pub const StatisticsSummaryReportBlock = struct {
        loss_reports: bool = false,
        duplicate_reports: bool = false,
        jitter_reports: bool = false,
        ttl_or_hop_limit: TtlOrHopLimit = .missing,
        ssrc: u32,
        begin_sequence: u16,
        end_sequence: u16,
        lost_packets: u32 = 0,
        duplicate_packets: u32 = 0,
        min_jitter: u32 = 0,
        max_jitter: u32 = 0,
        mean_jitter: u32 = 0,
        dev_jitter: u32 = 0,
        min_ttl_or_hop_limit: u8 = 0,
        max_ttl_or_hop_limit: u8 = 0,
        mean_ttl_or_hop_limit: u8 = 0,
        dev_ttl_or_hop_limit: u8 = 0,
    };

    pub const VoipMetricsReportBlock = struct {
        ssrc: u32,
        loss_rate: u8 = 0,
        discard_rate: u8 = 0,
        burst_density: u8 = 0,
        gap_density: u8 = 0,
        burst_duration: u16 = 0,
        gap_duration: u16 = 0,
        round_trip_delay: u16 = 0,
        end_system_delay: u16 = 0,
        signal_level: u8 = 0,
        noise_level: u8 = 0,
        rerl: u8 = 0,
        gmin: u8 = 0,
        r_factor: u8 = 0,
        ext_r_factor: u8 = 0,
        mos_lq: u8 = 0,
        mos_cq: u8 = 0,
        rx_config: u8 = 0,
        jb_nominal: u16 = 0,
        jb_maximum: u16 = 0,
        jb_abs_max: u16 = 0,
    };

    pub const DlrrReport = struct {
        ssrc: u32,
        last_rr: u32,
        dlrr: u32,

        pub fn roundTripDelay65536(self: DlrrReport, now_compact_ntp: u32) ?u32 {
            return roundTripDelayFromCompact(self.last_rr, self.dlrr, now_compact_ntp);
        }

        pub fn roundTripDelayNanos(self: DlrrReport, now_compact_ntp: u32) ?u64 {
            const delay = self.roundTripDelay65536(now_compact_ntp) orelse return null;
            return compactNtpDelayToNanos(delay);
        }
    };

    pub const DlrrReportBlock = struct {
        reports: []DlrrReport,

        pub fn wireLen(self: DlrrReportBlock) usize {
            return 4 + self.reports.len * 12;
        }

        pub fn deinit(self: *DlrrReportBlock, allocator: std.mem.Allocator) void {
            allocator.free(self.reports);
            self.* = undefined;
        }
    };

    pub const UnknownXrBlock = struct {
        header: XrHeader,
        payload: []const u8,

        pub fn wireLen(self: UnknownXrBlock) usize {
            return 4 + self.payload.len;
        }

        pub fn deinit(self: *UnknownXrBlock, allocator: std.mem.Allocator) void {
            allocator.free(@constCast(self.payload));
            self.* = undefined;
        }
    };

    pub const XrBlock = union(enum) {
        loss_rle: RleReportBlock,
        duplicate_rle: RleReportBlock,
        packet_receipt_times: PacketReceiptTimesReportBlock,
        receiver_reference_time: u64,
        dlrr: DlrrReportBlock,
        statistics_summary: StatisticsSummaryReportBlock,
        voip_metrics: VoipMetricsReportBlock,
        unknown: UnknownXrBlock,

        pub fn deinit(self: *XrBlock, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .loss_rle => |*rle| rle.deinit(allocator),
                .duplicate_rle => |*rle| rle.deinit(allocator),
                .packet_receipt_times => |*receipt| receipt.deinit(allocator),
                .dlrr => |*dlrr| dlrr.deinit(allocator),
                .unknown => |*unknown| unknown.deinit(allocator),
                else => {},
            }
            self.* = undefined;
        }

        pub fn wireLen(self: XrBlock) usize {
            return switch (self) {
                .loss_rle => |rle| rle.wireLen(),
                .duplicate_rle => |rle| rle.wireLen(),
                .packet_receipt_times => |receipt| receipt.wireLen(),
                .receiver_reference_time => 12,
                .dlrr => |dlrr| dlrr.wireLen(),
                .statistics_summary => 40,
                .voip_metrics => 36,
                .unknown => |unknown| unknown.wireLen(),
            };
        }
    };

    pub const ExtendedReport = struct {
        sender_ssrc: u32,
        blocks: []XrBlock = &.{},

        pub fn wireLen(self: ExtendedReport) usize {
            var len: usize = 8; // RTCP header + sender SSRC.
            for (self.blocks) |block| len += block.wireLen();
            return len;
        }

        pub fn deinit(self: *ExtendedReport, allocator: std.mem.Allocator) void {
            for (self.blocks) |*block| block.deinit(allocator);
            allocator.free(self.blocks);
            self.* = undefined;
        }
    };

    pub const NackPair = struct {
        packet_id: u16,
        lost_packet_bitmask: u16 = 0,

        pub fn contains(self: NackPair, sequence_number: u16) bool {
            if (sequence_number == self.packet_id) return true;
            const delta = sequence_number -% self.packet_id;
            if (delta == 0 or delta > 16) return false;
            return ((self.lost_packet_bitmask >> @intCast(delta - 1)) & 1) != 0;
        }

        pub fn sequenceCount(self: NackPair) usize {
            return 1 + @popCount(self.lost_packet_bitmask);
        }

        pub fn appendSequences(self: NackPair, list: *std.ArrayList(u16), allocator: std.mem.Allocator) Error!void {
            try list.append(allocator, self.packet_id);
            var bitmask = self.lost_packet_bitmask;
            var delta: u16 = 1;
            while (bitmask != 0) : (delta += 1) {
                if ((bitmask & 1) != 0) try list.append(allocator, self.packet_id +% delta);
                bitmask >>= 1;
            }
        }

        pub fn range(self: NackPair, context: anytype, comptime callback: fn (@TypeOf(context), u16) bool) void {
            if (!callback(context, self.packet_id)) return;
            var bitmask = self.lost_packet_bitmask;
            var delta: u16 = 1;
            while (bitmask != 0) : (delta += 1) {
                if ((bitmask & 1) != 0) {
                    if (!callback(context, self.packet_id +% delta)) return;
                }
                bitmask >>= 1;
            }
        }

        pub fn packetList(self: NackPair, out: []u16) Error![]u16 {
            if (out.len < self.sequenceCount()) return error.BufferTooShort;
            var count: usize = 0;
            const Collector = struct {
                out: []u16,
                count: *usize,

                fn append(collector: @This(), sequence_number: u16) bool {
                    collector.out[collector.count.*] = sequence_number;
                    collector.count.* += 1;
                    return true;
                }
            };
            self.range(Collector{ .out = out, .count = &count }, Collector.append);
            return out[0..count];
        }
    };

    pub fn nackPairsFromSequenceNumbers(allocator: std.mem.Allocator, sequence_numbers: []const u16) Error![]NackPair {
        if (sequence_numbers.len == 0) return allocator.alloc(NackPair, 0);
        var pairs: std.ArrayList(NackPair) = .empty;
        errdefer pairs.deinit(allocator);

        var pair = NackPair{ .packet_id = sequence_numbers[0] };
        for (sequence_numbers[1..]) |sequence_number| {
            const delta = sequence_number -% pair.packet_id;
            if (delta == 0) continue;
            if (delta > 16) {
                try pairs.append(allocator, pair);
                pair = .{ .packet_id = sequence_number };
                continue;
            }
            pair.lost_packet_bitmask |= @as(u16, 1) << @intCast(delta - 1);
        }
        try pairs.append(allocator, pair);
        return pairs.toOwnedSlice(allocator);
    }

    pub fn nackSequenceNumbers(allocator: std.mem.Allocator, pairs: []const NackPair) Error![]u16 {
        var sequence_numbers: std.ArrayList(u16) = .empty;
        errdefer sequence_numbers.deinit(allocator);
        for (pairs) |pair| try pair.appendSequences(&sequence_numbers, allocator);
        return sequence_numbers.toOwnedSlice(allocator);
    }

    pub const TransportLayerNack = struct {
        sender_ssrc: u32,
        media_ssrc: u32,
        pairs: []NackPair,

        pub fn wireLen(self: TransportLayerNack) usize {
            return 12 + self.pairs.len * 4;
        }
    };

    pub const TwccPacketStatus = enum(u2) {
        not_received = 0,
        small_delta = 1,
        large_delta = 2,
        received_without_delta = 3,
    };

    pub const TwccPacketResult = struct {
        status: TwccPacketStatus,
        /// Raw delta units from the transport-cc wire format. One tick is
        /// 250 microseconds; keeping the raw tick preserves exact round-trips
        /// and lets congestion controllers choose their own time type.
        delta_ticks: i16 = 0,

        pub fn received(self: TwccPacketResult) bool {
            return self.status == .small_delta or self.status == .large_delta or self.status == .received_without_delta;
        }

        pub fn deltaMicros(self: TwccPacketResult) i32 {
            return twccDeltaTicksToMicros(self.delta_ticks);
        }
    };

    pub const twcc_delta_tick_micros: i32 = 250;
    pub const twcc_reference_time_unit_micros: u64 = 64 * 1000;
    pub const twcc_small_delta_max_micros: i32 = @as(i32, std.math.maxInt(u8)) * twcc_delta_tick_micros;
    pub const twcc_large_delta_min_micros: i32 = @as(i32, std.math.minInt(i16)) * twcc_delta_tick_micros;
    pub const twcc_large_delta_max_micros: i32 = @as(i32, std.math.maxInt(i16)) * twcc_delta_tick_micros;

    pub fn twccDeltaTicksToMicros(delta_ticks: i16) i32 {
        return @as(i32, delta_ticks) * twcc_delta_tick_micros;
    }

    pub fn twccSmallDeltaFromMicros(delta_micros: i32) Error!u8 {
        // Match Pion/rtcp's RecvDelta.Marshal quantization: convert
        // microseconds to 250us wire ticks with truncation toward zero, then
        // validate the encoded tick range.
        const ticks = @divTrunc(delta_micros, twcc_delta_tick_micros);
        if (ticks < 0 or ticks > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
        return @intCast(ticks);
    }

    pub fn twccLargeDeltaFromMicros(delta_micros: i32) Error!i16 {
        const ticks = @divTrunc(delta_micros, twcc_delta_tick_micros);
        if (ticks < std.math.minInt(i16) or ticks > std.math.maxInt(i16)) return error.InvalidRtcpPacket;
        return @intCast(ticks);
    }

    pub fn twccReferenceTimeFromUnixMicros(unix_time_micros: u64) u24 {
        return @truncate(unix_time_micros / twcc_reference_time_unit_micros);
    }

    pub fn twccReferenceTimeToMicros(reference_time_64ms: u24) u64 {
        return @as(u64, reference_time_64ms) * twcc_reference_time_unit_micros;
    }

    pub const TransportWideCc = struct {
        sender_ssrc: u32,
        media_ssrc: u32,
        base_sequence_number: u16,
        reference_time_64ms: u24,
        feedback_packet_count: u8,
        packets: []TwccPacketResult,

        pub fn packetForSequence(self: TransportWideCc, sequence_number: u16) ?TwccPacketResult {
            const delta = sequence_number -% self.base_sequence_number;
            if (delta >= self.packets.len) return null;
            return self.packets[delta];
        }

        pub fn referenceTimeMicros(self: TransportWideCc) u64 {
            return twccReferenceTimeToMicros(self.reference_time_64ms);
        }

        pub fn arrivalTimeMicrosForIndex(self: TransportWideCc, packet_index: usize) ?u64 {
            if (packet_index >= self.packets.len) return null;
            if (self.packets[packet_index].status == .not_received or self.packets[packet_index].status == .received_without_delta) return null;
            var arrival_micros = self.referenceTimeMicros();
            for (self.packets[0 .. packet_index + 1]) |packet| {
                switch (packet.status) {
                    .small_delta, .large_delta => {
                        const delta_micros = packet.deltaMicros();
                        if (delta_micros >= 0) {
                            arrival_micros +|= @intCast(delta_micros);
                        } else {
                            arrival_micros -|= @intCast(-delta_micros);
                        }
                    },
                    .received_without_delta => return null,
                    .not_received => {},
                }
            }
            return arrival_micros;
        }

        pub fn arrivalTimeMicrosForSequence(self: TransportWideCc, sequence_number: u16) ?u64 {
            const delta = sequence_number -% self.base_sequence_number;
            if (delta >= self.packets.len) return null;
            return self.arrivalTimeMicrosForIndex(delta);
        }

        pub fn wireLen(self: TransportWideCc) Error!usize {
            if (self.packets.len > std.math.maxInt(u16)) return error.InvalidRtcpPacket;
            var payload_len: usize = 16 + twccPacketStatusChunksWireLen(self.packets);
            for (self.packets) |packet| {
                switch (packet.status) {
                    .not_received, .received_without_delta => {},
                    .small_delta => {
                        if (packet.delta_ticks < 0 or packet.delta_ticks > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
                        payload_len += 1;
                    },
                    .large_delta => payload_len += 2,
                }
            }
            payload_len = std.mem.alignForward(usize, payload_len, 4);
            return 4 + payload_len;
        }

        pub fn deinit(self: *TransportWideCc, allocator: std.mem.Allocator) void {
            allocator.free(self.packets);
            self.* = undefined;
        }
    };

    pub const TwccPacketStatusChunk = u16;

    pub const TwccChunkType = enum {
        run_length,
        status_vector,
    };

    pub const TwccSymbolSize = enum(u1) {
        one_bit = 0,
        two_bit = 1,
    };

    pub fn twccChunkType(chunk: TwccPacketStatusChunk) TwccChunkType {
        return if ((chunk & 0x8000) == 0) .run_length else .status_vector;
    }

    pub fn twccRunStatus(chunk: TwccPacketStatusChunk) Error!TwccPacketStatus {
        if (twccChunkType(chunk) != .run_length) return error.InvalidRtcpPacket;
        return @enumFromInt((chunk >> 13) & 0x03);
    }

    pub fn twccRunLength(chunk: TwccPacketStatusChunk) Error!u13 {
        if (twccChunkType(chunk) != .run_length) return error.InvalidRtcpPacket;
        const run_len: u13 = @truncate(chunk & 0x1fff);
        if (run_len == 0) return error.InvalidRtcpPacket;
        return run_len;
    }

    pub fn twccRunLengthChunk(status: TwccPacketStatus, run_len: u13) Error!TwccPacketStatusChunk {
        if (run_len == 0) return error.InvalidRtcpPacket;
        return (@as(u16, @intFromEnum(status)) << 13) | @as(u16, run_len);
    }

    pub fn twccStatusVectorCapacity(symbol_size: TwccSymbolSize) usize {
        return switch (symbol_size) {
            .one_bit => 14,
            .two_bit => 7,
        };
    }

    pub fn twccStatusVectorSymbolSize(chunk: TwccPacketStatusChunk) Error!TwccSymbolSize {
        if (twccChunkType(chunk) != .status_vector) return error.InvalidRtcpPacket;
        return @enumFromInt(@as(u1, @truncate((chunk >> 14) & 0x01)));
    }

    pub fn twccStatusVectorSymbol(chunk: TwccPacketStatusChunk, index: usize) Error!TwccPacketStatus {
        const symbol_size = try twccStatusVectorSymbolSize(chunk);
        if (index >= twccStatusVectorCapacity(symbol_size)) return error.InvalidRtcpPacket;
        return switch (symbol_size) {
            .one_bit => blk: {
                const shift: u4 = @intCast(13 - index);
                const raw: u2 = @intCast((chunk >> shift) & 0x01);
                break :blk @enumFromInt(raw);
            },
            .two_bit => blk: {
                const shift: u4 = @intCast(12 - 2 * index);
                const raw: u2 = @intCast((chunk >> shift) & 0x03);
                break :blk @enumFromInt(raw);
            },
        };
    }

    pub fn twccStatusVectorChunk(symbol_size: TwccSymbolSize, statuses: []const TwccPacketStatus) Error!TwccPacketStatusChunk {
        if (statuses.len > twccStatusVectorCapacity(symbol_size)) return error.InvalidRtcpPacket;
        var chunk: u16 = 0x8000 | (@as(u16, @intFromEnum(symbol_size)) << 14);
        for (statuses, 0..) |status, i| {
            switch (symbol_size) {
                .one_bit => {
                    if (status != .not_received and status != .small_delta) return error.InvalidRtcpPacket;
                    const bit: u16 = if (status == .small_delta) 1 else 0;
                    const shift: u4 = @intCast(13 - i);
                    chunk |= bit << shift;
                },
                .two_bit => {
                    const shift: u4 = @intCast(12 - 2 * i);
                    chunk |= @as(u16, @intFromEnum(status)) << shift;
                },
            }
        }
        return chunk;
    }

    pub const SenderStats = struct {
        ssrc: u32 = 0,
        packet_count: u32 = 0,
        octet_count: u32 = 0,
        last_rtp_timestamp: u32 = 0,
        initialized: bool = false,

        pub fn observe(self: *SenderStats, packet: rtp.Packet) void {
            if (!self.initialized) {
                self.initialized = true;
                self.ssrc = packet.header.ssrc;
            }
            self.last_rtp_timestamp = packet.header.timestamp;
            self.packet_count +|= 1;
            self.octet_count +|= @intCast(@min(packet.payload.len, @as(usize, std.math.maxInt(u32))));
        }

        pub fn senderReport(self: SenderStats, now_ns: u64, report_blocks: []ReportBlock) SenderReport {
            const ntp = ntpTimestamp(now_ns);
            return .{
                .sender_ssrc = self.ssrc,
                .ntp_timestamp_msw = ntp.msw,
                .ntp_timestamp_lsw = ntp.lsw,
                .rtp_timestamp = self.last_rtp_timestamp,
                .sender_packet_count = self.packet_count,
                .sender_octet_count = self.octet_count,
                .report_blocks = report_blocks,
            };
        }
    };

    pub fn ntpTimestamp(unix_time_ns: u64) struct { msw: u32, lsw: u32 } {
        const ntp_epoch_offset_seconds: u64 = 2_208_988_800;
        const seconds = unix_time_ns / std.time.ns_per_s + ntp_epoch_offset_seconds;
        const fractional_ns = unix_time_ns % std.time.ns_per_s;
        const fraction = (fractional_ns << 32) / std.time.ns_per_s;
        return .{ .msw = @truncate(seconds), .lsw = @truncate(fraction) };
    }

    pub fn compactNtpTimestamp(ntp_msw: u32, ntp_lsw: u32) u32 {
        // RTCP LSR/DLSR and XR DLRR use the middle 32 bits of the 64-bit NTP
        // timestamp: low 16 bits of the seconds word and high 16 bits of the
        // fractional word, in 1/65536-second units.
        return ((ntp_msw & 0xffff) << 16) | (ntp_lsw >> 16);
    }

    pub fn compactNtpFromUnixNanos(unix_time_ns: u64) u32 {
        const ntp = ntpTimestamp(unix_time_ns);
        return compactNtpTimestamp(ntp.msw, ntp.lsw);
    }

    pub fn compactNtpDelayToNanos(delay_units: u32) u64 {
        return (@as(u64, delay_units) * std.time.ns_per_s) / compact_ntp_units_per_second;
    }

    fn roundTripDelayFromCompact(last_report: u32, delay_since_report: u32, now_compact_ntp: u32) ?u32 {
        if (last_report == 0 or delay_since_report == 0) return null;
        return now_compact_ntp -% last_report -% delay_since_report;
    }

    pub fn decodeCumulativeLost(raw: u24) i32 {
        const value: i32 = @intCast(raw);
        return if ((raw & 0x80_0000) != 0) value - 0x100_0000 else value;
    }

    pub fn encodeCumulativeLost(lost: i32) Error!u24 {
        if (lost < -0x80_0000 or lost > 0x7f_ffff) return error.InvalidRtcpPacket;
        return @truncate(@as(u32, @bitCast(lost)));
    }

    pub const ReceiverStats = struct {
        ssrc: u32 = 0,
        clock_rate: u32 = 90_000,
        initialized: bool = false,
        base_seq: u16 = 0,
        max_seq: u16 = 0,
        /// RTCP extended highest sequence numbers store wrap cycles in the
        /// upper 16 bits, so each RTP sequence rollover advances by 1<<16.
        cycles: u32 = 0,
        received: u32 = 0,
        expected_prior: u32 = 0,
        received_prior: u32 = 0,
        transit_prior: ?i64 = null,
        transit_arrival_units: u64 = 0,
        transit_rtp_timestamp: u32 = 0,
        jitter_q4: u64 = 0,
        last_sender_report: u32 = 0,
        last_sender_report_arrival: u32 = 0,
        has_last_sender_report: bool = false,

        pub fn observe(self: *ReceiverStats, packet: rtp.Packet, arrival_time_ns: u64) void {
            const seq = packet.header.sequence_number;
            const arrival_rtp_units = self.arrivalRtpUnits(arrival_time_ns);
            if (!self.initialized) {
                self.initialized = true;
                self.ssrc = packet.header.ssrc;
                self.base_seq = seq;
                self.max_seq = seq;
                self.received = 1;
                self.setTransitPrior(packet.header.timestamp, arrival_rtp_units);
                return;
            }

            if (seq < self.max_seq and self.max_seq - seq > 0x8000) self.cycles +%= 1 << 16;
            if (seqNewer(seq, self.max_seq)) self.max_seq = seq;
            self.received +|= 1;

            if (self.transit_prior != null) {
                const arrival_delta = @as(i64, @intCast(arrival_rtp_units)) - @as(i64, @intCast(self.transit_arrival_units));
                const timestamp_delta = rtpTimestampDelta(packet.header.timestamp, self.transit_rtp_timestamp);
                const delta = @abs(arrival_delta - timestamp_delta);
                if (delta > self.jitter_q4 >> 4) {
                    self.jitter_q4 += delta - (self.jitter_q4 >> 4);
                } else {
                    self.jitter_q4 -= (self.jitter_q4 >> 4) - delta;
                }
            }
            self.setTransitPrior(packet.header.timestamp, arrival_rtp_units);
        }

        pub fn observeSenderReport(self: *ReceiverStats, report: SenderReport, arrival_time_ns: u64) void {
            self.last_sender_report = compactNtpTimestamp(report.ntp_timestamp_msw, report.ntp_timestamp_lsw);
            self.last_sender_report_arrival = compactNtpFromUnixNanos(arrival_time_ns);
            self.has_last_sender_report = true;
        }

        pub fn reportBlock(self: *ReceiverStats) ReportBlock {
            const expected = self.expectedPackets();
            const interval_expected = expected -% self.expected_prior;
            const interval_received = self.received -% self.received_prior;
            const interval_lost: i64 = @as(i64, interval_expected) - @as(i64, interval_received);
            var fraction_lost: u8 = 0;
            if (interval_expected != 0 and interval_lost > 0) {
                fraction_lost = @intCast(@min(@as(u64, 255), (@as(u64, @intCast(interval_lost)) << 8) / interval_expected));
            }
            self.expected_prior = expected;
            self.received_prior = self.received;

            const total_lost = @as(i64, expected) - @as(i64, self.received);
            const signed_lost: i32 = @intCast(std.math.clamp(total_lost, -0x80_0000, 0x7f_ffff));
            return .{
                .ssrc = self.ssrc,
                .fraction_lost = fraction_lost,
                .cumulative_lost = encodeCumulativeLost(signed_lost) catch unreachable,
                .highest_sequence_number = self.extendedHighestSequenceNumber(),
                .interarrival_jitter = @intCast(@min(@as(u64, std.math.maxInt(u32)), self.jitter_q4 >> 4)),
            };
        }

        pub fn reportBlockAt(self: *ReceiverStats, now_ns: u64) ReportBlock {
            var block = self.reportBlock();
            if (self.has_last_sender_report) {
                block.last_sender_report = self.last_sender_report;
                block.delay_since_last_sender_report = compactNtpFromUnixNanos(now_ns) -% self.last_sender_report_arrival;
            }
            return block;
        }

        pub fn expectedPackets(self: ReceiverStats) u32 {
            if (!self.initialized) return 0;
            return self.extendedHighestSequenceNumber() - @as(u32, self.base_seq) + 1;
        }

        pub fn extendedHighestSequenceNumber(self: ReceiverStats) u32 {
            return self.cycles + @as(u32, self.max_seq);
        }

        fn setTransitPrior(self: *ReceiverStats, rtp_timestamp: u32, arrival_rtp_units: u64) void {
            self.transit_arrival_units = arrival_rtp_units;
            self.transit_rtp_timestamp = rtp_timestamp;
            self.transit_prior = self.transitFromArrival(rtp_timestamp, arrival_rtp_units);
        }

        fn arrivalRtpUnits(self: ReceiverStats, arrival_time_ns: u64) u64 {
            // Convert arrival time to RTP timestamp units before subtracting
            // sender timestamps.  The jitter update below uses modulo-aware
            // RTP timestamp deltas so a normal 32-bit RTP timestamp rollover
            // does not look like multi-hour network jitter.
            return (arrival_time_ns / std.time.ns_per_s) * self.clock_rate + ((arrival_time_ns % std.time.ns_per_s) * self.clock_rate) / std.time.ns_per_s;
        }

        fn transitFromArrival(_: ReceiverStats, rtp_timestamp: u32, arrival_rtp_units: u64) i64 {
            return @as(i64, @intCast(arrival_rtp_units)) - @as(i64, rtp_timestamp);
        }

        fn rtpTimestampDelta(new_timestamp: u32, old_timestamp: u32) i64 {
            const forward = new_timestamp -% old_timestamp;
            if (forward <= std.math.maxInt(i31)) return @intCast(forward);
            return -@as(i64, @intCast(old_timestamp -% new_timestamp));
        }

        fn transit(self: ReceiverStats, rtp_timestamp: u32, arrival_time_ns: u64) i64 {
            const arrival_rtp_units = (arrival_time_ns / std.time.ns_per_s) * self.clock_rate + ((arrival_time_ns % std.time.ns_per_s) * self.clock_rate) / std.time.ns_per_s;
            return self.transitFromArrival(rtp_timestamp, arrival_rtp_units);
        }
    };

    pub const NackTracker = struct {
        initialized: bool = false,
        highest_seq: u16 = 0,
        missing: [128]u16 = [_]u16{0} ** 128,
        missing_len: usize = 0,

        pub fn observe(self: *NackTracker, sequence_number: u16) void {
            if (!self.initialized) {
                self.initialized = true;
                self.highest_seq = sequence_number;
                return;
            }
            if (seqNewer(sequence_number, self.highest_seq)) {
                var next = self.highest_seq +% 1;
                while (next != sequence_number) : (next +%= 1) {
                    self.addMissing(next);
                }
                self.highest_seq = sequence_number;
                self.removeMissing(sequence_number);
                return;
            }
            self.removeMissing(sequence_number);
        }

        pub fn pendingCount(self: NackTracker) usize {
            return self.missing_len;
        }

        pub fn clear(self: *NackTracker) void {
            self.missing_len = 0;
        }

        pub fn buildPairs(self: NackTracker, out: []NackPair) []NackPair {
            if (out.len == 0 or self.missing_len == 0) return out[0..0];
            var sorted = self.missing;
            const missing = sorted[0..self.missing_len];
            std.mem.sort(u16, missing, {}, seqLessThan);

            var count: usize = 0;
            for (missing) |seq| {
                var placed = false;
                for (out[0..count]) |*pair| {
                    const delta = seq -% pair.packet_id;
                    if (delta > 0 and delta <= 16) {
                        pair.lost_packet_bitmask |= @as(u16, 1) << @intCast(delta - 1);
                        placed = true;
                        break;
                    }
                }
                if (!placed) {
                    if (count == out.len) break;
                    out[count] = .{ .packet_id = seq };
                    count += 1;
                }
            }
            return out[0..count];
        }

        fn addMissing(self: *NackTracker, sequence_number: u16) void {
            for (self.missing[0..self.missing_len]) |existing| {
                if (existing == sequence_number) return;
            }
            if (self.missing_len < self.missing.len) {
                self.missing[self.missing_len] = sequence_number;
                self.missing_len += 1;
                return;
            }
            // Keep the newest window by evicting the oldest stored sequence.
            std.mem.copyForwards(u16, self.missing[0 .. self.missing.len - 1], self.missing[1..]);
            self.missing[self.missing.len - 1] = sequence_number;
        }

        fn removeMissing(self: *NackTracker, sequence_number: u16) void {
            var i: usize = 0;
            while (i < self.missing_len) {
                if (self.missing[i] == sequence_number) {
                    self.missing_len -= 1;
                    self.missing[i] = self.missing[self.missing_len];
                    return;
                }
                i += 1;
            }
        }
    };

    fn seqNewer(a: u16, b: u16) bool {
        return a != b and ((a -% b) < 0x8000);
    }

    fn seqLessThan(_: void, a: u16, b: u16) bool {
        if (a == b) return false;
        return ((a -% b) > 0x8000);
    }

    fn appendExtendedReportDestinations(list: *std.ArrayList(u32), allocator: std.mem.Allocator, xr: ExtendedReport) Error!void {
        try list.append(allocator, xr.sender_ssrc);
        for (xr.blocks) |block| {
            switch (block) {
                .loss_rle => |rle| try list.append(allocator, rle.ssrc),
                .duplicate_rle => |rle| try list.append(allocator, rle.ssrc),
                .packet_receipt_times => |receipt| try list.append(allocator, receipt.ssrc),
                .receiver_reference_time => {},
                .dlrr => |dlrr| for (dlrr.reports) |report| try list.append(allocator, report.ssrc),
                .statistics_summary => |summary| try list.append(allocator, summary.ssrc),
                .voip_metrics => |metrics| try list.append(allocator, metrics.ssrc),
                .unknown => {},
            }
        }
    }

    pub const Unknown = struct {
        header: Header,
        payload: []const u8,
        raw: []const u8 = &.{},
    };

    pub const Packet = union(enum) {
        sender_report: SenderReport,
        receiver_report: ReceiverReport,
        goodbye: Goodbye,
        source_description: SourceDescription,
        picture_loss_indication: PictureLossIndication,
        slice_loss_indication: SliceLossIndication,
        full_intra_request: FullIntraRequest,
        receiver_estimated_maximum_bitrate: ReceiverEstimatedMaximumBitrate,
        application_defined: ApplicationDefined,
        extended_report: ExtendedReport,
        rapid_resynchronization_request: RapidResynchronizationRequest,
        congestion_control_feedback: CongestionControlFeedback,
        transport_layer_nack: TransportLayerNack,
        transport_wide_cc: TransportWideCc,
        unknown: Unknown,

        pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .sender_report => |report| allocator.free(report.report_blocks),
                .receiver_report => |report| allocator.free(report.report_blocks),
                .goodbye => |*goodbye| goodbye.deinit(allocator),
                .source_description => |*sdes| sdes.deinit(allocator),
                .slice_loss_indication => |*sli| sli.deinit(allocator),
                .full_intra_request => |*fir| fir.deinit(allocator),
                .receiver_estimated_maximum_bitrate => |*remb| remb.deinit(allocator),
                .application_defined => |*app| app.deinit(allocator),
                .extended_report => |*xr| xr.deinit(allocator),
                .congestion_control_feedback => |*ccfb| ccfb.deinit(allocator),
                .transport_layer_nack => |nack| allocator.free(nack.pairs),
                .transport_wide_cc => |*twcc| twcc.deinit(allocator),
                else => {},
            }
            self.* = undefined;
        }

        pub fn destinationSsrcs(self: Packet, allocator: std.mem.Allocator) Error![]u32 {
            var out: std.ArrayList(u32) = .empty;
            errdefer out.deinit(allocator);
            switch (self) {
                .sender_report => |report| {
                    for (report.report_blocks) |block| try out.append(allocator, block.ssrc);
                    try out.append(allocator, report.sender_ssrc);
                },
                .receiver_report => |report| for (report.report_blocks) |block| try out.append(allocator, block.ssrc),
                .goodbye => |goodbye| try out.appendSlice(allocator, goodbye.sources),
                .source_description => |sdes| for (sdes.chunks) |chunk| try out.append(allocator, chunk.ssrc),
                .picture_loss_indication => |pli| try out.append(allocator, pli.media_ssrc),
                .slice_loss_indication => |sli| try out.append(allocator, sli.media_ssrc),
                .full_intra_request => |fir| for (fir.entries) |entry| try out.append(allocator, entry.ssrc),
                .receiver_estimated_maximum_bitrate => |remb| try out.appendSlice(allocator, remb.ssrcs),
                .application_defined => |app| try out.append(allocator, app.ssrc),
                .extended_report => |xr| try appendExtendedReportDestinations(&out, allocator, xr),
                .rapid_resynchronization_request => |rrr| try out.append(allocator, rrr.media_ssrc),
                .congestion_control_feedback => |ccfb| for (ccfb.report_blocks) |block| try out.append(allocator, block.media_ssrc),
                .transport_layer_nack => |nack| try out.append(allocator, nack.media_ssrc),
                .transport_wide_cc => |twcc| try out.append(allocator, twcc.media_ssrc),
                .unknown => {},
            }
            return out.toOwnedSlice(allocator);
        }

        pub fn wireLen(self: Packet) Error!usize {
            return switch (self) {
                .sender_report => |report| report.wireLen(),
                .receiver_report => |report| report.wireLen(),
                .goodbye => |goodbye| goodbye.wireLen(),
                .source_description => |sdes| sdes.wireLen(),
                .picture_loss_indication => |pli| pli.wireLen(),
                .slice_loss_indication => |sli| sli.wireLen(),
                .full_intra_request => |fir| fir.wireLen(),
                .receiver_estimated_maximum_bitrate => |remb| remb.wireLen(),
                .application_defined => |app| app.wireLen(),
                .extended_report => |xr| xr.wireLen(),
                .rapid_resynchronization_request => |rrr| rrr.wireLen(),
                .congestion_control_feedback => |ccfb| 4 + ccfb.wirePayloadLen(),
                .transport_layer_nack => |nack| nack.wireLen(),
                .transport_wide_cc => |twcc| try twcc.wireLen(),
                .unknown => |unknown| blk: {
                    if (unknown.raw.len != 0) break :blk unknown.raw.len;
                    if ((unknown.payload.len % 4) != 0) return error.InvalidRtcpPacket;
                    break :blk 4 + unknown.payload.len;
                },
            };
        }
    };

    pub const ParsedPacket = struct {
        packet: Packet,
        consumed: usize,

        pub fn deinit(self: *ParsedPacket, allocator: std.mem.Allocator) void {
            self.packet.deinit(allocator);
            self.* = undefined;
        }
    };

    pub fn parsePacket(allocator: std.mem.Allocator, bytes: []const u8) Error!ParsedPacket {
        const header = try Header.parse(bytes);
        const packet_len = header.packetLen();
        if (bytes.len < packet_len) return error.BufferTooShort;
        if (packet_len < 4) return error.InvalidRtcpPacket;
        const payload = try payloadWithoutPadding(header, bytes[0..packet_len]);

        const packet: Packet = switch (header.packet_type) {
            .sender_report => .{ .sender_report = try parseSenderReport(allocator, header, payload) },
            .receiver_report => .{ .receiver_report = try parseReceiverReport(allocator, header, payload) },
            .goodbye => .{ .goodbye = try parseGoodbye(allocator, header, payload) },
            .source_description => .{ .source_description = try parseSourceDescription(allocator, header, payload) },
            .application_defined => .{ .application_defined = try parseApplicationDefined(allocator, header, payload) },
            .extended_report => .{ .extended_report = try parseExtendedReport(allocator, payload) },
            .payload_feedback => if (header.count_or_format == payload_feedback_pli)
                .{ .picture_loss_indication = try parsePictureLossIndication(payload) }
            else if (header.count_or_format == payload_feedback_sli)
                .{ .slice_loss_indication = try parseSliceLossIndication(allocator, payload) }
            else if (header.count_or_format == payload_feedback_fir)
                .{ .full_intra_request = try parseFullIntraRequest(allocator, payload) }
            else if (header.count_or_format == payload_feedback_remb)
                .{ .receiver_estimated_maximum_bitrate = try parseReceiverEstimatedMaximumBitrate(allocator, payload) }
            else
                .{ .unknown = .{ .header = header, .payload = payload, .raw = bytes[0..packet_len] } },
            .transport_feedback => if (header.count_or_format == transport_feedback_nack)
                .{ .transport_layer_nack = try parseTransportLayerNack(allocator, payload) }
            else if (header.count_or_format == transport_feedback_sli)
                .{ .slice_loss_indication = try parseSliceLossIndication(allocator, payload) }
            else if (header.count_or_format == transport_feedback_rrr)
                .{ .rapid_resynchronization_request = try parseRapidResynchronizationRequest(payload) }
            else if (header.count_or_format == transport_feedback_ccfb)
                .{ .congestion_control_feedback = try parseCongestionControlFeedback(allocator, payload) }
            else if (header.count_or_format == transport_feedback_twcc)
                .{ .transport_wide_cc = try parseTransportWideCc(allocator, payload) }
            else
                .{ .unknown = .{ .header = header, .payload = payload, .raw = bytes[0..packet_len] } },
            else => .{ .unknown = .{ .header = header, .payload = payload, .raw = bytes[0..packet_len] } },
        };
        return .{ .packet = packet, .consumed = packet_len };
    }

    fn payloadWithoutPadding(header: Header, packet: []const u8) Error![]const u8 {
        const packet_len = header.packetLen();
        if (packet.len < packet_len) return error.BufferTooShort;
        var payload = packet[4..packet_len];
        if (!header.padding) return payload;
        if (payload.len == 0) return error.InvalidRtcpPacket;
        const padding_len = payload[payload.len - 1];
        // Pion/rtcp keeps the P bit in the common header and individual packet
        // parsers strip the trailing padding octets before decoding control
        // fields.  Validate the generic RTCP padding contract here so fixed
        // length packets (RR/PLI/FIR/TWCC) do not see padding bytes as payload.
        if (padding_len == 0 or padding_len > payload.len) return error.InvalidRtcpPacket;
        payload = payload[0 .. payload.len - padding_len];
        return payload;
    }

    pub fn writePacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet: Packet) Error!void {
        switch (packet) {
            .sender_report => |report| try writeSenderReport(list, allocator, report),
            .receiver_report => |report| try writeReceiverReport(list, allocator, report),
            .goodbye => |goodbye| try writeGoodbye(list, allocator, goodbye),
            .source_description => |sdes| try writeSourceDescription(list, allocator, sdes),
            .picture_loss_indication => |pli| try writePictureLossIndication(list, allocator, pli),
            .slice_loss_indication => |sli| try writeSliceLossIndication(list, allocator, sli),
            .full_intra_request => |fir| try writeFullIntraRequest(list, allocator, fir),
            .receiver_estimated_maximum_bitrate => |remb| try writeReceiverEstimatedMaximumBitrate(list, allocator, remb),
            .application_defined => |app| try writeApplicationDefined(list, allocator, app),
            .extended_report => |xr| try writeExtendedReport(list, allocator, xr),
            .rapid_resynchronization_request => |rrr| try writeRapidResynchronizationRequest(list, allocator, rrr),
            .congestion_control_feedback => |ccfb| try writeCongestionControlFeedback(list, allocator, ccfb),
            .transport_layer_nack => |nack| try writeTransportLayerNack(list, allocator, nack),
            .transport_wide_cc => |twcc| try writeTransportWideCc(list, allocator, twcc),
            .unknown => |unknown| {
                if (unknown.raw.len != 0) {
                    // Mirror Pion/rtcp RawPacket: unknown packets are a
                    // byte-for-byte compatibility escape hatch.  Preserve the
                    // original wire image, including the padding bit and
                    // trailing padding octets, instead of reconstructing a
                    // subtly different packet from the stripped payload.
                    const raw_header = try Header.parse(unknown.raw);
                    if (raw_header.packetLen() != unknown.raw.len) return error.InvalidRtcpPacket;
                    try list.appendSlice(allocator, unknown.raw);
                    return;
                }
                try writeHeader(list, allocator, unknown.header.count_or_format, unknown.header.packet_type, unknown.payload.len);
                try list.appendSlice(allocator, unknown.payload);
            },
        }
    }

    pub fn parseCompound(allocator: std.mem.Allocator, bytes: []const u8) Error![]Packet {
        const packets = try parsePackets(allocator, bytes);
        errdefer freePackets(allocator, packets);
        try validateCompound(packets);
        return packets;
    }

    pub fn parsePackets(allocator: std.mem.Allocator, bytes: []const u8) Error![]Packet {
        // Reduced-size RTCP (RFC 5506), used by WebRTC when `a=rtcp-rsize`
        // is negotiated, permits feedback-only datagrams that intentionally do
        // not satisfy the compound RTCP SR/RR + SDES/CNAME envelope.  Keep this
        // parser separate from parseCompound so callers must opt into accepting
        // reduced-size datagrams instead of weakening compound validation.
        var packets: std.ArrayList(Packet) = .empty;
        errdefer {
            for (packets.items) |*packet| packet.deinit(allocator);
            packets.deinit(allocator);
        }
        var pos: usize = 0;
        while (pos < bytes.len) {
            var parsed = try parsePacket(allocator, bytes[pos..]);
            errdefer parsed.deinit(allocator);
            if (parsed.consumed == 0) return error.InvalidRtcpPacket;
            try packets.append(allocator, parsed.packet);
            parsed.packet = undefined;
            pos += parsed.consumed;
        }
        if (packets.items.len == 0) return error.InvalidRtcpPacket;
        return packets.toOwnedSlice(allocator);
    }

    pub fn freePackets(allocator: std.mem.Allocator, packets: []Packet) void {
        for (packets) |*packet| packet.deinit(allocator);
        allocator.free(packets);
    }

    pub fn freeCompound(allocator: std.mem.Allocator, packets: []Packet) void {
        freePackets(allocator, packets);
    }

    pub fn compoundDestinationSsrcs(allocator: std.mem.Allocator, packets: []const Packet) Error![]u32 {
        if (packets.len == 0) return allocator.alloc(u32, 0);
        return packets[0].destinationSsrcs(allocator);
    }

    pub fn compoundCname(packets: []const Packet) Error![]const u8 {
        try validateCompound(packets);
        for (packets[1..]) |packet| {
            if (packet != .source_description) continue;
            const sdes = packet.source_description;
            for (sdes.chunks) |chunk| {
                for (chunk.items) |item| {
                    if (item.item_type == .cname) return item.value;
                }
            }
        }
        return error.InvalidRtcpPacket;
    }

    pub fn writeCompound(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packets: []const Packet) Error!void {
        try validateCompound(packets);
        try writePackets(list, allocator, packets);
    }

    pub fn writePackets(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packets: []const Packet) Error!void {
        if (packets.len == 0) return error.InvalidRtcpPacket;
        for (packets) |packet| try writePacket(list, allocator, packet);
    }

    pub fn packetsWireLen(packets: []const Packet) Error!usize {
        if (packets.len == 0) return error.InvalidRtcpPacket;
        var len: usize = 0;
        for (packets) |packet| len += try packet.wireLen();
        return len;
    }

    pub fn compoundWireLen(packets: []const Packet) Error!usize {
        try validateCompound(packets);
        return packetsWireLen(packets);
    }

    fn validateCompound(packets: []const Packet) Error!void {
        if (packets.len == 0) return error.InvalidRtcpPacket;
        switch (packets[0]) {
            .sender_report, .receiver_report => {},
            else => return error.InvalidRtcpPacket,
        }

        for (packets[1..]) |packet| {
            switch (packet) {
                .receiver_report => continue,
                .source_description => |sdes| {
                    for (sdes.chunks) |chunk| {
                        for (chunk.items) |item| {
                            if (item.item_type == .cname) return;
                        }
                    }
                    return error.InvalidRtcpPacket;
                },
                else => return error.InvalidRtcpPacket,
            }
        }
        return error.InvalidRtcpPacket;
    }

    fn parseSenderReport(allocator: std.mem.Allocator, header: Header, payload: []const u8) Error!SenderReport {
        const report_count = @as(usize, header.count_or_format);
        const fixed_len = 24 + report_count * 24;
        if (payload.len < fixed_len or ((payload.len - fixed_len) % 4) != 0) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        const ntp_timestamp_msw = try cursor.readInt(u32, .big);
        const ntp_timestamp_lsw = try cursor.readInt(u32, .big);
        const rtp_timestamp = try cursor.readInt(u32, .big);
        const sender_packet_count = try cursor.readInt(u32, .big);
        const sender_octet_count = try cursor.readInt(u32, .big);
        const report_blocks = try parseReportBlocks(allocator, &cursor, report_count);
        return .{
            .sender_ssrc = sender_ssrc,
            .ntp_timestamp_msw = ntp_timestamp_msw,
            .ntp_timestamp_lsw = ntp_timestamp_lsw,
            .rtp_timestamp = rtp_timestamp,
            .sender_packet_count = sender_packet_count,
            .sender_octet_count = sender_octet_count,
            .report_blocks = report_blocks,
            .profile_extensions = payload[fixed_len..],
        };
    }

    fn parseReceiverReport(allocator: std.mem.Allocator, header: Header, payload: []const u8) Error!ReceiverReport {
        const report_count = @as(usize, header.count_or_format);
        const fixed_len = 4 + report_count * 24;
        if (payload.len < fixed_len or ((payload.len - fixed_len) % 4) != 0) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        return .{
            .sender_ssrc = sender_ssrc,
            .report_blocks = try parseReportBlocks(allocator, &cursor, report_count),
            .profile_extensions = payload[fixed_len..],
        };
    }

    fn parseGoodbye(allocator: std.mem.Allocator, header: Header, payload: []const u8) Error!Goodbye {
        const source_count = @as(usize, header.count_or_format);
        if (payload.len < source_count * 4) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sources = try allocator.alloc(u32, source_count);
        errdefer allocator.free(sources);
        for (sources) |*source| source.* = try cursor.readInt(u32, .big);

        var reason: []const u8 = &.{};
        if (!cursor.eof()) {
            const reason_len = try cursor.readByte();
            if (cursor.remaining() < reason_len) return error.InvalidRtcpPacket;
            reason = try cursor.readSlice(reason_len);
            // BYE reason text is followed by zero padding to a 32-bit boundary.
            // Pion/rtcp ignores the trailing bytes after the counted reason;
            // keep the same behavior so packets from browsers/Pion round-trip.
        }
        return .{ .sources = sources, .reason = reason };
    }

    fn parseApplicationDefined(allocator: std.mem.Allocator, header: Header, payload: []const u8) Error!ApplicationDefined {
        if (payload.len < 8) return error.InvalidRtcpPacket;
        const data = try allocator.dupe(u8, payload[8..]);
        errdefer allocator.free(data);
        return .{
            .subtype = @intCast(header.count_or_format),
            .ssrc = std.mem.readInt(u32, payload[0..4], .big),
            .name = payload[4..8].*,
            .data = data,
        };
    }

    fn parsePictureLossIndication(payload: []const u8) Error!PictureLossIndication {
        if (payload.len != 8) return error.InvalidRtcpPacket;
        return .{
            .sender_ssrc = std.mem.readInt(u32, payload[0..4], .big),
            .media_ssrc = std.mem.readInt(u32, payload[4..8], .big),
        };
    }

    fn parseSliceLossIndication(allocator: std.mem.Allocator, payload: []const u8) Error!SliceLossIndication {
        if (payload.len < 8 or ((payload.len - 8) % 4) != 0) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        const media_ssrc = try cursor.readInt(u32, .big);
        const entries = try allocator.alloc(SliEntry, cursor.remaining() / 4);
        errdefer allocator.free(entries);
        for (entries) |*entry| {
            const raw = try cursor.readInt(u32, .big);
            entry.* = .{
                .first = @intCast((raw >> 19) & 0x1fff),
                .number = @intCast((raw >> 6) & 0x1fff),
                .picture = @intCast(raw & 0x3f),
            };
        }
        return .{ .sender_ssrc = sender_ssrc, .media_ssrc = media_ssrc, .entries = entries };
    }

    fn parseRapidResynchronizationRequest(payload: []const u8) Error!RapidResynchronizationRequest {
        if (payload.len != 8) return error.InvalidRtcpPacket;
        return .{
            .sender_ssrc = std.mem.readInt(u32, payload[0..4], .big),
            .media_ssrc = std.mem.readInt(u32, payload[4..8], .big),
        };
    }

    fn parseFullIntraRequest(allocator: std.mem.Allocator, payload: []const u8) Error!FullIntraRequest {
        if (payload.len < 8 or ((payload.len - 8) % 8) != 0) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        const media_ssrc = try cursor.readInt(u32, .big);
        const entries = try allocator.alloc(FirEntry, cursor.remaining() / 8);
        errdefer allocator.free(entries);
        for (entries) |*entry| {
            entry.* = .{
                .ssrc = try cursor.readInt(u32, .big),
                .sequence_number = try cursor.readByte(),
            };
            try cursor.skip(3); // Reserved.
        }
        if (entries.len == 0) return error.InvalidRtcpPacket;
        return .{ .sender_ssrc = sender_ssrc, .media_ssrc = media_ssrc, .entries = entries };
    }

    fn parseReceiverEstimatedMaximumBitrate(allocator: std.mem.Allocator, payload: []const u8) Error!ReceiverEstimatedMaximumBitrate {
        if (payload.len < 16) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        const media_ssrc = try cursor.readInt(u32, .big);
        if (media_ssrc != 0) return error.InvalidRtcpPacket;
        const identifier = try cursor.readSlice(4);
        if (!std.mem.eql(u8, identifier, "REMB")) return error.InvalidRtcpPacket;
        const num_ssrc = try cursor.readByte();
        const bitrate_hi = try cursor.readByte();
        const bitrate_mid = try cursor.readByte();
        const bitrate_lo = try cursor.readByte();
        const expected_len = 16 + @as(usize, num_ssrc) * 4;
        if (payload.len != expected_len) return error.InvalidRtcpPacket;
        const exponent: u6 = @truncate(bitrate_hi >> 2);
        const mantissa = (@as(u64, bitrate_hi & 0x03) << 16) | (@as(u64, bitrate_mid) << 8) | bitrate_lo;
        const bitrate = saturatedRembBitrate(mantissa, exponent);
        const ssrcs = try allocator.alloc(u32, num_ssrc);
        errdefer allocator.free(ssrcs);
        for (ssrcs) |*ssrc| ssrc.* = try cursor.readInt(u32, .big);
        return .{
            .sender_ssrc = sender_ssrc,
            .bitrate = bitrate,
            .ssrcs = ssrcs,
        };
    }

    fn saturatedRembBitrate(mantissa: u64, exponent: u6) u64 {
        if (mantissa == 0) return 0;
        const shift = @as(u32, exponent);
        if (shift >= @bitSizeOf(u64)) return std.math.maxInt(u64);
        const shift_amount: u6 = @intCast(shift);
        if (mantissa > (@as(u64, std.math.maxInt(u64)) >> shift_amount)) {
            return std.math.maxInt(u64);
        }
        return mantissa << shift_amount;
    }

    fn parseCongestionControlFeedback(allocator: std.mem.Allocator, payload: []const u8) Error!CongestionControlFeedback {
        if (payload.len < 8 or (payload.len % 4) != 0) return error.InvalidRtcpPacket;
        const sender_ssrc = std.mem.readInt(u32, payload[0..4], .big);
        const report_timestamp_offset = payload.len - 4;
        var pos: usize = 4;

        var blocks: std.ArrayList(CcFeedbackReportBlock) = .empty;
        errdefer {
            for (blocks.items) |*block| block.deinit(allocator);
            blocks.deinit(allocator);
        }

        while (pos < report_timestamp_offset) {
            const parsed = try parseCcFeedbackReportBlock(allocator, payload[pos..report_timestamp_offset]);
            var block = parsed.block;
            errdefer block.deinit(allocator);
            try blocks.append(allocator, block);
            block.metric_blocks = &.{};
            pos += parsed.consumed;
        }
        if (pos != report_timestamp_offset) return error.InvalidRtcpPacket;

        return .{
            .sender_ssrc = sender_ssrc,
            .report_blocks = try blocks.toOwnedSlice(allocator),
            .report_timestamp = std.mem.readInt(u32, payload[report_timestamp_offset..][0..4], .big),
        };
    }

    fn parseCcFeedbackReportBlock(allocator: std.mem.Allocator, bytes: []const u8) Error!struct { block: CcFeedbackReportBlock, consumed: usize } {
        if (bytes.len < 8) return error.InvalidRtcpPacket;
        const num_reports = std.mem.readInt(u16, bytes[6..8], .big);
        const metric_count = @as(usize, num_reports);
        const padded_metric_count = metric_count + (metric_count % 2);
        const metric_bytes = std.math.mul(usize, padded_metric_count, 2) catch return error.InvalidRtcpPacket;
        const consumed = std.math.add(usize, 8, metric_bytes) catch return error.InvalidRtcpPacket;
        if (bytes.len < consumed) return error.InvalidRtcpPacket;

        const metric_blocks = try allocator.alloc(CcFeedbackMetricBlock, metric_count);
        errdefer allocator.free(metric_blocks);
        var metric_pos: usize = 8;
        for (metric_blocks) |*metric| {
            metric.* = try parseCcFeedbackMetricBlock(bytes[metric_pos..][0..2]);
            metric_pos += 2;
        }
        return .{
            .block = .{
                .media_ssrc = std.mem.readInt(u32, bytes[0..4], .big),
                .begin_sequence = std.mem.readInt(u16, bytes[4..6], .big),
                .metric_blocks = metric_blocks,
            },
            .consumed = consumed,
        };
    }

    fn parseCcFeedbackMetricBlock(bytes: []const u8) Error!CcFeedbackMetricBlock {
        if (bytes.len != 2) return error.InvalidRtcpPacket;
        const received = (bytes[0] & 0x80) != 0;
        if (!received) return .{};
        return .{
            .received = true,
            .ecn = @enumFromInt((bytes[0] >> 5) & 0x03),
            .arrival_time_offset = std.mem.readInt(u16, bytes[0..2], .big) & 0x1fff,
        };
    }

    fn parseExtendedReport(allocator: std.mem.Allocator, payload: []const u8) Error!ExtendedReport {
        if (payload.len < 4 or (payload.len % 4) != 0) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        var blocks: std.ArrayList(XrBlock) = .empty;
        errdefer {
            for (blocks.items) |*block| block.deinit(allocator);
            blocks.deinit(allocator);
        }

        while (!cursor.eof()) {
            if (cursor.remaining() < 4) return error.InvalidRtcpPacket;
            const block_type: XrBlockType = @enumFromInt(try cursor.readByte());
            const type_specific = try cursor.readByte();
            const block_length_words = try cursor.readInt(u16, .big);
            const block_len = std.math.mul(usize, @as(usize, block_length_words) + 1, 4) catch return error.InvalidRtcpPacket;
            if (block_len < 4 or cursor.remaining() < block_len - 4) return error.InvalidRtcpPacket;
            const block_payload = try cursor.readSlice(block_len - 4);
            try blocks.append(allocator, try parseXrBlock(allocator, .{
                .block_type = block_type,
                .type_specific = type_specific,
                .block_length_words = block_length_words,
            }, block_payload));
        }

        return .{
            .sender_ssrc = sender_ssrc,
            .blocks = try blocks.toOwnedSlice(allocator),
        };
    }

    fn parseXrBlock(allocator: std.mem.Allocator, header: XrHeader, payload: []const u8) Error!XrBlock {
        switch (header.block_type) {
            .loss_rle => return .{ .loss_rle = try parseRleReportBlock(allocator, header, payload) },
            .duplicate_rle => return .{ .duplicate_rle = try parseRleReportBlock(allocator, header, payload) },
            .packet_receipt_times => return .{ .packet_receipt_times = try parsePacketReceiptTimesReportBlock(allocator, header, payload) },
            .receiver_reference_time => {
                if (header.type_specific != 0 or header.block_length_words != 2 or payload.len != 8) return error.InvalidRtcpPacket;
                return .{ .receiver_reference_time = std.mem.readInt(u64, payload[0..8], .big) };
            },
            .dlrr => {
                if (header.type_specific != 0 or (payload.len % 12) != 0) return error.InvalidRtcpPacket;
                const reports = try allocator.alloc(DlrrReport, payload.len / 12);
                errdefer allocator.free(reports);
                var cursor = wire.Cursor.init(payload);
                for (reports) |*report| {
                    report.* = .{
                        .ssrc = try cursor.readInt(u32, .big),
                        .last_rr = try cursor.readInt(u32, .big),
                        .dlrr = try cursor.readInt(u32, .big),
                    };
                }
                return .{ .dlrr = .{ .reports = reports } };
            },
            .statistics_summary => return .{ .statistics_summary = try parseStatisticsSummaryReportBlock(header, payload) },
            .voip_metrics => return .{ .voip_metrics = try parseVoipMetricsReportBlock(header, payload) },
            else => {
                const copy = try allocator.dupe(u8, payload);
                errdefer allocator.free(copy);
                return .{ .unknown = .{ .header = header, .payload = copy } };
            },
        }
    }

    fn parseRleReportBlock(allocator: std.mem.Allocator, header: XrHeader, payload: []const u8) Error!RleReportBlock {
        if (payload.len < 8 or (payload.len % 2) != 0) return error.InvalidRtcpPacket;
        const chunk_count = (payload.len - 8) / 2;
        const chunks = try allocator.alloc(XrChunk, chunk_count);
        errdefer allocator.free(chunks);
        var cursor = wire.Cursor.init(payload);
        const ssrc = try cursor.readInt(u32, .big);
        const begin_sequence = try cursor.readInt(u16, .big);
        const end_sequence = try cursor.readInt(u16, .big);
        for (chunks) |*chunk| chunk.* = try cursor.readInt(u16, .big);
        return .{
            .thinning = @intCast(header.type_specific & 0x0f),
            .ssrc = ssrc,
            .begin_sequence = begin_sequence,
            .end_sequence = end_sequence,
            .chunks = chunks,
        };
    }

    fn parsePacketReceiptTimesReportBlock(allocator: std.mem.Allocator, header: XrHeader, payload: []const u8) Error!PacketReceiptTimesReportBlock {
        if (payload.len < 8 or ((payload.len - 8) % 4) != 0) return error.InvalidRtcpPacket;
        const receipt_count = (payload.len - 8) / 4;
        const receipt_times = try allocator.alloc(u32, receipt_count);
        errdefer allocator.free(receipt_times);
        var cursor = wire.Cursor.init(payload);
        const ssrc = try cursor.readInt(u32, .big);
        const begin_sequence = try cursor.readInt(u16, .big);
        const end_sequence = try cursor.readInt(u16, .big);
        for (receipt_times) |*receipt_time| receipt_time.* = try cursor.readInt(u32, .big);
        return .{
            .thinning = @intCast(header.type_specific & 0x0f),
            .ssrc = ssrc,
            .begin_sequence = begin_sequence,
            .end_sequence = end_sequence,
            .receipt_times = receipt_times,
        };
    }

    fn parseStatisticsSummaryReportBlock(header: XrHeader, payload: []const u8) Error!StatisticsSummaryReportBlock {
        if (header.block_length_words != 9 or payload.len != 36) return error.InvalidRtcpPacket;
        return .{
            .loss_reports = (header.type_specific & 0x80) != 0,
            .duplicate_reports = (header.type_specific & 0x40) != 0,
            .jitter_reports = (header.type_specific & 0x20) != 0,
            .ttl_or_hop_limit = @enumFromInt((header.type_specific >> 3) & 0x03),
            .ssrc = std.mem.readInt(u32, payload[0..4], .big),
            .begin_sequence = std.mem.readInt(u16, payload[4..6], .big),
            .end_sequence = std.mem.readInt(u16, payload[6..8], .big),
            .lost_packets = std.mem.readInt(u32, payload[8..12], .big),
            .duplicate_packets = std.mem.readInt(u32, payload[12..16], .big),
            .min_jitter = std.mem.readInt(u32, payload[16..20], .big),
            .max_jitter = std.mem.readInt(u32, payload[20..24], .big),
            .mean_jitter = std.mem.readInt(u32, payload[24..28], .big),
            .dev_jitter = std.mem.readInt(u32, payload[28..32], .big),
            .min_ttl_or_hop_limit = payload[32],
            .max_ttl_or_hop_limit = payload[33],
            .mean_ttl_or_hop_limit = payload[34],
            .dev_ttl_or_hop_limit = payload[35],
        };
    }

    fn parseVoipMetricsReportBlock(header: XrHeader, payload: []const u8) Error!VoipMetricsReportBlock {
        if (header.type_specific != 0 or header.block_length_words != 8 or payload.len != 32) return error.InvalidRtcpPacket;
        return .{
            .ssrc = std.mem.readInt(u32, payload[0..4], .big),
            .loss_rate = payload[4],
            .discard_rate = payload[5],
            .burst_density = payload[6],
            .gap_density = payload[7],
            .burst_duration = std.mem.readInt(u16, payload[8..10], .big),
            .gap_duration = std.mem.readInt(u16, payload[10..12], .big),
            .round_trip_delay = std.mem.readInt(u16, payload[12..14], .big),
            .end_system_delay = std.mem.readInt(u16, payload[14..16], .big),
            .signal_level = payload[16],
            .noise_level = payload[17],
            .rerl = payload[18],
            .gmin = payload[19],
            .r_factor = payload[20],
            .ext_r_factor = payload[21],
            .mos_lq = payload[22],
            .mos_cq = payload[23],
            .rx_config = payload[24],
            .jb_nominal = std.mem.readInt(u16, payload[26..28], .big),
            .jb_maximum = std.mem.readInt(u16, payload[28..30], .big),
            .jb_abs_max = std.mem.readInt(u16, payload[30..32], .big),
        };
    }

    fn parseSourceDescription(allocator: std.mem.Allocator, header: Header, payload: []const u8) Error!SourceDescription {
        const chunk_count = @as(usize, header.count_or_format);
        var cursor = wire.Cursor.init(payload);
        const chunks = try allocator.alloc(SdesChunk, chunk_count);
        var initialized_chunks: usize = 0;
        errdefer {
            for (chunks[0..initialized_chunks]) |chunk| allocator.free(chunk.items);
            allocator.free(chunks);
        }
        for (chunks) |*chunk| {
            if (cursor.remaining() < 4) return error.InvalidRtcpPacket;
            const chunk_start = cursor.pos;
            const ssrc = try cursor.readInt(u32, .big);
            var items: std.ArrayList(SdesItem) = .empty;
            errdefer items.deinit(allocator);
            while (true) {
                const typ: SdesItemType = @enumFromInt(try cursor.readByte());
                if (typ == .end) break;
                const len = try cursor.readByte();
                const value = try cursor.readSlice(len);
                try items.append(allocator, .{ .item_type = typ, .value = value });
            }
            const consumed = cursor.pos - chunk_start;
            const padding = (4 - (consumed % 4)) % 4;
            if (cursor.remaining() < padding) return error.InvalidRtcpPacket;
            for (cursor.buf[cursor.pos .. cursor.pos + padding]) |byte| {
                if (byte != 0) return error.InvalidRtcpPacket;
            }
            try cursor.skip(padding);
            chunk.* = .{ .ssrc = ssrc, .items = try items.toOwnedSlice(allocator) };
            initialized_chunks += 1;
        }
        if (!cursor.eof()) return error.InvalidRtcpPacket;
        return .{ .chunks = chunks };
    }

    fn parseTransportLayerNack(allocator: std.mem.Allocator, payload: []const u8) Error!TransportLayerNack {
        if (payload.len < 8 or ((payload.len - 8) % 4) != 0) return error.InvalidRtcpPacket;
        const pair_count = (payload.len - 8) / 4;
        if (pair_count == 0) return error.InvalidRtcpPacket;
        const pairs = try allocator.alloc(NackPair, pair_count);
        errdefer allocator.free(pairs);
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        const media_ssrc = try cursor.readInt(u32, .big);
        for (pairs) |*pair| {
            pair.* = .{
                .packet_id = try cursor.readInt(u16, .big),
                .lost_packet_bitmask = try cursor.readInt(u16, .big),
            };
        }
        return .{ .sender_ssrc = sender_ssrc, .media_ssrc = media_ssrc, .pairs = pairs };
    }

    fn parseTransportWideCc(allocator: std.mem.Allocator, payload: []const u8) Error!TransportWideCc {
        if (payload.len < 16) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        const media_ssrc = try cursor.readInt(u32, .big);
        const base_sequence_number = try cursor.readInt(u16, .big);
        const packet_status_count = try cursor.readInt(u16, .big);
        const reference_time_64ms = try wire.readU24(&cursor);
        const feedback_packet_count = try cursor.readByte();

        var packets: std.ArrayList(TwccPacketResult) = .empty;
        errdefer packets.deinit(allocator);
        try packets.ensureTotalCapacity(allocator, packet_status_count);

        while (packets.items.len < packet_status_count) {
            if (cursor.remaining() < 2) return error.InvalidRtcpPacket;
            const chunk = try cursor.readInt(u16, .big);
            try appendTwccChunkStatuses(&packets, allocator, chunk, packet_status_count);
        }

        for (packets.items) |*packet| {
            switch (packet.status) {
                .not_received => {},
                .small_delta => {
                    const byte = try cursor.readByte();
                    packet.delta_ticks = byte;
                },
                .large_delta => packet.delta_ticks = try cursor.readInt(i16, .big),
                .received_without_delta => {},
            }
        }

        while (!cursor.eof()) {
            if (try cursor.readByte() != 0) return error.InvalidRtcpPacket;
        }

        return .{
            .sender_ssrc = sender_ssrc,
            .media_ssrc = media_ssrc,
            .base_sequence_number = base_sequence_number,
            .reference_time_64ms = reference_time_64ms,
            .feedback_packet_count = feedback_packet_count,
            .packets = try packets.toOwnedSlice(allocator),
        };
    }

    fn parseReportBlocks(allocator: std.mem.Allocator, cursor: *wire.Cursor, count: usize) Error![]ReportBlock {
        const blocks = try allocator.alloc(ReportBlock, count);
        errdefer allocator.free(blocks);
        for (blocks) |*block| {
            block.* = .{
                .ssrc = try cursor.readInt(u32, .big),
                .fraction_lost = try cursor.readByte(),
                .cumulative_lost = try wire.readU24(cursor),
                .highest_sequence_number = try cursor.readInt(u32, .big),
                .interarrival_jitter = try cursor.readInt(u32, .big),
                .last_sender_report = try cursor.readInt(u32, .big),
                .delay_since_last_sender_report = try cursor.readInt(u32, .big),
            };
        }
        return blocks;
    }

    fn writeSenderReport(list: *std.ArrayList(u8), allocator: std.mem.Allocator, report: SenderReport) Error!void {
        if (report.report_blocks.len > 31) return error.InvalidRtcpPacket;
        const profile_padding = (4 - (report.profile_extensions.len % 4)) % 4;
        try writeHeader(list, allocator, @intCast(report.report_blocks.len), .sender_report, 24 + report.report_blocks.len * 24 + report.profile_extensions.len + profile_padding);
        try wire.appendInt(list, allocator, u32, report.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, report.ntp_timestamp_msw, .big);
        try wire.appendInt(list, allocator, u32, report.ntp_timestamp_lsw, .big);
        try wire.appendInt(list, allocator, u32, report.rtp_timestamp, .big);
        try wire.appendInt(list, allocator, u32, report.sender_packet_count, .big);
        try wire.appendInt(list, allocator, u32, report.sender_octet_count, .big);
        for (report.report_blocks) |block| try writeReportBlock(list, allocator, block);
        try list.appendSlice(allocator, report.profile_extensions);
        try list.appendNTimes(allocator, 0, profile_padding);
    }

    fn writeReceiverReport(list: *std.ArrayList(u8), allocator: std.mem.Allocator, report: ReceiverReport) Error!void {
        if (report.report_blocks.len > 31) return error.InvalidRtcpPacket;
        const profile_padding = (4 - (report.profile_extensions.len % 4)) % 4;
        try writeHeader(list, allocator, @intCast(report.report_blocks.len), .receiver_report, 4 + report.report_blocks.len * 24 + report.profile_extensions.len + profile_padding);
        try wire.appendInt(list, allocator, u32, report.sender_ssrc, .big);
        for (report.report_blocks) |block| try writeReportBlock(list, allocator, block);
        try list.appendSlice(allocator, report.profile_extensions);
        try list.appendNTimes(allocator, 0, profile_padding);
    }

    fn writeGoodbye(list: *std.ArrayList(u8), allocator: std.mem.Allocator, goodbye: Goodbye) Error!void {
        if (goodbye.sources.len > 31 or goodbye.reason.len > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        for (goodbye.sources) |source| try wire.appendInt(&payload, allocator, u32, source, .big);
        if (goodbye.reason.len != 0) {
            try payload.append(allocator, @intCast(goodbye.reason.len));
            try payload.appendSlice(allocator, goodbye.reason);
        }
        try payload.appendNTimes(allocator, 0, (4 - (payload.items.len % 4)) % 4);
        try writeHeader(list, allocator, @intCast(goodbye.sources.len), .goodbye, payload.items.len);
        try list.appendSlice(allocator, payload.items);
    }

    fn writeSourceDescription(list: *std.ArrayList(u8), allocator: std.mem.Allocator, sdes: SourceDescription) Error!void {
        if (sdes.chunks.len == 0 or sdes.chunks.len > 31) return error.InvalidRtcpPacket;
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        for (sdes.chunks) |chunk| {
            const start = payload.items.len;
            try wire.appendInt(&payload, allocator, u32, chunk.ssrc, .big);
            for (chunk.items) |item| {
                if (item.item_type == .end or item.value.len > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
                try payload.append(allocator, @intFromEnum(item.item_type));
                try payload.append(allocator, @intCast(item.value.len));
                try payload.appendSlice(allocator, item.value);
            }
            try payload.append(allocator, @intFromEnum(SdesItemType.end));
            const consumed = payload.items.len - start;
            try payload.appendNTimes(allocator, 0, (4 - (consumed % 4)) % 4);
        }
        try writeHeader(list, allocator, @intCast(sdes.chunks.len), .source_description, payload.items.len);
        try list.appendSlice(allocator, payload.items);
    }

    fn writeApplicationDefined(list: *std.ArrayList(u8), allocator: std.mem.Allocator, app: ApplicationDefined) Error!void {
        const padded_data_len = std.math.add(usize, app.data.len, (4 - (app.data.len % 4)) % 4) catch return error.InvalidRtcpPacket;
        if (padded_data_len > max_rtcp_payload_len - 8) return error.InvalidRtcpPacket;
        // RTCP APP packets use the common-header P bit when the
        // application-dependent data is not naturally 32-bit aligned.  Pion/rtcp
        // fills every padding octet with the padding count, not just the final
        // octet, so preserve that wire image for deterministic interoperability.
        try writeHeaderWithPadding(list, allocator, app.subtype, .application_defined, 8 + padded_data_len, padded_data_len != app.data.len);
        try wire.appendInt(list, allocator, u32, app.ssrc, .big);
        try list.appendSlice(allocator, &app.name);
        try list.appendSlice(allocator, app.data);
        if (padded_data_len != app.data.len) {
            const padding_len: u8 = @intCast(padded_data_len - app.data.len);
            try list.appendNTimes(allocator, padding_len, padding_len);
        }
    }

    fn writePictureLossIndication(list: *std.ArrayList(u8), allocator: std.mem.Allocator, pli: PictureLossIndication) Error!void {
        try writeHeader(list, allocator, payload_feedback_pli, .payload_feedback, 8);
        try wire.appendInt(list, allocator, u32, pli.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, pli.media_ssrc, .big);
    }

    fn writeSliceLossIndication(list: *std.ArrayList(u8), allocator: std.mem.Allocator, sli: SliceLossIndication) Error!void {
        if (sli.entries.len > (max_rtcp_payload_len - 8) / 4) return error.InvalidRtcpPacket;
        // Match Pion/rtcp's wire image for SLI (PT=TSFB/FMT=2).  The parser
        // accepts the RFC 4585 PSFB variant as well because that is the IANA
        // assignment other stacks may emit.
        try writeHeader(list, allocator, transport_feedback_sli, .transport_feedback, 8 + sli.entries.len * 4);
        try wire.appendInt(list, allocator, u32, sli.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, sli.media_ssrc, .big);
        for (sli.entries) |entry| {
            const raw = ((@as(u32, entry.first) & 0x1fff) << 19) |
                ((@as(u32, entry.number) & 0x1fff) << 6) |
                (@as(u32, entry.picture) & 0x3f);
            try wire.appendInt(list, allocator, u32, raw, .big);
        }
    }

    fn writeFullIntraRequest(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fir: FullIntraRequest) Error!void {
        if (fir.entries.len == 0) return error.InvalidRtcpPacket;
        if (fir.entries.len > (max_rtcp_payload_len - 8) / 8) return error.InvalidRtcpPacket;
        try writeHeader(list, allocator, payload_feedback_fir, .payload_feedback, 8 + fir.entries.len * 8);
        try wire.appendInt(list, allocator, u32, fir.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, fir.media_ssrc, .big);
        for (fir.entries) |entry| {
            try wire.appendInt(list, allocator, u32, entry.ssrc, .big);
            try list.append(allocator, entry.sequence_number);
            try list.appendNTimes(allocator, 0, 3);
        }
    }

    fn writeRapidResynchronizationRequest(list: *std.ArrayList(u8), allocator: std.mem.Allocator, rrr: RapidResynchronizationRequest) Error!void {
        try writeHeader(list, allocator, transport_feedback_rrr, .transport_feedback, 8);
        try wire.appendInt(list, allocator, u32, rrr.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, rrr.media_ssrc, .big);
    }

    fn writeCongestionControlFeedback(list: *std.ArrayList(u8), allocator: std.mem.Allocator, ccfb: CongestionControlFeedback) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);

        try wire.appendInt(&payload, allocator, u32, ccfb.sender_ssrc, .big);
        for (ccfb.report_blocks) |block| try writeCcFeedbackReportBlock(&payload, allocator, block);
        try wire.appendInt(&payload, allocator, u32, ccfb.report_timestamp, .big);

        try writeHeader(list, allocator, transport_feedback_ccfb, .transport_feedback, payload.items.len);
        try list.appendSlice(allocator, payload.items);
    }

    fn writeCcFeedbackReportBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, block: CcFeedbackReportBlock) Error!void {
        if (block.metric_blocks.len > 16_384) return error.InvalidRtcpPacket;
        try wire.appendInt(list, allocator, u32, block.media_ssrc, .big);
        try wire.appendInt(list, allocator, u16, block.begin_sequence, .big);
        try wire.appendInt(list, allocator, u16, @intCast(block.metric_blocks.len), .big);
        for (block.metric_blocks) |metric| try writeCcFeedbackMetricBlock(list, allocator, metric);
        if ((block.metric_blocks.len % 2) != 0) try list.appendNTimes(allocator, 0, 2);
    }

    fn writeCcFeedbackMetricBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, metric: CcFeedbackMetricBlock) Error!void {
        var raw: u16 = 0;
        if (metric.received) {
            if (metric.arrival_time_offset > 0x1fff) return error.InvalidRtcpPacket;
            raw |= 0x8000;
            raw |= (@as(u16, @intFromEnum(metric.ecn)) & 0x03) << 13;
            raw |= metric.arrival_time_offset;
        }
        try wire.appendInt(list, allocator, u16, raw, .big);
    }

    fn writeExtendedReport(list: *std.ArrayList(u8), allocator: std.mem.Allocator, xr: ExtendedReport) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);

        try wire.appendInt(&payload, allocator, u32, xr.sender_ssrc, .big);
        for (xr.blocks) |block| try writeXrBlock(&payload, allocator, block);

        try writeHeader(list, allocator, 0, .extended_report, payload.items.len);
        try list.appendSlice(allocator, payload.items);
    }

    fn writeXrBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, block: XrBlock) Error!void {
        switch (block) {
            .loss_rle => |rle| try writeRleReportBlock(list, allocator, .loss_rle, rle),
            .duplicate_rle => |rle| try writeRleReportBlock(list, allocator, .duplicate_rle, rle),
            .packet_receipt_times => |receipt| try writePacketReceiptTimesReportBlock(list, allocator, receipt),
            .receiver_reference_time => |ntp| {
                try writeXrBlockHeader(list, allocator, .receiver_reference_time, 0, 2);
                try wire.appendInt(list, allocator, u64, ntp, .big);
            },
            .dlrr => |dlrr| {
                if (dlrr.reports.len > (max_rtcp_payload_len - 4) / 12) return error.InvalidRtcpPacket;
                const block_length_words: u16 = @intCast(dlrr.reports.len * 3);
                try writeXrBlockHeader(list, allocator, .dlrr, 0, block_length_words);
                for (dlrr.reports) |report| {
                    try wire.appendInt(list, allocator, u32, report.ssrc, .big);
                    try wire.appendInt(list, allocator, u32, report.last_rr, .big);
                    try wire.appendInt(list, allocator, u32, report.dlrr, .big);
                }
            },
            .statistics_summary => |summary| try writeStatisticsSummaryReportBlock(list, allocator, summary),
            .voip_metrics => |metrics| try writeVoipMetricsReportBlock(list, allocator, metrics),
            .unknown => |unknown| {
                if ((unknown.payload.len % 4) != 0) return error.InvalidRtcpPacket;
                const words = unknown.payload.len / 4;
                if (words > std.math.maxInt(u16)) return error.InvalidRtcpPacket;
                try writeXrBlockHeader(list, allocator, unknown.header.block_type, unknown.header.type_specific, @intCast(words));
                try list.appendSlice(allocator, unknown.payload);
            },
        }
    }

    fn writeRleReportBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, block_type: XrBlockType, rle: RleReportBlock) Error!void {
        if (rle.chunks.len > (max_rtcp_payload_len - 8) / 2) return error.InvalidRtcpPacket;
        const payload_len = 8 + rle.chunks.len * 2;
        if ((payload_len % 4) != 0) return error.InvalidRtcpPacket;
        try writeXrBlockHeader(list, allocator, block_type, rle.thinning & 0x0f, @intCast(payload_len / 4));
        try wire.appendInt(list, allocator, u32, rle.ssrc, .big);
        try wire.appendInt(list, allocator, u16, rle.begin_sequence, .big);
        try wire.appendInt(list, allocator, u16, rle.end_sequence, .big);
        for (rle.chunks) |chunk| try wire.appendInt(list, allocator, u16, chunk, .big);
    }

    fn writePacketReceiptTimesReportBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, receipt: PacketReceiptTimesReportBlock) Error!void {
        if (receipt.receipt_times.len > (max_rtcp_payload_len - 8) / 4) return error.InvalidRtcpPacket;
        const payload_len = 8 + receipt.receipt_times.len * 4;
        try writeXrBlockHeader(list, allocator, .packet_receipt_times, receipt.thinning & 0x0f, @intCast(payload_len / 4));
        try wire.appendInt(list, allocator, u32, receipt.ssrc, .big);
        try wire.appendInt(list, allocator, u16, receipt.begin_sequence, .big);
        try wire.appendInt(list, allocator, u16, receipt.end_sequence, .big);
        for (receipt.receipt_times) |receipt_time| try wire.appendInt(list, allocator, u32, receipt_time, .big);
    }

    fn writeStatisticsSummaryReportBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, summary: StatisticsSummaryReportBlock) Error!void {
        var type_specific: u8 = 0;
        if (summary.loss_reports) type_specific |= 0x80;
        if (summary.duplicate_reports) type_specific |= 0x40;
        if (summary.jitter_reports) type_specific |= 0x20;
        type_specific |= (@as(u8, @intFromEnum(summary.ttl_or_hop_limit)) & 0x03) << 3;
        try writeXrBlockHeader(list, allocator, .statistics_summary, type_specific, 9);
        try wire.appendInt(list, allocator, u32, summary.ssrc, .big);
        try wire.appendInt(list, allocator, u16, summary.begin_sequence, .big);
        try wire.appendInt(list, allocator, u16, summary.end_sequence, .big);
        try wire.appendInt(list, allocator, u32, summary.lost_packets, .big);
        try wire.appendInt(list, allocator, u32, summary.duplicate_packets, .big);
        try wire.appendInt(list, allocator, u32, summary.min_jitter, .big);
        try wire.appendInt(list, allocator, u32, summary.max_jitter, .big);
        try wire.appendInt(list, allocator, u32, summary.mean_jitter, .big);
        try wire.appendInt(list, allocator, u32, summary.dev_jitter, .big);
        try list.append(allocator, summary.min_ttl_or_hop_limit);
        try list.append(allocator, summary.max_ttl_or_hop_limit);
        try list.append(allocator, summary.mean_ttl_or_hop_limit);
        try list.append(allocator, summary.dev_ttl_or_hop_limit);
    }

    fn writeVoipMetricsReportBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, metrics: VoipMetricsReportBlock) Error!void {
        try writeXrBlockHeader(list, allocator, .voip_metrics, 0, 8);
        try wire.appendInt(list, allocator, u32, metrics.ssrc, .big);
        try list.append(allocator, metrics.loss_rate);
        try list.append(allocator, metrics.discard_rate);
        try list.append(allocator, metrics.burst_density);
        try list.append(allocator, metrics.gap_density);
        try wire.appendInt(list, allocator, u16, metrics.burst_duration, .big);
        try wire.appendInt(list, allocator, u16, metrics.gap_duration, .big);
        try wire.appendInt(list, allocator, u16, metrics.round_trip_delay, .big);
        try wire.appendInt(list, allocator, u16, metrics.end_system_delay, .big);
        try list.append(allocator, metrics.signal_level);
        try list.append(allocator, metrics.noise_level);
        try list.append(allocator, metrics.rerl);
        try list.append(allocator, metrics.gmin);
        try list.append(allocator, metrics.r_factor);
        try list.append(allocator, metrics.ext_r_factor);
        try list.append(allocator, metrics.mos_lq);
        try list.append(allocator, metrics.mos_cq);
        try list.append(allocator, metrics.rx_config);
        try list.append(allocator, 0); // Reserved byte in RFC 3611 section 4.7.
        try wire.appendInt(list, allocator, u16, metrics.jb_nominal, .big);
        try wire.appendInt(list, allocator, u16, metrics.jb_maximum, .big);
        try wire.appendInt(list, allocator, u16, metrics.jb_abs_max, .big);
    }

    fn writeXrBlockHeader(list: *std.ArrayList(u8), allocator: std.mem.Allocator, block_type: XrBlockType, type_specific: u8, block_length_words: u16) Error!void {
        try list.append(allocator, @intFromEnum(block_type));
        try list.append(allocator, type_specific);
        try wire.appendInt(list, allocator, u16, block_length_words, .big);
    }

    fn writeReceiverEstimatedMaximumBitrate(list: *std.ArrayList(u8), allocator: std.mem.Allocator, remb: ReceiverEstimatedMaximumBitrate) Error!void {
        if (remb.ssrcs.len > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
        var exponent: u6 = 0;
        var mantissa = remb.bitrate;
        while (mantissa >= (1 << 18)) {
            mantissa >>= 1;
            exponent += 1;
            if (exponent == std.math.maxInt(u6)) break;
        }
        if (mantissa >= (1 << 18)) return error.InvalidRtcpPacket;

        try writeHeader(list, allocator, payload_feedback_remb, .payload_feedback, 16 + remb.ssrcs.len * 4);
        try wire.appendInt(list, allocator, u32, remb.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, 0, .big);
        try list.appendSlice(allocator, "REMB");
        try list.append(allocator, @intCast(remb.ssrcs.len));
        try list.append(allocator, (@as(u8, exponent) << 2) | @as(u8, @intCast((mantissa >> 16) & 0x03)));
        try list.append(allocator, @intCast((mantissa >> 8) & 0xff));
        try list.append(allocator, @intCast(mantissa & 0xff));
        for (remb.ssrcs) |ssrc| try wire.appendInt(list, allocator, u32, ssrc, .big);
    }

    fn writeTransportLayerNack(list: *std.ArrayList(u8), allocator: std.mem.Allocator, nack: TransportLayerNack) Error!void {
        if (nack.pairs.len == 0 or nack.pairs.len > (max_rtcp_payload_len - 8) / 4) return error.InvalidRtcpPacket;
        try writeHeader(list, allocator, transport_feedback_nack, .transport_feedback, 8 + nack.pairs.len * 4);
        try wire.appendInt(list, allocator, u32, nack.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, nack.media_ssrc, .big);
        for (nack.pairs) |pair| {
            try wire.appendInt(list, allocator, u16, pair.packet_id, .big);
            try wire.appendInt(list, allocator, u16, pair.lost_packet_bitmask, .big);
        }
    }

    fn writeTransportWideCc(list: *std.ArrayList(u8), allocator: std.mem.Allocator, twcc: TransportWideCc) Error!void {
        if (twcc.packets.len > std.math.maxInt(u16)) return error.InvalidRtcpPacket;
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);

        try wire.appendInt(&payload, allocator, u32, twcc.sender_ssrc, .big);
        try wire.appendInt(&payload, allocator, u32, twcc.media_ssrc, .big);
        try wire.appendInt(&payload, allocator, u16, twcc.base_sequence_number, .big);
        try wire.appendInt(&payload, allocator, u16, @intCast(twcc.packets.len), .big);
        try wire.appendU24(&payload, allocator, twcc.reference_time_64ms);
        try payload.append(allocator, twcc.feedback_packet_count);

        try writeTwccPacketStatusChunks(&payload, allocator, twcc.packets);

        for (twcc.packets) |packet| {
            switch (packet.status) {
                .not_received => {},
                .small_delta => {
                    if (packet.delta_ticks < 0 or packet.delta_ticks > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
                    try payload.append(allocator, @intCast(packet.delta_ticks));
                },
                .large_delta => try wire.appendInt(&payload, allocator, i16, packet.delta_ticks, .big),
                .received_without_delta => {},
            }
        }

        try payload.appendNTimes(allocator, 0, (4 - (payload.items.len % 4)) % 4);
        try writeHeader(list, allocator, transport_feedback_twcc, .transport_feedback, payload.items.len);
        try list.appendSlice(allocator, payload.items);
    }

    fn writeReportBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, block: ReportBlock) Error!void {
        try wire.appendInt(list, allocator, u32, block.ssrc, .big);
        try list.append(allocator, block.fraction_lost);
        try wire.appendU24(list, allocator, block.cumulative_lost);
        try wire.appendInt(list, allocator, u32, block.highest_sequence_number, .big);
        try wire.appendInt(list, allocator, u32, block.interarrival_jitter, .big);
        try wire.appendInt(list, allocator, u32, block.last_sender_report, .big);
        try wire.appendInt(list, allocator, u32, block.delay_since_last_sender_report, .big);
    }

    fn writeHeader(list: *std.ArrayList(u8), allocator: std.mem.Allocator, count_or_format: u5, packet_type: PacketType, payload_len: usize) Error!void {
        try writeHeaderWithPadding(list, allocator, count_or_format, packet_type, payload_len, false);
    }

    fn writeHeaderWithPadding(list: *std.ArrayList(u8), allocator: std.mem.Allocator, count_or_format: u5, packet_type: PacketType, payload_len: usize, padding: bool) Error!void {
        if ((payload_len % 4) != 0 or payload_len / 4 > std.math.maxInt(u16)) return error.InvalidRtcpPacket;
        try list.append(allocator, 0x80 | (if (padding) @as(u8, 0x20) else 0) | @as(u8, count_or_format));
        try list.append(allocator, @intFromEnum(packet_type));
        try wire.appendInt(list, allocator, u16, @intCast(payload_len / 4), .big);
    }

    fn appendTwccChunkStatuses(
        packets: *std.ArrayList(TwccPacketResult),
        allocator: std.mem.Allocator,
        chunk: u16,
        packet_status_count: usize,
    ) Error!void {
        if (twccChunkType(chunk) == .run_length) {
            const status = try twccRunStatus(chunk);
            const run_len = try twccRunLength(chunk);
            var i: usize = 0;
            while (i < @as(usize, run_len) and packets.items.len < packet_status_count) : (i += 1) {
                try packets.append(allocator, .{ .status = status });
            }
            return;
        }

        const symbol_size = try twccStatusVectorSymbolSize(chunk);
        var i: usize = 0;
        while (i < twccStatusVectorCapacity(symbol_size) and packets.items.len < packet_status_count) : (i += 1) {
            try packets.append(allocator, .{ .status = try twccStatusVectorSymbol(chunk, i) });
        }
    }

    fn writeTwccPacketStatusChunks(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packets: []const TwccPacketResult) Error!void {
        var index: usize = 0;
        while (index < packets.len) {
            const run_len = twccSameStatusRunLength(packets, index, 0x1fff);
            const current_status = packets[index].status;
            const vector_capacity = if (twccStatusFitsOneBit(current_status))
                twccStatusVectorCapacity(.one_bit)
            else
                twccStatusVectorCapacity(.two_bit);

            // Long homogeneous runs are the case where RFC 8888-style status
            // vectors lose to a run-length chunk.  Short runs are deliberately
            // folded into vectors so mixed browser/Pion feedback frames do not
            // bloat into one chunk per packet.
            if (run_len > vector_capacity) {
                try writeTwccRunLengthChunk(list, allocator, current_status, run_len);
                index += run_len;
                continue;
            }

            var symbol_size: TwccSymbolSize = .one_bit;
            var vector_len = @min(twccStatusVectorCapacity(.one_bit), packets.len - index);
            for (packets[index .. index + vector_len]) |packet| {
                if (!twccStatusFitsOneBit(packet.status)) {
                    symbol_size = .two_bit;
                    vector_len = @min(twccStatusVectorCapacity(.two_bit), packets.len - index);
                    break;
                }
            }

            var statuses: [twccStatusVectorCapacity(.one_bit)]TwccPacketStatus = undefined;
            for (statuses[0..vector_len], packets[index .. index + vector_len]) |*status, packet| {
                status.* = packet.status;
            }
            const chunk = try twccStatusVectorChunk(symbol_size, statuses[0..vector_len]);
            try wire.appendInt(list, allocator, u16, chunk, .big);
            index += vector_len;
        }
    }

    fn twccPacketStatusChunksWireLen(packets: []const TwccPacketResult) usize {
        var index: usize = 0;
        var len: usize = 0;
        while (index < packets.len) {
            const run_len = twccSameStatusRunLength(packets, index, 0x1fff);
            const current_status = packets[index].status;
            const vector_capacity = if (twccStatusFitsOneBit(current_status))
                twccStatusVectorCapacity(.one_bit)
            else
                twccStatusVectorCapacity(.two_bit);

            if (run_len > vector_capacity) {
                len += 2;
                index += run_len;
                continue;
            }

            var vector_len = @min(twccStatusVectorCapacity(.one_bit), packets.len - index);
            for (packets[index .. index + vector_len]) |packet| {
                if (!twccStatusFitsOneBit(packet.status)) {
                    vector_len = @min(twccStatusVectorCapacity(.two_bit), packets.len - index);
                    break;
                }
            }
            len += 2;
            index += vector_len;
        }
        return len;
    }

    fn twccSameStatusRunLength(packets: []const TwccPacketResult, start: usize, max_len: usize) usize {
        const status = packets[start].status;
        var len: usize = 1;
        while (start + len < packets.len and len < max_len and packets[start + len].status == status) : (len += 1) {}
        return len;
    }

    fn twccStatusFitsOneBit(status: TwccPacketStatus) bool {
        return status == .not_received or status == .small_delta;
    }

    fn writeTwccRunLengthChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, status: TwccPacketStatus, run_len: usize) Error!void {
        if (run_len == 0 or run_len > 0x1fff) return error.InvalidRtcpPacket;
        const value = try twccRunLengthChunk(status, @intCast(run_len));
        try wire.appendInt(list, allocator, u16, value, .big);
    }
};

pub const sctp = struct {
    pub const datachannel_ppid: u32 = 50;
    pub const string_ppid: u32 = 51;
    pub const binary_ppid: u32 = 53;
    pub const string_empty_ppid: u32 = 56;
    pub const binary_empty_ppid: u32 = 57;

    pub const ChunkType = enum(u8) {
        data = 0,
        init = 1,
        init_ack = 2,
        sack = 3,
        heartbeat = 4,
        heartbeat_ack = 5,
        abort = 6,
        shutdown = 7,
        shutdown_ack = 8,
        error_chunk = 9,
        cookie_echo = 10,
        cookie_ack = 11,
        reconfig = 130,
        i_data = 64,
        forward_tsn = 192,
        i_forward_tsn = 194,
        shutdown_complete = 14,
        _,
    };

    pub const PayloadProtocolIdentifier = enum(u32) {
        webrtc_dcep = datachannel_ppid,
        webrtc_string = string_ppid,
        webrtc_binary = binary_ppid,
        webrtc_string_empty = string_empty_ppid,
        webrtc_binary_empty = binary_empty_ppid,
        _,
    };

    pub const Header = struct {
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
        checksum: u32,

        pub fn parse(bytes: []const u8) Error!Header {
            var cursor = wire.Cursor.init(bytes);
            const source_port = try cursor.readInt(u16, .big);
            const destination_port = try cursor.readInt(u16, .big);
            try validatePacketPorts(source_port, destination_port);
            return .{
                .source_port = source_port,
                .destination_port = destination_port,
                .verification_tag = try cursor.readInt(u32, .big),
                .checksum = try cursor.readInt(u32, .little),
            };
        }
    };

    pub const PacketOptions = struct {
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
    };

    pub const Chunk = struct {
        chunk_type: ChunkType,
        flags: u8,
        value: []const u8,
        consumed: usize,
    };

    pub const ParsedPacket = struct {
        header: Header,
        chunks: []Chunk,

        pub fn deinit(self: *ParsedPacket, allocator: std.mem.Allocator) void {
            allocator.free(self.chunks);
            self.* = undefined;
        }
    };

    pub const DataChunk = struct {
        unordered: bool = false,
        beginning: bool = true,
        ending: bool = true,
        immediate_sack: bool = false,
        interleaved: bool = false,
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16 = 0,
        message_identifier: u32 = 0,
        fragment_sequence_number: u32 = 0,
        payload_protocol_identifier: PayloadProtocolIdentifier,
        user_data: []const u8,

        pub fn flags(self: DataChunk) u8 {
            return (if (self.immediate_sack) @as(u8, 0x08) else 0) |
                (if (self.unordered) @as(u8, 0x04) else 0) |
                (if (self.beginning) @as(u8, 0x02) else 0) |
                (if (self.ending) @as(u8, 0x01) else 0);
        }

        pub fn parse(chunk: Chunk) Error!DataChunk {
            if ((chunk.flags & 0xf0) != 0 or chunk.value.len < 12) return error.InvalidSctpPacket;
            const base = DataChunk{
                .immediate_sack = (chunk.flags & 0x08) != 0,
                .unordered = (chunk.flags & 0x04) != 0,
                .beginning = (chunk.flags & 0x02) != 0,
                .ending = (chunk.flags & 0x01) != 0,
                .tsn = std.mem.readInt(u32, chunk.value[0..4], .big),
                .stream_id = std.mem.readInt(u16, chunk.value[4..6], .big),
                .stream_sequence_number = std.mem.readInt(u16, chunk.value[6..8], .big),
                .payload_protocol_identifier = .webrtc_binary,
                .user_data = &.{},
            };
            return switch (chunk.chunk_type) {
                .data => blk: {
                    const ppid: PayloadProtocolIdentifier = @enumFromInt(std.mem.readInt(u32, chunk.value[8..12], .big));
                    if (ppid == .webrtc_dcep and base.unordered) return error.InvalidSctpPacket;
                    break :blk .{
                        .immediate_sack = base.immediate_sack,
                        .unordered = base.unordered,
                        .beginning = base.beginning,
                        .ending = base.ending,
                        .tsn = base.tsn,
                        .stream_id = base.stream_id,
                        .stream_sequence_number = base.stream_sequence_number,
                        .payload_protocol_identifier = ppid,
                        .user_data = chunk.value[12..],
                    };
                },
                .i_data => blk: {
                    if (chunk.value.len < 16) return error.InvalidSctpPacket;
                    const mid = std.mem.readInt(u32, chunk.value[8..12], .big);
                    const ppid_or_fsn = std.mem.readInt(u32, chunk.value[12..16], .big);
                    if (!base.beginning and ppid_or_fsn == 0) return error.InvalidSctpPacket;
                    const ppid: PayloadProtocolIdentifier = if (base.beginning) @enumFromInt(ppid_or_fsn) else @enumFromInt(@as(u32, 0));
                    if (ppid == .webrtc_dcep and base.unordered) return error.InvalidSctpPacket;
                    break :blk .{
                        .immediate_sack = base.immediate_sack,
                        .unordered = base.unordered,
                        .beginning = base.beginning,
                        .ending = base.ending,
                        .interleaved = true,
                        .tsn = base.tsn,
                        .stream_id = base.stream_id,
                        .stream_sequence_number = @truncate(mid),
                        .message_identifier = mid,
                        .fragment_sequence_number = if (base.beginning) 0 else ppid_or_fsn,
                        .payload_protocol_identifier = ppid,
                        .user_data = chunk.value[16..],
                    };
                },
                else => return error.InvalidSctpPacket,
            };
        }
    };

    pub const InitParameterType = enum(u16) {
        heartbeat_info = 0x0001,
        unrecognized_parameters = 0x0008,
        state_cookie = 0x0007,
        outgoing_ssn_reset_request = 0x000d,
        reconfig_response = 0x0010,
        ecn_capable = 0x8000,
        zero_checksum_acceptable = 0x8001,
        random = 0x8002,
        chunk_list = 0x8003,
        requested_hmac_algorithm = 0x8004,
        supported_extensions = 0x8008,
        forward_tsn_supported = 0xc000,
        supported_address_types = 0x000c,
        _,
    };

    pub const ReconfigParameterType = enum(u16) {
        outgoing_ssn_reset_request = 0x000d,
        outgoing_ssn_reset_response = 0x0010,
        _,
    };

    pub const ReconfigResult = enum(u32) {
        success_nothing_to_do = 0,
        success_performed = 1,
        denied = 2,
        error_wrong_ssn = 3,
        error_request_already_in_progress = 4,
        error_bad_sequence_number = 5,
        in_progress = 6,
        _,
    };

    pub const SkippedStream = struct {
        stream_id: u16,
        stream_sequence_number: u16,
    };

    pub const SkippedMessage = struct {
        stream_id: u16,
        unordered: bool = false,
        message_identifier: u32,
    };

    pub const ErrorCauseCode = enum(u16) {
        invalid_stream_identifier = 0x0001,
        missing_mandatory_parameter = 0x0002,
        stale_cookie_error = 0x0003,
        out_of_resource = 0x0004,
        unresolvable_address = 0x0005,
        unrecognized_chunk_type = 0x0006,
        invalid_mandatory_parameter = 0x0007,
        unrecognized_parameters = 0x0008,
        no_user_data = 0x0009,
        cookie_received_while_shutting_down = 0x000a,
        restart_association_with_new_addresses = 0x000b,
        user_initiated_abort = 0x000c,
        protocol_violation = 0x000d,
        _,
    };

    pub const ErrorCause = struct {
        code: ErrorCauseCode,
        value: []const u8 = &.{},
    };

    pub const AbortChunk = struct {
        t_bit: bool = false,
        causes: []ErrorCause = &.{},

        pub fn deinit(self: *AbortChunk, allocator: std.mem.Allocator) void {
            allocator.free(self.causes);
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!AbortChunk {
            if (chunk.chunk_type != .abort or (chunk.flags & ~@as(u8, 0x01)) != 0) return error.InvalidSctpPacket;
            return .{ .t_bit = (chunk.flags & 0x01) != 0, .causes = try parseErrorCauses(allocator, chunk.value) };
        }
    };

    pub const ErrorChunk = struct {
        causes: []ErrorCause,

        pub fn deinit(self: *ErrorChunk, allocator: std.mem.Allocator) void {
            allocator.free(self.causes);
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!ErrorChunk {
            if (chunk.chunk_type != .error_chunk or chunk.flags != 0) return error.InvalidSctpPacket;
            return .{ .causes = try parseErrorCauses(allocator, chunk.value) };
        }
    };

    pub const ForwardTsnChunk = struct {
        new_cumulative_tsn: u32,
        skipped_streams: []SkippedStream = &.{},

        pub fn deinit(self: *ForwardTsnChunk, allocator: std.mem.Allocator) void {
            allocator.free(self.skipped_streams);
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!ForwardTsnChunk {
            if (chunk.chunk_type != .forward_tsn or chunk.flags != 0 or chunk.value.len < 4 or ((chunk.value.len - 4) % 4) != 0) return error.InvalidSctpPacket;
            var cursor = wire.Cursor.init(chunk.value);
            const new_cumulative_tsn = try cursor.readInt(u32, .big);
            const count = cursor.remaining() / 4;
            const skipped = try allocator.alloc(SkippedStream, count);
            errdefer allocator.free(skipped);
            for (skipped) |*stream| {
                stream.* = .{
                    .stream_id = try cursor.readInt(u16, .big),
                    .stream_sequence_number = try cursor.readInt(u16, .big),
                };
            }
            return .{ .new_cumulative_tsn = new_cumulative_tsn, .skipped_streams = skipped };
        }
    };

    pub const IForwardTsnChunk = struct {
        new_cumulative_tsn: u32,
        skipped_messages: []SkippedMessage = &.{},

        pub fn deinit(self: *IForwardTsnChunk, allocator: std.mem.Allocator) void {
            allocator.free(self.skipped_messages);
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!IForwardTsnChunk {
            if (chunk.chunk_type != .i_forward_tsn or chunk.flags != 0 or chunk.value.len < 4 or ((chunk.value.len - 4) % 8) != 0) return error.InvalidSctpPacket;
            var cursor = wire.Cursor.init(chunk.value);
            const new_cumulative_tsn = try cursor.readInt(u32, .big);
            var messages: std.ArrayList(SkippedMessage) = .empty;
            errdefer messages.deinit(allocator);
            while (!cursor.eof()) {
                const stream_id = try cursor.readInt(u16, .big);
                const flags = try cursor.readInt(u16, .big);
                if ((flags & ~@as(u16, 0x0001)) != 0) return error.InvalidSctpPacket;
                const message_identifier = try cursor.readInt(u32, .big);
                try appendSkippedMessageNormalized(&messages, allocator, .{
                    .stream_id = stream_id,
                    .unordered = (flags & 0x0001) != 0,
                    .message_identifier = message_identifier,
                });
            }
            return .{ .new_cumulative_tsn = new_cumulative_tsn, .skipped_messages = try messages.toOwnedSlice(allocator) };
        }
    };

    pub const InitParameter = struct {
        param_type: InitParameterType,
        value: []const u8,
    };

    pub const dtls_error_detection_method: u32 = 1;

    pub fn parseZeroChecksumAcceptable(parameter: InitParameter) Error!u32 {
        if (parameter.param_type != .zero_checksum_acceptable or parameter.value.len != 4) return error.InvalidSctpPacket;
        return std.mem.readInt(u32, parameter.value[0..4], .big);
    }

    pub fn zeroChecksumAcceptsDtls(parameter: InitParameter) Error!bool {
        return (try parseZeroChecksumAcceptable(parameter)) == dtls_error_detection_method;
    }

    pub fn writeZeroChecksumAcceptableParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, edmid: u32) Error!void {
        var value: [4]u8 = undefined;
        std.mem.writeInt(u32, &value, edmid, .big);
        _ = try writeInitParameter(list, allocator, .{ .param_type = .zero_checksum_acceptable, .value = &value });
    }

    pub const HeartbeatChunk = struct {
        info: []const u8,

        pub fn parse(chunk: Chunk) Error!HeartbeatChunk {
            if ((chunk.chunk_type != .heartbeat and chunk.chunk_type != .heartbeat_ack) or chunk.flags != 0) return error.InvalidSctpPacket;
            if (chunk.value.len == 0) return .{ .info = &.{} };
            if (chunk.value.len < 4) return error.InvalidSctpPacket;
            const param_type: InitParameterType = @enumFromInt(std.mem.readInt(u16, chunk.value[0..2], .big));
            const len = std.mem.readInt(u16, chunk.value[2..4], .big);
            if (param_type != .heartbeat_info or len < 4 or len > chunk.value.len) return error.InvalidSctpPacket;
            try validateZeroPadding(chunk.value[len..]);
            return .{ .info = chunk.value[4..len] };
        }
    };

    pub const ShutdownChunk = struct {
        cumulative_tsn_ack: u32,

        pub fn parse(chunk: Chunk) Error!ShutdownChunk {
            if (chunk.chunk_type != .shutdown or chunk.flags != 0 or chunk.value.len != 4) return error.InvalidSctpPacket;
            return .{ .cumulative_tsn_ack = std.mem.readInt(u32, chunk.value[0..4], .big) };
        }
    };

    pub const InitChunk = struct {
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
        parameters: []InitParameter = &.{},

        pub fn deinit(self: *InitChunk, allocator: std.mem.Allocator) void {
            allocator.free(self.parameters);
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!InitChunk {
            if ((chunk.chunk_type != .init and chunk.chunk_type != .init_ack) or chunk.flags != 0 or chunk.value.len < 16) return error.InvalidSctpPacket;
            var cursor = wire.Cursor.init(chunk.value);
            const initiate_tag = try cursor.readInt(u32, .big);
            const rwnd = try cursor.readInt(u32, .big);
            const outbound = try cursor.readInt(u16, .big);
            const inbound = try cursor.readInt(u16, .big);
            const initial_tsn = try cursor.readInt(u32, .big);
            try validateInitFixedFields(initiate_tag, rwnd, outbound, inbound);
            const parameters = try parseInitParameters(allocator, chunk.value[cursor.pos..]);
            return .{
                .initiate_tag = initiate_tag,
                .advertised_receiver_window_credit = rwnd,
                .outbound_streams = outbound,
                .inbound_streams = inbound,
                .initial_tsn = initial_tsn,
                .parameters = parameters,
            };
        }

        pub fn stateCookie(self: InitChunk) ?[]const u8 {
            for (self.parameters) |parameter| {
                if (parameter.param_type == .state_cookie) return parameter.value;
            }
            return null;
        }
    };

    pub const GapAckBlock = struct {
        start: u16,
        end: u16,
    };

    pub const OutgoingSsnResetRequest = struct {
        request_sequence_number: u32,
        response_sequence_number: u32,
        sender_last_assigned_tsn: u32,
        stream_numbers: []const u16 = &.{},
    };

    pub const OutgoingSsnResetResponse = struct {
        response_sequence_number: u32,
        result: ReconfigResult,
    };

    pub const ReconfigParameter = union(enum) {
        outgoing_ssn_reset_request: OutgoingSsnResetRequest,
        outgoing_ssn_reset_response: OutgoingSsnResetResponse,
        unknown: struct { param_type: ReconfigParameterType, value: []const u8 },
    };

    pub const ReconfigChunk = struct {
        parameters: []ReconfigParameter,

        pub fn deinit(self: *ReconfigChunk, allocator: std.mem.Allocator) void {
            for (self.parameters) |parameter| {
                switch (parameter) {
                    .outgoing_ssn_reset_request => |request| {
                        if (!isConstEmptyU16(request.stream_numbers)) allocator.free(@constCast(request.stream_numbers));
                    },
                    else => {},
                }
            }
            allocator.free(self.parameters);
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!ReconfigChunk {
            if (chunk.chunk_type != .reconfig or chunk.flags != 0) return error.InvalidSctpPacket;
            var cursor = wire.Cursor.init(chunk.value);
            var params: std.ArrayList(ReconfigParameter) = .empty;
            errdefer {
                for (params.items) |*param| {
                    if (param.* == .outgoing_ssn_reset_request and !isConstEmptyU16(param.outgoing_ssn_reset_request.stream_numbers)) {
                        allocator.free(@constCast(param.outgoing_ssn_reset_request.stream_numbers));
                    }
                }
                params.deinit(allocator);
            }
            while (!cursor.eof()) {
                if (cursor.remaining() < 4) {
                    try validateZeroPadding(cursor.buf[cursor.pos..]);
                    break;
                }
                const raw_type = try cursor.readInt(u16, .big);
                const param_type: ReconfigParameterType = @enumFromInt(raw_type);
                const len = try cursor.readInt(u16, .big);
                if (len < 4 or cursor.remaining() < len - 4) return error.InvalidSctpPacket;
                const value = try cursor.readSlice(len - 4);
                switch (param_type) {
                    .outgoing_ssn_reset_request => try params.append(allocator, .{ .outgoing_ssn_reset_request = try parseOutgoingSsnResetRequest(allocator, value) }),
                    .outgoing_ssn_reset_response => try params.append(allocator, .{ .outgoing_ssn_reset_response = try parseOutgoingSsnResetResponse(value) }),
                    else => switch (raw_type & 0xc000) {
                        0x0000, 0x4000 => return error.InvalidSctpPacket,
                        0x8000, 0xc000 => {},
                        else => unreachable,
                    },
                }
                if (!try skipTlvPadding(&cursor, len)) break;
            }
            if (params.items.len == 0) return error.InvalidSctpPacket;
            return .{ .parameters = try params.toOwnedSlice(allocator) };
        }
    };

    pub const SackChunk = struct {
        cumulative_tsn_ack: u32,
        advertised_receiver_window_credit: u32,
        gap_ack_blocks: []GapAckBlock = &.{},
        duplicate_tsns: []const u32 = &.{},

        pub fn deinit(self: *SackChunk, allocator: std.mem.Allocator) void {
            allocator.free(self.gap_ack_blocks);
            if (!isConstEmptyU32(self.duplicate_tsns)) allocator.free(@constCast(self.duplicate_tsns));
            self.* = undefined;
        }

        pub fn parse(allocator: std.mem.Allocator, chunk: Chunk) Error!SackChunk {
            if (chunk.chunk_type != .sack or chunk.flags != 0 or chunk.value.len < 12) return error.InvalidSctpPacket;
            var cursor = wire.Cursor.init(chunk.value);
            const cumulative_tsn_ack = try cursor.readInt(u32, .big);
            const rwnd = try cursor.readInt(u32, .big);
            const gap_count = try cursor.readInt(u16, .big);
            const duplicate_count = try cursor.readInt(u16, .big);
            if (cursor.remaining() != @as(usize, gap_count) * 4 + @as(usize, duplicate_count) * 4) return error.InvalidSctpPacket;
            const gaps = try allocator.alloc(GapAckBlock, gap_count);
            errdefer allocator.free(gaps);
            for (gaps) |*gap| {
                gap.* = .{ .start = try cursor.readInt(u16, .big), .end = try cursor.readInt(u16, .big) };
                if (gap.start == 0 or gap.end < gap.start) return error.InvalidSctpPacket;
            }
            const duplicates = try allocator.alloc(u32, duplicate_count);
            errdefer allocator.free(duplicates);
            for (duplicates) |*tsn| tsn.* = try cursor.readInt(u32, .big);
            return .{
                .cumulative_tsn_ack = cumulative_tsn_ack,
                .advertised_receiver_window_credit = rwnd,
                .gap_ack_blocks = gaps,
                .duplicate_tsns = duplicates,
            };
        }
    };

    pub const DataChannelType = enum(u8) {
        reliable = 0x00,
        partial_reliable_retransmit = 0x01,
        partial_reliable_timed = 0x02,
        reliable_unordered = 0x80,
        partial_reliable_retransmit_unordered = 0x81,
        partial_reliable_timed_unordered = 0x82,
        _,

        pub fn unordered(self: DataChannelType) Error!bool {
            try validateDataChannelType(self);
            return (@intFromEnum(self) & 0x80) != 0;
        }

        pub fn reliabilityMode(self: DataChannelType) Error!DataChannelReliabilityMode {
            try validateDataChannelType(self);
            return switch (@intFromEnum(self) & 0x7f) {
                0x00 => .reliable,
                0x01 => .retransmit,
                0x02 => .timed,
                else => unreachable,
            };
        }
    };

    pub const DataChannelReliabilityMode = enum {
        reliable,
        retransmit,
        timed,
    };

    pub const DataChannelReliability = struct {
        unordered: bool,
        mode: DataChannelReliabilityMode,
        parameter: u32,
    };

    pub const DataChannelIdRole = enum {
        dtls_client,
        dtls_server,
    };

    pub const DataChannelIdRegistry = struct {
        allocator: std.mem.Allocator,
        used_ids: std.ArrayList(u16) = .empty,
        max_channels: u16,

        pub fn init(allocator: std.mem.Allocator, max_channels: u16) Error!DataChannelIdRegistry {
            if (max_channels == 0) return error.InvalidSctpPacket;
            return .{ .allocator = allocator, .max_channels = max_channels };
        }

        pub fn deinit(self: *DataChannelIdRegistry) void {
            self.used_ids.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn reserve(self: *DataChannelIdRegistry, id: u16) Error!void {
            if (id >= self.max_channels or dataChannelIdUsed(self.used_ids.items, id)) return error.InvalidSctpPacket;
            try self.used_ids.append(self.allocator, id);
        }

        pub fn release(self: *DataChannelIdRegistry, id: u16) void {
            for (self.used_ids.items, 0..) |used, index| {
                if (used == id) {
                    _ = self.used_ids.swapRemove(index);
                    return;
                }
            }
        }

        pub fn allocate(self: *DataChannelIdRegistry, role: DataChannelIdRole) Error!u16 {
            const id = try nextDataChannelId(role, self.used_ids.items, self.max_channels);
            try self.reserve(id);
            return id;
        }

        pub fn allocateForDtlsRole(self: *DataChannelIdRegistry, role: sdp.DtlsRole) Error!u16 {
            return self.allocate(try dataChannelIdRoleFromDtlsRole(role));
        }

        pub fn contains(self: DataChannelIdRegistry, id: u16) bool {
            return dataChannelIdUsed(self.used_ids.items, id);
        }
    };

    pub const DataChannelPayloadKind = enum {
        dcep,
        string,
        binary,
    };

    pub const DataChannelPayloadInfo = struct {
        kind: DataChannelPayloadKind,
        is_string: bool = false,
        empty: bool = false,
        /// Per RFC 8831/Pion, empty string/binary PPIDs carry one dummy SCTP
        /// byte that receivers ignore and surface as a zero-length message.
        effective_len: usize,
    };

    pub const DataChannelPayload = struct {
        info: DataChannelPayloadInfo,
        data: []const u8,
    };

    pub const DataChannelChunkOptions = struct {
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16 = 0,
        message_identifier: u32 = 0,
        reliability: DataChannelReliability = .{
            .unordered = false,
            .mode = .reliable,
            .parameter = 0,
        },
        interleaved: bool = false,
        is_string: bool = false,
        immediate_sack: bool = false,
    };

    pub const DataChannelFragmentOptions = struct {
        first_tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16 = 0,
        message_identifier: u32 = 0,
        reliability: DataChannelReliability = .{
            .unordered = false,
            .mode = .reliable,
            .parameter = 0,
        },
        interleaved: bool = false,
        is_string: bool = false,
        immediate_sack: bool = false,
        max_payload_size: usize,
    };

    pub const DataChannelOpen = struct {
        channel_type: DataChannelType = .reliable,
        priority: u16 = 0,
        reliability_parameter: u32 = 0,
        label: []const u8,
        protocol: []const u8 = &.{},

        pub fn reliability(self: DataChannelOpen) Error!DataChannelReliability {
            return dataChannelReliability(self.channel_type, self.reliability_parameter);
        }
    };

    pub const DataChannelSendState = struct {
        next_tsn: u32,
        stream_sequence_number: u16 = 0,
        next_ordered_message_id: u32 = 0,
        next_unordered_message_id: u32 = 0,

        pub fn fragmentMessage(
            self: *DataChannelSendState,
            allocator: std.mem.Allocator,
            stream_id: u16,
            reliability: DataChannelReliability,
            interleaved: bool,
            max_payload_size: usize,
            is_string: bool,
            user_data: []const u8,
        ) Error![]DataChunk {
            const message_id = if (interleaved) self.nextMessageId(reliability.unordered) else 0;
            const chunks = try fragmentDataChannelMessage(allocator, .{
                .first_tsn = self.next_tsn,
                .stream_id = stream_id,
                .stream_sequence_number = self.stream_sequence_number,
                .message_identifier = message_id,
                .reliability = reliability,
                .interleaved = interleaved,
                .is_string = is_string,
                .max_payload_size = max_payload_size,
            }, user_data);
            self.advanceAfterSend(chunks.len, reliability.unordered, interleaved);
            return chunks;
        }

        pub fn fragmentDcep(
            self: *DataChannelSendState,
            allocator: std.mem.Allocator,
            stream_id: u16,
            interleaved: bool,
            max_payload_size: usize,
            user_data: []const u8,
        ) Error![]DataChunk {
            const reliability = DataChannelReliability{ .unordered = false, .mode = .reliable, .parameter = 0 };
            const message_id = if (interleaved) self.nextMessageId(false) else 0;
            const chunks = try fragmentDcepMessage(allocator, .{
                .first_tsn = self.next_tsn,
                .stream_id = stream_id,
                .stream_sequence_number = self.stream_sequence_number,
                .message_identifier = message_id,
                .reliability = reliability,
                .interleaved = interleaved,
                .max_payload_size = max_payload_size,
            }, user_data);
            self.advanceAfterSend(chunks.len, false, interleaved);
            return chunks;
        }

        fn nextMessageId(self: *DataChannelSendState, unordered: bool) u32 {
            if (unordered) {
                const id = self.next_unordered_message_id;
                self.next_unordered_message_id +%= 1;
                return id;
            }
            const id = self.next_ordered_message_id;
            self.next_ordered_message_id +%= 1;
            return id;
        }

        fn advanceAfterSend(self: *DataChannelSendState, chunk_count: usize, unordered: bool, interleaved: bool) void {
            self.next_tsn +%= @intCast(chunk_count);
            // RFC 4960 section 6.6 / Pion-sctp: unordered non-interleaved DATA
            // does not consume the Stream Sequence Number.  I-DATA uses MID
            // spaces instead, so SSN remains unchanged there too.
            if (!interleaved and !unordered) self.stream_sequence_number +%= 1;
        }
    };

    pub const DataChannelMessage = union(enum) {
        open: DataChannelOpen,
        ack: void,
    };

    pub const ReassembledMessage = struct {
        stream_id: u16,
        stream_sequence_number: u16,
        unordered: bool,
        payload_protocol_identifier: PayloadProtocolIdentifier,
        data: []u8,

        pub fn deinit(self: *ReassembledMessage, allocator: std.mem.Allocator) void {
            allocator.free(self.data);
            self.* = undefined;
        }

        pub fn dataChannelPayload(self: ReassembledMessage) Error!DataChannelPayload {
            return sctp.dataChannelPayload(self.payload_protocol_identifier, self.data);
        }
    };

    pub const ReceiveState = struct {
        allocator: std.mem.Allocator,
        cumulative_tsn_ack: u32,
        advertised_receiver_window_credit: u32 = 256 * 1024,
        received: std.ArrayList(u32) = .empty,
        duplicates: std.ArrayList(u32) = .empty,
        max_tracked: usize = 4096,

        pub fn init(allocator: std.mem.Allocator, initial_cumulative_tsn: u32, advertised_receiver_window_credit: u32) ReceiveState {
            return .{
                .allocator = allocator,
                .cumulative_tsn_ack = initial_cumulative_tsn,
                .advertised_receiver_window_credit = advertised_receiver_window_credit,
            };
        }

        pub fn deinit(self: *ReceiveState) void {
            self.received.deinit(self.allocator);
            self.duplicates.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn observeData(self: *ReceiveState, chunk: DataChunk) Error!void {
            try self.observeTsn(chunk.tsn);
        }

        pub fn observeForwardTsn(self: *ReceiveState, forward_tsn: ForwardTsnChunk) void {
            if (tsnAfter(forward_tsn.new_cumulative_tsn, self.cumulative_tsn_ack)) {
                self.cumulative_tsn_ack = forward_tsn.new_cumulative_tsn;
                self.dropAckedTracked();
                self.advanceCumulativeAck();
            }
        }

        pub fn sack(self: ReceiveState, allocator: std.mem.Allocator) Error!SackChunk {
            const sorted = try allocator.dupe(u32, self.received.items);
            defer allocator.free(sorted);
            std.mem.sort(u32, sorted, {}, tsnLessThan);

            var gaps: std.ArrayList(GapAckBlock) = .empty;
            errdefer gaps.deinit(allocator);
            var i: usize = 0;
            while (i < sorted.len) {
                const start_tsn = sorted[i];
                if (!tsnAfter(start_tsn, self.cumulative_tsn_ack)) {
                    i += 1;
                    continue;
                }
                const start_delta = start_tsn -% self.cumulative_tsn_ack;
                if (start_delta == 0 or start_delta > std.math.maxInt(u16)) return error.InvalidSctpPacket;
                var end_tsn = start_tsn;
                i += 1;
                while (i < sorted.len and sorted[i] == end_tsn +% 1) : (i += 1) {
                    end_tsn = sorted[i];
                }
                const end_delta = end_tsn -% self.cumulative_tsn_ack;
                if (end_delta > std.math.maxInt(u16)) return error.InvalidSctpPacket;
                try gaps.append(allocator, .{ .start = @intCast(start_delta), .end = @intCast(end_delta) });
            }

            const dups = try allocator.dupe(u32, self.duplicates.items);
            errdefer allocator.free(dups);
            return .{
                .cumulative_tsn_ack = self.cumulative_tsn_ack,
                .advertised_receiver_window_credit = self.advertised_receiver_window_credit,
                .gap_ack_blocks = try gaps.toOwnedSlice(allocator),
                .duplicate_tsns = dups,
            };
        }

        pub fn clearDuplicates(self: *ReceiveState) void {
            self.duplicates.clearRetainingCapacity();
        }

        fn observeTsn(self: *ReceiveState, tsn: u32) Error!void {
            if (!tsnAfter(tsn, self.cumulative_tsn_ack)) {
                try self.noteDuplicate(tsn);
                return;
            }
            for (self.received.items) |existing| {
                if (existing == tsn) {
                    try self.noteDuplicate(tsn);
                    return;
                }
            }
            if (self.received.items.len >= self.max_tracked) return error.InvalidSctpPacket;
            try self.received.append(self.allocator, tsn);
            self.advanceCumulativeAck();
        }

        fn noteDuplicate(self: *ReceiveState, tsn: u32) Error!void {
            if (self.duplicates.items.len >= self.max_tracked) return;
            try self.duplicates.append(self.allocator, tsn);
        }

        fn advanceCumulativeAck(self: *ReceiveState) void {
            while (true) {
                const next = self.cumulative_tsn_ack +% 1;
                var found_index: ?usize = null;
                for (self.received.items, 0..) |tsn, i| {
                    if (tsn == next) {
                        found_index = i;
                        break;
                    }
                }
                if (found_index) |index| {
                    _ = self.received.swapRemove(index);
                    self.cumulative_tsn_ack = next;
                } else break;
            }
        }

        fn dropAckedTracked(self: *ReceiveState) void {
            var i: usize = 0;
            while (i < self.received.items.len) {
                if (!tsnAfter(self.received.items[i], self.cumulative_tsn_ack)) {
                    _ = self.received.swapRemove(i);
                    continue;
                }
                i += 1;
            }
        }
    };

    pub const Reassembler = struct {
        allocator: std.mem.Allocator,
        max_buffered: usize = 256 * 1024,
        fragments: std.ArrayList(OwnedFragment) = .empty,
        buffered_bytes: usize = 0,

        const OwnedFragment = struct {
            chunk: DataChunk,
            data: []u8,
        };

        pub fn init(allocator: std.mem.Allocator, max_buffered: usize) Reassembler {
            return .{ .allocator = allocator, .max_buffered = max_buffered };
        }

        pub fn deinit(self: *Reassembler) void {
            for (self.fragments.items) |fragment| self.allocator.free(fragment.data);
            self.fragments.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn push(self: *Reassembler, chunk: DataChunk) Error!?ReassembledMessage {
            if (chunk.beginning and chunk.ending) {
                const owned = try self.allocator.dupe(u8, chunk.user_data);
                return .{
                    .stream_id = chunk.stream_id,
                    .stream_sequence_number = chunk.stream_sequence_number,
                    .unordered = chunk.unordered,
                    .payload_protocol_identifier = chunk.payload_protocol_identifier,
                    .data = owned,
                };
            }

            try self.storeFragment(chunk);
            return try self.tryReassemble(chunk);
        }

        pub fn forwardTsn(self: *Reassembler, forward_tsn: ForwardTsnChunk) void {
            self.dropFragmentsThroughTsn(forward_tsn.new_cumulative_tsn);
            for (forward_tsn.skipped_streams) |stream| {
                self.dropIncompleteOrdered(stream.stream_id, stream.stream_sequence_number);
            }
        }

        pub fn forwardIForwardTsn(self: *Reassembler, forward_tsn: IForwardTsnChunk) void {
            self.dropFragmentsThroughTsn(forward_tsn.new_cumulative_tsn);
            for (forward_tsn.skipped_messages) |message| {
                self.dropIncompleteInterleaved(message.stream_id, message.unordered, message.message_identifier);
            }
        }

        fn storeFragment(self: *Reassembler, chunk: DataChunk) Error!void {
            const next_buffered = std.math.add(usize, self.buffered_bytes, chunk.user_data.len) catch return error.InvalidSctpPacket;
            if (next_buffered > self.max_buffered) return error.InvalidSctpPacket;

            for (self.fragments.items) |fragment| {
                if (fragment.chunk.tsn == chunk.tsn) return;
            }

            const data = try self.allocator.dupe(u8, chunk.user_data);
            errdefer self.allocator.free(data);
            try self.fragments.append(self.allocator, .{ .chunk = copyChunkWithData(chunk, data), .data = data });
            self.buffered_bytes = next_buffered;
        }

        fn tryReassemble(self: *Reassembler, target: DataChunk) Error!?ReassembledMessage {
            var begin_index: ?usize = null;
            var end_index: ?usize = null;
            for (self.fragments.items, 0..) |fragment, i| {
                if (!sameMessage(fragment.chunk, target)) continue;
                if (fragment.chunk.beginning) begin_index = i;
                if (fragment.chunk.ending) end_index = i;
            }
            const begin = begin_index orelse return null;
            _ = end_index orelse return null;

            var total_len: usize = 0;
            const begin_chunk = self.fragments.items[begin].chunk;
            const ppid = begin_chunk.payload_protocol_identifier;
            if (begin_chunk.interleaved) {
                var fsn: u32 = 0;
                while (true) : (fsn +%= 1) {
                    const index = self.findFragmentByFsn(begin_chunk, fsn) orelse return null;
                    const fragment = self.fragments.items[index];
                    if (fragment.chunk.beginning and fsn != 0) return error.InvalidSctpPacket;
                    total_len = std.math.add(usize, total_len, fragment.data.len) catch return error.InvalidSctpPacket;
                    if (fragment.chunk.ending) break;
                }
            } else {
                var current_tsn = begin_chunk.tsn;
                while (true) : (current_tsn +%= 1) {
                    const index = self.findFragmentIndex(current_tsn, begin_chunk) orelse return null;
                    const fragment = self.fragments.items[index];
                    if (fragment.chunk.payload_protocol_identifier != ppid) return error.InvalidSctpPacket;
                    total_len = std.math.add(usize, total_len, fragment.data.len) catch return error.InvalidSctpPacket;
                    if (fragment.chunk.ending) break;
                }
            }

            var data = try self.allocator.alloc(u8, total_len);
            errdefer self.allocator.free(data);
            var out_pos: usize = 0;
            if (begin_chunk.interleaved) {
                var fsn: u32 = 0;
                while (true) : (fsn +%= 1) {
                    const index = self.findFragmentByFsn(begin_chunk, fsn).?;
                    const fragment = self.fragments.items[index];
                    @memcpy(data[out_pos .. out_pos + fragment.data.len], fragment.data);
                    out_pos += fragment.data.len;
                    if (fragment.chunk.ending) break;
                }
            } else {
                var current_tsn = begin_chunk.tsn;
                while (true) : (current_tsn +%= 1) {
                    const index = self.findFragmentIndex(current_tsn, begin_chunk).?;
                    const fragment = self.fragments.items[index];
                    @memcpy(data[out_pos .. out_pos + fragment.data.len], fragment.data);
                    out_pos += fragment.data.len;
                    if (fragment.chunk.ending) break;
                }
            }

            self.removeMessageFragments(begin_chunk);
            return .{
                .stream_id = begin_chunk.stream_id,
                .stream_sequence_number = begin_chunk.stream_sequence_number,
                .unordered = begin_chunk.unordered,
                .payload_protocol_identifier = ppid,
                .data = data,
            };
        }

        fn findFragmentIndex(self: Reassembler, tsn: u32, target: DataChunk) ?usize {
            for (self.fragments.items, 0..) |fragment, i| {
                if (fragment.chunk.tsn == tsn and sameMessage(fragment.chunk, target)) return i;
            }
            return null;
        }

        fn findFragmentByFsn(self: Reassembler, target: DataChunk, fsn: u32) ?usize {
            for (self.fragments.items, 0..) |fragment, i| {
                if (fragment.chunk.fragment_sequence_number == fsn and sameMessage(fragment.chunk, target)) return i;
            }
            return null;
        }

        fn removeMessageFragments(self: *Reassembler, target: DataChunk) void {
            var i: usize = 0;
            while (i < self.fragments.items.len) {
                if (sameMessage(self.fragments.items[i].chunk, target)) {
                    self.removeFragmentAt(i);
                    continue;
                }
                i += 1;
            }
        }

        fn dropFragmentsThroughTsn(self: *Reassembler, cumulative_tsn: u32) void {
            var i: usize = 0;
            while (i < self.fragments.items.len) {
                if (!tsnAfter(self.fragments.items[i].chunk.tsn, cumulative_tsn)) {
                    self.removeFragmentAt(i);
                    continue;
                }
                i += 1;
            }
        }

        fn dropIncompleteOrdered(self: *Reassembler, stream_id: u16, last_ssn: u16) void {
            var i: usize = 0;
            while (i < self.fragments.items.len) {
                const chunk = self.fragments.items[i].chunk;
                if (!chunk.interleaved and !chunk.unordered and chunk.stream_id == stream_id and !ssnAfter(chunk.stream_sequence_number, last_ssn)) {
                    if (!self.messageComplete(chunk)) {
                        self.removeFragmentAt(i);
                        continue;
                    }
                }
                i += 1;
            }
        }

        fn dropIncompleteInterleaved(self: *Reassembler, stream_id: u16, unordered: bool, last_mid: u32) void {
            var i: usize = 0;
            while (i < self.fragments.items.len) {
                const chunk = self.fragments.items[i].chunk;
                if (chunk.interleaved and chunk.stream_id == stream_id and chunk.unordered == unordered and !tsnAfter(chunk.message_identifier, last_mid)) {
                    if (!self.messageComplete(chunk)) {
                        self.removeFragmentAt(i);
                        continue;
                    }
                }
                i += 1;
            }
        }

        fn messageComplete(self: Reassembler, target: DataChunk) bool {
            return self.tryReassembleable(target) catch false;
        }

        fn tryReassembleable(self: Reassembler, target: DataChunk) Error!bool {
            var begin_index: ?usize = null;
            var end_index: ?usize = null;
            for (self.fragments.items, 0..) |fragment, i| {
                if (!sameMessage(fragment.chunk, target)) continue;
                if (fragment.chunk.beginning) begin_index = i;
                if (fragment.chunk.ending) end_index = i;
            }
            const begin = begin_index orelse return false;
            _ = end_index orelse return false;
            const begin_chunk = self.fragments.items[begin].chunk;
            if (begin_chunk.interleaved) {
                var fsn: u32 = 0;
                while (true) : (fsn +%= 1) {
                    const index = self.findFragmentByFsn(begin_chunk, fsn) orelse return false;
                    const fragment = self.fragments.items[index];
                    if (fragment.chunk.beginning and fsn != 0) return error.InvalidSctpPacket;
                    if (fragment.chunk.ending) return true;
                }
            } else {
                const ppid = begin_chunk.payload_protocol_identifier;
                var current_tsn = begin_chunk.tsn;
                while (true) : (current_tsn +%= 1) {
                    const index = self.findFragmentIndex(current_tsn, begin_chunk) orelse return false;
                    const fragment = self.fragments.items[index];
                    if (fragment.chunk.payload_protocol_identifier != ppid) return error.InvalidSctpPacket;
                    if (fragment.chunk.ending) return true;
                }
            }
        }

        fn removeFragmentAt(self: *Reassembler, index: usize) void {
            const removed = self.fragments.swapRemove(index);
            self.buffered_bytes -= removed.data.len;
            self.allocator.free(removed.data);
        }

        fn sameMessage(chunk: DataChunk, target: DataChunk) bool {
            if (chunk.interleaved != target.interleaved) return false;
            if (chunk.stream_id != target.stream_id or chunk.unordered != target.unordered) return false;
            return if (chunk.interleaved)
                chunk.message_identifier == target.message_identifier
            else
                chunk.stream_sequence_number == target.stream_sequence_number;
        }

        fn copyChunkWithData(chunk: DataChunk, data: []const u8) DataChunk {
            var out = chunk;
            out.user_data = data;
            return out;
        }
    };

    pub fn parsePacket(allocator: std.mem.Allocator, bytes: []const u8, verify_checksum: bool) Error!ParsedPacket {
        if (bytes.len < 12) return error.BufferTooShort;
        const received_checksum = std.mem.readInt(u32, bytes[8..12], .little);
        // Pion/sctp's zero-checksum mode only relaxes packets whose checksum
        // field is actually zero.  If a peer sends a non-zero checksum, validate
        // it even when the DTLS zero-checksum extension is enabled so corrupt
        // packets cannot bypass integrity checks by toggling receive policy.
        if ((verify_checksum or packetRequiresChecksum(bytes) or received_checksum != 0) and !try validChecksum(bytes)) return error.BadSctpChecksum;
        const header = try Header.parse(bytes[0..12]);

        var chunks: std.ArrayList(Chunk) = .empty;
        errdefer chunks.deinit(allocator);
        var pos: usize = 12;
        var has_init_chunk = false;
        while (pos < bytes.len) {
            if (bytes.len - pos < 4) return error.InvalidSctpPacket;
            const raw_chunk_type = bytes[pos];
            const chunk_type: ChunkType = @enumFromInt(raw_chunk_type);
            const flags = bytes[pos + 1];
            const len = std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big);
            if (len < 4 or bytes.len - pos < len) return error.InvalidSctpPacket;
            const padded_len = align4(len);
            if (bytes.len - pos < padded_len) return error.InvalidSctpPacket;
            try validateZeroPadding(bytes[pos + len .. pos + padded_len]);
            if (chunk_type == .init or chunk_type == .init_ack) {
                if (pos != 12 or has_init_chunk or bytes.len != pos + padded_len) return error.InvalidSctpPacket;
                if (chunk_type == .init and std.mem.readInt(u32, bytes[4..8], .big) != 0) return error.InvalidSctpPacket;
                has_init_chunk = true;
            }
            if (chunk_type == .cookie_echo and pos != 12) return error.InvalidSctpPacket;
            if (!supportedChunkType(chunk_type)) {
                // RFC 4960 encodes unknown-chunk handling in the high two bits:
                // 00/01 stop processing this packet, 10/11 skip and continue
                // (optionally reporting an ERROR chunk).  This parser has no
                // association command queue for reports, but it can still keep
                // known chunks before/after skip-able unknown chunks usable.
                switch (raw_chunk_type & 0xc0) {
                    0x00, 0x40 => break,
                    0x80, 0xc0 => {
                        pos += padded_len;
                        continue;
                    },
                    else => unreachable,
                }
            }
            try chunks.append(allocator, .{
                .chunk_type = chunk_type,
                .flags = flags,
                .value = bytes[pos + 4 .. pos + len],
                .consumed = padded_len,
            });
            pos += padded_len;
        }
        return .{ .header = header, .chunks = try chunks.toOwnedSlice(allocator) };
    }

    pub fn packetRequiresChecksum(bytes: []const u8) bool {
        if (bytes.len < 16) return false;
        const first_chunk_type: ChunkType = @enumFromInt(bytes[12]);
        return first_chunk_type == .init or first_chunk_type == .cookie_echo;
    }

    fn supportedChunkType(chunk_type: ChunkType) bool {
        return switch (chunk_type) {
            .data,
            .init,
            .init_ack,
            .sack,
            .heartbeat,
            .heartbeat_ack,
            .abort,
            .shutdown,
            .shutdown_ack,
            .error_chunk,
            .cookie_echo,
            .cookie_ack,
            .reconfig,
            .i_data,
            .forward_tsn,
            .i_forward_tsn,
            .shutdown_complete,
            => true,
            _ => false,
        };
    }

    pub fn writeInitPacket(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        options: PacketOptions,
        is_ack: bool,
        init: InitChunk,
    ) Error!void {
        if (!is_ack and options.verification_tag != 0) return error.InvalidSctpPacket;
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeInitChunk(list, allocator, if (is_ack) .init_ack else .init, init);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeInitChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunk_type: ChunkType, init: InitChunk) Error!void {
        if (chunk_type != .init and chunk_type != .init_ack) return error.InvalidSctpPacket;
        try validateInitFixedFields(init.initiate_tag, init.advertised_receiver_window_credit, init.outbound_streams, init.inbound_streams);
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(allocator);
        try wire.appendInt(&value, allocator, u32, init.initiate_tag, .big);
        try wire.appendInt(&value, allocator, u32, init.advertised_receiver_window_credit, .big);
        try wire.appendInt(&value, allocator, u16, init.outbound_streams, .big);
        try wire.appendInt(&value, allocator, u16, init.inbound_streams, .big);
        try wire.appendInt(&value, allocator, u32, init.initial_tsn, .big);
        for (init.parameters, 0..) |parameter, index| {
            const len = try writeInitParameter(&value, allocator, parameter);
            if (index + 1 != init.parameters.len) try appendTlvPadding(&value, allocator, len);
        }
        const chunk_len = 4 + value.items.len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(chunk_type));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try list.appendSlice(allocator, value.items);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    fn validateInitFixedFields(initiate_tag: u32, advertised_receiver_window_credit: u32, outbound_streams: u16, inbound_streams: u16) Error!void {
        // RFC 4960/Pion-sctp reject INIT/INIT-ACK chunks that cannot establish
        // a usable association.  Keeping this at the codec boundary catches
        // malformed browser/DataChannel handshakes before any association state
        // is derived from zero tags or zero stream counts.
        if (initiate_tag == 0) return error.InvalidSctpPacket;
        if (outbound_streams == 0 or inbound_streams == 0) return error.InvalidSctpPacket;
        if (advertised_receiver_window_credit < 1500) return error.InvalidSctpPacket;
    }

    pub fn writeAbortPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, t_bit: bool, causes: []const ErrorCause) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeAbortChunk(list, allocator, t_bit, causes);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeAbortChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, t_bit: bool, causes: []const ErrorCause) Error!void {
        try writeErrorLikeChunk(list, allocator, .abort, if (t_bit) 0x01 else 0x00, causes);
    }

    pub fn writeErrorPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, causes: []const ErrorCause) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeErrorChunk(list, allocator, causes);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeErrorChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, causes: []const ErrorCause) Error!void {
        if (causes.len == 0) return error.InvalidSctpPacket;
        try writeErrorLikeChunk(list, allocator, .error_chunk, 0, causes);
    }

    pub fn writeHeartbeatPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, ack: bool, info: []const u8) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeHeartbeatChunk(list, allocator, ack, info);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeHeartbeatChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, ack: bool, info: []const u8) Error!void {
        const param_len = 4 + info.len;
        const chunk_len = 4 + param_len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(if (ack) ChunkType.heartbeat_ack else ChunkType.heartbeat));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        // HEARTBEAT and HEARTBEAT-ACK bodies contain exactly one Heartbeat
        // Info variable parameter.  Keep the API focused on the opaque info
        // bytes, but serialize the TLV that RFC 9260 and Pion/sctp expect.
        try wire.appendInt(list, allocator, u16, @intFromEnum(InitParameterType.heartbeat_info), .big);
        try wire.appendInt(list, allocator, u16, @intCast(param_len), .big);
        try list.appendSlice(allocator, info);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn writeShutdownPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, cumulative_tsn_ack: u32) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeShutdownChunk(list, allocator, cumulative_tsn_ack);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeShutdownChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, cumulative_tsn_ack: u32) Error!void {
        try list.append(allocator, @intFromEnum(ChunkType.shutdown));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, 8, .big);
        try wire.appendInt(list, allocator, u32, cumulative_tsn_ack, .big);
    }

    pub fn writeShutdownAckPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeShutdownAckChunk(list, allocator);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeShutdownAckChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try list.append(allocator, @intFromEnum(ChunkType.shutdown_ack));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, 4, .big);
    }

    pub fn writeShutdownCompletePacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, t_bit: bool) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeShutdownCompleteChunk(list, allocator, t_bit);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeShutdownCompleteChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, t_bit: bool) Error!void {
        try list.append(allocator, @intFromEnum(ChunkType.shutdown_complete));
        try list.append(allocator, if (t_bit) 0x01 else 0x00);
        try wire.appendInt(list, allocator, u16, 4, .big);
    }

    pub fn validateEmptyControlChunk(chunk: Chunk, expected: ChunkType) Error!void {
        if (chunk.chunk_type != expected or chunk.value.len != 0) return error.InvalidSctpPacket;
        switch (expected) {
            .shutdown_ack => if (chunk.flags != 0) return error.InvalidSctpPacket,
            .shutdown_complete => if ((chunk.flags & ~@as(u8, 0x01)) != 0) return error.InvalidSctpPacket,
            .cookie_ack => if (chunk.flags != 0) return error.InvalidSctpPacket,
            else => return error.InvalidSctpPacket,
        }
    }

    pub fn writeCookieEchoPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, cookie: []const u8) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeCookieEchoChunk(list, allocator, cookie);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeCookieEchoChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, cookie: []const u8) Error!void {
        if (cookie.len == 0) return error.InvalidSctpPacket;
        const chunk_len = 4 + cookie.len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(ChunkType.cookie_echo));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try list.appendSlice(allocator, cookie);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn writeCookieAckPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeCookieAckChunk(list, allocator);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeCookieAckChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try list.append(allocator, @intFromEnum(ChunkType.cookie_ack));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, 4, .big);
    }

    pub fn cookieEchoValue(chunk: Chunk) Error![]const u8 {
        if (chunk.chunk_type != .cookie_echo or chunk.flags != 0 or chunk.value.len == 0) return error.InvalidSctpPacket;
        return chunk.value;
    }

    pub fn validateCookieAck(chunk: Chunk) Error!void {
        try validateEmptyControlChunk(chunk, .cookie_ack);
    }

    pub fn writeForwardTsnPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, forward_tsn: ForwardTsnChunk) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeForwardTsnChunk(list, allocator, forward_tsn);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeForwardTsnChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, forward_tsn: ForwardTsnChunk) Error!void {
        if (forward_tsn.skipped_streams.len > (std.math.maxInt(u16) - 8) / 4) return error.InvalidSctpPacket;
        const chunk_len = 8 + forward_tsn.skipped_streams.len * 4;
        try list.append(allocator, @intFromEnum(ChunkType.forward_tsn));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try wire.appendInt(list, allocator, u32, forward_tsn.new_cumulative_tsn, .big);
        for (forward_tsn.skipped_streams) |stream| {
            try wire.appendInt(list, allocator, u16, stream.stream_id, .big);
            try wire.appendInt(list, allocator, u16, stream.stream_sequence_number, .big);
        }
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn writeIForwardTsnPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, forward_tsn: IForwardTsnChunk) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeIForwardTsnChunk(list, allocator, forward_tsn);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeIForwardTsnChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, forward_tsn: IForwardTsnChunk) Error!void {
        if (forward_tsn.skipped_messages.len > (std.math.maxInt(u16) - 8) / 8) return error.InvalidSctpPacket;
        var normalized: std.ArrayList(SkippedMessage) = .empty;
        defer normalized.deinit(allocator);
        for (forward_tsn.skipped_messages) |message| try appendSkippedMessageNormalized(&normalized, allocator, message);

        const chunk_len = 8 + normalized.items.len * 8;
        try list.append(allocator, @intFromEnum(ChunkType.i_forward_tsn));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try wire.appendInt(list, allocator, u32, forward_tsn.new_cumulative_tsn, .big);
        for (normalized.items) |message| {
            try wire.appendInt(list, allocator, u16, message.stream_id, .big);
            try wire.appendInt(list, allocator, u16, if (message.unordered) @as(u16, 1) else @as(u16, 0), .big);
            try wire.appendInt(list, allocator, u32, message.message_identifier, .big);
        }
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn writeReconfigPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions, parameters: []const ReconfigParameter) Error!void {
        if (parameters.len == 0) return error.InvalidSctpPacket;
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeReconfigChunk(list, allocator, parameters);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeDataChannelResetPacket(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        options: PacketOptions,
        stream_id: u16,
        request_sequence_number: u32,
        response_sequence_number: u32,
        sender_last_assigned_tsn: u32,
    ) Error!void {
        const streams = [_]u16{stream_id};
        try writeReconfigPacket(list, allocator, options, &.{.{ .outgoing_ssn_reset_request = .{
            .request_sequence_number = request_sequence_number,
            .response_sequence_number = response_sequence_number,
            .sender_last_assigned_tsn = sender_last_assigned_tsn,
            .stream_numbers = &streams,
        } }});
    }

    pub fn writeDataChannelResetResponsePacket(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        options: PacketOptions,
        response_sequence_number: u32,
        result: ReconfigResult,
    ) Error!void {
        try writeReconfigPacket(list, allocator, options, &.{.{ .outgoing_ssn_reset_response = .{
            .response_sequence_number = response_sequence_number,
            .result = result,
        } }});
    }

    pub fn writeReconfigChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, parameters: []const ReconfigParameter) Error!void {
        if (parameters.len == 0) return error.InvalidSctpPacket;
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(allocator);
        for (parameters, 0..) |parameter, index| {
            const len = try writeReconfigParameter(&value, allocator, parameter);
            if (index + 1 != parameters.len) try appendTlvPadding(&value, allocator, len);
        }
        const chunk_len = 4 + value.items.len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(ChunkType.reconfig));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try list.appendSlice(allocator, value.items);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn writeSackPacket(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        options: PacketOptions,
        sack: SackChunk,
    ) Error!void {
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        try writeSackChunk(list, allocator, sack);
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeSackChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, sack: SackChunk) Error!void {
        if (sack.gap_ack_blocks.len > std.math.maxInt(u16) or sack.duplicate_tsns.len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        const chunk_len = 16 + sack.gap_ack_blocks.len * 4 + sack.duplicate_tsns.len * 4;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(ChunkType.sack));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try wire.appendInt(list, allocator, u32, sack.cumulative_tsn_ack, .big);
        try wire.appendInt(list, allocator, u32, sack.advertised_receiver_window_credit, .big);
        try wire.appendInt(list, allocator, u16, @intCast(sack.gap_ack_blocks.len), .big);
        try wire.appendInt(list, allocator, u16, @intCast(sack.duplicate_tsns.len), .big);
        for (sack.gap_ack_blocks) |gap| {
            if (gap.start == 0 or gap.end < gap.start) return error.InvalidSctpPacket;
            try wire.appendInt(list, allocator, u16, gap.start, .big);
            try wire.appendInt(list, allocator, u16, gap.end, .big);
        }
        for (sack.duplicate_tsns) |tsn| try wire.appendInt(list, allocator, u32, tsn, .big);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn writeDataPacket(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        options: PacketOptions,
        chunks: []const DataChunk,
    ) Error!void {
        if (chunks.len == 0) return error.InvalidSctpPacket;
        const start = list.items.len;
        try writePacketHeader(list, allocator, options);
        for (chunks) |chunk| try writeDataChunk(list, allocator, chunk);

        // SCTP stores the CRC32C checksum in little-endian form and computes it
        // with the checksum field itself zeroed.  This mirrors the kernel SCTP
        // implementation's libcrc32c path and lets the codec catch corruption
        // before upper layers parse DCEP or user data.
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeDataChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunk: DataChunk) Error!void {
        const value_len = (if (chunk.interleaved) @as(usize, 16) else @as(usize, 12)) + chunk.user_data.len;
        const chunk_len = 4 + value_len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        if (chunk.interleaved and !chunk.beginning and chunk.fragment_sequence_number == 0) return error.InvalidSctpPacket;
        // DCEP OPEN/ACK traffic is the control plane for WebRTC data channels.
        // Pion/datachannel always emits it ordered and reliable, regardless of
        // the negotiated user-data channel reliability.  The DATA chunk only
        // carries the unordered bit, so prevent the codec from generating the
        // one visible DCEP reliability violation here.
        if (chunk.payload_protocol_identifier == .webrtc_dcep and chunk.unordered) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(if (chunk.interleaved) ChunkType.i_data else ChunkType.data));
        try list.append(allocator, chunk.flags());
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try wire.appendInt(list, allocator, u32, chunk.tsn, .big);
        try wire.appendInt(list, allocator, u16, chunk.stream_id, .big);
        if (chunk.interleaved) {
            // RFC 8260 I-DATA replaces SSN with a reserved field plus a
            // Message Identifier.  The fourth word carries the PPID only on the
            // beginning fragment; subsequent fragments carry the Fragment
            // Sequence Number.  Pion/sctp follows the same layout.
            try wire.appendInt(list, allocator, u16, 0, .big);
            try wire.appendInt(list, allocator, u32, chunk.message_identifier, .big);
            try wire.appendInt(
                list,
                allocator,
                u32,
                if (chunk.beginning) @intFromEnum(chunk.payload_protocol_identifier) else chunk.fragment_sequence_number,
                .big,
            );
        } else {
            try wire.appendInt(list, allocator, u16, chunk.stream_sequence_number, .big);
            try wire.appendInt(list, allocator, u32, @intFromEnum(chunk.payload_protocol_identifier), .big);
        }
        try list.appendSlice(allocator, chunk.user_data);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    pub fn checksum(bytes: []const u8) Error!u32 {
        if (bytes.len < 12) return error.BufferTooShort;
        var crc = std.hash.crc.Crc32Iscsi.init();
        crc.update(bytes[0..8]);
        crc.update(&[_]u8{ 0, 0, 0, 0 });
        crc.update(bytes[12..]);
        return crc.final();
    }

    pub fn validChecksum(bytes: []const u8) Error!bool {
        if (bytes.len < 12) return error.BufferTooShort;
        const expected = try checksum(bytes);
        const actual = std.mem.readInt(u32, bytes[8..12], .little);
        return expected == actual;
    }

    fn writePacketHeader(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: PacketOptions) Error!void {
        try validatePacketPorts(options.source_port, options.destination_port);
        try wire.appendInt(list, allocator, u16, options.source_port, .big);
        try wire.appendInt(list, allocator, u16, options.destination_port, .big);
        try wire.appendInt(list, allocator, u32, options.verification_tag, .big);
        try wire.appendInt(list, allocator, u32, 0, .little);
    }

    fn validatePacketPorts(source_port: u16, destination_port: u16) Error!void {
        // Pion/sctp rejects packets with either SCTP port set to zero before
        // association dispatch.  Enforce the same invariant in the stateless
        // codec so generated packets are routable and parsed packets cannot be
        // mistaken for an application association.
        if (source_port == 0 or destination_port == 0) return error.InvalidSctpPacket;
    }

    fn parseErrorCauses(allocator: std.mem.Allocator, bytes: []const u8) Error![]ErrorCause {
        var cursor = wire.Cursor.init(bytes);
        var causes: std.ArrayList(ErrorCause) = .empty;
        errdefer causes.deinit(allocator);
        while (!cursor.eof()) {
            if (cursor.remaining() < 4) {
                try validateZeroPadding(cursor.buf[cursor.pos..]);
                break;
            }
            const code: ErrorCauseCode = @enumFromInt(try cursor.readInt(u16, .big));
            const len = try cursor.readInt(u16, .big);
            if (len < 4 or cursor.remaining() < len - 4) return error.InvalidSctpPacket;
            const value = try cursor.readSlice(len - 4);
            try causes.append(allocator, .{ .code = code, .value = value });
            if (!try skipTlvPadding(&cursor, len)) break;
        }
        return causes.toOwnedSlice(allocator);
    }

    fn writeErrorLikeChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunk_type: ChunkType, flags: u8, causes: []const ErrorCause) Error!void {
        if (chunk_type != .abort and chunk_type != .error_chunk) return error.InvalidSctpPacket;
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(allocator);
        for (causes, 0..) |cause, index| {
            const len = try writeErrorCause(&value, allocator, cause);
            if (index + 1 != causes.len) try appendTlvPadding(&value, allocator, len);
        }
        const chunk_len = 4 + value.items.len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(chunk_type));
        try list.append(allocator, flags);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try list.appendSlice(allocator, value.items);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    fn writeErrorCause(list: *std.ArrayList(u8), allocator: std.mem.Allocator, cause: ErrorCause) Error!usize {
        const len = 4 + cause.value.len;
        if (len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try wire.appendInt(list, allocator, u16, @intFromEnum(cause.code), .big);
        try wire.appendInt(list, allocator, u16, @intCast(len), .big);
        try list.appendSlice(allocator, cause.value);
        return len;
    }

    fn parseInitParameters(allocator: std.mem.Allocator, bytes: []const u8) Error![]InitParameter {
        var cursor = wire.Cursor.init(bytes);
        var params: std.ArrayList(InitParameter) = .empty;
        errdefer params.deinit(allocator);
        while (!cursor.eof()) {
            if (cursor.remaining() < 4) {
                try validateZeroPadding(cursor.buf[cursor.pos..]);
                break;
            }
            const raw_type = try cursor.readInt(u16, .big);
            const param_type: InitParameterType = @enumFromInt(raw_type);
            const len = try cursor.readInt(u16, .big);
            if (len < 4 or cursor.remaining() < len - 4) return error.InvalidSctpPacket;
            const value = try cursor.readSlice(len - 4);
            if (knownInitParameter(param_type)) {
                if (param_type == .zero_checksum_acceptable and value.len != 4) return error.InvalidSctpPacket;
                try params.append(allocator, .{ .param_type = param_type, .value = value });
            } else {
                switch (raw_type & 0xc000) {
                    0x0000, 0x4000 => return error.InvalidSctpPacket,
                    0x8000, 0xc000 => {},
                    else => unreachable,
                }
            }
            if (!try skipTlvPadding(&cursor, len)) break;
        }
        return params.toOwnedSlice(allocator);
    }

    fn knownInitParameter(param_type: InitParameterType) bool {
        return switch (param_type) {
            .heartbeat_info,
            .unrecognized_parameters,
            .state_cookie,
            .outgoing_ssn_reset_request,
            .reconfig_response,
            .ecn_capable,
            .zero_checksum_acceptable,
            .random,
            .chunk_list,
            .requested_hmac_algorithm,
            .supported_extensions,
            .forward_tsn_supported,
            .supported_address_types,
            => true,
            _ => false,
        };
    }

    fn writeInitParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, parameter: InitParameter) Error!usize {
        const len = 4 + parameter.value.len;
        if (len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try wire.appendInt(list, allocator, u16, @intFromEnum(parameter.param_type), .big);
        try wire.appendInt(list, allocator, u16, @intCast(len), .big);
        try list.appendSlice(allocator, parameter.value);
        return len;
    }

    fn parseOutgoingSsnResetRequest(allocator: std.mem.Allocator, value: []const u8) Error!OutgoingSsnResetRequest {
        if (value.len < 12 or (value.len % 2) != 0) return error.InvalidSctpPacket;
        var cursor = wire.Cursor.init(value);
        const request_sequence_number = try cursor.readInt(u32, .big);
        const response_sequence_number = try cursor.readInt(u32, .big);
        const sender_last_assigned_tsn = try cursor.readInt(u32, .big);
        const count = cursor.remaining() / 2;
        const streams = try allocator.alloc(u16, count);
        errdefer allocator.free(streams);
        for (streams) |*stream| stream.* = try cursor.readInt(u16, .big);
        return .{
            .request_sequence_number = request_sequence_number,
            .response_sequence_number = response_sequence_number,
            .sender_last_assigned_tsn = sender_last_assigned_tsn,
            .stream_numbers = streams,
        };
    }

    fn parseOutgoingSsnResetResponse(value: []const u8) Error!OutgoingSsnResetResponse {
        if (value.len != 8) return error.InvalidSctpPacket;
        return .{
            .response_sequence_number = std.mem.readInt(u32, value[0..4], .big),
            .result = @enumFromInt(std.mem.readInt(u32, value[4..8], .big)),
        };
    }

    fn writeReconfigParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, parameter: ReconfigParameter) Error!usize {
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(allocator);
        const param_type: ReconfigParameterType = switch (parameter) {
            .outgoing_ssn_reset_request => |request| blk: {
                try wire.appendInt(&value, allocator, u32, request.request_sequence_number, .big);
                try wire.appendInt(&value, allocator, u32, request.response_sequence_number, .big);
                try wire.appendInt(&value, allocator, u32, request.sender_last_assigned_tsn, .big);
                for (request.stream_numbers) |stream| try wire.appendInt(&value, allocator, u16, stream, .big);
                break :blk .outgoing_ssn_reset_request;
            },
            .outgoing_ssn_reset_response => |response| blk: {
                try wire.appendInt(&value, allocator, u32, response.response_sequence_number, .big);
                try wire.appendInt(&value, allocator, u32, @intFromEnum(response.result), .big);
                break :blk .outgoing_ssn_reset_response;
            },
            .unknown => |unknown| blk: {
                try value.appendSlice(allocator, unknown.value);
                break :blk unknown.param_type;
            },
        };
        const len = 4 + value.items.len;
        if (len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try wire.appendInt(list, allocator, u16, @intFromEnum(param_type), .big);
        try wire.appendInt(list, allocator, u16, @intCast(len), .big);
        try list.appendSlice(allocator, value.items);
        return len;
    }

    fn isConstEmptyU16(value: []const u16) bool {
        return value.ptr == (&[_]u16{}).ptr and value.len == 0;
    }

    fn appendSkippedMessageNormalized(list: *std.ArrayList(SkippedMessage), allocator: std.mem.Allocator, message: SkippedMessage) Error!void {
        for (list.items) |*existing| {
            if (existing.stream_id == message.stream_id and existing.unordered == message.unordered) {
                if (tsnAfter(message.message_identifier, existing.message_identifier)) {
                    existing.message_identifier = message.message_identifier;
                }
                return;
            }
        }
        try list.append(allocator, message);
    }

    fn appendTlvPadding(list: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) Error!void {
        try list.appendNTimes(allocator, 0, align4(len) - len);
    }

    fn skipTlvPadding(cursor: *wire.Cursor, len: usize) Error!bool {
        const padding = align4(len) - len;
        if (cursor.remaining() < padding) {
            // Mature SCTP encoders such as Pion omit padding for the final
            // variable-length parameter/cause from the chunk length; that
            // padding is packet chunk padding instead and has already been
            // stripped by parsePacket.  Accept the truncated-final-padding
            // form as long as any bytes still present are zero.
            try validateZeroPadding(cursor.buf[cursor.pos..]);
            return false;
        }
        try validateZeroPadding(cursor.buf[cursor.pos .. cursor.pos + padding]);
        try cursor.skip(padding);
        return true;
    }

    fn validateZeroPadding(bytes: []const u8) Error!void {
        for (bytes) |byte| {
            if (byte != 0) return error.InvalidSctpPacket;
        }
    }

    pub fn dataChannelPayloadProtocol(is_string: bool, len: usize) PayloadProtocolIdentifier {
        if (is_string) return if (len == 0) .webrtc_string_empty else .webrtc_string;
        return if (len == 0) .webrtc_binary_empty else .webrtc_binary;
    }

    pub fn dataChannelPayloadInfo(ppid: PayloadProtocolIdentifier, user_data_len: usize) Error!DataChannelPayloadInfo {
        return switch (ppid) {
            .webrtc_dcep => .{ .kind = .dcep, .effective_len = user_data_len },
            .webrtc_string => .{ .kind = .string, .is_string = true, .effective_len = user_data_len },
            .webrtc_binary => .{ .kind = .binary, .effective_len = user_data_len },
            .webrtc_string_empty => blk: {
                try validateEmptyDataChannelPayloadLength(user_data_len);
                break :blk .{ .kind = .string, .is_string = true, .empty = true, .effective_len = 0 };
            },
            .webrtc_binary_empty => blk: {
                try validateEmptyDataChannelPayloadLength(user_data_len);
                break :blk .{ .kind = .binary, .empty = true, .effective_len = 0 };
            },
            _ => error.InvalidSctpPacket,
        };
    }

    fn validateEmptyDataChannelPayloadLength(user_data_len: usize) Error!void {
        // RFC 8831 / Pion datachannel encodes empty string/binary messages with
        // special PPIDs and a single dummy payload byte.  A packet carrying the
        // empty PPID without exactly that placeholder is malformed; otherwise a
        // truncated SCTP DATA chunk would be indistinguishable from a legitimate
        // empty message.
        if (user_data_len != 1) return error.InvalidSctpPacket;
    }

    pub fn dataChannelPayload(ppid: PayloadProtocolIdentifier, user_data: []const u8) Error!DataChannelPayload {
        const info = try dataChannelPayloadInfo(ppid, user_data.len);
        return .{
            .info = info,
            .data = if (info.empty) user_data[0..0] else user_data[0..info.effective_len],
        };
    }

    pub fn dataChannelChunk(options: DataChannelChunkOptions, user_data: []const u8) DataChunk {
        const ppid = dataChannelPayloadProtocol(options.is_string, user_data.len);
        const empty = user_data.len == 0;
        const payload = if (empty) &[_]u8{0} else user_data;
        return .{
            .unordered = ppid != .webrtc_dcep and options.reliability.unordered,
            .interleaved = options.interleaved,
            .immediate_sack = options.immediate_sack,
            .tsn = options.tsn,
            .stream_id = options.stream_id,
            .stream_sequence_number = options.stream_sequence_number,
            .message_identifier = options.message_identifier,
            .payload_protocol_identifier = ppid,
            .user_data = payload,
        };
    }

    pub fn dataChannelDcepChunk(options: DataChannelChunkOptions, user_data: []const u8) DataChunk {
        // Pion/sctp follows the DCEP requirement from draft-ietf-rtcweb-data-
        // protocol section 6: DATA_CHANNEL_OPEN/ACK messages are always sent
        // with ordered, reliable delivery, even when the negotiated user data
        // channel itself is unordered or partially reliable.
        return .{
            .unordered = false,
            .interleaved = options.interleaved,
            .immediate_sack = options.immediate_sack,
            .tsn = options.tsn,
            .stream_id = options.stream_id,
            .stream_sequence_number = options.stream_sequence_number,
            .message_identifier = options.message_identifier,
            .payload_protocol_identifier = .webrtc_dcep,
            .user_data = user_data,
        };
    }

    pub fn fragmentDataChannelMessage(allocator: std.mem.Allocator, options: DataChannelFragmentOptions, user_data: []const u8) Error![]DataChunk {
        if (options.max_payload_size == 0) return error.InvalidSctpPacket;
        const ppid = dataChannelPayloadProtocol(options.is_string, user_data.len);
        const payload = if (user_data.len == 0) &[_]u8{0} else user_data;
        const chunk_count = (payload.len + options.max_payload_size - 1) / options.max_payload_size;
        const chunks = try allocator.alloc(DataChunk, chunk_count);
        errdefer allocator.free(chunks);

        var offset: usize = 0;
        for (chunks, 0..) |*chunk, index| {
            const remaining = payload.len - offset;
            const fragment_len = @min(options.max_payload_size, remaining);
            const beginning = index == 0;
            const ending = offset + fragment_len == payload.len;
            chunk.* = .{
                .unordered = options.reliability.unordered,
                .beginning = beginning,
                .ending = ending,
                .immediate_sack = options.immediate_sack,
                .interleaved = options.interleaved,
                .tsn = options.first_tsn +% @as(u32, @intCast(index)),
                .stream_id = options.stream_id,
                .stream_sequence_number = if (options.interleaved) @truncate(options.message_identifier) else options.stream_sequence_number,
                .message_identifier = options.message_identifier,
                .fragment_sequence_number = @intCast(index),
                .payload_protocol_identifier = if (!options.interleaved or beginning) ppid else @enumFromInt(@as(u32, 0)),
                .user_data = payload[offset .. offset + fragment_len],
            };
            offset += fragment_len;
        }
        return chunks;
    }

    pub fn fragmentDcepMessage(allocator: std.mem.Allocator, options: DataChannelFragmentOptions, user_data: []const u8) Error![]DataChunk {
        if (options.max_payload_size == 0 or user_data.len == 0) return error.InvalidSctpPacket;
        var ordered_options = options;
        ordered_options.reliability.unordered = false;
        const chunks = try fragmentDataChannelMessage(allocator, ordered_options, user_data);
        for (chunks, 0..) |*chunk, index| {
            chunk.unordered = false;
            chunk.payload_protocol_identifier = if (!ordered_options.interleaved or index == 0) .webrtc_dcep else @enumFromInt(@as(u32, 0));
        }
        return chunks;
    }

    pub fn freeDataChannelFragments(allocator: std.mem.Allocator, chunks: []DataChunk) void {
        allocator.free(chunks);
    }

    pub fn dataChannelReliability(channel_type: DataChannelType, reliability_parameter: u32) Error!DataChannelReliability {
        return .{
            .unordered = try channel_type.unordered(),
            .mode = try channel_type.reliabilityMode(),
            .parameter = reliability_parameter,
        };
    }

    pub fn nextDataChannelId(role: DataChannelIdRole, used_ids: []const u16, max_channels: u16) Error!u16 {
        if (max_channels == 0) return error.InvalidSctpPacket;
        var candidate: u16 = switch (role) {
            .dtls_client => 0,
            .dtls_server => 1,
        };
        while (candidate < max_channels) : (candidate +%= 2) {
            if (!dataChannelIdUsed(used_ids, candidate)) return candidate;
            if (candidate > std.math.maxInt(u16) - 2) break;
        }
        return error.InvalidSctpPacket;
    }

    pub fn dataChannelIdRoleFromDtlsRole(role: sdp.DtlsRole) Error!DataChannelIdRole {
        return switch (role) {
            .client => .dtls_client,
            .server => .dtls_server,
            .auto => error.InvalidSctpPacket,
        };
    }

    pub fn nextDataChannelIdForDtlsRole(role: sdp.DtlsRole, used_ids: []const u16, max_channels: u16) Error!u16 {
        return nextDataChannelId(try dataChannelIdRoleFromDtlsRole(role), used_ids, max_channels);
    }

    pub fn writeDcepOpen(list: *std.ArrayList(u8), allocator: std.mem.Allocator, open: DataChannelOpen) Error!void {
        if (open.label.len > std.math.maxInt(u16) or open.protocol.len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try validateDataChannelType(open.channel_type);
        try validateDcepString(open.label);
        try validateDcepString(open.protocol);
        try list.append(allocator, 0x03); // DATA_CHANNEL_OPEN
        try list.append(allocator, @intFromEnum(open.channel_type));
        try wire.appendInt(list, allocator, u16, open.priority, .big);
        try wire.appendInt(list, allocator, u32, open.reliability_parameter, .big);
        try wire.appendInt(list, allocator, u16, @intCast(open.label.len), .big);
        try wire.appendInt(list, allocator, u16, @intCast(open.protocol.len), .big);
        try list.appendSlice(allocator, open.label);
        try list.appendSlice(allocator, open.protocol);
    }

    pub fn writeDcepAck(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        // Pion/datachannel serializes ACK as the message type followed by the
        // three reserved bytes from the DCEP common header.  Accepting the
        // historical one-byte form on parse keeps old fixtures working, but
        // emit the interoperable 4-byte wire image.
        try list.appendSlice(allocator, &.{ 0x02, 0, 0, 0 }); // DATA_CHANNEL_ACK
    }

    pub fn parseDcepMessage(bytes: []const u8) Error!DataChannelMessage {
        if (bytes.len == 0) return error.InvalidSctpPacket;
        return switch (bytes[0]) {
            0x02 => blk: {
                if (bytes.len != 1 and bytes.len != 4) return error.InvalidSctpPacket;
                if (bytes.len == 4 and !std.mem.eql(u8, bytes[1..4], &.{ 0, 0, 0 })) return error.InvalidSctpPacket;
                break :blk .{ .ack = {} };
            },
            0x03 => blk: {
                if (bytes.len < 12) return error.InvalidSctpPacket;
                const channel_type: DataChannelType = @enumFromInt(bytes[1]);
                try validateDataChannelType(channel_type);
                const priority = std.mem.readInt(u16, bytes[2..4], .big);
                const reliability_parameter = std.mem.readInt(u32, bytes[4..8], .big);
                const label_len = std.mem.readInt(u16, bytes[8..10], .big);
                const protocol_len = std.mem.readInt(u16, bytes[10..12], .big);
                const label_start: usize = 12;
                const protocol_start = label_start + @as(usize, label_len);
                const end = protocol_start + @as(usize, protocol_len);
                if (end != bytes.len) return error.InvalidSctpPacket;
                const label = bytes[label_start..protocol_start];
                const protocol = bytes[protocol_start..end];
                try validateDcepString(label);
                try validateDcepString(protocol);
                break :blk .{ .open = .{
                    .channel_type = channel_type,
                    .priority = priority,
                    .reliability_parameter = reliability_parameter,
                    .label = label,
                    .protocol = protocol,
                } };
            },
            else => error.InvalidSctpPacket,
        };
    }

    fn validateDcepString(value: []const u8) Error!void {
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidSctpPacket;
    }

    fn validateDataChannelType(channel_type: DataChannelType) Error!void {
        switch (channel_type) {
            .reliable,
            .partial_reliable_retransmit,
            .partial_reliable_timed,
            .reliable_unordered,
            .partial_reliable_retransmit_unordered,
            .partial_reliable_timed_unordered,
            => {},
            _ => return error.InvalidSctpPacket,
        }
    }

    fn dataChannelIdUsed(used_ids: []const u16, id: u16) bool {
        for (used_ids) |used| {
            if (used == id) return true;
        }
        return false;
    }

    fn isConstEmptyU32(value: []const u32) bool {
        return value.ptr == (&[_]u32{}).ptr and value.len == 0;
    }

    fn tsnAfter(a: u32, b: u32) bool {
        return a != b and ((a -% b) < 0x8000_0000);
    }

    fn ssnAfter(a: u16, b: u16) bool {
        return a != b and ((a -% b) < 0x8000);
    }

    fn tsnLessThan(_: void, a: u32, b: u32) bool {
        if (a == b) return false;
        return ((a -% b) > 0x8000_0000);
    }

    fn align4(value: usize) usize {
        return (value + 3) & ~@as(usize, 3);
    }
};

pub const magic_cookie = stun.magic_cookie;

fn appendFmt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) std.mem.Allocator.Error!void {
    const rendered = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(rendered);
    try list.appendSlice(allocator, rendered);
}

test "STUN binding message roundtrip" {
    const allocator = std.testing.allocator;
    const tid: [12]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const attrs = [_]stun.Attribute{.{ .attr_type = .username, .value = "user:peer" }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try stun.write(&encoded, allocator, .request, .binding, tid, &attrs);
    var parsed = try stun.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(stun.Class.request, parsed.class);
    try std.testing.expectEqual(stun.Method.binding, parsed.method);
    try std.testing.expectEqualStrings("user:peer", parsed.attributes[0].value);
    try std.testing.expectEqualStrings("user", stun.iceUsernameLocalUfrag(parsed.attributes[0].value));
    try std.testing.expectEqualStrings("peer", stun.iceUsernameRemoteUfrag(parsed.attributes[0].value).?);
    try std.testing.expectEqualStrings("user", stun.iceUsernameLocalUfrag("user"));
    try std.testing.expect(stun.iceUsernameRemoteUfrag("user") == null);
    try std.testing.expectEqualStrings("", stun.iceUsernameLocalUfrag(":peer"));

    var unknown_attrs_value: std.ArrayList(u8) = .empty;
    defer unknown_attrs_value.deinit(allocator);
    try stun.writeUnknownAttributesValue(&unknown_attrs_value, allocator, &.{
        .software,
        .use_candidate,
    });
    const unknown_attrs = try stun.parseUnknownAttributesValue(allocator, unknown_attrs_value.items);
    defer allocator.free(unknown_attrs);
    try std.testing.expectEqual(@as(usize, 2), unknown_attrs.len);
    try std.testing.expectEqual(stun.AttributeType.software, unknown_attrs[0]);
    try std.testing.expectEqual(stun.AttributeType.use_candidate, unknown_attrs[1]);
    try std.testing.expectError(error.InvalidStunAttribute, stun.parseUnknownAttributesValue(allocator, &.{0x00}));

    var trailing = try encoded.clone(allocator);
    defer trailing.deinit(allocator);
    try trailing.append(allocator, 0);
    try std.testing.expectError(error.InvalidStunMessage, stun.parse(allocator, trailing.items));

    var bad_length = try encoded.clone(allocator);
    defer bad_length.deinit(allocator);
    bad_length.items[3] = 1; // STUN message length must be 32-bit aligned.
    try std.testing.expectError(error.InvalidStunMessage, stun.parse(allocator, bad_length.items));

    const too_large_attr = try allocator.alloc(u8, @as(usize, std.math.maxInt(u16)) + 1);
    defer allocator.free(too_large_attr);
    var invalid_write: std.ArrayList(u8) = .empty;
    defer invalid_write.deinit(allocator);
    try std.testing.expectError(error.InvalidStunAttribute, stun.write(&invalid_write, allocator, .request, .binding, tid, &.{
        .{ .attr_type = .software, .value = too_large_attr },
    }));
}

test "STUN XOR-MAPPED-ADDRESS helper" {
    const allocator = std.testing.allocator;
    const tid: [12]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    var value: std.ArrayList(u8) = .empty;
    defer value.deinit(allocator);
    try stun.writeXorMappedAddress(&value, allocator, .ipv4, 54321, &.{ 192, 0, 2, 99 }, tid);
    const decoded = try stun.parseXorMappedAddress(value.items, tid);
    try std.testing.expectEqual(@as(u16, 54321), decoded.port);
    try std.testing.expectEqualStrings(&.{ 192, 0, 2, 99 }, decoded.bytes());
}

test "STUN ICE binding request authenticates integrity and fingerprint" {
    const allocator = std.testing.allocator;
    const tid: [12]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8 };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try stun.writeIceBindingRequest(&encoded, allocator, .{
        .transaction_id = tid,
        .username = "remote:local",
        .password = "ice-password",
        .priority = stun.priority(126, 65_535, 1),
        .role = .controlling,
        .tie_breaker = 0x0102030405060708,
        .use_candidate = true,
    });

    try stun.validateFingerprint(encoded.items);
    try stun.validateMessageIntegrity(encoded.items, "ice-password");
    try std.testing.expectError(error.BadMessageIntegrity, stun.validateMessageIntegrity(encoded.items, "wrong-password"));

    var parsed = try stun.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(stun.Class.request, parsed.class);
    try std.testing.expectEqualStrings("remote:local", stun.attrValue(parsed, .username).?);
    try std.testing.expectEqual(@as(u32, stun.priority(126, 65_535, 1)), try stun.attrU32(parsed, .priority));
    const decoded_priority = try stun.decodePriority(try stun.attrU32(parsed, .priority));
    try std.testing.expectEqual(@as(u8, 126), decoded_priority.type_preference);
    try std.testing.expectEqual(@as(u16, 65_535), decoded_priority.local_preference);
    try std.testing.expectEqual(@as(u8, 1), decoded_priority.component_id);
    try std.testing.expectError(error.InvalidStunAttribute, stun.decodePriority(0));
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), try stun.attrU64(parsed, .ice_controlling));
    try std.testing.expect(stun.attrValue(parsed, .use_candidate) != null);
    const validated = try stun.validateIceBindingRequest(encoded.items, parsed, "remote:local", "ice-password");
    try std.testing.expectEqual(stun.IceRole.controlling, validated.role);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), validated.tie_breaker);
    try std.testing.expect(validated.use_candidate);
    try std.testing.expectEqual(stun.IceRoleConflictDecision.reject_role_conflict, stun.resolveRoleConflict(.controlling, 0x0102030405060708, validated));
    try std.testing.expectEqual(stun.IceRoleConflictDecision.switch_role, stun.resolveRoleConflict(.controlling, 1, validated));
    try std.testing.expectEqual(stun.IceRoleConflictDecision.no_conflict, stun.resolveRoleConflict(.controlled, 1, validated));

    const controlled_request = stun.ValidatedIceBindingRequest{
        .username = "remote:local",
        .priority = validated.priority,
        .role = .controlled,
        .tie_breaker = 10,
        .use_candidate = false,
    };
    try std.testing.expectEqual(stun.IceRoleConflictDecision.reject_role_conflict, stun.resolveRoleConflict(.controlled, 9, controlled_request));
    try std.testing.expectEqual(stun.IceRoleConflictDecision.switch_role, stun.resolveRoleConflict(.controlled, 10, controlled_request));

    encoded.clearRetainingCapacity();
    try stun.writeIceRoleConflictError(&encoded, allocator, tid, "ice-password");
    var conflict = try stun.parse(allocator, encoded.items);
    defer conflict.deinit(allocator);
    try std.testing.expectEqual(stun.Class.error_response, conflict.class);
    const role_conflict = try stun.parseErrorCodeAttribute(stun.attrValue(conflict, .error_code).?);
    try std.testing.expectEqual(@as(u16, stun.error_code_role_conflict), role_conflict.code);
    try std.testing.expectEqualStrings(stun.role_conflict_reason, role_conflict.reason);
    try stun.validateMessageIntegrity(encoded.items, "ice-password");
    try stun.validateFingerprint(encoded.items);
    try std.testing.expectError(error.InvalidStunAttribute, stun.parseErrorCodeAttribute(&.{ 0, 0, 4 }));
    const too_long_reason = try allocator.alloc(u8, stun.error_code_reason_max_len + 1);
    defer allocator.free(too_long_reason);
    try std.testing.expectError(error.InvalidStunAttribute, stun.writeAuthenticatedBindingError(&encoded, allocator, tid, 400, too_long_reason, "ice-password"));

    var malformed_fingerprint_order = try std.ArrayList(u8).initCapacity(allocator, encoded.items.len + 8);
    defer malformed_fingerprint_order.deinit(allocator);
    try malformed_fingerprint_order.appendSlice(allocator, encoded.items);
    const new_len = std.mem.readInt(u16, malformed_fingerprint_order.items[2..4], .big) + 8;
    std.mem.writeInt(u16, malformed_fingerprint_order.items[2..4], new_len, .big);
    try wire.appendInt(&malformed_fingerprint_order, allocator, u16, @intFromEnum(stun.AttributeType.software), .big);
    try wire.appendInt(&malformed_fingerprint_order, allocator, u16, 4, .big);
    try malformed_fingerprint_order.appendSlice(allocator, "late");
    try std.testing.expectError(error.InvalidStunAttribute, stun.validateFingerprint(malformed_fingerprint_order.items));
    try std.testing.expectError(error.InvalidStunAttribute, stun.parse(allocator, malformed_fingerprint_order.items));

    encoded.items[encoded.items.len - 1] ^= 0xff;
    try std.testing.expectError(error.BadFingerprint, stun.validateFingerprint(encoded.items));

    var invalid_order: std.ArrayList(u8) = .empty;
    defer invalid_order.deinit(allocator);
    try std.testing.expectError(error.InvalidStunAttribute, stun.write(&invalid_order, allocator, .request, .binding, tid, &.{
        .{ .attr_type = .message_integrity, .value = &([_]u8{0} ** stun.message_integrity_len) },
        .{ .attr_type = .software, .value = "after-integrity" },
    }));
    try std.testing.expectError(error.InvalidStunAttribute, stun.write(&invalid_order, allocator, .request, .binding, tid, &.{
        .{ .attr_type = .fingerprint, .value = &([_]u8{0} ** stun.fingerprint_len) },
        .{ .attr_type = .message_integrity, .value = &([_]u8{0} ** stun.message_integrity_len) },
    }));
    try std.testing.expectError(error.InvalidStunAttribute, stun.write(&invalid_order, allocator, .request, .binding, tid, &.{
        .{ .attr_type = .fingerprint, .value = &([_]u8{0} ** stun.fingerprint_len) },
        .{ .attr_type = .software, .value = "after-fingerprint" },
    }));

    var fingerprint_then_attribute: std.ArrayList(u8) = .empty;
    defer fingerprint_then_attribute.deinit(allocator);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u16, stun.encodeType(.binding, .request), .big);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u16, 16, .big);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u32, stun.magic_cookie, .big);
    try fingerprint_then_attribute.appendSlice(allocator, &tid);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u16, @intFromEnum(stun.AttributeType.fingerprint), .big);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u16, stun.fingerprint_len, .big);
    try fingerprint_then_attribute.appendNTimes(allocator, 0, stun.fingerprint_len);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u16, @intFromEnum(stun.AttributeType.software), .big);
    try wire.appendInt(&fingerprint_then_attribute, allocator, u16, 4, .big);
    try fingerprint_then_attribute.appendSlice(allocator, "late");
    try std.testing.expectError(error.InvalidStunAttribute, stun.parse(allocator, fingerprint_then_attribute.items));

    invalid_order.clearRetainingCapacity();
    try stun.write(&invalid_order, allocator, .request, .binding, tid, &.{
        .{ .attr_type = .message_integrity, .value = &([_]u8{0} ** stun.message_integrity_len) },
        .{ .attr_type = .fingerprint, .value = &([_]u8{0} ** stun.fingerprint_len) },
    });
    var ordered = try stun.parse(allocator, invalid_order.items);
    defer ordered.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), ordered.attributes.len);

    var malformed_order: std.ArrayList(u8) = .empty;
    defer malformed_order.deinit(allocator);
    const malformed_payload_len = 4 + stun.message_integrity_len + 4 + "after".len + 3;
    try wire.appendInt(&malformed_order, allocator, u16, stun.encodeType(.binding, .request), .big);
    try wire.appendInt(&malformed_order, allocator, u16, malformed_payload_len, .big);
    try wire.appendInt(&malformed_order, allocator, u32, stun.magic_cookie, .big);
    try malformed_order.appendSlice(allocator, &tid);
    try wire.appendInt(&malformed_order, allocator, u16, @intFromEnum(stun.AttributeType.message_integrity), .big);
    try wire.appendInt(&malformed_order, allocator, u16, stun.message_integrity_len, .big);
    try malformed_order.appendNTimes(allocator, 0, stun.message_integrity_len);
    try wire.appendInt(&malformed_order, allocator, u16, @intFromEnum(stun.AttributeType.software), .big);
    try wire.appendInt(&malformed_order, allocator, u16, 5, .big);
    try malformed_order.appendSlice(allocator, "after");
    try malformed_order.appendNTimes(allocator, 0, 3);
    try std.testing.expectError(error.InvalidStunAttribute, stun.parse(allocator, malformed_order.items));
}

test "ICE candidate parser and SDP parser" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(sdp.SdpType.offer, sdp.parseSdpType("offer"));
    try std.testing.expectEqual(sdp.SdpType.pranswer, sdp.parseSdpType("pranswer"));
    try std.testing.expectEqual(sdp.SdpType.answer, sdp.parseSdpType("answer"));
    try std.testing.expectEqual(sdp.SdpType.rollback, sdp.parseSdpType("rollback"));
    try std.testing.expectEqual(sdp.SdpType.unknown, sdp.parseSdpType("OFFER"));
    try std.testing.expectEqual(sdp.SdpType.offer, sdp.parseSdpTypeIgnoreCase("OFFER"));
    try std.testing.expectEqual(sdp.SdpType.pranswer, sdp.parseSdpTypeIgnoreCase("PrAnswer"));
    try std.testing.expectEqual(sdp.SdpType.unknown, sdp.parseSdpTypeIgnoreCase("bogus"));
    try std.testing.expectEqualStrings("offer", sdp.SdpType.offer.string());
    try std.testing.expectEqualStrings("unknown", sdp.SdpType.unknown.string());
    const line = "candidate:1 1 UDP 2130706431 192.0.2.1 54400 typ host";
    const candidate = try ice.Candidate.parse(line);
    try std.testing.expectEqual(ice.CandidateType.host, candidate.candidate_type);
    try std.testing.expectEqualStrings("host", candidate.candidate_type.string());
    try std.testing.expectEqual(ice.CandidateType.srflx, ice.candidateTypeFromString("srflx").?);
    try std.testing.expect(ice.candidateTypeFromString("SRFLX") == null);
    try std.testing.expectEqual(ice.Component.rtp, ice.componentFromId(@intCast(candidate.component)));
    try std.testing.expectEqual(@as(u8, 1), ice.Component.rtp.id());
    try std.testing.expectEqualStrings("rtp", ice.Component.rtp.string());
    try std.testing.expectEqual(ice.Component.rtcp, ice.componentFromString("rtcp"));
    try std.testing.expectEqual(ice.Component.unknown, ice.componentFromString("RTCP"));
    try std.testing.expectEqual(ice.NetworkType.udp4, ice.networkTypeFromString("udp4"));
    try std.testing.expectEqual(ice.NetworkType.unknown, ice.networkTypeFromString("UDP4"));
    try std.testing.expectEqualStrings("tcp6", ice.NetworkType.tcp6.string());
    try std.testing.expectEqual(ice.Transport.udp, ice.NetworkType.udp6.protocol().?);
    try std.testing.expectEqual(ice.Transport.tcp, ice.NetworkType.tcp4.protocol().?);
    try std.testing.expect(ice.NetworkType.unknown.protocol() == null);
    try std.testing.expectEqual(@as(usize, 2), ice.supported_network_types.len);
    try std.testing.expectEqual(ice.NetworkType.udp4, ice.supported_network_types[0]);
    try std.testing.expectEqual(@as(u16, 54400), candidate.port);
    try std.testing.expectEqual(@as(u8, 126), candidate.candidate_type.preference());
    try std.testing.expectEqual(@as(u32, 2_130_706_431), try candidate.computedPriority(.{}));
    try std.testing.expectEqual(@as(u64, (((@as(u64, 1) << 32) - 1) * 100) + 2 * 200 + 1), ice.pairPriority(200, 100));
    try std.testing.expectEqual(ice.pairPriority(200, 100), ice.pairPriorityForRole(200, 100, .controlling));
    try std.testing.expectEqual(ice.pairPriority(200, 100), ice.pairPriorityForRole(100, 200, .controlled));

    const tcp = try ice.Candidate.parse("candidate:1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active");
    try std.testing.expectEqual(ice.Transport.tcp, tcp.transport);
    try std.testing.expectEqualStrings("tcp", tcp.transport.string());
    try std.testing.expectEqual(ice.Transport.udp, ice.transportFromString("UDP").?);
    try std.testing.expect(ice.transportFromString("sctp") == null);
    try std.testing.expectEqualStrings("active", tcp.tcp_type.?);
    try std.testing.expectEqual(ice.TcpType.active, (try tcp.parsedTcpType()).?);
    try std.testing.expectEqualStrings("active", (try tcp.parsedTcpType()).?.string());
    try std.testing.expectEqual(ice.TcpType.passive, ice.tcpTypeFromString("passive").?);
    try std.testing.expect(ice.tcpTypeFromString("PASSIVE") == null);
    try std.testing.expectEqualStrings("active", tcp.extensionValue("tcptype").?);
    try std.testing.expectEqual(@as(u32, 1_675_624_447), try tcp.computedPriority(.{}));

    const relay = try ice.Candidate.parse("candidate:848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 5001");
    try std.testing.expectEqual(ice.CandidateType.relay, relay.candidate_type);
    try std.testing.expectEqualStrings("192.168.0.1", relay.related_address.?);
    try std.testing.expectEqual(@as(u16, 5001), relay.related_port.?);
    try std.testing.expectEqual(@as(u32, 1_023), try relay.computedPriority(.{}));

    var extended = try ice.Candidate.parseOwned(allocator, "candidate:4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10");
    defer extended.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), extended.extensions.len);
    try std.testing.expectEqualStrings("generation", extended.extensions[0].key);
    try std.testing.expectEqualStrings("0", extended.extensions[0].value);
    try std.testing.expectEqualStrings("network-cost", extended.extensions[2].key);
    try std.testing.expectEqualStrings("10", extended.extensions[2].value);
    try std.testing.expectEqualStrings("2", extended.extensionValue("network-id").?);
    try std.testing.expectEqualStrings("10", extended.extensionValue("NETWORK-COST").?);
    var extended_line: std.ArrayList(u8) = .empty;
    defer extended_line.deinit(allocator);
    try extended.write(&extended_line, allocator);
    try std.testing.expectEqualStrings(
        "candidate:4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10",
        extended_line.items,
    );
    const extended_attr = try sdp.formatCandidateAttribute(allocator, extended);
    defer allocator.free(extended_attr);
    try std.testing.expectEqualStrings(extended_line.items, extended_attr);
    const extended_sdp_line = try sdp.formatCandidateLine(allocator, extended);
    defer allocator.free(extended_sdp_line);
    try std.testing.expectEqualStrings(
        "a=candidate:4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10\r\n",
        extended_sdp_line,
    );
    var candidate_lines: std.ArrayList(u8) = .empty;
    defer candidate_lines.deinit(allocator);
    try sdp.appendCandidateLine(&candidate_lines, allocator, extended);
    try sdp.appendEndOfCandidatesLine(&candidate_lines, allocator);
    try std.testing.expectEqualStrings(
        "a=candidate:4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10\r\n" ++
            "a=end-of-candidates\r\n",
        candidate_lines.items,
    );

    var empty_ext = try ice.Candidate.parseOwned(allocator, "candidate:1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active empty-value-1  empty-value-2 ");
    defer empty_ext.deinit(allocator);
    try std.testing.expectEqualStrings("active", empty_ext.extensionValue("tcptype").?);
    try std.testing.expectEqual(@as(usize, 0), empty_ext.extensionValue("empty-value-1").?.len);
    try std.testing.expectEqual(@as(usize, 0), empty_ext.extensionValue("empty-value-2").?.len);
    var empty_ext_line: std.ArrayList(u8) = .empty;
    defer empty_ext_line.deinit(allocator);
    try empty_ext.write(&empty_ext_line, allocator);
    try std.testing.expectEqualStrings(
        "candidate:1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active empty-value-1  empty-value-2 ",
        empty_ext_line.items,
    );

    try empty_ext.addExtension(allocator, .{ .key = "empty-value-1", .value = "updated" });
    try std.testing.expectEqualStrings("updated", empty_ext.extensionValue("empty-value-1").?);
    try empty_ext.addExtension(allocator, .{ .key = "new-empty", .value = "" });
    try std.testing.expectEqual(@as(usize, 0), empty_ext.extensionValue("new-empty").?.len);
    try empty_ext.addExtension(allocator, .{ .key = "tcptype", .value = "passive" });
    try std.testing.expectEqualStrings("passive", empty_ext.extensionValue("tcptype").?);
    const exported_exts = try empty_ext.exportedExtensions(allocator);
    defer allocator.free(exported_exts);
    try std.testing.expectEqualStrings("tcptype", exported_exts[0].key);
    try std.testing.expectEqualStrings("passive", exported_exts[0].value);
    try std.testing.expectEqualStrings("empty-value-1", exported_exts[1].key);
    try std.testing.expectError(error.InvalidIceCandidate, empty_ext.addExtension(allocator, .{ .key = "tcptype", .value = "INVALID" }));
    try std.testing.expectError(error.InvalidIceCandidate, empty_ext.addExtension(allocator, .{ .key = "", .value = "" }));
    try std.testing.expect(try empty_ext.removeExtension(allocator, "empty-value-2"));
    try std.testing.expect(empty_ext.extensionValue("empty-value-2") == null);
    try std.testing.expect(try empty_ext.removeExtension(allocator, "tcptype"));
    try std.testing.expect(empty_ext.extensionValue("tcptype") == null);
    try std.testing.expect(!(try empty_ext.removeExtension(allocator, "missing")));

    const mdns = try ice.Candidate.parse("candidate:1380287402 1 udp 2130706431 e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local 60542 typ host");
    try std.testing.expectEqualStrings("e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local", mdns.address);

    const zone = try ice.Candidate.parse("candidate:750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a%eth0%eth1 53987 typ host");
    try std.testing.expectEqualStrings("fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a", zone.address);
    var zone_line: std.ArrayList(u8) = .empty;
    defer zone_line.deinit(allocator);
    try zone.write(&zone_line, allocator);
    try std.testing.expectEqualStrings(
        "candidate:750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host",
        zone_line.items,
    );
    var invalid_write_line: std.ArrayList(u8) = .empty;
    defer invalid_write_line.deinit(allocator);
    const bad_writer_candidate = ice.Candidate{
        .foundation = "bad foundation",
        .component = 1,
        .transport = .udp,
        .priority = 1,
        .address = "192.0.2.1",
        .port = 9,
        .candidate_type = .host,
    };
    try std.testing.expectError(error.InvalidIceCandidate, bad_writer_candidate.write(&invalid_write_line, allocator));
    var reserved_extension = [_]ice.CandidateExtension{.{ .key = "tcptype", .value = "active" }};
    try std.testing.expectError(error.InvalidIceCandidate, sdp.formatCandidateLine(allocator, .{
        .foundation = "1",
        .component = 1,
        .transport = .udp,
        .priority = 1,
        .address = "192.0.2.1",
        .port = 9,
        .candidate_type = .host,
        .extensions = &reserved_extension,
    }));

    // Match the mature Pion ICE parser's defensive checks for SDP candidate
    // lines: malformed addresses, incomplete related-address pairs, invalid
    // TCP directions, and CR/LF injection in extension fields must be rejected
    // before candidates enter ICE pair selection.
    try std.testing.expectError(error.InvalidIceCandidate, ice.Candidate.parse("candidate:111111111111111111111111111111111 1 udp 500 127.0.0.1 80 typ host"));
    try std.testing.expectError(error.InvalidIceCandidate, ice.Candidate.parse("candidate:3$3 1 udp 500 127.0.0.1 80 typ host"));
    try std.testing.expectError(error.InvalidIceCandidate, ice.Candidate.parse("candidate:4207374051 1 udp 1685790463 191.228.238.68 99999999 typ srflx raddr 192.168.0.278 rport 53991"));
    try std.testing.expectError(error.InvalidIceCandidate, ice.Candidate.parse("candidate:848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1"));
    try std.testing.expectError(error.InvalidIceCandidate, ice.Candidate.parse("candidate:1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype INVALID"));
    try std.testing.expectError(error.InvalidIceCandidate, ice.Candidate.parse("candidate:750 1 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host ext valu\nu"));
    try std.testing.expectError(error.UnknownIceCandidateType, ice.Candidate.parse("candidate:1 1 udp 2122162783 192.168.84.254 46492 typ zzz generation 0"));

    const text =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "i=Session information\r\n" ++
        "u=https://example.com/sdp\r\n" ++
        "e=j.doe@example.com (Jane Doe)\r\n" ++
        "p=+1 617 555-6011\r\n" ++
        "c=IN IP4 198.51.100.1\r\n" ++
        "b=AS:1234\r\n" ++
        "b=X-YZ:128\r\n" ++
        "t=0 0\r\n" ++
        "r=604800 3600 0 90000\r\n" ++
        "z=2882844526 -1h 2898848070 0\r\n" ++
        "k=prompt\r\n" ++
        "a=group:BUNDLE 0\r\n" ++
        "m=application 9/2 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "i=Data channel media\r\n" ++
        "c=IN IP4 0.0.0.0\r\n" ++
        "b=TIAS:64000\r\n" ++
        "k=clear:media-key\r\n" ++
        "a=rtcp:9 IN IP4 0.0.0.0\r\n" ++
        "a=mid:0\r\n";
    var session = try sdp.parse(allocator, text);
    defer session.deinit(allocator);
    const parsed_origin = try sdp.parseOriginAttribute(session.origin);
    try std.testing.expectEqualStrings("-", parsed_origin.username);
    try std.testing.expectEqual(@as(u64, 0), parsed_origin.session_id);
    try std.testing.expectEqual(@as(u64, 0), parsed_origin.session_version);
    try std.testing.expectEqualStrings("IN", parsed_origin.network_type);
    try std.testing.expectEqualStrings("IP4", parsed_origin.address_type);
    try std.testing.expectEqualStrings("127.0.0.1", parsed_origin.unicast_address);
    const parsed_timing = try sdp.parseTimingAttribute(session.timing);
    try std.testing.expectEqual(@as(u64, 0), parsed_timing.start_time);
    try std.testing.expectEqual(@as(u64, 0), parsed_timing.stop_time);
    try std.testing.expectEqualStrings("IN", session.connection.?.network_type);
    try std.testing.expectEqualStrings("IP4", session.connection.?.address_type);
    try std.testing.expectEqualStrings("198.51.100.1", session.connection.?.address);
    try std.testing.expectEqualStrings("Session information", session.information.?);
    try std.testing.expectEqualStrings("https://example.com/sdp", session.uri.?);
    try std.testing.expectEqualStrings("j.doe@example.com (Jane Doe)", session.email.?);
    try std.testing.expectEqualStrings("+1 617 555-6011", session.phone.?);
    try std.testing.expectEqualStrings("prompt", session.encryption_key.?);
    try std.testing.expectEqual(@as(usize, 1), session.repeat_times.len);
    try std.testing.expectEqualStrings("604800 3600 0 90000", session.repeat_times[0]);
    try std.testing.expectEqualStrings("2882844526 -1h 2898848070 0", session.time_zones.?);
    try std.testing.expectEqual(@as(usize, 2), session.bandwidth.len);
    try std.testing.expectEqualStrings("AS", session.bandwidth[0].typ);
    try std.testing.expectEqual(@as(u64, 1234), session.bandwidth[0].bandwidth);
    try std.testing.expect(!session.bandwidth[0].experimental);
    try std.testing.expectEqualStrings("YZ", session.bandwidth[1].typ);
    try std.testing.expectEqual(@as(u64, 128), session.bandwidth[1].bandwidth);
    try std.testing.expect(session.bandwidth[1].experimental);
    try std.testing.expectEqualStrings("BUNDLE 0", session.attributes[0].value);
    try std.testing.expectEqualStrings("application", session.media[0].kind);
    try std.testing.expect(sdp.hasApplicationMedia(session));
    try std.testing.expectEqualStrings("application", sdp.applicationMedia(session).?.kind);
    try std.testing.expect(sdp.hasDataChannelMedia(session));
    try std.testing.expect(sdp.mediaLooksLikeDataChannel(session.media[0]));
    try std.testing.expectEqualStrings("application", sdp.dataChannelMedia(session).?.kind);
    try std.testing.expectEqual(@as(u16, 9), session.media[0].port);
    try std.testing.expectEqual(@as(?u16, 2), session.media[0].port_range);
    try std.testing.expectEqualStrings("Data channel media", session.media[0].title.?);
    try std.testing.expectEqualStrings("0.0.0.0", session.media[0].connection.?.address);
    try std.testing.expectEqual(@as(usize, 1), session.media[0].bandwidth.len);
    try std.testing.expectEqualStrings("TIAS", session.media[0].bandwidth[0].typ);
    try std.testing.expectEqual(@as(u64, 64000), session.media[0].bandwidth[0].bandwidth);
    try std.testing.expectEqualStrings("clear:media-key", session.media[0].encryption_key.?);
    const parsed_rtcp = (try sdp.extractRtcpAddress(session.media[0])).?;
    try std.testing.expectEqual(@as(u16, 9), parsed_rtcp.port);
    try std.testing.expectEqualStrings("IN", parsed_rtcp.connection.?.network_type);
    try std.testing.expectEqualStrings("IP4", parsed_rtcp.connection.?.address_type);
    try std.testing.expectEqualStrings("0.0.0.0", parsed_rtcp.connection.?.address);
    try std.testing.expectEqualStrings("rtcp", session.media[0].attributes[0].name);
    try std.testing.expectEqualStrings("mid", session.media[0].attributes[1].name);
    const formatted_session = try sdp.formatSessionLines(allocator, session);
    defer allocator.free(formatted_session);
    try std.testing.expectEqualStrings(text, formatted_session);
    var appended_session: std.ArrayList(u8) = .empty;
    defer appended_session.deinit(allocator);
    try sdp.appendSessionLines(&appended_session, allocator, session);
    try std.testing.expectEqualStrings(text, appended_session.items);
    const group_attr_line = try sdp.formatAttributeLine(allocator, session.attributes[0]);
    defer allocator.free(group_attr_line);
    try std.testing.expectEqualStrings("a=group:BUNDLE 0\r\n", group_attr_line);
    const property_attr_line = try sdp.formatAttributeLine(allocator, .{ .name = "rtcp-mux", .value = "" });
    defer allocator.free(property_attr_line);
    try std.testing.expectEqualStrings("a=rtcp-mux\r\n", property_attr_line);
    var generic_attr_lines: std.ArrayList(u8) = .empty;
    defer generic_attr_lines.deinit(allocator);
    try sdp.appendAttributeLine(&generic_attr_lines, allocator, session.media[0].attributes[1]);
    try sdp.appendAttributeLine(&generic_attr_lines, allocator, .{ .name = "rtcp-mux", .value = "" });
    try std.testing.expectEqualStrings("a=mid:0\r\na=rtcp-mux\r\n", generic_attr_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatAttributeLine(allocator, .{ .name = "bad name", .value = "" }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatAttributeLine(allocator, .{ .name = "mid", .value = "bad\nvalue" }));
    const session_name_line = try sdp.formatSessionNameLine(allocator, "A Seminar");
    defer allocator.free(session_name_line);
    try std.testing.expectEqualStrings("s=A Seminar\r\n", session_name_line);
    var session_name_lines: std.ArrayList(u8) = .empty;
    defer session_name_lines.deinit(allocator);
    try sdp.appendSessionNameLine(&session_name_lines, allocator, "-");
    try std.testing.expectEqualStrings("s=-\r\n", session_name_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionNameLine(allocator, "bad\nname"));
    const session_header = try sdp.formatSessionHeaderLines(allocator, session);
    defer allocator.free(session_header);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
            "s=-\r\n" ++
            "i=Session information\r\n" ++
            "u=https://example.com/sdp\r\n" ++
            "e=j.doe@example.com (Jane Doe)\r\n" ++
            "p=+1 617 555-6011\r\n" ++
            "c=IN IP4 198.51.100.1\r\n" ++
            "b=AS:1234\r\n" ++
            "b=X-YZ:128\r\n" ++
            "t=0 0\r\n" ++
            "r=604800 3600 0 90000\r\n" ++
            "z=2882844526 -1h 2898848070 0\r\n" ++
            "k=prompt\r\n",
        session_header,
    );
    var session_header_lines: std.ArrayList(u8) = .empty;
    defer session_header_lines.deinit(allocator);
    try sdp.appendSessionHeaderLines(&session_header_lines, allocator, session);
    try std.testing.expectEqualStrings(session_header, session_header_lines.items);
    const origin_attr = try sdp.formatOriginAttribute(allocator, parsed_origin);
    defer allocator.free(origin_attr);
    try std.testing.expectEqualStrings("- 0 0 IN IP4 127.0.0.1", origin_attr);
    const origin_line = try sdp.formatOriginLine(allocator, parsed_origin);
    defer allocator.free(origin_line);
    try std.testing.expectEqualStrings("o=- 0 0 IN IP4 127.0.0.1\r\n", origin_line);
    var origin_lines: std.ArrayList(u8) = .empty;
    defer origin_lines.deinit(allocator);
    try sdp.appendOriginLine(&origin_lines, allocator, parsed_origin);
    try std.testing.expectEqualStrings("o=- 0 0 IN IP4 127.0.0.1\r\n", origin_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatOriginLine(allocator, .{
        .username = "bad user",
        .session_id = 0,
        .session_version = 0,
        .network_type = "IN",
        .address_type = "IP4",
        .unicast_address = "127.0.0.1",
    }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatOriginLine(allocator, .{
        .username = "-",
        .session_id = 0,
        .session_version = 0,
        .network_type = "NET",
        .address_type = "IP4",
        .unicast_address = "127.0.0.1",
    }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatOriginLine(allocator, .{
        .username = "-",
        .session_id = 0,
        .session_version = 0,
        .network_type = "IN",
        .address_type = "IP5",
        .unicast_address = "127.0.0.1",
    }));
    const origin_default_ip4 = try sdp.parseOriginAttribute("- 0 0 IN IP4");
    try std.testing.expectEqualStrings("0.0.0.0", origin_default_ip4.unicast_address);
    const origin_default_ip6 = try sdp.parseOriginAttribute("- 0 0 IN IP6");
    try std.testing.expectEqualStrings("::", origin_default_ip6.unicast_address);
    const origin_default_address_type = try sdp.parseOriginAttribute("- 0 0 IN");
    try std.testing.expectEqualStrings("IP4", origin_default_address_type.address_type);
    try std.testing.expectEqualStrings("0.0.0.0", origin_default_address_type.unicast_address);
    try std.testing.expectError(error.InvalidSdp, sdp.parseOriginAttribute("- not-id 0 IN IP4 127.0.0.1"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseOriginAttribute("- 0 0 NET IP4 127.0.0.1"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseOriginAttribute("- 0 0 IN IP5 127.0.0.1"));
    const timing_attr = try sdp.formatTimingAttribute(allocator, parsed_timing);
    defer allocator.free(timing_attr);
    try std.testing.expectEqualStrings("0 0", timing_attr);
    const timing_line = try sdp.formatTimingLine(allocator, parsed_timing);
    defer allocator.free(timing_line);
    try std.testing.expectEqualStrings("t=0 0\r\n", timing_line);
    var timing_lines: std.ArrayList(u8) = .empty;
    defer timing_lines.deinit(allocator);
    try sdp.appendTimingLine(&timing_lines, allocator, .{ .start_time = 1, .stop_time = 2 });
    try std.testing.expectEqualStrings("t=1 2\r\n", timing_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.parseTimingAttribute("0"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseTimingAttribute("0 0 extra"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseTimingAttribute("start 0"));
    const parsed_repeat = try sdp.parseRepeatTimeAttribute(allocator, "7d 1h 0 25h");
    defer allocator.free(parsed_repeat.offsets);
    try std.testing.expectEqual(@as(i64, 604800), parsed_repeat.interval);
    try std.testing.expectEqual(@as(i64, 3600), parsed_repeat.duration);
    try std.testing.expectEqualSlices(i64, &[_]i64{ 0, 90000 }, parsed_repeat.offsets);
    const repeat_attr = try sdp.formatRepeatTimeAttribute(allocator, parsed_repeat);
    defer allocator.free(repeat_attr);
    try std.testing.expectEqualStrings("604800 3600 0 90000", repeat_attr);
    const parsed_zones = try sdp.parseTimeZonesAttribute(allocator, "2882844526 -1h 2898848070 0");
    defer allocator.free(parsed_zones);
    try std.testing.expectEqual(@as(usize, 2), parsed_zones.len);
    try std.testing.expectEqual(@as(u64, 2882844526), parsed_zones[0].adjustment_time);
    try std.testing.expectEqual(@as(i64, -3600), parsed_zones[0].offset);
    try std.testing.expectEqual(@as(i64, 0), parsed_zones[1].offset);
    const zones_attr = try sdp.formatTimeZonesAttribute(allocator, parsed_zones);
    defer allocator.free(zones_attr);
    try std.testing.expectEqualStrings("2882844526 -3600 2898848070 0", zones_attr);
    try std.testing.expectError(error.InvalidSdp, sdp.parseRepeatTimeAttribute(allocator, "7d"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseRepeatTimeAttribute(allocator, "bad 1h"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseTimeZonesAttribute(allocator, ""));
    try std.testing.expectError(error.InvalidSdp, sdp.parseTimeZonesAttribute(allocator, "2882844526"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatTimeZonesAttribute(allocator, &.{}));
    var invalid_header_session = session;
    invalid_header_session.name = "bad\nname";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.information = "bad\ninfo";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.uri = "bad\nuri";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.email = "bad\nemail";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.phone = "bad\nphone";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.encryption_key = "bad\nkey";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.repeat_times = &.{"bad\nrepeat"};
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    invalid_header_session = session;
    invalid_header_session.time_zones = "bad\nzone";
    try std.testing.expectError(error.InvalidSdp, sdp.formatSessionHeaderLines(allocator, invalid_header_session));
    const media_line = try sdp.formatMediaLine(allocator, session.media[0].kind, session.media[0].port, session.media[0].protocol, session.media[0].formats);
    defer allocator.free(media_line);
    try std.testing.expectEqualStrings("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n", media_line);
    const ranged_media_line = try sdp.formatRangedMediaLine(allocator, session.media[0].kind, session.media[0].port, session.media[0].port_range, session.media[0].protocol, session.media[0].formats);
    defer allocator.free(ranged_media_line);
    try std.testing.expectEqualStrings("m=application 9/2 UDP/DTLS/SCTP webrtc-datachannel\r\n", ranged_media_line);
    var media_lines: std.ArrayList(u8) = .empty;
    defer media_lines.deinit(allocator);
    try sdp.appendMediaLine(&media_lines, allocator, "video", 0, "UDP/TLS/RTP/SAVPF", "96 97");
    try sdp.appendRangedMediaLine(&media_lines, allocator, "audio", 5004, 2, "RTP/AVP", "0");
    try std.testing.expectEqualStrings(
        "m=video 0 UDP/TLS/RTP/SAVPF 96 97\r\n" ++
            "m=audio 5004/2 RTP/AVP 0\r\n",
        media_lines.items,
    );
    try std.testing.expectError(error.InvalidSdp, sdp.formatMediaLine(allocator, "", 9, "UDP/TLS/RTP/SAVPF", "96"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatMediaLine(allocator, "video", 9, "UDP TLS", "96"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatMediaLine(allocator, "video", 9, "UDP/TLS/RTP/SAVPF", ""));
    try std.testing.expectError(error.InvalidSdp, sdp.parse(allocator, "v=0\r\nm=audio 5004/not-a-range RTP/AVP 0\r\n"));
    const information_line = try sdp.formatInformationLine(allocator, "Media title");
    defer allocator.free(information_line);
    try std.testing.expectEqualStrings("i=Media title\r\n", information_line);
    var information_lines: std.ArrayList(u8) = .empty;
    defer information_lines.deinit(allocator);
    try sdp.appendInformationLine(&information_lines, allocator, "Session info");
    try sdp.appendUriLine(&information_lines, allocator, "https://example.com/sdp");
    try sdp.appendEmailLine(&information_lines, allocator, "j.doe@example.com");
    try sdp.appendPhoneLine(&information_lines, allocator, "+1 617 555-6011");
    try sdp.appendRepeatTimeLine(&information_lines, allocator, "604800 3600 0 90000");
    try sdp.appendTimeZonesLine(&information_lines, allocator, "2882844526 -1h 2898848070 0");
    try sdp.appendEncryptionKeyLine(&information_lines, allocator, "prompt");
    try std.testing.expectEqualStrings(
        "i=Session info\r\n" ++
            "u=https://example.com/sdp\r\n" ++
            "e=j.doe@example.com\r\n" ++
            "p=+1 617 555-6011\r\n" ++
            "r=604800 3600 0 90000\r\n" ++
            "z=2882844526 -1h 2898848070 0\r\n" ++
            "k=prompt\r\n",
        information_lines.items,
    );
    try std.testing.expectError(error.InvalidSdp, sdp.formatInformationLine(allocator, "bad\ninfo"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatUriLine(allocator, "bad\nuri"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatEmailLine(allocator, "bad\nemail"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatPhoneLine(allocator, "bad\nphone"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatEncryptionKeyLine(allocator, "bad\nkey"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatRepeatTimeLine(allocator, "bad\nrepeat"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatTimeZonesLine(allocator, "bad\nzone"));
    const connection_line = try sdp.formatConnectionLine(allocator, "IN", "IP4", "0.0.0.0");
    defer allocator.free(connection_line);
    try std.testing.expectEqualStrings("c=IN IP4 0.0.0.0\r\n", connection_line);
    var connection_lines: std.ArrayList(u8) = .empty;
    defer connection_lines.deinit(allocator);
    try sdp.appendConnectionLine(&connection_lines, allocator, "IN", "IP6", "::");
    try std.testing.expectEqualStrings("c=IN IP6 ::\r\n", connection_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatConnectionLine(allocator, "IN", "IP4", "bad address"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatConnectionLine(allocator, "in", "IP4", "0.0.0.0"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatConnectionLine(allocator, "IN", "ip4", "0.0.0.0"));
    try std.testing.expectError(error.InvalidSdp, sdp.parse(allocator, "v=0\r\nc=IN IP4\r\n"));
    try std.testing.expectError(error.InvalidSdp, sdp.parse(allocator, "v=0\r\nc=NET IP4 0.0.0.0\r\n"));
    try std.testing.expectError(error.InvalidSdp, sdp.parse(allocator, "v=0\r\nc=IN IP5 0.0.0.0\r\n"));
    const multicast_address = try sdp.formatConnectionAddress(allocator, .{ .address = "224.2.1.1", .ttl = 127, .range = 3 });
    defer allocator.free(multicast_address);
    try std.testing.expectEqualStrings("224.2.1.1/127/3", multicast_address);
    const parsed_multicast_address = try sdp.parseConnectionAddress(multicast_address);
    try std.testing.expectEqualStrings("224.2.1.1", parsed_multicast_address.address);
    try std.testing.expectEqual(@as(?u16, 127), parsed_multicast_address.ttl);
    try std.testing.expectEqual(@as(?u16, 3), parsed_multicast_address.range);
    const structured_connection_line = try sdp.formatStructuredConnectionLine(allocator, "IN", "IP4", parsed_multicast_address);
    defer allocator.free(structured_connection_line);
    try std.testing.expectEqualStrings("c=IN IP4 224.2.1.1/127/3\r\n", structured_connection_line);
    var structured_connection_lines: std.ArrayList(u8) = .empty;
    defer structured_connection_lines.deinit(allocator);
    try sdp.appendStructuredConnectionLine(&structured_connection_lines, allocator, "IN", "IP4", .{ .address = "224.2.1.1", .ttl = 127 });
    try std.testing.expectEqualStrings("c=IN IP4 224.2.1.1/127\r\n", structured_connection_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatConnectionAddress(allocator, .{ .address = "224.2.1.1", .range = 3 }));
    try std.testing.expectError(error.InvalidSdp, sdp.parseConnectionAddress("224.2.1.1/not-a-ttl"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseConnectionAddress("224.2.1.1/1/2/3"));
    const bandwidth_attr = try sdp.formatBandwidthAttribute(allocator, .{ .typ = "AS", .bandwidth = 1234 });
    defer allocator.free(bandwidth_attr);
    try std.testing.expectEqualStrings("AS:1234", bandwidth_attr);
    const bandwidth_line = try sdp.formatBandwidthLine(allocator, .{ .typ = "YZ", .bandwidth = 128, .experimental = true });
    defer allocator.free(bandwidth_line);
    try std.testing.expectEqualStrings("b=X-YZ:128\r\n", bandwidth_line);
    var bandwidth_lines: std.ArrayList(u8) = .empty;
    defer bandwidth_lines.deinit(allocator);
    try sdp.appendBandwidthLine(&bandwidth_lines, allocator, .{ .typ = "TIAS", .bandwidth = 64000 });
    try std.testing.expectEqualStrings("b=TIAS:64000\r\n", bandwidth_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatBandwidthLine(allocator, .{ .typ = "", .bandwidth = 1 }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatBandwidthLine(allocator, .{ .typ = "bad type", .bandwidth = 1 }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatBandwidthLine(allocator, .{ .typ = "FOO", .bandwidth = 1 }));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBandwidthLine("AS"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBandwidthLine("AS:"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBandwidthLine("X-:1"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBandwidthLine("FOO:1"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBandwidthLine("AS:not-a-number"));
    const rtcp_attr = try sdp.formatRtcpAttribute(allocator, .{ .port = 9, .connection = sdp.unspecified_ipv4_connection });
    defer allocator.free(rtcp_attr);
    try std.testing.expectEqualStrings("9 IN IP4 0.0.0.0", rtcp_attr);
    const rtcp_line = try sdp.formatRtcpLine(allocator, .{ .port = 9, .connection = sdp.unspecified_ipv4_connection });
    defer allocator.free(rtcp_line);
    try std.testing.expectEqualStrings("a=rtcp:9 IN IP4 0.0.0.0\r\n", rtcp_line);
    const rtcp_muxed_attr = try sdp.formatRtcpAttribute(allocator, .{ .port = 9 });
    defer allocator.free(rtcp_muxed_attr);
    try std.testing.expectEqualStrings("9", rtcp_muxed_attr);
    var rtcp_lines: std.ArrayList(u8) = .empty;
    defer rtcp_lines.deinit(allocator);
    try sdp.appendRtcpLine(&rtcp_lines, allocator, .{ .port = 9, .connection = sdp.unspecified_ipv4_connection });
    try std.testing.expectEqualStrings("a=rtcp:9 IN IP4 0.0.0.0\r\n", rtcp_lines.items);
    const parsed_rtcp_without_connection = try sdp.parseRtcpAttribute("9");
    try std.testing.expectEqual(@as(u16, 9), parsed_rtcp_without_connection.port);
    try std.testing.expect(parsed_rtcp_without_connection.connection == null);
    try std.testing.expectError(error.InvalidSdp, sdp.parseRtcpAttribute(""));
    try std.testing.expectError(error.InvalidSdp, sdp.parseRtcpAttribute("9 IN IP4"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseRtcpAttribute("9 IN IP4 0.0.0.0 extra"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseRtcpAttribute("9 NET IP4 0.0.0.0"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseRtcpAttribute("9 IN IP5 0.0.0.0"));
    const mid_line = try sdp.formatMidLine(allocator, "0");
    defer allocator.free(mid_line);
    try std.testing.expectEqualStrings("a=mid:0\r\n", mid_line);
    const bundle_attr = try sdp.formatBundleGroupAttribute(allocator, &.{ "0", "1" });
    defer allocator.free(bundle_attr);
    try std.testing.expectEqualStrings("BUNDLE 0 1", bundle_attr);
    const parsed_bundle_mids = try sdp.parseBundleGroupAttribute(allocator, bundle_attr);
    defer sdp.freeBundleMids(allocator, parsed_bundle_mids);
    try std.testing.expectEqual(@as(usize, 2), parsed_bundle_mids.len);
    try std.testing.expectEqualStrings("0", parsed_bundle_mids[0]);
    try std.testing.expectEqualStrings("1", parsed_bundle_mids[1]);
    const extracted_bundle_mids = try sdp.extractBundleMids(allocator, session);
    defer sdp.freeBundleMids(allocator, extracted_bundle_mids);
    try std.testing.expectEqual(@as(usize, 1), extracted_bundle_mids.len);
    try std.testing.expectEqualStrings("0", extracted_bundle_mids[0]);
    try std.testing.expect(sdp.bundleMatchesMid(session, "0"));
    try std.testing.expect(!sdp.bundleMatchesMid(session, "1"));
    const bundle_line = try sdp.formatBundleGroupLine(allocator, &.{ "0", "1" });
    defer allocator.free(bundle_line);
    try std.testing.expectEqualStrings("a=group:BUNDLE 0 1\r\n", bundle_line);
    var mid_bundle_lines: std.ArrayList(u8) = .empty;
    defer mid_bundle_lines.deinit(allocator);
    try sdp.appendBundleGroupLine(&mid_bundle_lines, allocator, &.{ "0", "1" });
    try sdp.appendMidLine(&mid_bundle_lines, allocator, "0");
    try std.testing.expectEqualStrings("a=group:BUNDLE 0 1\r\na=mid:0\r\n", mid_bundle_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatMidLine(allocator, ""));
    try std.testing.expectError(error.InvalidSdp, sdp.formatBundleGroupLine(allocator, &.{}));
    try std.testing.expectError(error.InvalidSdp, sdp.formatBundleGroupLine(allocator, &.{"bad mid"}));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBundleGroupAttribute(allocator, "BUNDLE"));
    try std.testing.expectError(error.InvalidSdp, sdp.parseBundleGroupAttribute(allocator, "LS 0"));
    var no_bundle_attrs = [_]sdp.Attribute{.{ .name = "group", .value = "LS 0" }};
    const no_bundle_mids = try sdp.extractBundleMids(allocator, .{
        .attributes = &no_bundle_attrs,
        .media = &.{},
    });
    defer sdp.freeBundleMids(allocator, no_bundle_mids);
    try std.testing.expectEqual(@as(usize, 0), no_bundle_mids.len);
    var audio_only = try sdp.parse(allocator, "v=0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n");
    defer audio_only.deinit(allocator);
    try std.testing.expect(sdp.bundleMatchesMid(audio_only, "anything"));
    try std.testing.expect(!sdp.hasApplicationMedia(audio_only));
    try std.testing.expect(sdp.applicationMedia(audio_only) == null);
    try std.testing.expect(!sdp.hasDataChannelMedia(audio_only));
    try std.testing.expect(sdp.dataChannelMedia(audio_only) == null);
}

test "ICE candidate priority helpers mirror RFC and Pion defaults" {
    try std.testing.expectEqual(@as(u8, 126), ice.candidateTypePreference(.host));
    try std.testing.expectEqual(@as(u8, 110), ice.candidateTypePreference(.prflx));
    try std.testing.expectEqual(@as(u8, 100), ice.candidateTypePreference(.srflx));
    try std.testing.expectEqual(@as(u8, 0), ice.candidateTypePreference(.relay));

    try std.testing.expectEqual(@as(u8, 99), ice.typePreference(.host, .{ .transport = .tcp }));
    try std.testing.expectEqual(@as(u8, 116), ice.typePreference(.host, .{ .transport = .tcp, .tcp_priority_offset = 10 }));
    try std.testing.expectEqual(@as(u8, 0), ice.typePreference(.relay, .{ .transport = .tcp }));

    try std.testing.expectEqual(@as(u16, 65_535), ice.localPreference(.host, .{}));
    try std.testing.expectEqual(@as(u16, 3), ice.relayLocalPreference(.udp));
    try std.testing.expectEqual(@as(u16, 1), ice.relayLocalPreference(.tcp));
    try std.testing.expectEqualStrings("tls", ice.RelayProtocol.tls.string());
    try std.testing.expectEqual(ice.RelayProtocol.dtls, ice.relayProtocolFromString("dtls").?);
    try std.testing.expect(ice.relayProtocolFromString("DTLS") == null);
    try std.testing.expectEqual(@as(u16, (6 << 13) + 8_191), ice.tcpLocalPreference(.host, .active, ice.max_tcp_other_preference));
    try std.testing.expectEqual(@as(u16, (6 << 13) + 8_191), ice.tcpLocalPreference(.prflx, .so, ice.max_tcp_other_preference));
    try std.testing.expectEqual(@as(u16, 1234), ice.localPreference(.srflx, .{ .local_preference = 1234 }));

    // These vectors are taken from Pion ICE's Candidate.Priority tests.  The
    // helper keeps generated SDP priorities aligned with common WebRTC stacks
    // without callers having to remember the RFC bit layout.
    try std.testing.expectEqual(@as(u32, 2_130_706_431), try ice.candidatePriority(.host, 1, .{}));
    try std.testing.expectEqual(@as(u32, 1_675_624_447), try ice.candidatePriority(.host, 1, .{ .transport = .tcp, .tcp_type = .active }));
    try std.testing.expectEqual(@as(u32, 1_671_430_143), try ice.candidatePriority(.host, 1, .{ .transport = .tcp, .tcp_type = .passive }));
    try std.testing.expectEqual(@as(u32, 1_667_235_839), try ice.candidatePriority(.host, 1, .{ .transport = .tcp, .tcp_type = .so }));
    try std.testing.expectEqual(@as(u32, 1_862_270_975), try ice.candidatePriority(.prflx, 1, .{}));
    try std.testing.expectEqual(@as(u32, 1_407_188_991), try ice.candidatePriority(.prflx, 1, .{ .transport = .tcp, .tcp_type = .so }));
    try std.testing.expectEqual(@as(u32, 1_694_498_815), try ice.candidatePriority(.srflx, 1, .{}));
    try std.testing.expectEqual(@as(u32, 1_023), try ice.candidatePriority(.relay, 1, .{ .relay_protocol = .udp }));
    try std.testing.expectEqual(@as(u32, 511), try ice.candidatePriority(.relay, 1, .{ .relay_protocol = .tcp }));
    try std.testing.expectError(error.InvalidIceCandidate, ice.candidatePriority(.host, 0, .{}));
}

test "SDP extracts DTLS fingerprint ICE credentials and RTP extmaps" {
    const allocator = std.testing.allocator;
    const text =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-lite\r\n" ++
        "a=group:LS 0\r\n" ++
        "a=group:BUNDLE 1 0\r\n" ++
        "a=extmap:9 " ++ sdp.audio_level_uri ++ "\r\n" ++
        "a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:10:20:30:40:50:60:70:80:90:A0:B0:C0:D0:E0:F0:01\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=setup:passive\r\n" ++
        "a=ice-ufrag:wrong\r\n" ++
        "a=ice-pwd:wrong-pwd\r\n" ++
        "a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n" ++
        "a=extmap:2/sendonly " ++ sdp.abs_send_time_uri ++ "\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=mid:1\r\n" ++
        "a=setup:active\r\n" ++
        "a=ice-ufrag:bundle-ufrag\r\n" ++
        "a=ice-pwd:bundle-pwd\r\n" ++
        "a=ice-options:google-ice trickle\r\n" ++
        "a=fingerprint:sha-256 01:23:45:67:89:AB:CD:EF:FE:DC:BA:98:76:54:32:10:11:33:55:77:99:BB:DD:FF:00:22:44:66:88:AA:CC:EE\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=rtcp-rsize\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=max-message-size:262144\r\n" ++
        "a=extmap-allow-mixed\r\n" ++
        "a=extmap:3/recvonly " ++ sdp.transport_cc_uri ++ " appdata\r\n" ++
        "a=extmap:4 " ++ sdp.sdes_mid_uri ++ "\r\n";
    var session = try sdp.parse(allocator, text);
    defer session.deinit(allocator);

    const group_values = try sdp.collectAttrValues(allocator, session.attributes, "group");
    defer sdp.freeAttrValues(allocator, group_values);
    try std.testing.expectEqual(@as(usize, 2), group_values.len);
    try std.testing.expectEqualStrings("LS 0", group_values[0]);
    try std.testing.expectEqualStrings("BUNDLE 1 0", group_values[1]);

    const selected_media = sdp.selectCandidateMedia(session).?;
    try std.testing.expectEqual(@as(u16, 1), selected_media.index);
    try std.testing.expectEqualStrings("application", selected_media.media.kind);
    try std.testing.expectEqualStrings("1", sdp.findAttr(selected_media.media.attributes, "mid").?);
    const media_mid_0 = sdp.mediaByMid(session, "0").?;
    try std.testing.expectEqual(@as(u16, 0), media_mid_0.index);
    try std.testing.expectEqualStrings("audio", media_mid_0.media.kind);
    try std.testing.expect(sdp.mediaByMid(session, "missing") == null);

    const fingerprint = try sdp.extractFingerprint(session);
    try std.testing.expectEqualStrings("sha-256", fingerprint.algorithm);
    try std.testing.expectEqualStrings("11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:10:20:30:40:50:60:70:80:90:A0:B0:C0:D0:E0:F0:01", fingerprint.value);

    const creds = try sdp.extractIceCredentials(session);
    try std.testing.expectEqualStrings("bundle-ufrag", creds.ufrag);
    try std.testing.expectEqualStrings("bundle-pwd", creds.password);

    const transport = sdp.extractTransportAttributes(session);
    try std.testing.expect(transport.ice_lite);
    try std.testing.expect(transport.rtcp_mux);
    try std.testing.expect(transport.rtcp_rsize);

    try std.testing.expect(sdp.extMapAllowMixed(session));
    try std.testing.expect(sdp.supportsIceTrickle(session));
    const twcc = (try sdp.findExtMapInSession(session, sdp.transport_cc_uri)).?;
    try std.testing.expectEqual(@as(u16, 3), twcc.id);
    try std.testing.expectEqual(sdp.ExtMapDirection.recvonly, twcc.direction);
    try std.testing.expectEqualStrings("appdata", twcc.extension_attributes);
    try std.testing.expectEqual(@as(u8, 3), try twcc.rtpId());

    const mid = (try sdp.findExtMapInSession(session, sdp.sdes_mid_uri)).?;
    try std.testing.expectEqual(@as(u16, 4), mid.id);

    const extmaps = try sdp.extractExtMaps(allocator, session);
    defer sdp.freeExtMaps(allocator, extmaps);
    try std.testing.expectEqual(@as(usize, 3), extmaps.len); // session-level audio level is shadowed by BUNDLE media.

    const media_extension_map = try sdp.rtpExtensionsFromMedia(allocator, session.media[1]);
    defer sdp.freeRtpExtensionMap(allocator, media_extension_map);
    try std.testing.expectEqual(@as(usize, 2), media_extension_map.len);
    try std.testing.expectEqualStrings(sdp.transport_cc_uri, media_extension_map[0].uri);
    try std.testing.expectEqual(@as(u8, 3), media_extension_map[0].id);
    try std.testing.expectEqualStrings(sdp.sdes_mid_uri, media_extension_map[1].uri);
    try std.testing.expectEqual(@as(u8, 4), media_extension_map[1].id);

    const parsed_extmap = try sdp.parseExtMapAttribute("7/inactive urn:example:ext attrs");
    try std.testing.expectEqual(@as(u16, 7), parsed_extmap.id);
    try std.testing.expectEqual(sdp.ExtMapDirection.inactive, parsed_extmap.direction);
    try std.testing.expectEqualStrings("urn:example:ext", parsed_extmap.uri);
    try std.testing.expectEqualStrings("attrs", parsed_extmap.extension_attributes);
    try std.testing.expectEqualStrings("/inactive", parsed_extmap.direction.suffix());
    const formatted_extmap = try sdp.formatExtMapAttribute(allocator, parsed_extmap);
    defer allocator.free(formatted_extmap);
    try std.testing.expectEqualStrings("7/inactive urn:example:ext attrs", formatted_extmap);
    const formatted_extmap_line = try sdp.formatExtMapLine(allocator, parsed_extmap);
    defer allocator.free(formatted_extmap_line);
    try std.testing.expectEqualStrings("a=extmap:7/inactive urn:example:ext attrs\r\n", formatted_extmap_line);
    var extmap_lines: std.ArrayList(u8) = .empty;
    defer extmap_lines.deinit(allocator);
    try sdp.appendExtMapLine(&extmap_lines, allocator, .{ .id = 4, .uri = sdp.sdes_mid_uri });
    try std.testing.expectEqualStrings("a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n", extmap_lines.items);
    const max_extmap_line = try sdp.formatExtMapLine(allocator, .{ .id = sdp.max_extmap_id, .uri = sdp.sdes_mid_uri });
    defer allocator.free(max_extmap_line);
    try std.testing.expectEqualStrings("a=extmap:246 urn:ietf:params:rtp-hdrext:sdes:mid\r\n", max_extmap_line);
    try std.testing.expectError(error.InvalidSdp, sdp.formatExtMapLine(allocator, .{ .id = 0, .uri = "urn:bad" }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatExtMapLine(allocator, .{ .id = sdp.max_extmap_id + 1, .uri = sdp.sdes_mid_uri }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatExtMapLine(allocator, .{ .id = 1, .uri = "" }));

    try std.testing.expectError(error.InvalidSdp, sdp.parseExtMapAttribute("0 " ++ sdp.sdes_mid_uri));
    try std.testing.expectError(error.InvalidSdp, sdp.parseExtMapAttribute("247 " ++ sdp.sdes_mid_uri));

    const ice_options_attr = try sdp.formatIceOptionsAttribute(allocator, &.{ sdp.ice_option_trickle, "google-ice", "TrIcKlE" });
    defer allocator.free(ice_options_attr);
    try std.testing.expectEqualStrings("trickle google-ice", ice_options_attr);
    const ice_options_line = try sdp.formatIceOptionsLine(allocator, &.{ sdp.ice_option_renomination, sdp.ice_option_trickle });
    defer allocator.free(ice_options_line);
    try std.testing.expectEqualStrings("a=ice-options:renomination trickle\r\n", ice_options_line);
    var ice_option_lines: std.ArrayList(u8) = .empty;
    defer ice_option_lines.deinit(allocator);
    try sdp.appendIceOptionsLine(&ice_option_lines, allocator, &.{sdp.ice_option_trickle});
    try std.testing.expectEqualStrings("a=ice-options:trickle\r\n", ice_option_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatIceOptionsAttribute(allocator, &.{}));
    try std.testing.expectError(error.InvalidSdp, sdp.formatIceOptionsLine(allocator, &.{""}));
    try std.testing.expectError(error.InvalidSdp, sdp.formatIceOptionsLine(allocator, &.{"bad option"}));

    var media_trickle = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-options:google-ice\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=ice-options:renomination\tTrIcKlE\r\n");
    defer media_trickle.deinit(allocator);
    try std.testing.expect(sdp.supportsIceTrickle(media_trickle));
    try std.testing.expect(sdp.supportsIceRenomination(media_trickle));

    var repeated_session_options = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-options:google-ice\r\n" ++
        "a=ice-options:trickle\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n");
    defer repeated_session_options.deinit(allocator);
    try std.testing.expect(sdp.supportsIceTrickle(repeated_session_options));

    var session_renomination = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-options:ReNomination\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n");
    defer session_renomination.deinit(allocator);
    try std.testing.expect(sdp.supportsIceRenomination(session_renomination));

    var no_trickle = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-options:nottrickle\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n");
    defer no_trickle.deinit(allocator);
    try std.testing.expect(!sdp.supportsIceTrickle(no_trickle));
    try std.testing.expect(!sdp.supportsIceRenomination(no_trickle));

    const codec_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n" ++
        "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
        "a=rtcp-fb:111 goog-remb\r\n" ++
        "a=rtcp-fb:111 ccm fir\r\n" ++
        "a=rtcp-fb:* ccm fir\r\n" ++
        "a=rtcp-fb:* nack\r\n" ++
        "a=rtcp-fb:* NACK\r\n";
    var codec_session = try sdp.parse(allocator, codec_text);
    defer codec_session.deinit(allocator);
    const codecs = try sdp.extractRtpCodecs(allocator, codec_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, codecs);
    try std.testing.expectEqual(@as(usize, 1), codecs.len);
    try std.testing.expectEqual(@as(u8, 111), codecs[0].payload_type);
    try std.testing.expectEqualStrings("audio/opus", codecs[0].mime_type);
    try std.testing.expectEqualStrings("opus", codecs[0].codec_name);
    try std.testing.expectEqual(@as(u32, 48000), codecs[0].clock_rate);
    try std.testing.expectEqual(@as(u16, 2), codecs[0].channels);
    try std.testing.expectEqualStrings("minptime=10;useinbandfec=1", codecs[0].fmtp);
    try std.testing.expectEqual(@as(usize, 3), codecs[0].rtcp_feedback.len);
    try std.testing.expectEqualStrings("goog-remb", codecs[0].rtcp_feedback[0].typ);
    try std.testing.expectEqualStrings("", codecs[0].rtcp_feedback[0].parameter);
    try std.testing.expectEqualStrings("ccm", codecs[0].rtcp_feedback[1].typ);
    try std.testing.expectEqualStrings("fir", codecs[0].rtcp_feedback[1].parameter);
    try std.testing.expectEqualStrings("nack", codecs[0].rtcp_feedback[2].typ);
    try std.testing.expect(codecs[0].rtcp_feedback[0].isType(sdp.rtcp_feedback_goog_remb));
    try std.testing.expect(codecs[0].rtcp_feedback[1].isType(sdp.rtcp_feedback_ccm));
    try std.testing.expectEqualStrings(sdp.rtcp_feedback_parameter_fir, codecs[0].rtcp_feedback[1].parameter);
    try std.testing.expect(codecs[0].rtcp_feedback[2].isType(sdp.rtcp_feedback_nack));
    try std.testing.expect(sdp.rtcpFeedbackContains(codecs[0].rtcp_feedback, .{ .typ = "nack" }));
    try std.testing.expect(!sdp.rtcpFeedbackContains(codecs[0].rtcp_feedback, .{ .typ = "NACK" }));
    try std.testing.expect(sdp.rtcpFeedbackContainsIgnoreCase(codecs[0].rtcp_feedback, .{ .typ = "NACK" }));
    const negotiated_feedback = try sdp.rtcpFeedbackIntersection(allocator, &.{
        .{ .typ = "nack" },
        .{ .typ = "transport-cc" },
        .{ .typ = "ccm", .parameter = "fir" },
    }, codecs[0].rtcp_feedback);
    defer allocator.free(negotiated_feedback);
    try std.testing.expectEqual(@as(usize, 2), negotiated_feedback.len);
    try std.testing.expectEqualStrings("nack", negotiated_feedback[0].typ);
    try std.testing.expectEqualStrings("ccm", negotiated_feedback[1].typ);
    try std.testing.expectEqualStrings("fir", negotiated_feedback[1].parameter);
    const deduped_feedback = try sdp.rtcpFeedbackDeduplicate(allocator, &.{
        .{ .typ = "nack" },
        .{ .typ = "NACK" },
        .{ .typ = "nack", .parameter = "pli" },
        .{ .typ = "nack", .parameter = "PLI" },
    });
    defer allocator.free(deduped_feedback);
    try std.testing.expectEqual(@as(usize, 2), deduped_feedback.len);
    try std.testing.expectEqualStrings("nack", deduped_feedback[0].typ);
    try std.testing.expectEqualStrings("nack", deduped_feedback[1].typ);
    try std.testing.expectEqualStrings("pli", deduped_feedback[1].parameter);
    const formatted_remb = try sdp.formatRtcpFeedbackAttribute(allocator, 111, codecs[0].rtcp_feedback[0]);
    defer allocator.free(formatted_remb);
    try std.testing.expectEqualStrings("111 goog-remb", formatted_remb);
    const formatted_fir = try sdp.formatRtcpFeedbackAttribute(allocator, 111, codecs[0].rtcp_feedback[1]);
    defer allocator.free(formatted_fir);
    try std.testing.expectEqualStrings("111 ccm fir", formatted_fir);
    const formatted_wildcard = try sdp.formatRtcpFeedbackAttribute(allocator, null, codecs[0].rtcp_feedback[2]);
    defer allocator.free(formatted_wildcard);
    try std.testing.expectEqualStrings("* nack", formatted_wildcard);
    const formatted_line = try sdp.formatRtcpFeedbackLine(allocator, 111, codecs[0].rtcp_feedback[1]);
    defer allocator.free(formatted_line);
    try std.testing.expectEqualStrings("a=rtcp-fb:111 ccm fir\r\n", formatted_line);
    const formatted_wildcard_line = try sdp.formatRtcpFeedbackLine(allocator, null, codecs[0].rtcp_feedback[2]);
    defer allocator.free(formatted_wildcard_line);
    try std.testing.expectEqualStrings("a=rtcp-fb:* nack\r\n", formatted_wildcard_line);
    var feedback_lines: std.ArrayList(u8) = .empty;
    defer feedback_lines.deinit(allocator);
    try sdp.appendRtcpFeedbackLines(&feedback_lines, allocator, 111, codecs[0].rtcp_feedback);
    try std.testing.expectEqualStrings(
        "a=rtcp-fb:111 goog-remb\r\n" ++
            "a=rtcp-fb:111 ccm fir\r\n" ++
            "a=rtcp-fb:111 nack\r\n",
        feedback_lines.items,
    );
    const formatted_fmtp = try sdp.formatFmtpAttribute(allocator, 111, codecs[0].fmtp);
    defer allocator.free(formatted_fmtp);
    try std.testing.expectEqualStrings("111 minptime=10;useinbandfec=1", formatted_fmtp);
    const formatted_fmtp_line = try sdp.formatFmtpLine(allocator, 111, codecs[0].fmtp);
    defer allocator.free(formatted_fmtp_line);
    try std.testing.expectEqualStrings("a=fmtp:111 minptime=10;useinbandfec=1\r\n", formatted_fmtp_line);
    var fmtp_lines: std.ArrayList(u8) = .empty;
    defer fmtp_lines.deinit(allocator);
    try sdp.appendFmtpLine(&fmtp_lines, allocator, 111, codecs[0].fmtp);
    try sdp.appendFmtpLine(&fmtp_lines, allocator, 111, "");
    try std.testing.expectEqualStrings("a=fmtp:111 minptime=10;useinbandfec=1\r\n", fmtp_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatFmtpLine(allocator, 111, ""));
    const formatted_rtpmap = try sdp.formatRtpMapAttribute(allocator, codecs[0].payload_type, codecs[0].codec_name, codecs[0].clock_rate, codecs[0].channels);
    defer allocator.free(formatted_rtpmap);
    try std.testing.expectEqualStrings("111 opus/48000/2", formatted_rtpmap);
    const formatted_rtpmap_line = try sdp.formatRtpMapLine(allocator, codecs[0].payload_type, codecs[0].codec_name, codecs[0].clock_rate, codecs[0].channels);
    defer allocator.free(formatted_rtpmap_line);
    try std.testing.expectEqualStrings("a=rtpmap:111 opus/48000/2\r\n", formatted_rtpmap_line);
    const formatted_video_rtpmap_line = try sdp.formatRtpMapLine(allocator, 96, "VP8", 90_000, 0);
    defer allocator.free(formatted_video_rtpmap_line);
    try std.testing.expectEqualStrings("a=rtpmap:96 VP8/90000\r\n", formatted_video_rtpmap_line);
    var rtpmap_lines: std.ArrayList(u8) = .empty;
    defer rtpmap_lines.deinit(allocator);
    try sdp.appendRtpMapLine(&rtpmap_lines, allocator, codecs[0].payload_type, codecs[0].codec_name, codecs[0].clock_rate, codecs[0].channels);
    try std.testing.expectEqualStrings("a=rtpmap:111 opus/48000/2\r\n", rtpmap_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatRtpMapLine(allocator, 111, "", 48_000, 2));
    try std.testing.expectError(error.InvalidSdp, sdp.formatRtpMapLine(allocator, 111, "opus", 0, 2));
    var codec_lines: std.ArrayList(u8) = .empty;
    defer codec_lines.deinit(allocator);
    try sdp.appendRtpCodecLines(&codec_lines, allocator, codecs[0]);
    try std.testing.expectEqualStrings(
        "a=rtpmap:111 opus/48000/2\r\n" ++
            "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
            "a=rtcp-fb:111 goog-remb\r\n" ++
            "a=rtcp-fb:111 ccm fir\r\n" ++
            "a=rtcp-fb:111 nack\r\n",
        codec_lines.items,
    );

    const fmtp_params = try sdp.parseFmtpParameters(allocator, " Key = Value ; flag ; apt=96 ");
    defer sdp.freeFmtpParameters(allocator, fmtp_params);
    try std.testing.expectEqual(@as(usize, 3), fmtp_params.len);
    try std.testing.expectEqualStrings("Key", fmtp_params[0].key);
    try std.testing.expectEqualStrings("Value", fmtp_params[0].value);
    try std.testing.expectEqualStrings("flag", fmtp_params[1].key);
    try std.testing.expectEqualStrings("", fmtp_params[1].value);
    try std.testing.expectEqualStrings("96", sdp.fmtpParameter(" Key = Value ; flag ; apt=96 ", "APT").?);
    try std.testing.expectEqualStrings("", sdp.fmtpParameter("flag", "flag").?);
    try std.testing.expect(sdp.h264FmtpCompatible(
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
        "packetization-mode=1;profile-level-id=42e029",
    ));
    try std.testing.expect(!sdp.h264FmtpCompatible(
        "packetization-mode=0;profile-level-id=42e01f",
        "packetization-mode=1;profile-level-id=42e01f",
    ));
    try std.testing.expect(!sdp.h264FmtpCompatible(
        "packetization-mode=1;profile-level-id=42e01f",
        "packetization-mode=1",
    ));
    try std.testing.expect(!sdp.h264ProfileLevelIdMatches("zzzzzz", "42e01f"));
    try std.testing.expect(sdp.vp9FmtpCompatible("profile-id=0", ""));
    try std.testing.expect(sdp.vp9FmtpCompatible("profile-id=1", "profile-id=1"));
    try std.testing.expect(!sdp.vp9FmtpCompatible("", "profile-id=1"));
    try std.testing.expect(sdp.av1FmtpCompatible("profile=0", ""));
    try std.testing.expect(sdp.av1FmtpCompatible("profile=1", "profile=1"));
    try std.testing.expect(!sdp.av1FmtpCompatible("", "profile=1"));

    try std.testing.expect(sdp.rtpCodecCompatible(
        .{ .payload_type = 111, .mime_type = "audio/opus", .codec_name = "opus", .clock_rate = 0, .channels = 0 },
        .{ .payload_type = 111, .mime_type = "audio/OPUS", .codec_name = "opus", .clock_rate = 48000, .channels = 2 },
    ));
    try std.testing.expect(!sdp.rtpCodecCompatible(
        .{ .payload_type = 111, .mime_type = "audio/opus", .codec_name = "opus", .clock_rate = 48000, .channels = 2 },
        .{ .payload_type = 111, .mime_type = "audio/opus", .codec_name = "opus", .clock_rate = 44100, .channels = 2 },
    ));
    try std.testing.expect(sdp.rtpCodecCompatible(
        .{ .payload_type = 9, .mime_type = "audio/G722", .codec_name = "G722", .clock_rate = 0 },
        .{ .payload_type = 9, .mime_type = "audio/G722", .codec_name = "G722", .clock_rate = 90000 },
    ));
    try std.testing.expect(!sdp.rtpCodecCompatible(
        .{ .payload_type = 9, .mime_type = "audio/G722", .codec_name = "G722", .clock_rate = 0 },
        .{ .payload_type = 9, .mime_type = "audio/G722", .codec_name = "G722", .clock_rate = 8000 },
    ));
    try std.testing.expect(sdp.rtpCodecCompatible(
        .{ .payload_type = 96, .mime_type = "video/H264", .codec_name = "H264", .clock_rate = 90000, .fmtp = "packetization-mode=1;profile-level-id=42e01f" },
        .{ .payload_type = 126, .mime_type = "video/h264", .codec_name = "H264", .clock_rate = 90000, .fmtp = "packetization-mode=1;profile-level-id=42e029" },
    ));
    try std.testing.expect(sdp.rtpCodecCompatible(
        .{ .payload_type = 120, .mime_type = "application/custom", .codec_name = "custom", .clock_rate = 90000, .fmtp = "key1=value1;key2=value2" },
        .{ .payload_type = 121, .mime_type = "application/custom", .codec_name = "custom", .clock_rate = 90000, .fmtp = "key1=value1;key2=value2;key3=value3" },
    ));
    try std.testing.expect(sdp.rtpCodecCompatible(
        .{ .payload_type = 120, .mime_type = "application/custom", .codec_name = "custom", .clock_rate = 0, .fmtp = "key1=value1" },
        .{ .payload_type = 121, .mime_type = "application/custom", .codec_name = "custom", .clock_rate = 90000, .fmtp = "key1=value1" },
    ));
    try std.testing.expect(!sdp.rtpCodecCompatible(
        .{ .payload_type = 120, .mime_type = "application/custom", .codec_name = "custom", .clock_rate = 90000, .fmtp = "key1=value1" },
        .{ .payload_type = 121, .mime_type = "application/custom", .codec_name = "custom", .clock_rate = 90000, .fmtp = "key1=different" },
    ));
    try std.testing.expect(!sdp.rtpCodecCompatible(
        .{ .payload_type = 96, .mime_type = "video/VP9", .codec_name = "VP9", .clock_rate = 90000, .fmtp = "" },
        .{ .payload_type = 98, .mime_type = "video/VP9", .codec_name = "VP9", .clock_rate = 90000, .fmtp = "profile-id=1" },
    ));

    const no_channels_codec_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 101\r\n" ++
        "a=rtpmap:101 opus/90000\r\n";
    var no_channels_codec_session = try sdp.parse(allocator, no_channels_codec_text);
    defer no_channels_codec_session.deinit(allocator);
    const no_channels_codecs = try sdp.extractRtpCodecs(allocator, no_channels_codec_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, no_channels_codecs);
    try std.testing.expectEqual(@as(u16, 0), no_channels_codecs[0].channels);

    const rtx_codec_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n" ++
        "a=rtpmap:96 VP8/90000\r\n" ++
        "a=rtcp-fb:96 nack pli\r\n" ++
        "a=rtpmap:97 rtx/90000\r\n" ++
        "a=fmtp:97 apt=96;rtx-time=3000\r\n";
    var rtx_codec_session = try sdp.parse(allocator, rtx_codec_text);
    defer rtx_codec_session.deinit(allocator);
    const rtx_codecs = try sdp.extractRtpCodecs(allocator, rtx_codec_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, rtx_codecs);
    try std.testing.expectEqual(@as(usize, 2), rtx_codecs.len);
    try std.testing.expectEqualStrings("video/VP8", rtx_codecs[0].mime_type);
    try std.testing.expectEqualStrings("VP8", rtx_codecs[0].codec_name);
    try std.testing.expectEqual(@as(?u8, null), rtx_codecs[0].apt);
    try std.testing.expectEqualStrings("video/rtx", rtx_codecs[1].mime_type);
    try std.testing.expectEqualStrings("rtx", rtx_codecs[1].codec_name);
    try std.testing.expectEqual(@as(?u8, 96), rtx_codecs[1].apt);
    try std.testing.expectEqualStrings("apt=96;rtx-time=3000", rtx_codecs[1].fmtp);
    const associated_vp8 = sdp.rtxAssociatedCodec(rtx_codecs, rtx_codecs[1]).?;
    try std.testing.expectEqual(@as(u8, 96), associated_vp8.payload_type);
    try std.testing.expectEqualStrings("video/VP8", associated_vp8.mime_type);
    try std.testing.expectEqual(@as(?u8, 97), sdp.rtxPayloadTypeForPrimary(rtx_codecs, 96));
    try std.testing.expectEqual(@as(?u8, null), sdp.rtxPayloadTypeForPrimary(rtx_codecs, 42));
    try std.testing.expect(sdp.rtxPrimaryPayloadExists(rtx_codecs, rtx_codecs[1]));
    try std.testing.expect(sdp.findCodecByPayloadType(rtx_codecs, 42) == null);

    const flexfec_codec_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96 120 121\r\n" ++
        "a=rtpmap:96 VP8/90000\r\n" ++
        "a=rtpmap:120 flexfec-03/90000\r\n" ++
        "a=rtpmap:121 ulpfec/90000\r\n";
    var flexfec_codec_session = try sdp.parse(allocator, flexfec_codec_text);
    defer flexfec_codec_session.deinit(allocator);
    const flexfec_codecs = try sdp.extractRtpCodecs(allocator, flexfec_codec_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, flexfec_codecs);
    try std.testing.expectEqualStrings("video/flexfec-03", flexfec_codecs[1].mime_type);
    try std.testing.expectEqualStrings("video/ulpfec", flexfec_codecs[2].mime_type);
    try std.testing.expectEqual(@as(?u8, 120), sdp.fecPayloadType(flexfec_codecs));
    try std.testing.expectEqual(@as(?u8, null), sdp.fecPayloadType(rtx_codecs));

    const invalid_payload_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 128\r\n" ++
        "a=rtpmap:128 VP8/90000\r\n";
    var invalid_payload_session = try sdp.parse(allocator, invalid_payload_text);
    defer invalid_payload_session.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractRtpCodecs(allocator, invalid_payload_session.media[0]));

    const invalid_apt_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 97\r\n" ++
        "a=rtpmap:97 rtx/90000\r\n" ++
        "a=fmtp:97 apt=128\r\n";
    var invalid_apt_session = try sdp.parse(allocator, invalid_apt_text);
    defer invalid_apt_session.deinit(allocator);
    const invalid_apt_codecs = try sdp.extractRtpCodecs(allocator, invalid_apt_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, invalid_apt_codecs);
    try std.testing.expectEqual(@as(?u8, null), invalid_apt_codecs[0].apt);
    try std.testing.expect(!sdp.rtxPrimaryPayloadExists(invalid_apt_codecs, invalid_apt_codecs[0]));

    const static_codec_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 RTP/AVP 0 8 9\r\n";
    var static_codec_session = try sdp.parse(allocator, static_codec_text);
    defer static_codec_session.deinit(allocator);
    const static_codecs = try sdp.extractRtpCodecs(allocator, static_codec_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, static_codecs);
    try std.testing.expectEqual(@as(usize, 3), static_codecs.len);
    try std.testing.expectEqualStrings("audio/PCMU", static_codecs[0].mime_type);
    try std.testing.expectEqualStrings("PCMU", static_codecs[0].codec_name);
    try std.testing.expectEqual(@as(u32, 8000), static_codecs[0].clock_rate);
    try std.testing.expectEqual(@as(u16, 0), static_codecs[0].channels);
    try std.testing.expectEqualStrings("audio/PCMA", static_codecs[1].mime_type);
    try std.testing.expectEqualStrings("audio/G722", static_codecs[2].mime_type);

    const rid_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=rid:f send pt=96;max-width=1280\r\n" ++
        "a=rid:h send pt=96;max-width=640\r\n" ++
        "a=rid:q send pt=96;max-width=320\r\n" ++
        "a=simulcast:send f;~h;;q;\r\n";
    var rid_session = try sdp.parse(allocator, rid_text);
    defer rid_session.deinit(allocator);
    const rids = try sdp.extractRids(allocator, rid_session.media[0]);
    defer allocator.free(rids);
    try std.testing.expectEqual(@as(usize, 3), rids.len);
    try std.testing.expectEqualStrings("f", rids[0].id);
    try std.testing.expectEqualStrings("send", rids[0].direction);
    try std.testing.expectEqualStrings("pt=96;max-width=1280", rids[0].parameters);
    try std.testing.expect(!rids[0].paused);
    try std.testing.expectEqualStrings("h", rids[1].id);
    try std.testing.expect(rids[1].paused);
    try std.testing.expectEqualStrings("q", rids[2].id);
    try std.testing.expect(!rids[2].paused);

    const track_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:audio\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc:2000 msid:audio_stream audio_track\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:malformed-msid\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc:2500 msid:malformed_stream malformed_track extra\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:bare-ssrc\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc:2550\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:media-msid\r\n" ++
        "a=sendonly\r\n" ++
        "a=msid:media_stream media_track\r\n" ++
        "a=ssrc:2600\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:video\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc-group:FID 3000 4000\r\n" ++
        "a=ssrc-group:FEC-FR 3000 5000\r\n" ++
        "a=ssrc:3000 msid:video_stream video_track\r\n" ++
        "a=ssrc:4000 msid:rtx_stream rtx_track\r\n" ++
        "a=ssrc:5000 msid:fec_stream fec_track\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:simulcast\r\n" ++
        "a=ssrc:7000 msid:sim_stream sim_track\r\n" ++
        "a=rid:f send pt=96\r\n" ++
        "a=rid:h send pt=96\r\n" ++
        "a=simulcast:send f;~h\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:inactive\r\n" ++
        "a=inactive\r\n" ++
        "a=ssrc:9000 msid:ignore ignore\r\n";
    var track_session = try sdp.parse(allocator, track_text);
    defer track_session.deinit(allocator);
    const tracks = try sdp.extractTrackDetails(allocator, track_session);
    defer sdp.freeTrackDetails(allocator, tracks);
    try std.testing.expectEqual(@as(usize, 6), tracks.len);
    try std.testing.expectEqual(sdp.MediaDirection.sendrecv, sdp.parseMediaDirection("SENDRECV").?);
    try std.testing.expect(sdp.parseMediaDirection("sideways") == null);
    try std.testing.expectEqual(sdp.MediaDirection.sendrecv, sdp.mediaDirection(track_session.media[0]).?);
    try std.testing.expectEqual(sdp.MediaDirection.inactive, sdp.mediaDirection(track_session.media[6]).?);
    try std.testing.expect(sdp.mediaDirection(rid_session.media[0]) == null);
    try std.testing.expectEqual(sdp.MediaDirection.recvonly, sdp.reverseMediaDirection(.sendonly));
    try std.testing.expectEqual(sdp.MediaDirection.sendonly, sdp.reverseMediaDirection(.recvonly));
    try std.testing.expectEqual(sdp.MediaDirection.inactive, sdp.reverseMediaDirection(.inactive));
    try std.testing.expect(sdp.mediaDirectionIntersects(&.{ .sendrecv, .recvonly }, &.{.recvonly}));
    try std.testing.expect(!sdp.mediaDirectionIntersects(&.{.sendonly}, &.{ .recvonly, .inactive }));
    try std.testing.expectEqualSlices(sdp.MediaDirection, &[_]sdp.MediaDirection{ .recvonly, .sendrecv, .sendonly }, sdp.preferredLocalDirectionsForRemote(.sendrecv));
    try std.testing.expectEqualSlices(sdp.MediaDirection, &[_]sdp.MediaDirection{.recvonly}, sdp.preferredLocalDirectionsForRemote(.sendonly));
    try std.testing.expectEqualSlices(sdp.MediaDirection, &[_]sdp.MediaDirection{ .sendonly, .sendrecv }, sdp.preferredLocalDirectionsForRemote(.recvonly));
    try std.testing.expectEqual(@as(usize, 0), sdp.preferredLocalDirectionsForRemote(.inactive).len);
    const direction_line = try sdp.formatMediaDirectionLine(allocator, .sendrecv);
    defer allocator.free(direction_line);
    try std.testing.expectEqualStrings("a=sendrecv\r\n", direction_line);
    var direction_lines: std.ArrayList(u8) = .empty;
    defer direction_lines.deinit(allocator);
    try sdp.appendMediaDirectionLine(&direction_lines, allocator, .inactive);
    try std.testing.expectEqualStrings("a=inactive\r\n", direction_lines.items);
    try std.testing.expectEqualStrings("audio", tracks[0].mid);
    try std.testing.expectEqual(@as(?u32, 2000), tracks[0].ssrc);
    try std.testing.expectEqualStrings("audio_stream", tracks[0].stream_id);
    try std.testing.expectEqualStrings("audio_track", tracks[0].track_id);
    try std.testing.expectEqualStrings("malformed-msid", tracks[1].mid);
    try std.testing.expectEqual(@as(?u32, 2500), tracks[1].ssrc);
    try std.testing.expectEqualStrings("", tracks[1].stream_id);
    try std.testing.expectEqualStrings("", tracks[1].track_id);
    try std.testing.expectEqualStrings("bare-ssrc", tracks[2].mid);
    try std.testing.expectEqual(@as(?u32, 2550), tracks[2].ssrc);
    try std.testing.expectEqualStrings("", tracks[2].stream_id);
    try std.testing.expectEqualStrings("", tracks[2].track_id);
    try std.testing.expectEqualStrings("media-msid", tracks[3].mid);
    try std.testing.expectEqual(@as(?u32, 2600), tracks[3].ssrc);
    try std.testing.expectEqualStrings("media_stream", tracks[3].stream_id);
    try std.testing.expectEqualStrings("media_track", tracks[3].track_id);
    try std.testing.expectEqualStrings("video", tracks[4].mid);
    try std.testing.expectEqual(@as(?u32, 3000), tracks[4].ssrc);
    try std.testing.expectEqual(@as(?u32, 4000), tracks[4].rtx_ssrc);
    try std.testing.expectEqual(@as(?u32, 5000), tracks[4].fec_ssrc);
    try std.testing.expectEqualStrings("video_track", sdp.trackDetailsForMid(tracks, "video").?.track_id);
    try std.testing.expectEqualStrings("video_track", sdp.trackDetailsForSsrc(tracks, 3000).?.track_id);
    try std.testing.expect(sdp.trackDetailsForSsrc(tracks, 4000) == null);
    try std.testing.expect(sdp.trackDetailsForSsrc(tracks, 5000) == null);
    try std.testing.expectEqual(sdp.RtpCodecType.audio, sdp.rtpCodecTypeForMediaKind("AUDIO"));
    try std.testing.expectEqual(sdp.RtpCodecType.video, sdp.rtpCodecTypeForMediaKind("video"));
    try std.testing.expectEqual(sdp.RtpCodecType.unknown, sdp.rtpCodecTypeForMediaKind("application"));
    try std.testing.expectEqualStrings("audio", sdp.RtpCodecType.audio.mediaKind());
    try std.testing.expectEqualStrings("unknown", sdp.RtpCodecType.unknown.mediaKind());
    try std.testing.expectEqualStrings("simulcast", tracks[5].mid);
    try std.testing.expectEqualStrings("sim_stream", tracks[5].stream_id);
    try std.testing.expectEqual(@as(usize, 2), tracks[5].rids.len);
    try std.testing.expectEqualStrings("f", tracks[5].rids[0].id);
    try std.testing.expect(tracks[5].rids[1].paused);
    try std.testing.expectEqualStrings("sim_track", sdp.trackDetailsForRid(tracks, "simulcast", "f").?.track_id);
    try std.testing.expectEqualStrings("sim_track", sdp.trackDetailsForRid(tracks, "simulcast", "h").?.track_id);
    try std.testing.expect(sdp.trackDetailsForRid(tracks, "video", "f") == null);
    try std.testing.expect(!sdp.tracksContainRepeatedMid(tracks));
    const rid_line = try sdp.formatRidLine(allocator, tracks[5].rids[0]);
    defer allocator.free(rid_line);
    try std.testing.expectEqualStrings("a=rid:f send pt=96\r\n", rid_line);
    const simulcast_line = try sdp.formatSimulcastLine(allocator, "send", tracks[5].rids);
    defer allocator.free(simulcast_line);
    try std.testing.expectEqualStrings("a=simulcast:send f;~h\r\n", simulcast_line);
    var rid_lines: std.ArrayList(u8) = .empty;
    defer rid_lines.deinit(allocator);
    try sdp.appendRidLine(&rid_lines, allocator, tracks[5].rids[0]);
    try sdp.appendSimulcastLine(&rid_lines, allocator, "send", tracks[5].rids);
    try std.testing.expectEqualStrings("a=rid:f send pt=96\r\na=simulcast:send f;~h\r\n", rid_lines.items);
    try std.testing.expectError(error.InvalidSdp, sdp.formatRidLine(allocator, .{ .id = "", .direction = "send" }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatRidLine(allocator, .{ .id = "f", .direction = "send", .parameters = "bad\nparam" }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatSimulcastLine(allocator, "send", &.{}));
    const ssrc_line = try sdp.formatSsrcLine(allocator, 3000, "msid", "video_stream video_track");
    defer allocator.free(ssrc_line);
    try std.testing.expectEqualStrings("a=ssrc:3000 msid:video_stream video_track\r\n", ssrc_line);
    const fid_line = try sdp.formatSsrcGroupLine(allocator, "FID", &.{ 3000, 4000 });
    defer allocator.free(fid_line);
    try std.testing.expectEqualStrings("a=ssrc-group:FID 3000 4000\r\n", fid_line);
    var ssrc_lines: std.ArrayList(u8) = .empty;
    defer ssrc_lines.deinit(allocator);
    try sdp.appendSsrcGroupLine(&ssrc_lines, allocator, "FEC-FR", &.{ 3000, 5000 });
    try sdp.appendSsrcLine(&ssrc_lines, allocator, 3000, "cname", "stream-id");
    try std.testing.expectEqualStrings("a=ssrc-group:FEC-FR 3000 5000\r\na=ssrc:3000 cname:stream-id\r\n", ssrc_lines.items);
    const msid_line = try sdp.formatMsidLine(allocator, "video_stream", "video_track");
    defer allocator.free(msid_line);
    try std.testing.expectEqualStrings("a=msid:video_stream video_track\r\n", msid_line);
    const msid_semantic_line = try sdp.formatMsidSemanticLine(allocator, "WMS*");
    defer allocator.free(msid_semantic_line);
    try std.testing.expectEqualStrings("a=msid-semantic:WMS*\r\n", msid_semantic_line);
    const msid_semantic_attr = try sdp.formatMsidSemanticAttribute(allocator, sdp.msid_semantic_wms, &.{ "stream-a", "stream-b" });
    defer allocator.free(msid_semantic_attr);
    try std.testing.expectEqualStrings("WMS stream-a stream-b", msid_semantic_attr);
    const wildcard_msid_semantic_line = try sdp.formatWildcardMsidSemanticLine(allocator);
    defer allocator.free(wildcard_msid_semantic_line);
    try std.testing.expectEqualStrings("a=msid-semantic:WMS *\r\n", wildcard_msid_semantic_line);
    const token_msid_semantic_line = try sdp.formatMsidSemanticTokensLine(allocator, sdp.msid_semantic_wms, &.{"video_stream"});
    defer allocator.free(token_msid_semantic_line);
    try std.testing.expectEqualStrings("a=msid-semantic:WMS video_stream\r\n", token_msid_semantic_line);
    var msid_lines: std.ArrayList(u8) = .empty;
    defer msid_lines.deinit(allocator);
    try sdp.appendMsidSemanticLine(&msid_lines, allocator, "WMS*");
    try sdp.appendMsidSemanticTokensLine(&msid_lines, allocator, sdp.msid_semantic_wms, &.{"*"});
    try sdp.appendMsidLine(&msid_lines, allocator, "video_stream", "video_track");
    try std.testing.expectEqualStrings(
        "a=msid-semantic:WMS*\r\n" ++
            "a=msid-semantic:WMS *\r\n" ++
            "a=msid:video_stream video_track\r\n",
        msid_lines.items,
    );
    try std.testing.expectError(error.InvalidSdp, sdp.formatMsidLine(allocator, "", "track"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatMsidLine(allocator, "stream", "bad track"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatMsidSemanticLine(allocator, "bad\nvalue"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatMsidSemanticTokensLine(allocator, "", &.{"*"}));
    try std.testing.expectError(error.InvalidSdp, sdp.formatMsidSemanticTokensLine(allocator, sdp.msid_semantic_wms, &.{"bad stream"}));
    try std.testing.expectError(error.InvalidSdp, sdp.formatSsrcLine(allocator, 3000, "", "value"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatSsrcLine(allocator, 3000, "msid", "bad\nvalue"));
    try std.testing.expectError(error.InvalidSdp, sdp.formatSsrcGroupLine(allocator, "FID", &.{3000}));

    const duplicate_ssrc_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:dup-audio\r\n" ++
        "a=ssrc:1234 msid:audio_stream audio_track\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:dup-video\r\n" ++
        "a=ssrc:1234 msid:video_stream video_track\r\n";
    var duplicate_ssrc_session = try sdp.parse(allocator, duplicate_ssrc_text);
    defer duplicate_ssrc_session.deinit(allocator);
    const duplicate_tracks = try sdp.extractTrackDetails(allocator, duplicate_ssrc_session);
    defer sdp.freeTrackDetails(allocator, duplicate_tracks);
    try std.testing.expectEqual(@as(usize, 2), duplicate_tracks.len);
    try std.testing.expectEqualStrings("dup-audio", duplicate_tracks[0].mid);
    try std.testing.expectEqualStrings("audio_track", duplicate_tracks[0].track_id);
    try std.testing.expectEqualStrings("dup-video", duplicate_tracks[1].mid);
    try std.testing.expectEqualStrings("video_track", duplicate_tracks[1].track_id);

    const plan_b_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:plan-b\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc:1111 msid:stream track-a\r\n" ++
        "a=ssrc:2222 msid:stream track-b\r\n";
    var plan_b_session = try sdp.parse(allocator, plan_b_text);
    defer plan_b_session.deinit(allocator);
    const plan_b_tracks = try sdp.extractTrackDetails(allocator, plan_b_session);
    defer sdp.freeTrackDetails(allocator, plan_b_tracks);
    try std.testing.expectEqual(@as(usize, 2), plan_b_tracks.len);
    try std.testing.expect(sdp.tracksContainRepeatedMid(plan_b_tracks));
    try std.testing.expectEqualStrings("track-a", sdp.trackDetailsForMid(plan_b_tracks, "plan-b").?.track_id);

    const possible_plan_b_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:video\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc:3333 msid:stream track\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=sendrecv\r\n" ++
        "a=ssrc:4444 msid:stream audio\r\n";
    var possible_plan_b_session = try sdp.parse(allocator, possible_plan_b_text);
    defer possible_plan_b_session.deinit(allocator);
    try std.testing.expect(sdp.sessionPossiblyPlanB(possible_plan_b_session));
    try std.testing.expect(!sdp.sessionPossiblyPlanB(duplicate_ssrc_session));

    const media_only =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=mid:data\r\n" ++
        "a=ice-ufrag:media-ufrag\r\n" ++
        "a=ice-pwd:media-pwd\r\n" ++
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24\r\n";
    var media_session = try sdp.parse(allocator, media_only);
    defer media_session.deinit(allocator);
    const media_fingerprint = try sdp.extractFingerprint(media_session);
    try std.testing.expectEqualStrings("75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24", media_fingerprint.value);
    const media_creds = try sdp.extractIceCredentials(media_session);
    try std.testing.expectEqualStrings("media-ufrag", media_creds.ufrag);

    const candidate_details_text =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=group:BUNDLE video audio\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:audio\r\n" ++
        "a=ice-ufrag:audio-ufrag\r\n" ++
        "a=ice-pwd:audio-pwd\r\n" ++
        "a=candidate:1 1 udp 2122162783 10.0.0.1 5000 typ host generation 0\r\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" ++
        "a=mid:video\r\n" ++
        "a=ice-ufrag:video-ufrag\r\n" ++
        "a=ice-pwd:video-pwd\r\n" ++
        "a=candidate:1 1 udp 2122162783 192.168.84.254 46492 typ host generation 0 network-id 2 ufrag video-ufrag\r\n" ++
        "a=candidate:2 1 udp not-a-priority 192.168.84.254 50000 typ host generation 0\r\n" ++
        "a=end-of-candidates\r\n";
    var candidate_session = try sdp.parse(allocator, candidate_details_text);
    defer candidate_session.deinit(allocator);
    var ice_details = try sdp.extractIceDetails(allocator, candidate_session);
    defer ice_details.deinit(allocator);
    try std.testing.expectEqualStrings("video-ufrag", ice_details.credentials.ufrag);
    try std.testing.expectEqualStrings("video-pwd", ice_details.credentials.password);
    try std.testing.expectEqual(@as(usize, 1), ice_details.candidates.len);
    try std.testing.expectEqualStrings("video", ice_details.candidates[0].sdp_mid.?);
    try std.testing.expectEqual(@as(u16, 1), ice_details.candidates[0].sdp_mline_index);
    try std.testing.expectEqualStrings("192.168.84.254", ice_details.candidates[0].candidate.address);
    try std.testing.expectEqual(@as(u16, 46492), ice_details.candidates[0].candidate.port);
    try std.testing.expectEqual(@as(usize, 3), ice_details.candidates[0].candidate.extensions.len);
    try std.testing.expect(sdp.descriptionContainsUfrag(candidate_session, "video-ufrag"));
    try std.testing.expectEqualStrings("video-ufrag", sdp.candidateUfrag(ice_details.candidates[0].candidate).?);
    try std.testing.expect(sdp.candidateMatchesDescriptionUfrag(candidate_session, ice_details.candidates[0].candidate));
    var stale_candidate = try ice.Candidate.parseOwned(allocator, "candidate:9 1 udp 2122162783 192.0.2.9 5000 typ host ufrag stale-ufrag");
    defer stale_candidate.deinit(allocator);
    try std.testing.expect(!sdp.candidateMatchesDescriptionUfrag(candidate_session, stale_candidate));
    var no_ufrag_candidate = try ice.Candidate.parseOwned(allocator, "candidate:10 1 udp 2122162783 192.0.2.10 5000 typ host");
    defer no_ufrag_candidate.deinit(allocator);
    try std.testing.expect(sdp.candidateMatchesDescriptionUfrag(candidate_session, no_ufrag_candidate));
    try std.testing.expect(ice_details.end_of_candidates);

    const unknown_candidate_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=ice-ufrag:ufrag\r\n" ++
        "a=ice-pwd:pwd\r\n" ++
        "a=candidate:1 1 udp 2122162783 192.168.84.254 46492 typ zzz generation 0\r\n";
    var unknown_candidate_session = try sdp.parse(allocator, unknown_candidate_text);
    defer unknown_candidate_session.deinit(allocator);
    var unknown_candidate_details = try sdp.extractIceDetails(allocator, unknown_candidate_session);
    defer unknown_candidate_details.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), unknown_candidate_details.candidates.len);
    try std.testing.expect(!unknown_candidate_details.end_of_candidates);

    const malformed_candidate_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=ice-ufrag:ufrag\r\n" ++
        "a=ice-pwd:pwd\r\n" ++
        "a=candidate:1 1 udp not-a-priority 192.168.84.254 50000 typ host generation 0\r\n";
    var malformed_candidate_session = try sdp.parse(allocator, malformed_candidate_text);
    defer malformed_candidate_session.deinit(allocator);
    try std.testing.expectError(error.InvalidIceCandidate, sdp.extractIceDetails(allocator, malformed_candidate_session));

    try std.testing.expectEqual(sdp.DtlsRole.client, try sdp.extractDtlsRole(session));

    const sctp_params = try sdp.extractSctpParameters(session);
    try std.testing.expectEqual(@as(u16, 5000), sctp_params.port);
    try std.testing.expectEqual(@as(u32, 262144), sctp_params.max_message_size);
    try std.testing.expectEqual(@as(?u16, null), sctp_params.max_channels);
    try std.testing.expectEqualStrings("webrtc-datachannel", sctp_params.protocol);
    const sctp_port_line = try sdp.formatSctpPortLine(allocator, sctp_params.port);
    defer allocator.free(sctp_port_line);
    try std.testing.expectEqualStrings("a=sctp-port:5000\r\n", sctp_port_line);
    const max_message_size_line = try sdp.formatMaxMessageSizeLine(allocator, sctp_params.max_message_size);
    defer allocator.free(max_message_size_line);
    try std.testing.expectEqualStrings("a=max-message-size:262144\r\n", max_message_size_line);
    var sctp_lines: std.ArrayList(u8) = .empty;
    defer sctp_lines.deinit(allocator);
    try sdp.appendSctpDataChannelLines(&sctp_lines, allocator, sctp_params, false);
    try std.testing.expectEqualStrings("a=sctp-port:5000\r\na=max-message-size:262144\r\n", sctp_lines.items);
    const legacy_sctpmap_line = try sdp.formatSctpMapLine(allocator, 5000, 256);
    defer allocator.free(legacy_sctpmap_line);
    try std.testing.expectEqualStrings("a=sctpmap:5000 webrtc-datachannel 256\r\n", legacy_sctpmap_line);
    try std.testing.expectError(error.InvalidSdp, sdp.formatSctpPortLine(allocator, 0));
    try std.testing.expectError(error.InvalidSdp, sdp.formatSctpMapLine(allocator, 0, null));
    try std.testing.expect((try sdp.extractSctpInit(allocator, session)) == null);

    const sctp_init_datachannel =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=mid:data\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=sctp-init:Q29va2llTW9uc3Rlcg==\r\n";
    var sctp_init_session = try sdp.parse(allocator, sctp_init_datachannel);
    defer sctp_init_session.deinit(allocator);
    const sctp_init = (try sdp.extractSctpInit(allocator, sctp_init_session)).?;
    defer allocator.free(sctp_init);
    try std.testing.expectEqualStrings("CookieMonster", sctp_init);

    const legacy_datachannel =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 63743 DTLS/SCTP 5000\r\n" ++
        "a=mid:data\r\n" ++
        "a=setup:actpass\r\n" ++
        "a=sctpmap:5000 webrtc-datachannel 256\r\n" ++
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24\r\n" ++
        "a=ice-ufrag:media-ufrag\r\n" ++
        "a=ice-pwd:media-pwd\r\n";
    var legacy_session = try sdp.parse(allocator, legacy_datachannel);
    defer legacy_session.deinit(allocator);
    try std.testing.expectEqual(sdp.DtlsRole.auto, try sdp.extractDtlsRole(legacy_session));
    const legacy_sctp = try sdp.extractSctpParameters(legacy_session);
    try std.testing.expectEqual(@as(u16, 5000), legacy_sctp.port);
    try std.testing.expectEqual(sdp.sctp_max_message_size_unset, legacy_sctp.max_message_size);
    try std.testing.expectEqual(@as(?u16, 256), legacy_sctp.max_channels);
    try std.testing.expectEqualStrings("webrtc-datachannel", legacy_sctp.protocol);

    var invalid_sctp_init = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=sctp-init:*\r\n");
    defer invalid_sctp_init.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractSctpInit(allocator, invalid_sctp_init));
}

test "SDP rejects missing or malformed DTLS/ICE details" {
    const allocator = std.testing.allocator;

    var no_fingerprint = try sdp.parse(allocator, "v=0\r\ns=-\r\nt=0 0\r\n");
    defer no_fingerprint.deinit(allocator);
    try std.testing.expectError(error.MissingFingerprint, sdp.extractFingerprint(no_fingerprint));

    var bad_fingerprint = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=fingerprint:sha-256-only\r\n");
    defer bad_fingerprint.deinit(allocator);
    try std.testing.expectError(error.InvalidFingerprint, sdp.extractFingerprint(bad_fingerprint));

    var unsupported_fingerprint = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=fingerprint:md5 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n");
    defer unsupported_fingerprint.deinit(allocator);
    try std.testing.expectError(error.InvalidFingerprint, sdp.extractFingerprint(unsupported_fingerprint));

    var malformed_fingerprint = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=fingerprint:sha-256 75745AA6A4E552F4A7674C01C7EE913F213DA2E3537B6F3086F230AA65FB0424\r\n");
    defer malformed_fingerprint.deinit(allocator);
    try std.testing.expectError(error.InvalidFingerprint, sdp.extractFingerprint(malformed_fingerprint));

    var missing_pwd = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-ufrag:ufrag\r\n");
    defer missing_pwd.deinit(allocator);
    try std.testing.expectError(error.MissingIcePwd, sdp.extractIceCredentials(missing_pwd));

    var invalid_ufrag_token = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-ufrag:bad ufrag\r\n" ++
        "a=ice-pwd:pwd\r\n");
    defer invalid_ufrag_token.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractIceCredentials(invalid_ufrag_token));

    var session_ufrag_media_pwd = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-ufrag:session-ufrag\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=ice-ufrag:media-ufrag\r\n" ++
        "a=ice-pwd:media-pwd\r\n");
    defer session_ufrag_media_pwd.deinit(allocator);
    try std.testing.expectError(error.MissingIcePwd, sdp.extractIceCredentials(session_ufrag_media_pwd));

    var session_pwd_media_ufrag = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-pwd:session-pwd\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=ice-ufrag:media-ufrag\r\n" ++
        "a=ice-pwd:media-pwd\r\n");
    defer session_pwd_media_ufrag.deinit(allocator);
    try std.testing.expectError(error.MissingIceUfrag, sdp.extractIceCredentials(session_pwd_media_ufrag));

    var invalid_sctp_port = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:not-a-port\r\n");
    defer invalid_sctp_port.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractSctpParameters(invalid_sctp_port));

    var mismatched_sctpmap = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=sctpmap:6000 webrtc-datachannel 256\r\n");
    defer mismatched_sctpmap.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractSctpParameters(mismatched_sctpmap));

    var invalid_sctpmap_protocol = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctpmap:5000 not-datachannel 256\r\n");
    defer invalid_sctpmap_protocol.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractSctpParameters(invalid_sctpmap_protocol));

    var invalid_format_protocol = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP not-datachannel\r\n" ++
        "a=sctp-port:5000\r\n");
    defer invalid_format_protocol.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractSctpParameters(invalid_format_protocol));

    var invalid_setup = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=setup:sideways\r\n");
    defer invalid_setup.deinit(allocator);
    try std.testing.expectError(error.InvalidSdp, sdp.extractDtlsRole(invalid_setup));

    var no_setup = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
    defer no_setup.deinit(allocator);
    try std.testing.expectEqual(sdp.DtlsRole.auto, try sdp.extractDtlsRole(no_setup));
    try std.testing.expectEqual(sdp.DtlsRole.auto, (try sdp.parseDtlsSetupAttribute("holdconn")).dtlsRole());
    try std.testing.expectEqualStrings("actpass", sdp.DtlsRole.auto.setupAttribute());
    try std.testing.expectEqualStrings("active", sdp.DtlsRole.client.setupAttribute());
    try std.testing.expectEqualStrings("passive", sdp.DtlsRole.server.setupAttribute());
    const setup_line = try sdp.formatDtlsSetupLine(allocator, .client);
    defer allocator.free(setup_line);
    try std.testing.expectEqualStrings("a=setup:active\r\n", setup_line);
    const valid_fingerprint = "75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24";
    const fingerprint_line = try sdp.formatFingerprintLine(allocator, .{ .algorithm = "sha-256", .value = valid_fingerprint });
    defer allocator.free(fingerprint_line);
    try std.testing.expectEqualStrings("a=fingerprint:sha-256 " ++ valid_fingerprint ++ "\r\n", fingerprint_line);
    const creds_line = sdp.IceCredentials{ .ufrag = "ufrag", .password = "pwd" };
    const ufrag_line = try sdp.formatIceUfragLine(allocator, creds_line);
    defer allocator.free(ufrag_line);
    try std.testing.expectEqualStrings("a=ice-ufrag:ufrag\r\n", ufrag_line);
    const pwd_line = try sdp.formatIcePwdLine(allocator, creds_line);
    defer allocator.free(pwd_line);
    try std.testing.expectEqualStrings("a=ice-pwd:pwd\r\n", pwd_line);
    const ice_lite_line = try sdp.formatIceLiteLine(allocator);
    defer allocator.free(ice_lite_line);
    try std.testing.expectEqualStrings("a=ice-lite\r\n", ice_lite_line);
    var transport_lines: std.ArrayList(u8) = .empty;
    defer transport_lines.deinit(allocator);
    try sdp.appendTransportAttributeLines(&transport_lines, allocator, .{
        .ice_credentials = creds_line,
        .fingerprint = .{ .algorithm = "sha-256", .value = valid_fingerprint },
        .dtls_role = .client,
        .transport_attributes = .{ .ice_lite = true, .rtcp_mux = true, .rtcp_rsize = true },
        .extmap_allow_mixed = true,
    });
    try std.testing.expectEqualStrings(
        "a=ice-lite\r\n" ++
            "a=setup:active\r\n" ++
            "a=fingerprint:sha-256 " ++ valid_fingerprint ++ "\r\n" ++
            "a=ice-ufrag:ufrag\r\n" ++
            "a=ice-pwd:pwd\r\n" ++
            "a=rtcp-mux\r\n" ++
            "a=rtcp-rsize\r\n" ++
            "a=extmap-allow-mixed\r\n",
        transport_lines.items,
    );
    try std.testing.expectError(error.InvalidSdp, sdp.formatIceUfragLine(allocator, .{ .ufrag = "", .password = "pwd" }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatIcePwdLine(allocator, .{ .ufrag = "ufrag", .password = "" }));
    try std.testing.expectError(error.InvalidSdp, sdp.formatIcePwdLine(allocator, .{ .ufrag = "ufrag", .password = "bad pwd" }));
    try std.testing.expectError(error.InvalidFingerprint, sdp.formatFingerprintLine(allocator, .{ .algorithm = "", .value = valid_fingerprint }));
    try std.testing.expectError(error.InvalidFingerprint, sdp.formatFingerprintLine(allocator, .{ .algorithm = "sha-256", .value = "AA:BB" }));
}

test "RTP and DTLS record parsers" {
    const allocator = std.testing.allocator;
    var rtp_bytes = [_]u8{ 0x80, 96, 0x12, 0x34, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef };
    var header = try rtp.Header.parse(allocator, &rtp_bytes);
    defer header.deinit(allocator);
    try std.testing.expectEqual(@as(u2, 2), header.version);
    try std.testing.expectEqual(@as(u16, 0x1234), header.sequence_number);

    const dtls_bytes = [_]u8{ 22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0xff };
    const record = try dtls.Record.parse(&dtls_bytes);
    try std.testing.expectEqual(dtls.ContentType.handshake, record.content_type);
    try std.testing.expectEqual(@as(u48, 2), record.sequence_number);
    try std.testing.expectEqualStrings(&.{0xff}, record.fragment);

    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);
    try dtls.writeRecord(&written, allocator, .{ .content_type = .application_data, .epoch = 1, .sequence_number = 3 }, "dtls");
    const written_record = try dtls.Record.parse(written.items);
    try std.testing.expectEqual(dtls.ContentType.application_data, written_record.content_type);
    try std.testing.expectEqual(@as(u16, 1), written_record.epoch);
    try std.testing.expectEqual(@as(u48, 3), written_record.sequence_number);
    try std.testing.expectEqualStrings("dtls", written_record.fragment);

    written.clearRetainingCapacity();
    try dtls.writeRecords(&written, allocator, &.{
        .{ .options = .{ .content_type = .application_data, .epoch = 1, .sequence_number = 3 }, .fragment = "dtls" },
        .{ .options = .{ .content_type = .alert, .epoch = 1, .sequence_number = 4 }, .fragment = "alert" },
    });
    const records = try dtls.parseRecords(allocator, written.items);
    defer dtls.freeRecords(allocator, records);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    try std.testing.expectEqual(dtls.ContentType.application_data, records[0].content_type);
    try std.testing.expectEqualStrings("dtls", records[0].fragment);
    try std.testing.expectEqual(dtls.ContentType.alert, records[1].content_type);
    try std.testing.expectEqual(@as(u48, 4), records[1].sequence_number);
    try std.testing.expectEqualStrings("alert", records[1].fragment);
    try std.testing.expectError(error.BufferTooShort, dtls.parseRecords(allocator, written.items[0 .. written.items.len - 1]));
    try std.testing.expectError(error.InvalidDtlsRecord, dtls.writeRecords(&written, allocator, &.{}));

    var invalid_dtls = try written.clone(allocator);
    defer invalid_dtls.deinit(allocator);
    invalid_dtls.items[1] = 0x03; // TLS record versions are not valid DTLS wire versions.
    try std.testing.expectError(error.InvalidDtlsRecord, dtls.Record.parse(invalid_dtls.items));
    invalid_dtls.items[1] = 0xfe;
    invalid_dtls.items[0] = 0xff; // Unknown content type.
    try std.testing.expectError(error.InvalidDtlsRecord, dtls.Record.parse(invalid_dtls.items));
}

test "RTP packet extension padding and writer" {
    const allocator = std.testing.allocator;
    var one_byte_extensions: std.ArrayList(u8) = .empty;
    defer one_byte_extensions.deinit(allocator);
    const audio_level = try rtp.audioLevelPayload(8, true);
    const twcc_payload = rtp.transportWideSequenceNumberPayload(0x1234);
    const abs_send_time = rtp.absoluteSendTimePayload(0x010203);
    const playout_delay = try rtp.playoutDelayPayload(1 << 4, 1 << 8);
    const video_orientation = rtp.videoOrientationPayload(.{ .rotation = .rotate_90, .flip = true, .camera = true });
    const capture_time_ns: u64 = 1_650_000_000;
    const capture_offset = rtp.captureClockOffsetFromNanos(1_250_000_000);
    const abs_capture_time = rtp.absCaptureTimePayload(rtp.absCaptureTimeFromUnixNanos(capture_time_ns), capture_offset);
    try rtp.writeOneByteHeaderExtensions(&one_byte_extensions, allocator, &.{
        .{ .id = 1, .data = "m" },
        .{ .id = 3, .data = &twcc_payload },
        .{ .id = 4, .data = &abs_send_time },
        .{ .id = 5, .data = &audio_level },
        .{ .id = 6, .data = &playout_delay },
        .{ .id = 8, .data = &video_orientation },
        .{ .id = 7, .data = abs_capture_time[0..rtp.absCaptureTimePayloadLen(capture_offset)] },
        .{ .id = 9, .data = "video" },
        .{ .id = 10, .data = "f" },
        .{ .id = 11, .data = "rtx-f" },
    });
    try std.testing.expectEqual(@as(usize, 0), one_byte_extensions.items.len % 4);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try rtp.writePacket(&encoded, allocator, .{
        .marker = true,
        .payload_type = 111,
        .sequence_number = 10,
        .timestamp = 99,
        .ssrc = 0x01020304,
        .extension = .{ .profile = rtp.one_byte_header_extension_profile, .data = one_byte_extensions.items },
        .padding_len = 4,
    }, "opus");

    var packet = try rtp.Packet.parse(allocator, encoded.items);
    defer packet.deinit(allocator);
    try std.testing.expect(packet.header.marker);
    try std.testing.expectEqual(@as(u7, 111), packet.header.payload_type);
    try std.testing.expectEqual(@as(u16, 0xbede), packet.extension.?.profile);
    const parsed_extensions = try rtp.parseHeaderExtensionElements(allocator, packet.extension.?);
    defer rtp.freeHeaderExtensionElements(allocator, parsed_extensions);
    try std.testing.expectEqualStrings("m", rtp.findHeaderExtension(parsed_extensions, 1).?);
    try std.testing.expectEqual(@as(?u16, 0x1234), try rtp.transportWideSequenceNumber(parsed_extensions, 3));
    try std.testing.expectEqual(@as(?u16, 2), try rtp.transportWideSequenceNumber(&.{.{ .id = 3, .data = &.{ 0x00, 0x02, 0xff } }}, 3));
    try std.testing.expectError(error.InvalidRtpPacket, rtp.transportWideSequenceNumber(&.{.{ .id = 3, .data = &.{0x00} }}, 3));
    try std.testing.expectEqual(@as(?u24, 0x010203), try rtp.absoluteSendTime24(parsed_extensions, 4));
    try std.testing.expectEqual(@as(?u24, 0x010203), try rtp.absoluteSendTime24(&.{.{ .id = 4, .data = &.{ 0x01, 0x02, 0x03, 0xff } }}, 4));
    try std.testing.expectError(error.InvalidRtpPacket, rtp.absoluteSendTime24(&.{.{ .id = 4, .data = &.{ 0x01, 0x02 } }}, 4));
    var mutable_extensions = try allocator.dupe(rtp.HeaderExtensionElement, parsed_extensions);
    defer allocator.free(mutable_extensions);
    try rtp.setHeaderExtension(allocator, &mutable_extensions, 3, &.{ 0xab, 0xcd });
    try rtp.setHeaderExtension(allocator, &mutable_extensions, 12, "new");
    try std.testing.expectEqual(@as(?u16, 0xabcd), try rtp.transportWideSequenceNumber(mutable_extensions, 3));
    try std.testing.expectEqualStrings("new", rtp.findHeaderExtension(mutable_extensions, 12).?);
    try rtp.setHeaderExtensionForProfile(allocator, &mutable_extensions, rtp.one_byte_header_extension_profile, 14, "ok");
    try std.testing.expectEqualStrings("ok", rtp.findHeaderExtension(mutable_extensions, 14).?);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.setHeaderExtensionForProfile(allocator, &mutable_extensions, rtp.one_byte_header_extension_profile, 15, "bad"));
    try std.testing.expectError(error.InvalidRtpPacket, rtp.setHeaderExtensionForProfile(allocator, &mutable_extensions, rtp.one_byte_header_extension_profile, 2, "0123456789abcdefg"));
    try rtp.setHeaderExtensionForProfile(allocator, &mutable_extensions, rtp.two_byte_header_extension_profile, 200, "wide");
    try std.testing.expectEqualStrings("wide", rtp.findHeaderExtension(mutable_extensions, 200).?);
    const mutable_ids = try rtp.headerExtensionIds(allocator, mutable_extensions);
    defer allocator.free(mutable_ids);
    try std.testing.expectEqual(@as(u8, 1), mutable_ids[0]);
    try std.testing.expectEqual(@as(u8, 200), mutable_ids[mutable_ids.len - 1]);
    try std.testing.expect(try rtp.deleteHeaderExtension(allocator, &mutable_extensions, 1));
    try std.testing.expect(rtp.findHeaderExtension(mutable_extensions, 1) == null);
    try std.testing.expect(!(try rtp.deleteHeaderExtension(allocator, &mutable_extensions, 42)));
    try std.testing.expectError(error.InvalidRtpPacket, rtp.setHeaderExtension(allocator, &mutable_extensions, 0, "bad"));
    rtp.clearHeaderExtensions(allocator, &mutable_extensions);
    try std.testing.expectEqual(@as(usize, 0), mutable_extensions.len);
    const send_ntp: u64 = 0xa0c65b1000100000;
    const receive_ntp: u64 = 0xa0c65b1001000000;
    const send_unix_ns = rtp.unixNanosFromNtpTime(send_ntp);
    const receive_unix_ns = rtp.unixNanosFromNtpTime(receive_ntp);
    const send_timestamp = rtp.absoluteSendTimeFromUnixNanos(send_unix_ns);
    try std.testing.expectEqual(@as(u24, @truncate(rtp.ntpTimeFromUnixNanos(send_unix_ns) >> 14)), send_timestamp);
    const estimated_unix_ns = rtp.estimateAbsoluteSendTimeUnixNanos(send_timestamp, receive_unix_ns);
    const diff = if (estimated_unix_ns > send_unix_ns) estimated_unix_ns - send_unix_ns else send_unix_ns - estimated_unix_ns;
    try std.testing.expect(diff <= 4 * std.time.ns_per_us);
    const parsed_audio_level = (try rtp.audioLevel(parsed_extensions, 5)).?;
    try std.testing.expect(parsed_audio_level.voice);
    try std.testing.expectEqual(@as(u7, 8), parsed_audio_level.level);
    const extra_audio_level = (try rtp.audioLevel(&.{.{ .id = 5, .data = &.{ 0x88, 0xff } }}, 5)).?;
    try std.testing.expect(extra_audio_level.voice);
    try std.testing.expectEqual(@as(u7, 8), extra_audio_level.level);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.audioLevel(&.{.{ .id = 5, .data = &.{} }}, 5));
    try std.testing.expectError(error.InvalidRtpPacket, rtp.audioLevelPayload(128, false));
    const parsed_playout_delay = (try rtp.playoutDelay(parsed_extensions, 6)).?;
    try std.testing.expectEqual(@as(u12, 1 << 4), parsed_playout_delay.min_delay);
    try std.testing.expectEqual(@as(u12, 1 << 8), parsed_playout_delay.max_delay);
    const extra_playout_delay = (try rtp.playoutDelay(&.{.{ .id = 6, .data = &.{ 0x01, 0x01, 0x00, 0xff, 0xff } }}, 6)).?;
    try std.testing.expectEqual(@as(u12, 1 << 4), extra_playout_delay.min_delay);
    try std.testing.expectEqual(@as(u12, 1 << 8), extra_playout_delay.max_delay);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.playoutDelay(&.{.{ .id = 6, .data = &.{ 0x01, 0x01 } }}, 6));
    try std.testing.expectError(error.InvalidRtpPacket, rtp.playoutDelayPayload(1 << 12, 1 << 12));
    const parsed_video_orientation = (try rtp.videoOrientation(parsed_extensions, 8)).?;
    try std.testing.expectEqual(rtp.VideoRotation.rotate_90, parsed_video_orientation.rotation);
    try std.testing.expect(parsed_video_orientation.flip);
    try std.testing.expect(parsed_video_orientation.camera);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.videoOrientation(&.{.{ .id = 8, .data = &.{0xf0} }}, 8));
    const parsed_abs_capture_time = (try rtp.absCaptureTime(parsed_extensions, 7)).?;
    const capture_diff = if (parsed_abs_capture_time.captureUnixNanos() > capture_time_ns)
        parsed_abs_capture_time.captureUnixNanos() - capture_time_ns
    else
        capture_time_ns - parsed_abs_capture_time.captureUnixNanos();
    try std.testing.expect(capture_diff <= 1);
    try std.testing.expectEqual(@as(i64, 1_250_000_000), parsed_abs_capture_time.estimatedCaptureClockOffsetNanos().?);
    const short_abs_capture_time = (try rtp.absCaptureTime(&.{.{ .id = 7, .data = abs_capture_time[0..12] }}, 7)).?;
    try std.testing.expect(short_abs_capture_time.estimated_capture_clock_offset == null);
    var extra_abs_capture_time_buf: [17]u8 = undefined;
    @memcpy(extra_abs_capture_time_buf[0..16], &abs_capture_time);
    extra_abs_capture_time_buf[16] = 0xff;
    const extra_abs_capture_time = (try rtp.absCaptureTime(&.{.{ .id = 7, .data = &extra_abs_capture_time_buf }}, 7)).?;
    try std.testing.expectEqual(@as(i64, 1_250_000_000), extra_abs_capture_time.estimatedCaptureClockOffsetNanos().?);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.absCaptureTime(&.{.{ .id = 7, .data = abs_capture_time[0..7] }}, 7));
    try std.testing.expectEqual(@as(i64, -250_000_000), rtp.captureClockOffsetNanos(rtp.captureClockOffsetFromNanos(-250_000_000)));
    try std.testing.expectEqualStrings("video", rtp.mid(parsed_extensions, 9).?);
    try std.testing.expectEqualStrings("f", rtp.rtpStreamId(parsed_extensions, 10).?);
    try std.testing.expectEqualStrings("rtx-f", rtp.repairedRtpStreamId(parsed_extensions, 11).?);
    try std.testing.expectEqualStrings("opus", packet.payload);
    try std.testing.expectEqual(@as(u8, 4), packet.padding_len);
    const demux = try rtp.unknownRtpDemuxDetails(allocator, encoded.items, 9, 10, 11);
    try std.testing.expectEqualStrings("video", demux.mid);
    try std.testing.expectEqualStrings("f", demux.rid);
    try std.testing.expectEqualStrings("rtx-f", demux.repaired_rid);
    try std.testing.expect(!demux.padding_only);

    encoded.clearRetainingCapacity();
    try rtp.writePacket(&encoded, allocator, .{
        .payload_type = 111,
        .sequence_number = 11,
        .timestamp = 100,
        .ssrc = 0x01020304,
        .extension = .{ .profile = rtp.one_byte_header_extension_profile, .data = one_byte_extensions.items },
        .padding_len = 4,
    }, "");
    const padding_only_demux = try rtp.unknownRtpDemuxDetails(allocator, encoded.items, 9, 10, 11);
    try std.testing.expect(padding_only_demux.padding_only);
    try std.testing.expectEqualStrings("video", padding_only_demux.mid);

    const reserved_extension = rtp.Extension{
        .profile = rtp.one_byte_header_extension_profile,
        .data = &.{ 0xf0, 0xaa, 0xbb, 0xcc },
    };
    try std.testing.expectError(error.InvalidRtpPacket, rtp.parseHeaderExtensionElements(allocator, reserved_extension));
    const lenient_reserved = try rtp.parseHeaderExtensionElementsLenient(allocator, reserved_extension);
    defer rtp.freeHeaderExtensionElements(allocator, lenient_reserved);
    try std.testing.expectEqual(@as(usize, 0), lenient_reserved.len);

    const non_zero_padding = rtp.Extension{
        .profile = rtp.one_byte_header_extension_profile,
        .data = &.{ 0x01, 0xaa, 0xbb, 0xcc },
    };
    try std.testing.expectError(error.InvalidRtpPacket, rtp.parseHeaderExtensionElements(allocator, non_zero_padding));
    const lenient_non_zero_padding = try rtp.parseHeaderExtensionElementsLenient(allocator, non_zero_padding);
    defer rtp.freeHeaderExtensionElements(allocator, lenient_non_zero_padding);
    try std.testing.expectEqual(@as(usize, 0), lenient_non_zero_padding.len);

    const raw_extension = try rtp.parseHeaderExtensionElements(allocator, .{
        .profile = 0xbeef,
        .data = &.{ 0xde, 0xad, 0xbe, 0xef },
    });
    defer rtp.freeHeaderExtensionElements(allocator, raw_extension);
    try std.testing.expectEqual(@as(usize, 1), raw_extension.len);
    try std.testing.expectEqual(@as(u8, 0), raw_extension[0].id);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, raw_extension[0].data);
    var mutable_raw = try allocator.dupe(rtp.HeaderExtensionElement, raw_extension);
    defer allocator.free(mutable_raw);
    try rtp.setRawHeaderExtension(allocator, &mutable_raw, &.{});
    try std.testing.expectEqual(@as(usize, 0), rtp.findHeaderExtension(mutable_raw, 0).?.len);
    try rtp.setHeaderExtensionForProfile(allocator, &mutable_raw, 0xbeef, 0, "raw");
    try std.testing.expectEqualStrings("raw", rtp.findHeaderExtension(mutable_raw, 0).?);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.setHeaderExtensionForProfile(allocator, &mutable_raw, 0xbeef, 1, "bad"));
    const raw_ids = try rtp.headerExtensionIds(allocator, mutable_raw);
    defer allocator.free(raw_ids);
    try std.testing.expectEqualSlices(u8, &.{0}, raw_ids);
    try std.testing.expect(try rtp.deleteHeaderExtension(allocator, &mutable_raw, 0));
    try std.testing.expect(rtp.findHeaderExtension(mutable_raw, 0) == null);

    const cryptex_one = try rtp.parseHeaderExtensionElements(allocator, .{
        .profile = rtp.cryptex_one_byte_header_extension_profile,
        .data = one_byte_extensions.items,
    });
    defer rtp.freeHeaderExtensionElements(allocator, cryptex_one);
    try std.testing.expectEqualStrings("m", rtp.findHeaderExtension(cryptex_one, 1).?);

    var two_byte_extensions: std.ArrayList(u8) = .empty;
    defer two_byte_extensions.deinit(allocator);
    try rtp.writeTwoByteHeaderExtensions(&two_byte_extensions, allocator, &.{
        .{ .id = 16, .data = "rid" },
        .{ .id = 20, .data = &.{} },
    });
    const parsed_two = try rtp.parseHeaderExtensionElements(allocator, .{
        .profile = rtp.two_byte_header_extension_profile,
        .data = two_byte_extensions.items,
    });
    defer rtp.freeHeaderExtensionElements(allocator, parsed_two);
    try std.testing.expectEqualStrings("rid", rtp.findHeaderExtension(parsed_two, 16).?);
    try std.testing.expectEqual(@as(usize, 0), rtp.findHeaderExtension(parsed_two, 20).?.len);

    const cryptex_two = try rtp.parseHeaderExtensionElements(allocator, .{
        .profile = rtp.cryptex_two_byte_header_extension_profile,
        .data = two_byte_extensions.items,
    });
    defer rtp.freeHeaderExtensionElements(allocator, cryptex_two);
    try std.testing.expectEqualStrings("rid", rtp.findHeaderExtension(cryptex_two, 16).?);

    var vla_payload: std.ArrayList(u8) = .empty;
    defer vla_payload.deinit(allocator);
    const vla_layers = [_]rtp.SpatialLayer{
        .{ .rtp_stream_id = 0, .spatial_id = 0, .target_bitrates_kbps = &.{150} },
        .{ .rtp_stream_id = 1, .spatial_id = 0, .target_bitrates_kbps = &.{ 240, 400 } },
        .{ .rtp_stream_id = 2, .spatial_id = 0, .target_bitrates_kbps = &.{ 720, 1200 } },
    };
    try rtp.writeVideoLayerAllocationPayload(&vla_payload, allocator, .{
        .rtp_stream_id = 0,
        .rtp_stream_count = 3,
        .active_spatial_layers = &vla_layers,
    });
    try std.testing.expectEqual(vla_payload.items.len, try rtp.videoLayerAllocationPayloadLen(.{
        .rtp_stream_id = 0,
        .rtp_stream_count = 3,
        .active_spatial_layers = &vla_layers,
    }));
    try std.testing.expectEqualSlices(u8, &.{
        0x21, 0x14, 0x96, 0x01, 0xf0, 0x01, 0x90, 0x03, 0xd0, 0x05, 0xb0, 0x09,
    }, vla_payload.items);
    const parsed_vla = try rtp.parseVideoLayerAllocationPayload(allocator, vla_payload.items);
    defer rtp.freeVideoLayerAllocation(allocator, parsed_vla);
    try std.testing.expectEqual(@as(u2, 0), parsed_vla.rtp_stream_id);
    try std.testing.expectEqual(@as(u3, 3), parsed_vla.rtp_stream_count);
    try std.testing.expectEqual(@as(usize, 3), parsed_vla.active_spatial_layers.len);
    try std.testing.expectEqual(@as(u32, 150), parsed_vla.active_spatial_layers[0].target_bitrates_kbps[0]);
    try std.testing.expectEqual(@as(u32, 400), parsed_vla.active_spatial_layers[1].target_bitrates_kbps[1]);
    const vla_element = [_]rtp.HeaderExtensionElement{.{ .id = 22, .data = vla_payload.items }};
    const parsed_vla_from_element = (try rtp.videoLayerAllocation(allocator, &vla_element, 22)).?;
    defer rtp.freeVideoLayerAllocation(allocator, parsed_vla_from_element);
    try std.testing.expectEqual(@as(u2, 0), parsed_vla_from_element.rtp_stream_id);
    try std.testing.expect((try rtp.videoLayerAllocation(allocator, &vla_element, 23)) == null);

    vla_payload.clearRetainingCapacity();
    const vla_layers_with_resolution = [_]rtp.SpatialLayer{
        .{ .rtp_stream_id = 0, .spatial_id = 0, .target_bitrates_kbps = &.{150}, .width = 320, .height = 180, .framerate = 30 },
        .{ .rtp_stream_id = 1, .spatial_id = 0, .target_bitrates_kbps = &.{ 240, 400 }, .width = 640, .height = 360, .framerate = 30 },
        .{ .rtp_stream_id = 2, .spatial_id = 0, .target_bitrates_kbps = &.{ 720, 1200 }, .width = 1280, .height = 720, .framerate = 30 },
    };
    try rtp.writeVideoLayerAllocationPayload(&vla_payload, allocator, .{
        .rtp_stream_id = 2,
        .rtp_stream_count = 3,
        .active_spatial_layers = &vla_layers_with_resolution,
        .has_resolution_and_framerate = true,
    });
    try std.testing.expectEqual(vla_payload.items.len, try rtp.videoLayerAllocationPayloadLen(.{
        .rtp_stream_id = 2,
        .rtp_stream_count = 3,
        .active_spatial_layers = &vla_layers_with_resolution,
        .has_resolution_and_framerate = true,
    }));
    try std.testing.expectEqualSlices(u8, &.{
        0xa1, 0x14, 0x96, 0x01, 0xf0, 0x01, 0x90, 0x03, 0xd0, 0x05, 0xb0, 0x09,
        0x01, 0x3f, 0x00, 0xb3, 0x1e, 0x02, 0x7f, 0x01, 0x67, 0x1e, 0x04, 0xff,
        0x02, 0xcf, 0x1e,
    }, vla_payload.items);
    const parsed_vla_with_resolution = try rtp.parseVideoLayerAllocationPayload(allocator, vla_payload.items);
    defer rtp.freeVideoLayerAllocation(allocator, parsed_vla_with_resolution);
    try std.testing.expect(parsed_vla_with_resolution.has_resolution_and_framerate);
    try std.testing.expectEqual(@as(u2, 2), parsed_vla_with_resolution.rtp_stream_id);
    try std.testing.expectEqual(@as(u16, 1280), parsed_vla_with_resolution.active_spatial_layers[2].width);
    try std.testing.expectEqual(@as(u16, 720), parsed_vla_with_resolution.active_spatial_layers[2].height);
    try std.testing.expectEqual(@as(u8, 30), parsed_vla_with_resolution.active_spatial_layers[2].framerate);

    try vla_payload.appendSlice(allocator, &.{ 0xaa, 0xbb });
    const parsed_vla_with_trailing = try rtp.parseVideoLayerAllocationPayload(allocator, vla_payload.items);
    defer rtp.freeVideoLayerAllocation(allocator, parsed_vla_with_trailing);
    try std.testing.expect(parsed_vla_with_trailing.has_resolution_and_framerate);
    try std.testing.expectEqual(@as(usize, 3), parsed_vla_with_trailing.active_spatial_layers.len);
    try std.testing.expectEqual(@as(u16, 1280), parsed_vla_with_trailing.active_spatial_layers[2].width);

    vla_payload.clearRetainingCapacity();
    try rtp.writeVideoLayerAllocationPayload(&vla_payload, allocator, .{
        .rtp_stream_id = 0,
        .rtp_stream_count = 1,
        .active_spatial_layers = &.{},
    });
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00 }, vla_payload.items);
    try std.testing.expectEqual(@as(usize, 3), try rtp.videoLayerAllocationPayloadLen(.{
        .rtp_stream_id = 0,
        .rtp_stream_count = 1,
        .active_spatial_layers = &.{},
    }));

    try std.testing.expectError(error.InvalidRtpPacket, rtp.writeVideoLayerAllocationPayload(&vla_payload, allocator, .{
        .rtp_stream_id = 0,
        .rtp_stream_count = 5,
        .active_spatial_layers = &.{},
    }));

    try std.testing.expectError(error.InvalidRtpPacket, rtp.writeOneByteHeaderExtensions(&two_byte_extensions, allocator, &.{
        .{ .id = 15, .data = "reserved" },
    }));

    const too_large_extension = try allocator.alloc(u8, (@as(usize, std.math.maxInt(u16)) + 1) * 4);
    defer allocator.free(too_large_extension);
    try std.testing.expectError(error.InvalidRtpPacket, rtp.writePacket(&encoded, allocator, .{
        .payload_type = 111,
        .sequence_number = 11,
        .timestamp = 100,
        .ssrc = 0x01020304,
        .extension = .{ .profile = rtp.one_byte_header_extension_profile, .data = too_large_extension },
    }, ""));
}

test "SRTCP NULL_HMAC_SHA1_80 authenticates index and rejects replay" {
    const allocator = std.testing.allocator;
    const auth_key = [_]u8{0x24} ** srtp.hmac_sha1_len;
    var sender = srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    var receiver = srtp.Context{ .keys = .{ .auth_key = &auth_key } };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try sender.protectRtcpPacket(&encoded, allocator, .{ .picture_loss_indication = .{
        .sender_ssrc = 0x01020304,
        .media_ssrc = 0x11121314,
    } });

    var auth = try receiver.unprotectRtcp(allocator, encoded.items);
    defer auth.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), auth.verified.index);
    try std.testing.expect(!auth.verified.encrypted);
    try std.testing.expectEqual(@as(u32, 0x01020304), auth.rtcp.picture_loss_indication.sender_ssrc);

    try std.testing.expectError(error.SrtpReplay, receiver.verifyRtcp(encoded.items));

    var tampered = try allocator.dupe(u8, encoded.items);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x55;
    var fresh = srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    try std.testing.expectError(error.BadSrtpAuthTag, fresh.verifyRtcp(tampered));

    encoded.clearRetainingCapacity();
    var sdes_items = [_]rtcp.SdesItem{.{ .item_type = .cname, .value = "compound@example.test" }};
    var sdes_chunks = [_]rtcp.SdesChunk{.{ .ssrc = 0x01020304, .items = &sdes_items }};
    const compound_packets = [_]rtcp.Packet{
        .{ .receiver_report = .{ .sender_ssrc = 0x01020304 } },
        .{ .source_description = .{ .chunks = &sdes_chunks } },
        .{ .picture_loss_indication = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x11121314 } },
    };
    try sender.protectRtcpCompound(&encoded, allocator, &compound_packets);

    var compound = try receiver.unprotectRtcpCompound(allocator, encoded.items);
    defer compound.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), compound.verified.index);
    try std.testing.expectEqual(@as(usize, 3), compound.rtcp.len);
    try std.testing.expectEqual(@as(u32, 0x01020304), compound.rtcp[0].receiver_report.sender_ssrc);
    try std.testing.expectEqualStrings("compound@example.test", compound.rtcp[1].source_description.cname(0x01020304).?);
    try std.testing.expectEqual(@as(u32, 0x11121314), compound.rtcp[2].picture_loss_indication.media_ssrc);

    encoded.clearRetainingCapacity();
    const reduced_size_packets = [_]rtcp.Packet{
        .{ .picture_loss_indication = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x21222324 } },
        .{ .rapid_resynchronization_request = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x31323334 } },
    };
    try sender.protectRtcpPackets(&encoded, allocator, &reduced_size_packets);
    var reduced = try receiver.unprotectRtcpPackets(allocator, encoded.items);
    defer reduced.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2), reduced.verified.index);
    try std.testing.expectEqual(@as(usize, 2), reduced.rtcp.len);
    try std.testing.expectEqual(@as(u32, 0x21222324), reduced.rtcp[0].picture_loss_indication.media_ssrc);
    try std.testing.expectEqual(@as(u32, 0x31323334), reduced.rtcp[1].rapid_resynchronization_request.media_ssrc);
}

test "SRTP NULL_HMAC_SHA1_80 authenticates ROC and rejects replay" {
    const allocator = std.testing.allocator;
    const auth_key = [_]u8{0x42} ** srtp.hmac_sha1_len;
    var sender = srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    var receiver = srtp.Context{ .keys = .{ .auth_key = &auth_key } };

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try sender.protectRtpPacket(&first, allocator, .{
        .payload_type = 111,
        .sequence_number = 0xfffe,
        .timestamp = 90_000,
        .ssrc = 0x01020304,
    }, "first");
    var first_rtp = try receiver.unprotectRtp(allocator, first.items);
    defer first_rtp.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0), first_rtp.verified.roc);
    try std.testing.expectEqual(@as(u64, 0xfffe), first_rtp.verified.packet_index);
    try std.testing.expectEqualStrings("first", first_rtp.rtp.payload);

    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try sender.protectRtpPacket(&second, allocator, .{
        .payload_type = 111,
        .sequence_number = 0xffff,
        .timestamp = 90_960,
        .ssrc = 0x01020304,
    }, "second");
    var second_rtp = try receiver.unprotectRtp(allocator, second.items);
    defer second_rtp.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0), second_rtp.verified.roc);

    var wrapped: std.ArrayList(u8) = .empty;
    defer wrapped.deinit(allocator);
    try sender.protectRtpPacket(&wrapped, allocator, .{
        .payload_type = 111,
        .sequence_number = 0,
        .timestamp = 91_920,
        .ssrc = 0x01020304,
    }, "wrapped");
    var wrapped_rtp = try receiver.unprotectRtp(allocator, wrapped.items);
    defer wrapped_rtp.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), wrapped_rtp.verified.roc);
    try std.testing.expectEqual(@as(u64, 0x1_0000), wrapped_rtp.verified.packet_index);
    try std.testing.expectEqualStrings("wrapped", wrapped_rtp.rtp.payload);

    // The replay window is checked after authentication, so duplicates with a
    // valid tag are rejected without letting an attacker advance the ROC state.
    try std.testing.expectError(error.SrtpReplay, receiver.verifyRtp(first.items));

    var tampered = try allocator.dupe(u8, second.items);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    var fresh_receiver = srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    try std.testing.expectError(error.BadSrtpAuthTag, fresh_receiver.verifyRtp(tampered));
}

test "RTCP SDES and compound packets" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var sdes_items = [_]rtcp.SdesItem{.{ .item_type = .cname, .value = "alice@example.test" }};
    var sdes_chunks = [_]rtcp.SdesChunk{.{ .ssrc = 0x01020304, .items = &sdes_items }};
    var bye_sources = [_]u32{0x01020304};
    var packets = [_]rtcp.Packet{
        .{ .receiver_report = .{ .sender_ssrc = 0x01020304 } },
        .{ .source_description = .{ .chunks = &sdes_chunks } },
        .{ .picture_loss_indication = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x11121314 } },
        .{ .goodbye = .{ .sources = &bye_sources, .reason = "done" } },
    };

    try rtcp.writeCompound(&encoded, allocator, &packets);
    try std.testing.expectEqual(@as(usize, encoded.items.len), try rtcp.compoundWireLen(&packets));
    const parsed = try rtcp.parseCompound(allocator, encoded.items);
    defer rtcp.freeCompound(allocator, parsed);
    try std.testing.expectEqual(@as(usize, 4), parsed.len);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed[0].receiver_report.sender_ssrc);
    try std.testing.expectEqualStrings("alice@example.test", parsed[1].source_description.cname(0x01020304).?);
    try std.testing.expectEqualStrings("alice@example.test", try rtcp.compoundCname(parsed));
    try std.testing.expectEqual(@as(usize, 20), parsed[1].source_description.chunks[0].items[0].wireLen());
    try std.testing.expectEqual(@as(usize, 28), parsed[1].source_description.chunks[0].wireLen());
    try std.testing.expectEqual(@as(usize, 32), parsed[1].source_description.wireLen());
    try std.testing.expectEqual(@as(u32, 0x11121314), parsed[2].picture_loss_indication.media_ssrc);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed[3].goodbye.sources[0]);
    try std.testing.expectEqualStrings("done", parsed[3].goodbye.reason);
    try std.testing.expectEqual(@as(usize, 16), parsed[3].goodbye.wireLen());
    const empty_compound_destinations = try rtcp.compoundDestinationSsrcs(allocator, parsed);
    defer allocator.free(empty_compound_destinations);
    try std.testing.expectEqual(@as(usize, 0), empty_compound_destinations.len);

    var single = try rtcp.parsePacket(allocator, encoded.items[parsed[0].receiver_report.report_blocks.len..]);
    defer single.deinit(allocator);
    try std.testing.expect(single.consumed > 0);

    encoded.clearRetainingCapacity();
    var short_cname_items = [_]rtcp.SdesItem{.{ .item_type = .cname, .value = "AB" }};
    var short_cname_chunks = [_]rtcp.SdesChunk{.{ .ssrc = 0x01020304, .items = &short_cname_items }};
    try rtcp.writePacket(&encoded, allocator, .{ .source_description = .{ .chunks = &short_cname_chunks } });
    encoded.items[encoded.items.len - 1] = 0xff;
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, encoded.items));

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writeCompound(&encoded, allocator, &.{}));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.compoundWireLen(&.{}));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.packetsWireLen(&.{}));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writeCompound(&encoded, allocator, &.{
        .{ .picture_loss_indication = .{ .sender_ssrc = 1, .media_ssrc = 2 } },
    }));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePackets(&encoded, allocator, &.{}));

    encoded.clearRetainingCapacity();
    const reduced_size_packets = [_]rtcp.Packet{
        .{ .picture_loss_indication = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x11121314 } },
        .{ .rapid_resynchronization_request = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x21222324 } },
    };
    try rtcp.writePackets(&encoded, allocator, &reduced_size_packets);
    try std.testing.expectEqual(@as(usize, encoded.items.len), try rtcp.packetsWireLen(&reduced_size_packets));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.compoundWireLen(&reduced_size_packets));
    const parsed_reduced = try rtcp.parsePackets(allocator, encoded.items);
    defer rtcp.freePackets(allocator, parsed_reduced);
    try std.testing.expectEqual(@as(usize, 2), parsed_reduced.len);
    try std.testing.expectEqual(@as(u32, 0x11121314), parsed_reduced[0].picture_loss_indication.media_ssrc);
    try std.testing.expectEqual(@as(u32, 0x21222324), parsed_reduced[1].rapid_resynchronization_request.media_ssrc);
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parseCompound(allocator, encoded.items));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.compoundCname(parsed_reduced));

    var no_cname_items = [_]rtcp.SdesItem{.{ .item_type = .name, .value = "alice" }};
    var no_cname_chunks = [_]rtcp.SdesChunk{.{ .ssrc = 0x01020304, .items = &no_cname_items }};
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writeCompound(&encoded, allocator, &.{
        .{ .receiver_report = .{ .sender_ssrc = 0x01020304 } },
        .{ .source_description = .{ .chunks = &no_cname_chunks } },
    }));

    encoded.clearRetainingCapacity();
    var sr_blocks = [_]rtcp.ReportBlock{.{ .ssrc = 0x20212223 }};
    var sr_packets = [_]rtcp.Packet{
        .{ .sender_report = .{
            .sender_ssrc = 0x01020304,
            .ntp_timestamp_msw = 1,
            .ntp_timestamp_lsw = 2,
            .rtp_timestamp = 3,
            .sender_packet_count = 4,
            .sender_octet_count = 5,
            .report_blocks = &sr_blocks,
        } },
        .{ .picture_loss_indication = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x33333333 } },
    };
    const compound_destinations = try rtcp.compoundDestinationSsrcs(allocator, &sr_packets);
    defer allocator.free(compound_destinations);
    try std.testing.expectEqualSlices(u32, &.{ 0x20212223, 0x01020304 }, compound_destinations);

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .receiver_report = .{ .sender_ssrc = 0x01020304 } });
    try rtcp.writePacket(&encoded, allocator, .{ .picture_loss_indication = .{ .sender_ssrc = 1, .media_ssrc = 2 } });
    try rtcp.writePacket(&encoded, allocator, .{ .source_description = .{ .chunks = &sdes_chunks } });
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parseCompound(allocator, encoded.items));

    encoded.clearRetainingCapacity();
    var single_bye_sources = [_]u32{0x902f9e2e};
    try rtcp.writePacket(&encoded, allocator, .{ .goodbye = .{ .sources = &single_bye_sources, .reason = "F" } });
    var bye = try rtcp.parsePacket(allocator, encoded.items);
    defer bye.deinit(allocator);
    switch (bye.packet) {
        .goodbye => |goodbye| {
            try std.testing.expectEqual(@as(usize, 1), goodbye.sources.len);
            try std.testing.expectEqual(@as(u32, 0x902f9e2e), goodbye.sources[0]);
            try std.testing.expectEqualStrings("F", goodbye.reason);
        },
        else => return error.InvalidRtcpPacket,
    }

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .goodbye = .{
        .sources = &single_bye_sources,
        .reason = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    } }));
}

test "RTCP application-defined APP packets" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try rtcp.writePacket(&encoded, allocator, .{ .application_defined = .{
        .subtype = 31,
        .ssrc = 0x4baae1ab,
        .name = "NAME".*,
        .data = "ABCD",
    } });
    try std.testing.expectEqualStrings(&.{
        0x9f, 0xcc, 0x00, 0x03,
        0x4b, 0xaa, 0xe1, 0xab,
        0x4e, 0x41, 0x4d, 0x45,
        0x41, 0x42, 0x43, 0x44,
    }, encoded.items);
    var parsed = try rtcp.parsePacket(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, encoded.items.len), parsed.consumed);
    try std.testing.expectEqual(@as(u5, 31), parsed.packet.application_defined.subtype);
    try std.testing.expectEqual(@as(u32, 0x4baae1ab), parsed.packet.application_defined.ssrc);
    try std.testing.expectEqualStrings("NAME", &parsed.packet.application_defined.name);
    try std.testing.expectEqualStrings("ABCD", parsed.packet.application_defined.data);
    try std.testing.expectEqual(@as(usize, 16), parsed.packet.application_defined.wireLen());

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .application_defined = .{
        .ssrc = 0x4baae1ab,
        .name = "NAME".*,
        .data = "ABCDE",
    } });
    try std.testing.expectEqualStrings(&.{
        0xa0, 0xcc, 0x00, 0x04,
        0x4b, 0xaa, 0xe1, 0xab,
        0x4e, 0x41, 0x4d, 0x45,
        0x41, 0x42, 0x43, 0x44,
        0x45, 0x03, 0x03, 0x03,
    }, encoded.items);
    var padded = try rtcp.parsePacket(allocator, encoded.items);
    defer padded.deinit(allocator);
    try std.testing.expectEqual(@as(u5, 0), padded.packet.application_defined.subtype);
    try std.testing.expectEqualStrings("ABCDE", padded.packet.application_defined.data);
    try std.testing.expectEqual(@as(usize, 20), padded.packet.application_defined.wireLen());

    try std.testing.expectError(error.BufferTooShort, rtcp.parsePacket(allocator, &.{
        0x80, 0xcc, 0x00, 0x02,
        0x4b, 0xaa, 0xe1, 0xab,
        0x4e, 0x41, 0x4d,
    }));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, &.{
        0x80, 0xcc, 0x00, 0x01,
        0x4b, 0xaa, 0xe1, 0xab,
    }));

    encoded.clearRetainingCapacity();
    const too_large = try allocator.alloc(u8, rtcp.max_rtcp_payload_len - 8 + 1);
    defer allocator.free(too_large);
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .application_defined = .{
        .ssrc = 0x4baae1ab,
        .name = "NAME".*,
        .data = too_large,
    } }));
}

test "RTCP full intra request feedback" {
    const allocator = std.testing.allocator;
    var entries = [_]rtcp.FirEntry{
        .{ .ssrc = 0x11121314, .sequence_number = 7 },
        .{ .ssrc = 0x21222324, .sequence_number = 8 },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try rtcp.writePacket(&encoded, allocator, .{ .full_intra_request = .{
        .sender_ssrc = 0x01020304,
        .media_ssrc = 0,
        .entries = &entries,
    } });

    var parsed = try rtcp.parsePacket(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.packet.full_intra_request.sender_ssrc);
    try std.testing.expectEqual(@as(usize, 2), parsed.packet.full_intra_request.entries.len);
    try std.testing.expectEqual(@as(u32, 0x11121314), parsed.packet.full_intra_request.entries[0].ssrc);
    try std.testing.expectEqual(@as(u8, 7), parsed.packet.full_intra_request.entries[0].sequence_number);
    try std.testing.expectEqual(@as(usize, 28), parsed.packet.full_intra_request.wireLen());

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .full_intra_request = .{
        .sender_ssrc = 1,
        .entries = &.{},
    } }));
    const too_many_fir_entries = try allocator.alloc(rtcp.FirEntry, (((@as(usize, std.math.maxInt(u16)) * 4) - 8) / 8) + 1);
    defer allocator.free(too_many_fir_entries);
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .full_intra_request = .{
        .sender_ssrc = 1,
        .entries = too_many_fir_entries,
    } }));
}

test "RTCP unknown packets preserve raw wire image" {
    const allocator = std.testing.allocator;
    // Unknown RTCP types are treated like Pion's RawPacket escape hatch: the
    // full packet bytes must survive parse/write unchanged, including padding.
    const raw = [_]u8{
        0xa2, 0xfa, 0x00, 0x02,
        0xde, 0xad, 0xbe, 0xef,
        0x00, 0x00, 0x00, 0x04,
    };

    var parsed = try rtcp.parsePacket(allocator, &raw);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u5, 2), parsed.packet.unknown.header.count_or_format);
    try std.testing.expect(parsed.packet.unknown.header.padding);
    try std.testing.expectEqual(@as(usize, 4), parsed.packet.unknown.payload.len);
    try std.testing.expectEqualSlices(u8, raw[4..8], parsed.packet.unknown.payload);
    try std.testing.expectEqualSlices(u8, &raw, parsed.packet.unknown.raw);
    try std.testing.expectEqual(@as(usize, raw.len), try parsed.packet.wireLen());

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try rtcp.writePacket(&encoded, allocator, parsed.packet);
    try std.testing.expectEqualSlices(u8, &raw, encoded.items);

    var manual: std.ArrayList(u8) = .empty;
    defer manual.deinit(allocator);
    try rtcp.writePacket(&manual, allocator, .{ .unknown = .{
        .header = .{
            .version = 2,
            .padding = false,
            .count_or_format = 3,
            .packet_type = @enumFromInt(0xfb),
            .length_words_minus_one = 1,
        },
        .payload = &.{ 0xca, 0xfe, 0xba, 0xbe },
    } });
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0xfb, 0x00, 0x01, 0xca, 0xfe, 0xba, 0xbe }, manual.items);
}

test "RTCP receiver report and feedback packets" {
    const allocator = std.testing.allocator;

    var report_blocks = [_]rtcp.ReportBlock{.{
        .ssrc = 0x01020304,
        .fraction_lost = 7,
        .cumulative_lost = 3,
        .highest_sequence_number = 0x0001_0203,
        .interarrival_jitter = 44,
        .last_sender_report = 55,
        .delay_since_last_sender_report = 66,
    }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try rtcp.writePacket(&encoded, allocator, .{ .receiver_report = .{
        .sender_ssrc = 0x0a0b0c0d,
        .report_blocks = &report_blocks,
        .profile_extensions = &.{ 0xaa, 0xbb },
    } });
    var rr = try rtcp.parsePacket(allocator, encoded.items);
    defer rr.deinit(allocator);
    try std.testing.expectEqual(@as(usize, encoded.items.len), rr.consumed);
    try std.testing.expectEqual(@as(u32, 0x0a0b0c0d), rr.packet.receiver_report.sender_ssrc);
    try std.testing.expectEqual(@as(usize, encoded.items.len), rr.packet.receiver_report.wireLen());
    try std.testing.expectEqual(@as(usize, encoded.items.len), try rr.packet.wireLen());
    try std.testing.expectEqual(@as(u24, 3), rr.packet.receiver_report.report_blocks[0].cumulative_lost);
    try std.testing.expectEqual(@as(usize, 24), rr.packet.receiver_report.report_blocks[0].wireLen());
    try std.testing.expectEqual(@as(i32, 3), rr.packet.receiver_report.report_blocks[0].cumulativeLostSigned());
    try std.testing.expectEqual(@as(u32, 44), rr.packet.receiver_report.report_blocks[0].interarrival_jitter);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0, 0 }, rr.packet.receiver_report.profile_extensions);
    const report_block = rr.packet.receiver_report.report_blocks[0];
    const rr_now_compact_ntp = report_block.last_sender_report +% report_block.delay_since_last_sender_report +% 0x00008000;
    try std.testing.expectEqual(@as(u32, 0x00008000), report_block.roundTripDelay65536(rr_now_compact_ntp).?);
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s / 2), report_block.roundTripDelayNanos(rr_now_compact_ntp).?);
    try std.testing.expect((rtcp.ReportBlock{ .ssrc = 1, .last_sender_report = 0, .delay_since_last_sender_report = 1 }).roundTripDelay65536(rr_now_compact_ntp) == null);
    try std.testing.expect((rtcp.ReportBlock{ .ssrc = 1, .last_sender_report = 1, .delay_since_last_sender_report = 0 }).roundTripDelayNanos(rr_now_compact_ntp) == null);

    var duplicate_loss_block = rtcp.ReportBlock{ .ssrc = 1 };
    try duplicate_loss_block.setCumulativeLostSigned(-2);
    try std.testing.expectEqual(@as(u24, 0xff_fffe), duplicate_loss_block.cumulative_lost);
    try std.testing.expectEqual(@as(i32, -2), duplicate_loss_block.cumulativeLostSigned());
    try std.testing.expectEqual(@as(i32, -0x80_0000), rtcp.decodeCumulativeLost(0x80_0000));
    try std.testing.expectEqual(@as(u24, 0x7f_ffff), try rtcp.encodeCumulativeLost(0x7f_ffff));
    try std.testing.expectError(error.InvalidRtcpPacket, duplicate_loss_block.setCumulativeLostSigned(0x80_0000));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.encodeCumulativeLost(-0x80_0001));

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .sender_report = .{
        .sender_ssrc = 0x01020304,
        .ntp_timestamp_msw = 1,
        .ntp_timestamp_lsw = 2,
        .rtp_timestamp = 3,
        .sender_packet_count = 4,
        .sender_octet_count = 5,
        .profile_extensions = &.{ 0xcc, 0xdd, 0xee },
    } });
    var sr = try rtcp.parsePacket(allocator, encoded.items);
    defer sr.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x01020304), sr.packet.sender_report.sender_ssrc);
    try std.testing.expectEqual(@as(usize, encoded.items.len), sr.packet.sender_report.wireLen());
    try std.testing.expectEqualSlices(u8, &.{ 0xcc, 0xdd, 0xee, 0 }, sr.packet.sender_report.profile_extensions);

    var padded_rr: std.ArrayList(u8) = .empty;
    defer padded_rr.deinit(allocator);
    try padded_rr.append(allocator, 0xa0); // V=2, P=1, RC=0.
    try padded_rr.append(allocator, @intFromEnum(rtcp.PacketType.receiver_report));
    try wire.appendInt(&padded_rr, allocator, u16, 2, .big); // 12-byte packet: 4 header + 4 body + 4 padding.
    try wire.appendInt(&padded_rr, allocator, u32, 0x01020304, .big);
    try padded_rr.appendSlice(allocator, &.{ 0, 0, 0, 4 });
    var padded = try rtcp.parsePacket(allocator, padded_rr.items);
    defer padded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, padded_rr.items.len), padded.consumed);
    try std.testing.expectEqual(@as(u32, 0x01020304), padded.packet.receiver_report.sender_ssrc);

    padded_rr.items[padded_rr.items.len - 1] = 0;
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, padded_rr.items));
    padded_rr.items[padded_rr.items.len - 1] = 9;
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, padded_rr.items));

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .picture_loss_indication = .{
        .sender_ssrc = 0x11111111,
        .media_ssrc = 0x22222222,
    } });
    var pli = try rtcp.parsePacket(allocator, encoded.items);
    defer pli.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x11111111), pli.packet.picture_loss_indication.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 0x22222222), pli.packet.picture_loss_indication.media_ssrc);
    try std.testing.expectEqual(@as(usize, 12), pli.packet.picture_loss_indication.wireLen());
    const pli_destinations = try pli.packet.destinationSsrcs(allocator);
    defer allocator.free(pli_destinations);
    try std.testing.expectEqualSlices(u32, &.{0x22222222}, pli_destinations);

    encoded.clearRetainingCapacity();
    var sli_entries = [_]rtcp.SliEntry{.{
        .first = 0x0aaa,
        .number = 0,
        .picture = 0x2c,
    }};
    try rtcp.writePacket(&encoded, allocator, .{ .slice_loss_indication = .{
        .sender_ssrc = 0x902f9e2e,
        .media_ssrc = 0x902f9e2e,
        .entries = &sli_entries,
    } });
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x82, 0xcd, 0x00, 0x03,
        0x90, 0x2f, 0x9e, 0x2e,
        0x90, 0x2f, 0x9e, 0x2e,
        0x55, 0x50, 0x00, 0x2c,
    }, encoded.items);
    var sli = try rtcp.parsePacket(allocator, encoded.items);
    defer sli.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x902f9e2e), sli.packet.slice_loss_indication.sender_ssrc);
    try std.testing.expectEqual(@as(usize, 1), sli.packet.slice_loss_indication.entries.len);
    try std.testing.expectEqual(@as(u16, 0x0aaa), sli.packet.slice_loss_indication.entries[0].first);
    try std.testing.expectEqual(@as(u16, 0), sli.packet.slice_loss_indication.entries[0].number);
    try std.testing.expectEqual(@as(u8, 0x2c), sli.packet.slice_loss_indication.entries[0].picture);
    try std.testing.expectEqual(@as(usize, 16), sli.packet.slice_loss_indication.wireLen());

    var psfb_sli_bytes = try allocator.dupe(u8, encoded.items);
    defer allocator.free(psfb_sli_bytes);
    psfb_sli_bytes[1] = @intFromEnum(rtcp.PacketType.payload_feedback);
    var psfb_sli = try rtcp.parsePacket(allocator, psfb_sli_bytes);
    defer psfb_sli.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 0x0aaa), psfb_sli.packet.slice_loss_indication.entries[0].first);

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .rapid_resynchronization_request = .{
        .sender_ssrc = 0x902f9e2e,
        .media_ssrc = 0xbc5e9a40,
    } });
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x85, 0xcd, 0x00, 0x02,
        0x90, 0x2f, 0x9e, 0x2e,
        0xbc, 0x5e, 0x9a, 0x40,
    }, encoded.items);
    var rrr = try rtcp.parsePacket(allocator, encoded.items);
    defer rrr.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x902f9e2e), rrr.packet.rapid_resynchronization_request.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 0xbc5e9a40), rrr.packet.rapid_resynchronization_request.media_ssrc);
    try std.testing.expectEqual(@as(usize, 12), rrr.packet.rapid_resynchronization_request.wireLen());

    const ccfb_wire = [_]u8{
        0x8b, 0xcd, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x04,
        0x9f, 0xfd, 0x9f, 0xfc,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x00, 0x03,
        0x9f, 0xfd, 0x9f, 0xfc,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    };
    var ccfb = try rtcp.parsePacket(allocator, &ccfb_wire);
    defer ccfb.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), ccfb.packet.congestion_control_feedback.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 1), ccfb.packet.congestion_control_feedback.report_timestamp);
    try std.testing.expectEqual(@as(u64, (std.time.us_per_s) / 1024), ccfb.packet.congestion_control_feedback.reportTimestampMicros());
    try std.testing.expectEqual(@as(usize, 2), ccfb.packet.congestion_control_feedback.report_blocks.len);
    try std.testing.expectEqual(@as(u32, 1), ccfb.packet.congestion_control_feedback.report_blocks[0].media_ssrc);
    try std.testing.expectEqual(@as(u16, 2), ccfb.packet.congestion_control_feedback.report_blocks[0].begin_sequence);
    try std.testing.expectEqual(@as(usize, 4), ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks.len);
    try std.testing.expectEqual(@as(usize, 16), ccfb.packet.congestion_control_feedback.report_blocks[0].wireLen());
    try std.testing.expect(ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[0].received);
    try std.testing.expectEqual(rtcp.Ecn.non_ect, ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[0].ecn);
    try std.testing.expectEqual(@as(u16, 8189), ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[0].arrival_time_offset);
    try std.testing.expectEqual(@as(u64, (8189 * std.time.us_per_s) / 1024), ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[0].arrivalOffsetMicros().?);
    try std.testing.expectEqual(@as(u64, 0), ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[0].arrivalTimeMicros(ccfb.packet.congestion_control_feedback.report_timestamp).?);
    try std.testing.expect(!ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[2].received);
    try std.testing.expect(ccfb.packet.congestion_control_feedback.report_blocks[0].metric_blocks[2].arrivalOffsetMicros() == null);
    try std.testing.expectEqual(@as(u32, 2), ccfb.packet.congestion_control_feedback.report_blocks[1].media_ssrc);
    try std.testing.expectEqual(@as(usize, 3), ccfb.packet.congestion_control_feedback.report_blocks[1].metric_blocks.len);
    try std.testing.expectEqual(@as(usize, 16), ccfb.packet.congestion_control_feedback.report_blocks[1].wireLen());
    try std.testing.expectEqual(@as(usize, 40), ccfb.packet.congestion_control_feedback.wirePayloadLen());
    try std.testing.expectEqual(@as(usize, ccfb_wire.len), try ccfb.packet.wireLen());
    try std.testing.expectEqual(@as(u16, 8189), ccfb.packet.congestion_control_feedback.report_blocks[0].metricForSequence(2).?.arrival_time_offset);
    try std.testing.expectEqual(@as(u64, (8189 * std.time.us_per_s) / 1024), ccfb.packet.congestion_control_feedback.report_blocks[0].arrivalOffsetMicrosForSequence(2).?);
    try std.testing.expectEqual(@as(u64, 0), ccfb.packet.congestion_control_feedback.report_blocks[0].arrivalTimeMicrosForSequence(ccfb.packet.congestion_control_feedback.report_timestamp, 2).?);
    try std.testing.expect(!ccfb.packet.congestion_control_feedback.report_blocks[0].metricForSequence(4).?.received);
    try std.testing.expect(ccfb.packet.congestion_control_feedback.report_blocks[0].arrivalOffsetMicrosForSequence(4) == null);
    try std.testing.expect(ccfb.packet.congestion_control_feedback.report_blocks[0].metricForSequence(6) == null);
    try std.testing.expectEqual(@as(u16, 8189), ccfb.packet.congestion_control_feedback.metricForMediaSequence(2, 2).?.arrival_time_offset);
    try std.testing.expectEqual(@as(u64, (8189 * std.time.us_per_s) / 1024), ccfb.packet.congestion_control_feedback.arrivalOffsetMicrosForMediaSequence(2, 2).?);
    try std.testing.expectEqual(@as(u64, 0), ccfb.packet.congestion_control_feedback.arrivalTimeMicrosForMediaSequence(2, 2).?);
    try std.testing.expect(ccfb.packet.congestion_control_feedback.metricForMediaSequence(3, 2) == null);
    try std.testing.expect(ccfb.packet.congestion_control_feedback.arrivalOffsetMicrosForMediaSequence(3, 2) == null);
    try std.testing.expectEqual(@as(u64, 0), rtcp.ccFeedbackArrivalOffsetToMicros(0x2000));
    try std.testing.expectEqual(@as(u64, 2 * std.time.us_per_s), (rtcp.CcFeedbackMetricBlock{
        .received = true,
        .arrival_time_offset = 1024,
    }).arrivalTimeMicros(3 * 1024).?);

    var wrap_metrics = [_]rtcp.CcFeedbackMetricBlock{
        .{ .received = true, .arrival_time_offset = 1 },
        .{ .received = true, .arrival_time_offset = 2 },
        .{ .received = true, .arrival_time_offset = 3 },
    };
    const wrap_block = rtcp.CcFeedbackReportBlock{
        .media_ssrc = 9,
        .begin_sequence = 0xfffe,
        .metric_blocks = &wrap_metrics,
    };
    try std.testing.expectEqual(@as(u16, 1), wrap_block.metricForSequence(0xfffe).?.arrival_time_offset);
    try std.testing.expectEqual(@as(u16, 2), wrap_block.metricForSequence(0xffff).?.arrival_time_offset);
    try std.testing.expectEqual(@as(u16, 3), wrap_block.metricForSequence(0).?.arrival_time_offset);
    try std.testing.expect(wrap_block.metricForSequence(1) == null);
    const ccfb_destinations = try ccfb.packet.destinationSsrcs(allocator);
    defer allocator.free(ccfb_destinations);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, ccfb_destinations);

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, ccfb.packet);
    try std.testing.expectEqualSlices(u8, &ccfb_wire, encoded.items);

    encoded.clearRetainingCapacity();
    var invalid_ccfb_metric = [_]rtcp.CcFeedbackMetricBlock{.{ .received = true, .arrival_time_offset = 0x2000 }};
    var invalid_ccfb_blocks = [_]rtcp.CcFeedbackReportBlock{.{
        .media_ssrc = 1,
        .metric_blocks = &invalid_ccfb_metric,
    }};
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .congestion_control_feedback = .{
        .sender_ssrc = 1,
        .report_blocks = &invalid_ccfb_blocks,
        .report_timestamp = 2,
    } }));

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .congestion_control_feedback = .{
        .sender_ssrc = 1,
        .report_blocks = &.{},
        .report_timestamp = 2,
    } });
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x8b, 0xcd, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
    }, encoded.items);

    const xr_wire = [_]u8{
        0x80, 0xcf, 0x00, 0x32,
        0x01, 0x02, 0x03, 0x04,
        0x01, 0x0c, 0x00, 0x04,
        0x12, 0x34, 0x56, 0x89,
        0x00, 0x05, 0x00, 0x0c,
        0x40, 0x06, 0x00, 0x06,
        0x87, 0x65, 0x00, 0x00,
        0x02, 0x06, 0x00, 0x04,
        0x12, 0x34, 0x56, 0x89,
        0x00, 0x05, 0x00, 0x0c,
        0x41, 0x23, 0x3f, 0xff,
        0xff, 0xff, 0x00, 0x00,
        0x03, 0x03, 0x00, 0x07,
        0x98, 0x76, 0x54, 0x32,
        0x3c, 0x48, 0x3c, 0xd9,
        0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33,
        0x44, 0x44, 0x44, 0x44,
        0x55, 0x55, 0x55, 0x55,
        0x04, 0x00, 0x00, 0x02,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x05, 0x00, 0x00, 0x06,
        0x88, 0x88, 0x88, 0x88,
        0x12, 0x34, 0x56, 0x78,
        0x99, 0x99, 0x99, 0x99,
        0x09, 0x09, 0x09, 0x09,
        0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22,
        0x06, 0xe8, 0x00, 0x09,
        0xfe, 0xdc, 0xba, 0x98,
        0x12, 0x34, 0x56, 0x78,
        0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33,
        0x44, 0x44, 0x44, 0x44,
        0x55, 0x55, 0x55, 0x55,
        0x66, 0x66, 0x66, 0x66,
        0x01, 0x02, 0x03, 0x04,
        0x07, 0x00, 0x00, 0x08,
        0x89, 0xab, 0xcd, 0xef,
        0x05, 0x06, 0x07, 0x08,
        0x11, 0x11, 0x22, 0x22,
        0x33, 0x33, 0x44, 0x44,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66,
        0x63, 0xab, 0x00, 0x01,
        0xde, 0xad, 0xbe, 0xef,
    };
    var xr = try rtcp.parsePacket(allocator, &xr_wire);
    defer xr.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x01020304), xr.packet.extended_report.sender_ssrc);
    try std.testing.expectEqual(@as(usize, 8), xr.packet.extended_report.blocks.len);
    try std.testing.expectEqual(@as(usize, xr_wire.len), xr.packet.extended_report.wireLen());
    try std.testing.expectEqual(@as(u4, 12), xr.packet.extended_report.blocks[0].loss_rle.thinning);
    try std.testing.expectEqual(@as(u32, 0x12345689), xr.packet.extended_report.blocks[0].loss_rle.ssrc);
    try std.testing.expectEqual(@as(u16, 5), xr.packet.extended_report.blocks[0].loss_rle.begin_sequence);
    try std.testing.expectEqual(@as(u16, 0x4006), xr.packet.extended_report.blocks[0].loss_rle.chunks[0]);
    try std.testing.expectEqual(@as(usize, 20), xr.packet.extended_report.blocks[0].wireLen());
    try std.testing.expectEqual(@as(rtcp.XrChunk, 0x4006), rtcp.xrRunLengthChunk(1, 6));
    try std.testing.expectEqual(rtcp.XrChunkType.run_length, rtcp.xrChunkType(xr.packet.extended_report.blocks[0].loss_rle.chunks[0]));
    try std.testing.expectEqual(@as(u1, 1), try rtcp.xrChunkRunType(xr.packet.extended_report.blocks[0].loss_rle.chunks[0]));
    try std.testing.expectEqual(@as(u15, 6), rtcp.xrChunkValue(xr.packet.extended_report.blocks[0].loss_rle.chunks[0]));
    try std.testing.expectEqual(@as(u4, 6), xr.packet.extended_report.blocks[1].duplicate_rle.thinning);
    try std.testing.expectEqual(@as(u16, 0x4123), xr.packet.extended_report.blocks[1].duplicate_rle.chunks[0]);
    try std.testing.expectEqual(rtcp.XrChunkType.run_length, rtcp.xrChunkType(xr.packet.extended_report.blocks[1].duplicate_rle.chunks[0]));
    try std.testing.expectEqual(@as(u1, 1), try rtcp.xrChunkRunType(xr.packet.extended_report.blocks[1].duplicate_rle.chunks[0]));
    try std.testing.expectEqual(rtcp.XrChunkType.bit_vector, rtcp.xrChunkType(0x8123));
    try std.testing.expectEqual(@as(rtcp.XrChunk, 0x8123), rtcp.xrBitVectorChunk(0x0123));
    try std.testing.expectEqual(@as(u15, 0x0123), rtcp.xrChunkValue(0x8123));
    try std.testing.expectEqual(@as(rtcp.XrChunk, 0), rtcp.xrTerminatingNullChunk());
    try std.testing.expectEqual(rtcp.XrChunkType.terminating_null, rtcp.xrChunkType(rtcp.xrTerminatingNullChunk()));
    try std.testing.expectEqual(@as(u15, 0), rtcp.xrChunkValue(0));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.xrChunkRunType(0x8123));
    try std.testing.expectEqual(@as(u4, 3), xr.packet.extended_report.blocks[2].packet_receipt_times.thinning);
    try std.testing.expectEqual(@as(u32, 0x98765432), xr.packet.extended_report.blocks[2].packet_receipt_times.ssrc);
    try std.testing.expectEqual(@as(u16, 15432), xr.packet.extended_report.blocks[2].packet_receipt_times.begin_sequence);
    try std.testing.expectEqual(@as(u16, 15577), xr.packet.extended_report.blocks[2].packet_receipt_times.end_sequence);
    try std.testing.expectEqual(@as(usize, 5), xr.packet.extended_report.blocks[2].packet_receipt_times.receipt_times.len);
    try std.testing.expectEqual(@as(usize, 32), xr.packet.extended_report.blocks[2].wireLen());
    try std.testing.expectEqual(@as(u32, 0x33333333), xr.packet.extended_report.blocks[2].packet_receipt_times.receipt_times[2]);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), xr.packet.extended_report.blocks[3].receiver_reference_time);
    try std.testing.expectEqual(@as(usize, 12), xr.packet.extended_report.blocks[3].wireLen());
    try std.testing.expectEqual(@as(usize, 2), xr.packet.extended_report.blocks[4].dlrr.reports.len);
    try std.testing.expectEqual(@as(usize, 28), xr.packet.extended_report.blocks[4].wireLen());
    try std.testing.expectEqual(@as(u32, 0x88888888), xr.packet.extended_report.blocks[4].dlrr.reports[0].ssrc);
    try std.testing.expectEqual(@as(u32, 0x12345678), xr.packet.extended_report.blocks[4].dlrr.reports[0].last_rr);
    try std.testing.expectEqual(@as(u32, 0x99999999), xr.packet.extended_report.blocks[4].dlrr.reports[0].dlrr);
    const dlrr_report = xr.packet.extended_report.blocks[4].dlrr.reports[0];
    const now_compact_ntp = dlrr_report.last_rr +% dlrr_report.dlrr +% 0x00010000;
    try std.testing.expectEqual(@as(u32, 0x00010000), dlrr_report.roundTripDelay65536(now_compact_ntp).?);
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s), dlrr_report.roundTripDelayNanos(now_compact_ntp).?);
    try std.testing.expect((rtcp.DlrrReport{ .ssrc = 1, .last_rr = 0, .dlrr = 1 }).roundTripDelay65536(now_compact_ntp) == null);
    try std.testing.expect((rtcp.DlrrReport{ .ssrc = 1, .last_rr = 1, .dlrr = 0 }).roundTripDelayNanos(now_compact_ntp) == null);
    try std.testing.expectEqual(@as(u32, 0x09090909), xr.packet.extended_report.blocks[4].dlrr.reports[1].ssrc);
    try std.testing.expect(xr.packet.extended_report.blocks[5].statistics_summary.loss_reports);
    try std.testing.expect(xr.packet.extended_report.blocks[5].statistics_summary.duplicate_reports);
    try std.testing.expect(xr.packet.extended_report.blocks[5].statistics_summary.jitter_reports);
    try std.testing.expectEqual(rtcp.TtlOrHopLimit.ipv4, xr.packet.extended_report.blocks[5].statistics_summary.ttl_or_hop_limit);
    try std.testing.expectEqual(@as(u32, 0xfedcba98), xr.packet.extended_report.blocks[5].statistics_summary.ssrc);
    try std.testing.expectEqual(@as(u32, 0x11111111), xr.packet.extended_report.blocks[5].statistics_summary.lost_packets);
    try std.testing.expectEqual(@as(u8, 0x04), xr.packet.extended_report.blocks[5].statistics_summary.dev_ttl_or_hop_limit);
    try std.testing.expectEqual(@as(usize, 40), xr.packet.extended_report.blocks[5].wireLen());
    try std.testing.expectEqual(@as(u32, 0x89abcdef), xr.packet.extended_report.blocks[6].voip_metrics.ssrc);
    try std.testing.expectEqual(@as(u8, 0x05), xr.packet.extended_report.blocks[6].voip_metrics.loss_rate);
    try std.testing.expectEqual(@as(u16, 0x1111), xr.packet.extended_report.blocks[6].voip_metrics.burst_duration);
    try std.testing.expectEqual(@as(u8, 0x99), xr.packet.extended_report.blocks[6].voip_metrics.rx_config);
    try std.testing.expectEqual(@as(u16, 0x5566), xr.packet.extended_report.blocks[6].voip_metrics.jb_abs_max);
    try std.testing.expectEqual(@as(usize, 36), xr.packet.extended_report.blocks[6].wireLen());
    try std.testing.expectEqual(@as(u8, 0xab), xr.packet.extended_report.blocks[7].unknown.header.type_specific);
    try std.testing.expectEqual(@as(rtcp.XrBlockType, @enumFromInt(0x63)), xr.packet.extended_report.blocks[7].unknown.header.block_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, xr.packet.extended_report.blocks[7].unknown.payload);
    try std.testing.expectEqual(@as(usize, 8), xr.packet.extended_report.blocks[7].wireLen());
    const xr_destinations = try xr.packet.destinationSsrcs(allocator);
    defer allocator.free(xr_destinations);
    try std.testing.expectEqualSlices(u32, &.{
        0x01020304,
        0x12345689,
        0x12345689,
        0x98765432,
        0x88888888,
        0x09090909,
        0xfedcba98,
        0x89abcdef,
    }, xr_destinations);

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, xr.packet);
    try std.testing.expectEqualSlices(u8, &xr_wire, encoded.items);

    encoded.clearRetainingCapacity();
    var nack_pairs = [_]rtcp.NackPair{.{
        .packet_id = 100,
        .lost_packet_bitmask = 0b0000_0000_0000_1010,
    }};
    try rtcp.writePacket(&encoded, allocator, .{ .transport_layer_nack = .{
        .sender_ssrc = 0x33333333,
        .media_ssrc = 0x44444444,
        .pairs = &nack_pairs,
    } });
    var nack = try rtcp.parsePacket(allocator, encoded.items);
    defer nack.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x33333333), nack.packet.transport_layer_nack.sender_ssrc);
    try std.testing.expect(nack.packet.transport_layer_nack.pairs[0].contains(100));
    try std.testing.expect(nack.packet.transport_layer_nack.pairs[0].contains(102));
    try std.testing.expect(nack.packet.transport_layer_nack.pairs[0].contains(104));
    try std.testing.expect(!nack.packet.transport_layer_nack.pairs[0].contains(101));
    try std.testing.expectEqual(@as(usize, 16), nack.packet.transport_layer_nack.wireLen());
    const nack_destinations = try nack.packet.destinationSsrcs(allocator);
    defer allocator.free(nack_destinations);
    try std.testing.expectEqualSlices(u32, &.{0x44444444}, nack_destinations);
    const too_many_nacks = try allocator.alloc(rtcp.NackPair, (((@as(usize, std.math.maxInt(u16)) * 4) - 8) / 4) + 1);
    defer allocator.free(too_many_nacks);
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .transport_layer_nack = .{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .pairs = too_many_nacks,
    } }));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .transport_layer_nack = .{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .pairs = &.{},
    } }));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, &.{
        0x81, 0xcd, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
    }));

    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .receiver_estimated_maximum_bitrate = .{
        .sender_ssrc = 1,
        .bitrate = 8_927_168,
        .ssrcs = &[_]u32{1215622422},
    } });
    try std.testing.expectEqualSlices(u8, &[_]u8{
        143, 206, 0,   5,
        0,   0,   0,   1,
        0,   0,   0,   0,
        'R', 'E', 'M', 'B',
        1,   26,  32,  223,
        72,  116, 237, 22,
    }, encoded.items);
    var remb = try rtcp.parsePacket(allocator, encoded.items);
    defer remb.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), remb.packet.receiver_estimated_maximum_bitrate.sender_ssrc);
    try std.testing.expectEqual(@as(u64, 8_927_168), remb.packet.receiver_estimated_maximum_bitrate.bitrate);
    try std.testing.expectEqualSlices(u32, &[_]u32{1215622422}, remb.packet.receiver_estimated_maximum_bitrate.ssrcs);
    try std.testing.expectEqual(@as(usize, 24), remb.packet.receiver_estimated_maximum_bitrate.wireLen());

    encoded.items[8] = 1; // REMB media SSRC must be zero.
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, encoded.items));

    const max_remb_wire = [_]u8{
        143, 206, 0,   4,
        0,   0,   0,   0,
        0,   0,   0,   0,
        'R', 'E', 'M', 'B',
        0,   255, 255, 255,
    };
    var max_remb = try rtcp.parsePacket(allocator, &max_remb_wire);
    defer max_remb.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u64), max_remb.packet.receiver_estimated_maximum_bitrate.bitrate);
}

test "RTCP transport-wide congestion feedback" {
    const allocator = std.testing.allocator;
    var packet_results = [_]rtcp.TwccPacketResult{
        .{ .status = .small_delta, .delta_ticks = 4 },
        .{ .status = .not_received },
        .{ .status = .large_delta, .delta_ticks = -3 },
        .{ .status = .received_without_delta },
        .{ .status = .small_delta, .delta_ticks = 1 },
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try rtcp.writePacket(&encoded, allocator, .{ .transport_wide_cc = .{
        .sender_ssrc = 0x01020304,
        .media_ssrc = 0x11121314,
        .base_sequence_number = 500,
        .reference_time_64ms = 0x00a0b0,
        .feedback_packet_count = 7,
        .packets = &packet_results,
    } });

    var parsed = try rtcp.parsePacket(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, encoded.items.len), parsed.consumed);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.packet.transport_wide_cc.sender_ssrc);
    try std.testing.expectEqual(@as(u16, 500), parsed.packet.transport_wide_cc.base_sequence_number);
    try std.testing.expectEqual(@as(u24, 0x00a0b0), parsed.packet.transport_wide_cc.reference_time_64ms);
    try std.testing.expectEqual(@as(u64, 64_000), rtcp.twcc_reference_time_unit_micros);
    try std.testing.expectEqual(@as(u64, 0x00a0b0 * 64_000), parsed.packet.transport_wide_cc.referenceTimeMicros());
    try std.testing.expectEqual(@as(u24, 0x00a0b0), rtcp.twccReferenceTimeFromUnixMicros(parsed.packet.transport_wide_cc.referenceTimeMicros() + 63_999));
    try std.testing.expectEqual(@as(u64, 0x00a0b0 * 64_000), rtcp.twccReferenceTimeToMicros(0x00a0b0));
    try std.testing.expectEqual(@as(usize, encoded.items.len), try parsed.packet.transport_wide_cc.wireLen());
    try std.testing.expectEqual(@as(usize, encoded.items.len), try parsed.packet.wireLen());
    try std.testing.expectEqual(@as(u8, 7), parsed.packet.transport_wide_cc.feedback_packet_count);
    try std.testing.expectEqual(@as(usize, 5), parsed.packet.transport_wide_cc.packets.len);
    try std.testing.expect(parsed.packet.transport_wide_cc.packets[0].received());
    try std.testing.expectEqual(@as(i32, 1000), parsed.packet.transport_wide_cc.packets[0].deltaMicros());
    try std.testing.expectEqual(@as(i32, 250), rtcp.twcc_delta_tick_micros);
    try std.testing.expectEqual(@as(i32, 63_750), rtcp.twcc_small_delta_max_micros);
    try std.testing.expectEqual(@as(i32, -8_192_000), rtcp.twcc_large_delta_min_micros);
    try std.testing.expectEqual(@as(i32, 8_191_750), rtcp.twcc_large_delta_max_micros);
    try std.testing.expectEqual(@as(i32, -8_192_000), rtcp.twccDeltaTicksToMicros(std.math.minInt(i16)));
    try std.testing.expectEqual(@as(u8, 255), try rtcp.twccSmallDeltaFromMicros(63_999));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccSmallDeltaFromMicros(-250));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccSmallDeltaFromMicros(64_000));
    try std.testing.expectEqual(@as(i16, 32767), try rtcp.twccLargeDeltaFromMicros(8_191_999));
    try std.testing.expectEqual(@as(i16, -32768), try rtcp.twccLargeDeltaFromMicros(-8_192_000));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccLargeDeltaFromMicros(-8_192_250));
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, parsed.packet.transport_wide_cc.packets[1].status);
    try std.testing.expectEqual(@as(i16, -3), parsed.packet.transport_wide_cc.packets[2].delta_ticks);
    try std.testing.expect(parsed.packet.transport_wide_cc.packets[3].received());
    try std.testing.expectEqual(@as(i16, 0), parsed.packet.transport_wide_cc.packets[3].delta_ticks);
    try std.testing.expectEqual(@as(i16, 4), parsed.packet.transport_wide_cc.packetForSequence(500).?.delta_ticks);
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, parsed.packet.transport_wide_cc.packetForSequence(501).?.status);
    try std.testing.expectEqual(@as(i16, -3), parsed.packet.transport_wide_cc.packetForSequence(502).?.delta_ticks);
    try std.testing.expect(parsed.packet.transport_wide_cc.packetForSequence(505) == null);
    try std.testing.expectEqual(parsed.packet.transport_wide_cc.referenceTimeMicros() + 1000, parsed.packet.transport_wide_cc.arrivalTimeMicrosForSequence(500).?);
    try std.testing.expect(parsed.packet.transport_wide_cc.arrivalTimeMicrosForSequence(501) == null);
    try std.testing.expectEqual(parsed.packet.transport_wide_cc.referenceTimeMicros() + 250, parsed.packet.transport_wide_cc.arrivalTimeMicrosForSequence(502).?);
    try std.testing.expect(parsed.packet.transport_wide_cc.arrivalTimeMicrosForSequence(503) == null);
    try std.testing.expect(parsed.packet.transport_wide_cc.arrivalTimeMicrosForIndex(4) == null);
    try std.testing.expect(parsed.packet.transport_wide_cc.arrivalTimeMicrosForIndex(5) == null);

    var continuous_packets = [_]rtcp.TwccPacketResult{
        .{ .status = .small_delta, .delta_ticks = 4 },
        .{ .status = .not_received },
        .{ .status = .large_delta, .delta_ticks = -3 },
        .{ .status = .small_delta, .delta_ticks = 1 },
    };
    const continuous_twcc = rtcp.TransportWideCc{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .base_sequence_number = 10,
        .reference_time_64ms = 3,
        .feedback_packet_count = 0,
        .packets = &continuous_packets,
    };
    try std.testing.expectEqual(continuous_twcc.referenceTimeMicros() + 500, continuous_twcc.arrivalTimeMicrosForIndex(3).?);
    try std.testing.expectEqual(continuous_twcc.referenceTimeMicros() + 250, continuous_twcc.arrivalTimeMicrosForSequence(12).?);
    // Mixed packet statuses should be serialized as a compact status-vector
    // chunk rather than as five tiny run-length chunks; this is the wire shape
    // Pion's TWCC support and browser stacks commonly exchange.
    try std.testing.expectEqual(@as(usize, 28), encoded.items.len);
    try std.testing.expectEqual(@as(rtcp.TwccPacketStatusChunk, 0xd2d0), std.mem.readInt(u16, encoded.items[20..22], .big));

    const wrap_twcc = rtcp.TransportWideCc{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .base_sequence_number = 0xfffe,
        .reference_time_64ms = 0,
        .feedback_packet_count = 0,
        .packets = &packet_results,
    };
    try std.testing.expectEqual(@as(i16, 4), wrap_twcc.packetForSequence(0xfffe).?.delta_ticks);
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, wrap_twcc.packetForSequence(0xffff).?.status);
    try std.testing.expectEqual(@as(i16, -3), wrap_twcc.packetForSequence(0).?.delta_ticks);
    try std.testing.expect(wrap_twcc.packetForSequence(3) == null);

    const run_chunk = try rtcp.twccRunLengthChunk(.large_delta, 3);
    try std.testing.expectEqual(rtcp.TwccChunkType.run_length, rtcp.twccChunkType(run_chunk));
    try std.testing.expectEqual(rtcp.TwccPacketStatus.large_delta, try rtcp.twccRunStatus(run_chunk));
    try std.testing.expectEqual(@as(u13, 3), try rtcp.twccRunLength(run_chunk));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccRunLengthChunk(.small_delta, 0));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccRunLength(0));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccRunStatus(0x8000));

    const one_bit_vector = try rtcp.twccStatusVectorChunk(.one_bit, &.{
        .not_received,
        .small_delta,
        .not_received,
    });
    try std.testing.expectEqual(@as(rtcp.TwccPacketStatusChunk, 0x9000), one_bit_vector);
    try std.testing.expectEqual(rtcp.TwccChunkType.status_vector, rtcp.twccChunkType(one_bit_vector));
    try std.testing.expectEqual(rtcp.TwccSymbolSize.one_bit, try rtcp.twccStatusVectorSymbolSize(one_bit_vector));
    try std.testing.expectEqual(@as(usize, 14), rtcp.twccStatusVectorCapacity(.one_bit));
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, try rtcp.twccStatusVectorSymbol(one_bit_vector, 0));
    try std.testing.expectEqual(rtcp.TwccPacketStatus.small_delta, try rtcp.twccStatusVectorSymbol(one_bit_vector, 1));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccStatusVectorSymbol(one_bit_vector, 14));
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.twccStatusVectorChunk(.one_bit, &.{.large_delta}));

    var long_run: [15]rtcp.TwccPacketResult = undefined;
    for (&long_run) |*packet| packet.* = .{ .status = .not_received };
    encoded.clearRetainingCapacity();
    try rtcp.writePacket(&encoded, allocator, .{ .transport_wide_cc = .{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .base_sequence_number = 1,
        .reference_time_64ms = 0,
        .feedback_packet_count = 0,
        .packets = &long_run,
    } });
    try std.testing.expectEqual(@as(rtcp.TwccPacketStatusChunk, 15), std.mem.readInt(u16, encoded.items[20..22], .big));
    var invalid_twcc_delta = [_]rtcp.TwccPacketResult{.{ .status = .small_delta, .delta_ticks = -1 }};
    try std.testing.expectError(error.InvalidRtcpPacket, (rtcp.TransportWideCc{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .base_sequence_number = 1,
        .reference_time_64ms = 0,
        .feedback_packet_count = 0,
        .packets = &invalid_twcc_delta,
    }).wireLen());

    // Also parse a hand-built status-vector chunk.  The writer intentionally
    // emits whichever chunk shape is compact for the status sequence, but this
    // fixture keeps direct coverage for two-bit status-vector decoding.
    var vector_encoded: std.ArrayList(u8) = .empty;
    defer vector_encoded.deinit(allocator);
    try vector_encoded.append(allocator, @as(u8, 0x80) | @as(u8, rtcp.transport_feedback_twcc));
    try vector_encoded.append(allocator, @intFromEnum(rtcp.PacketType.transport_feedback));
    try wire.appendInt(&vector_encoded, allocator, u16, 6, .big); // 24-byte payload.
    try wire.appendInt(&vector_encoded, allocator, u32, 0x01020304, .big);
    try wire.appendInt(&vector_encoded, allocator, u32, 0x11121314, .big);
    try wire.appendInt(&vector_encoded, allocator, u16, 700, .big);
    try wire.appendInt(&vector_encoded, allocator, u16, 4, .big);
    try wire.appendU24(&vector_encoded, allocator, 0x000102);
    try vector_encoded.append(allocator, 9);
    const two_bit_vector = try rtcp.twccStatusVectorChunk(.two_bit, &.{
        .small_delta,
        .not_received,
        .large_delta,
        .received_without_delta,
    });
    try std.testing.expectEqual(@as(rtcp.TwccPacketStatusChunk, 0xd2c0), two_bit_vector);
    try std.testing.expectEqual(@as(usize, 7), rtcp.twccStatusVectorCapacity(.two_bit));
    try std.testing.expectEqual(rtcp.TwccSymbolSize.two_bit, try rtcp.twccStatusVectorSymbolSize(two_bit_vector));
    try std.testing.expectEqual(rtcp.TwccPacketStatus.received_without_delta, try rtcp.twccStatusVectorSymbol(two_bit_vector, 3));
    try wire.appendInt(&vector_encoded, allocator, u16, two_bit_vector, .big);
    try vector_encoded.append(allocator, 8);
    try wire.appendInt(&vector_encoded, allocator, i16, -2, .big);
    try vector_encoded.appendNTimes(allocator, 0, 3);

    var parsed_vector = try rtcp.parsePacket(allocator, vector_encoded.items);
    defer parsed_vector.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 700), parsed_vector.packet.transport_wide_cc.base_sequence_number);
    try std.testing.expectEqual(@as(usize, 4), parsed_vector.packet.transport_wide_cc.packets.len);
    try std.testing.expectEqual(@as(i16, 8), parsed_vector.packet.transport_wide_cc.packets[0].delta_ticks);
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, parsed_vector.packet.transport_wide_cc.packets[1].status);
    try std.testing.expectEqual(@as(i16, -2), parsed_vector.packet.transport_wide_cc.packets[2].delta_ticks);
    try std.testing.expectEqual(rtcp.TwccPacketStatus.received_without_delta, parsed_vector.packet.transport_wide_cc.packets[3].status);
}

test "RTCP sender stats builds sender report" {
    const allocator = std.testing.allocator;
    var stats = rtcp.SenderStats{};

    inline for (.{ 10, 11 }) |seq| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try rtp.writePacket(&bytes, allocator, .{
            .payload_type = 96,
            .sequence_number = seq,
            .timestamp = @as(u32, seq) * 3000,
            .ssrc = 0x11223344,
        }, "abcd");
        var packet = try rtp.Packet.parse(allocator, bytes.items);
        defer packet.deinit(allocator);
        stats.observe(packet);
    }

    const ntp = rtcp.ntpTimestamp(1_500_000_000);
    try std.testing.expectEqual(@as(u32, 2_208_988_801), ntp.msw);
    try std.testing.expectEqual(@as(u32, 0x8000_0000), ntp.lsw);
    try std.testing.expectEqual(@as(u32, 0x7e81_8000), rtcp.compactNtpTimestamp(ntp.msw, ntp.lsw));
    try std.testing.expectEqual(@as(u32, 0x7e81_8000), rtcp.compactNtpFromUnixNanos(1_500_000_000));
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s / 2), rtcp.compactNtpDelayToNanos(0x0000_8000));

    const report = stats.senderReport(1_500_000_000, &.{});
    try std.testing.expectEqual(@as(u32, 0x11223344), report.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 33_000), report.rtp_timestamp);
    try std.testing.expectEqual(@as(u32, 2), report.sender_packet_count);
    try std.testing.expectEqual(@as(u32, 8), report.sender_octet_count);
    try std.testing.expectEqual(ntp.msw, report.ntp_timestamp_msw);
    try std.testing.expectEqual(ntp.lsw, report.ntp_timestamp_lsw);
}

test "RTCP receiver stats builds receiver report block" {
    const allocator = std.testing.allocator;
    var stats = rtcp.ReceiverStats{ .clock_rate = 90_000 };

    inline for (.{ 1, 2, 4 }) |seq| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try rtp.writePacket(&bytes, allocator, .{
            .payload_type = 96,
            .sequence_number = seq,
            .timestamp = @as(u32, seq) * 3000,
            .ssrc = 0x01020304,
        }, "x");
        var packet = try rtp.Packet.parse(allocator, bytes.items);
        defer packet.deinit(allocator);
        stats.observe(packet, @as(u64, seq) * 33 * std.time.ns_per_ms);
    }

    const first = stats.reportBlock();
    try std.testing.expectEqual(@as(u32, 0x01020304), first.ssrc);
    try std.testing.expectEqual(@as(u24, 1), first.cumulative_lost);
    try std.testing.expectEqual(@as(u32, 4), first.highest_sequence_number);
    try std.testing.expect(first.fraction_lost > 0);

    var more_bytes: std.ArrayList(u8) = .empty;
    defer more_bytes.deinit(allocator);
    try rtp.writePacket(&more_bytes, allocator, .{
        .payload_type = 96,
        .sequence_number = 5,
        .timestamp = 15_000,
        .ssrc = 0x01020304,
    }, "x");
    var more = try rtp.Packet.parse(allocator, more_bytes.items);
    defer more.deinit(allocator);
    stats.observe(more, 200 * std.time.ns_per_ms);
    const second = stats.reportBlock();
    try std.testing.expectEqual(@as(u24, 1), second.cumulative_lost);
    try std.testing.expectEqual(@as(u32, 5), second.highest_sequence_number);
    try std.testing.expect(second.interarrival_jitter > 0);

    const sr_ntp = rtcp.ntpTimestamp(1_500_000_000);
    stats.observeSenderReport(.{
        .sender_ssrc = 0x01020304,
        .ntp_timestamp_msw = sr_ntp.msw,
        .ntp_timestamp_lsw = sr_ntp.lsw,
        .rtp_timestamp = 0,
        .sender_packet_count = 0,
        .sender_octet_count = 0,
    }, 2 * std.time.ns_per_s);
    const third = stats.reportBlockAt(2 * std.time.ns_per_s + 250 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0x7e81_8000), third.last_sender_report);
    try std.testing.expectEqual(@as(u32, 0x0000_4000), third.delay_since_last_sender_report);
    try std.testing.expectEqual(@as(u64, 250 * std.time.ns_per_ms), rtcp.compactNtpDelayToNanos(third.delay_since_last_sender_report));

    var wrap_stats = rtcp.ReceiverStats{ .clock_rate = 90_000 };
    inline for (.{ 0xfffe, 0xffff, 0 }) |seq| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try rtp.writePacket(&bytes, allocator, .{
            .payload_type = 96,
            .sequence_number = seq,
            .timestamp = @as(u32, seq) * 3000,
            .ssrc = 0x11223344,
        }, "x");
        var packet = try rtp.Packet.parse(allocator, bytes.items);
        defer packet.deinit(allocator);
        wrap_stats.observe(packet, @as(u64, seq) * std.time.ns_per_ms);
    }
    const wrap_report = wrap_stats.reportBlock();
    try std.testing.expectEqual(@as(u32, 0x11223344), wrap_report.ssrc);
    try std.testing.expectEqual(@as(u32, 0x0001_0000), wrap_report.highest_sequence_number);
    try std.testing.expectEqual(@as(u32, 3), wrap_stats.expectedPackets());
    try std.testing.expectEqual(@as(u24, 0), wrap_report.cumulative_lost);

    var duplicate_stats = rtcp.ReceiverStats{ .clock_rate = 90_000 };
    inline for (.{ 10, 10 }) |seq| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try rtp.writePacket(&bytes, allocator, .{
            .payload_type = 96,
            .sequence_number = seq,
            .timestamp = @as(u32, seq) * 3000,
            .ssrc = 0x99aabbcc,
        }, "x");
        var packet = try rtp.Packet.parse(allocator, bytes.items);
        defer packet.deinit(allocator);
        duplicate_stats.observe(packet, @as(u64, seq) * std.time.ns_per_ms);
    }
    const duplicate_report = duplicate_stats.reportBlock();
    try std.testing.expectEqual(@as(u32, 1), duplicate_stats.expectedPackets());
    try std.testing.expectEqual(@as(i32, -1), duplicate_report.cumulativeLostSigned());
    try std.testing.expectEqual(@as(u24, 0xff_ffff), duplicate_report.cumulative_lost);

    const TimestampWrapPacket = struct {
        seq: u16,
        timestamp: u32,
        arrival_ns: u64,
    };
    const timestamp_wrap_packets = [_]TimestampWrapPacket{
        .{ .seq = 1, .timestamp = 0xffff_0000, .arrival_ns = 0 },
        .{ .seq = 2, .timestamp = 0x0000_5f90, .arrival_ns = std.time.ns_per_s },
    };
    var timestamp_wrap_stats = rtcp.ReceiverStats{ .clock_rate = 90_000 };
    for (timestamp_wrap_packets) |fixture| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try rtp.writePacket(&bytes, allocator, .{
            .payload_type = 96,
            .sequence_number = fixture.seq,
            .timestamp = fixture.timestamp,
            .ssrc = 0x55667788,
        }, "x");
        var packet = try rtp.Packet.parse(allocator, bytes.items);
        defer packet.deinit(allocator);
        timestamp_wrap_stats.observe(packet, fixture.arrival_ns);
    }
    const timestamp_wrap_report = timestamp_wrap_stats.reportBlock();
    try std.testing.expectEqual(@as(u32, 0), timestamp_wrap_report.interarrival_jitter);
}

test "RTCP NACK tracker detects RTP gaps and wraparound" {
    const allocator = std.testing.allocator;
    const sequence_numbers = [_]u16{ 100, 102, 104, 117, 0xfffe, 0xffff, 0 };
    const pairs_from_list = try rtcp.nackPairsFromSequenceNumbers(allocator, &sequence_numbers);
    defer allocator.free(pairs_from_list);
    try std.testing.expectEqual(@as(usize, 3), pairs_from_list.len);
    try std.testing.expectEqual(@as(u16, 100), pairs_from_list[0].packet_id);
    try std.testing.expect(pairs_from_list[0].contains(102));
    try std.testing.expect(pairs_from_list[0].contains(104));
    var packet_list_buf: [17]u16 = undefined;
    const packet_list = try pairs_from_list[0].packetList(&packet_list_buf);
    try std.testing.expectEqualSlices(u16, &.{ 100, 102, 104 }, packet_list);
    var too_small_packet_list: [2]u16 = undefined;
    try std.testing.expectError(error.BufferTooShort, pairs_from_list[0].packetList(&too_small_packet_list));

    const RangeCollector = struct {
        list: *std.ArrayList(u16),

        fn appendUntilSecond(collector: @This(), sequence_number: u16) bool {
            collector.list.append(std.testing.allocator, sequence_number) catch unreachable;
            return collector.list.items.len < 2;
        }
    };
    var early_range: std.ArrayList(u16) = .empty;
    defer early_range.deinit(allocator);
    pairs_from_list[0].range(RangeCollector{ .list = &early_range }, RangeCollector.appendUntilSecond);
    try std.testing.expectEqualSlices(u16, &.{ 100, 102 }, early_range.items);
    try std.testing.expectEqual(@as(u16, 117), pairs_from_list[1].packet_id);
    try std.testing.expectEqual(@as(u16, 0xfffe), pairs_from_list[2].packet_id);
    try std.testing.expect(pairs_from_list[2].contains(0xffff));
    try std.testing.expect(pairs_from_list[2].contains(0));

    const expanded = try rtcp.nackSequenceNumbers(allocator, pairs_from_list);
    defer allocator.free(expanded);
    try std.testing.expectEqualSlices(u16, &sequence_numbers, expanded);

    var tracker = rtcp.NackTracker{};
    tracker.observe(1000);
    tracker.observe(1003);
    try std.testing.expectEqual(@as(usize, 2), tracker.pendingCount());
    var pairs_buf: [8]rtcp.NackPair = undefined;
    const pairs = tracker.buildPairs(&pairs_buf);
    try std.testing.expectEqual(@as(usize, 1), pairs.len);
    try std.testing.expect(pairs[0].contains(1001));
    try std.testing.expect(pairs[0].contains(1002));
    tracker.observe(1001);
    try std.testing.expectEqual(@as(usize, 1), tracker.pendingCount());
    try std.testing.expect(tracker.buildPairs(&pairs_buf)[0].contains(1002));

    var wrap = rtcp.NackTracker{};
    wrap.observe(0xfffe);
    wrap.observe(1);
    const wrap_pairs = wrap.buildPairs(&pairs_buf);
    try std.testing.expectEqual(@as(usize, 1), wrap_pairs.len);
    try std.testing.expect(wrap_pairs[0].contains(0xffff));
    try std.testing.expect(wrap_pairs[0].contains(0));
    wrap.observe(0xffff);
    wrap.observe(0);
    try std.testing.expectEqual(@as(usize, 0), wrap.pendingCount());
}

test "SCTP receive state generates SACK gaps and duplicates" {
    const allocator = std.testing.allocator;
    var state = sctp.ReceiveState.init(allocator, 1000, 4096);
    defer state.deinit();

    try state.observeData(.{ .tsn = 1002, .stream_id = 0, .stream_sequence_number = 0, .payload_protocol_identifier = .webrtc_string, .user_data = &.{} });
    var sack = try state.sack(allocator);
    defer sack.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1000), sack.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(usize, 1), sack.gap_ack_blocks.len);
    try std.testing.expectEqual(@as(u16, 2), sack.gap_ack_blocks[0].start);
    try std.testing.expectEqual(@as(u16, 2), sack.gap_ack_blocks[0].end);

    try state.observeData(.{ .tsn = 1001, .stream_id = 0, .stream_sequence_number = 0, .payload_protocol_identifier = .webrtc_string, .user_data = &.{} });
    sack.deinit(allocator);
    sack = try state.sack(allocator);
    try std.testing.expectEqual(@as(u32, 1002), sack.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(usize, 0), sack.gap_ack_blocks.len);

    try state.observeData(.{ .tsn = 1002, .stream_id = 0, .stream_sequence_number = 0, .payload_protocol_identifier = .webrtc_string, .user_data = &.{} });
    sack.deinit(allocator);
    sack = try state.sack(allocator);
    try std.testing.expectEqualSlices(u32, &.{1002}, sack.duplicate_tsns);
    state.clearDuplicates();

    try state.observeData(.{ .tsn = 1005, .stream_id = 0, .stream_sequence_number = 0, .payload_protocol_identifier = .webrtc_string, .user_data = &.{} });
    try state.observeData(.{ .tsn = 1006, .stream_id = 0, .stream_sequence_number = 0, .payload_protocol_identifier = .webrtc_string, .user_data = &.{} });
    sack.deinit(allocator);
    sack = try state.sack(allocator);
    try std.testing.expectEqual(@as(u32, 1002), sack.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(usize, 1), sack.gap_ack_blocks.len);
    try std.testing.expectEqual(@as(u16, 3), sack.gap_ack_blocks[0].start);
    try std.testing.expectEqual(@as(u16, 4), sack.gap_ack_blocks[0].end);

    state.observeForwardTsn(.{ .new_cumulative_tsn = 1004 });
    sack.deinit(allocator);
    sack = try state.sack(allocator);
    try std.testing.expectEqual(@as(u32, 1006), sack.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(usize, 0), sack.gap_ack_blocks.len);
}

test "SCTP ABORT and ERROR causes" {
    const allocator = std.testing.allocator;
    const cause_text = "closing association";
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try sctp.writeAbortPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, true, &.{.{ .code = .user_initiated_abort, .value = cause_text }});
    try std.testing.expect(try sctp.validChecksum(encoded.items));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeAbortPacket(&encoded, allocator, .{
        .source_port = 0,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, true, &.{}));
    var zero_source_port = try encoded.clone(allocator);
    defer zero_source_port.deinit(allocator);
    zero_source_port.items[0] = 0;
    zero_source_port.items[1] = 0;
    std.mem.writeInt(u32, zero_source_port.items[8..12], 0, .little);
    const zero_source_checksum = try sctp.checksum(zero_source_port.items);
    std.mem.writeInt(u32, zero_source_port.items[8..12], zero_source_checksum, .little);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parsePacket(allocator, zero_source_port.items, true));
    var zero_destination_port = try encoded.clone(allocator);
    defer zero_destination_port.deinit(allocator);
    zero_destination_port.items[2] = 0;
    zero_destination_port.items[3] = 0;
    std.mem.writeInt(u32, zero_destination_port.items[8..12], 0, .little);
    const zero_destination_checksum = try sctp.checksum(zero_destination_port.items);
    std.mem.writeInt(u32, zero_destination_port.items[8..12], zero_destination_checksum, .little);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parsePacket(allocator, zero_destination_port.items, true));
    var parsed = try sctp.parsePacket(allocator, encoded.items, true);
    defer parsed.deinit(allocator);
    var abort_chunk = try sctp.AbortChunk.parse(allocator, parsed.chunks[0]);
    defer abort_chunk.deinit(allocator);
    try std.testing.expect(abort_chunk.t_bit);
    try std.testing.expectEqual(sctp.ErrorCauseCode.user_initiated_abort, abort_chunk.causes[0].code);
    try std.testing.expectEqualStrings(cause_text, abort_chunk.causes[0].value);

    encoded.clearRetainingCapacity();
    try sctp.writeErrorPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{.{ .code = .protocol_violation, .value = "bad chunk" }});
    var error_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer error_packet.deinit(allocator);
    var error_chunk = try sctp.ErrorChunk.parse(allocator, error_packet.chunks[0]);
    defer error_chunk.deinit(allocator);
    try std.testing.expectEqual(sctp.ErrorCauseCode.protocol_violation, error_chunk.causes[0].code);
    try std.testing.expectEqualStrings("bad chunk", error_chunk.causes[0].value);
    // Pion/sctp follows the SCTP chunk rule that padding after the final
    // variable-length cause is chunk padding, not part of the ERROR chunk
    // length.  Keep accepting that mature wire image.
    try std.testing.expectEqual(@as(usize, 13), error_packet.chunks[0].value.len);

    encoded.items[encoded.items.len - 1] = 0xff; // non-zero ERROR cause padding
    std.mem.writeInt(u32, encoded.items[8..12], 0, .little);
    const repaired_error_checksum = try sctp.checksum(encoded.items);
    std.mem.writeInt(u32, encoded.items[8..12], repaired_error_checksum, .little);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parsePacket(allocator, encoded.items, true));

    encoded.clearRetainingCapacity();
    try sctp.writeErrorPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{
        .{ .code = .invalid_mandatory_parameter, .value = "abc" },
        .{ .code = .protocol_violation, .value = "tail" },
    });
    const first_cause_len = 4 + "abc".len;
    const inter_cause_padding_index = 12 + 4 + first_cause_len;
    try std.testing.expectEqual(@as(u8, 0), encoded.items[inter_cause_padding_index]);
    var two_cause_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer two_cause_packet.deinit(allocator);
    var two_cause_error = try sctp.ErrorChunk.parse(allocator, two_cause_packet.chunks[0]);
    defer two_cause_error.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), two_cause_error.causes.len);
    try std.testing.expectEqualStrings("abc", two_cause_error.causes[0].value);
    try std.testing.expectEqualStrings("tail", two_cause_error.causes[1].value);

    encoded.items[inter_cause_padding_index] = 0xff;
    std.mem.writeInt(u32, encoded.items[8..12], 0, .little);
    const repaired_inter_cause_checksum = try sctp.checksum(encoded.items);
    std.mem.writeInt(u32, encoded.items[8..12], repaired_inter_cause_checksum, .little);
    var bad_error_padding = try sctp.parsePacket(allocator, encoded.items, true);
    defer bad_error_padding.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.ErrorChunk.parse(allocator, bad_error_padding.chunks[0]));

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeErrorChunk(&encoded, allocator, &.{}));
}

test "SCTP HEARTBEAT and SHUTDOWN lifecycle packets" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try sctp.writeHeartbeatPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, false, "heartbeat-info");
    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var heartbeat_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer heartbeat_packet.deinit(allocator);
    const heartbeat = try sctp.HeartbeatChunk.parse(heartbeat_packet.chunks[0]);
    try std.testing.expectEqualStrings("heartbeat-info", heartbeat.info);
    const heartbeat_info = try allocator.dupe(u8, heartbeat.info);
    defer allocator.free(heartbeat_info);

    encoded.clearRetainingCapacity();
    try sctp.writeHeartbeatPacket(&encoded, allocator, .{ .source_port = 5000, .destination_port = 5000, .verification_tag = 0x01020304 }, true, heartbeat_info);
    var heartbeat_ack_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer heartbeat_ack_packet.deinit(allocator);
    try std.testing.expectEqual(sctp.ChunkType.heartbeat_ack, heartbeat_ack_packet.chunks[0].chunk_type);
    const heartbeat_ack = try sctp.HeartbeatChunk.parse(heartbeat_ack_packet.chunks[0]);
    try std.testing.expectEqualStrings("heartbeat-info", heartbeat_ack.info);

    encoded.clearRetainingCapacity();
    try sctp.writeShutdownPacket(&encoded, allocator, .{ .source_port = 5000, .destination_port = 5000, .verification_tag = 0x01020304 }, 12345);
    var shutdown_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer shutdown_packet.deinit(allocator);
    const shutdown = try sctp.ShutdownChunk.parse(shutdown_packet.chunks[0]);
    try std.testing.expectEqual(@as(u32, 12345), shutdown.cumulative_tsn_ack);

    encoded.clearRetainingCapacity();
    try sctp.writeShutdownAckPacket(&encoded, allocator, .{ .source_port = 5000, .destination_port = 5000, .verification_tag = 0x01020304 });
    var shutdown_ack_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer shutdown_ack_packet.deinit(allocator);
    try sctp.validateEmptyControlChunk(shutdown_ack_packet.chunks[0], .shutdown_ack);

    encoded.clearRetainingCapacity();
    try sctp.writeShutdownCompletePacket(&encoded, allocator, .{ .source_port = 5000, .destination_port = 5000, .verification_tag = 0x01020304 }, true);
    var shutdown_complete_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer shutdown_complete_packet.deinit(allocator);
    try sctp.validateEmptyControlChunk(shutdown_complete_packet.chunks[0], .shutdown_complete);
    try std.testing.expectEqual(@as(u8, 1), shutdown_complete_packet.chunks[0].flags);

    encoded.clearRetainingCapacity();
    try sctp.writeHeartbeatChunk(&encoded, allocator, false, "");
    const empty_heartbeat = try sctp.HeartbeatChunk.parse(.{
        .chunk_type = .heartbeat,
        .flags = 0,
        .value = encoded.items[4..],
        .consumed = encoded.items.len,
    });
    try std.testing.expectEqual(@as(usize, 0), empty_heartbeat.info.len);
}

test "SCTP FORWARD-TSN packet roundtrip" {
    const allocator = std.testing.allocator;
    var skipped = [_]sctp.SkippedStream{
        .{ .stream_id = 1, .stream_sequence_number = 7 },
        .{ .stream_id = 2, .stream_sequence_number = 9 },
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try sctp.writeForwardTsnPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, .{
        .new_cumulative_tsn = 9000,
        .skipped_streams = &skipped,
    });

    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var parsed = try sctp.parsePacket(allocator, encoded.items, true);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(sctp.ChunkType.forward_tsn, parsed.chunks[0].chunk_type);
    var forward = try sctp.ForwardTsnChunk.parse(allocator, parsed.chunks[0]);
    defer forward.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 9000), forward.new_cumulative_tsn);
    try std.testing.expectEqual(@as(usize, 2), forward.skipped_streams.len);
    try std.testing.expectEqual(@as(u16, 1), forward.skipped_streams[0].stream_id);
    try std.testing.expectEqual(@as(u16, 7), forward.skipped_streams[0].stream_sequence_number);

    encoded.clearRetainingCapacity();
    try sctp.writeForwardTsnChunk(&encoded, allocator, .{ .new_cumulative_tsn = 42 });
    var empty_forward = try sctp.ForwardTsnChunk.parse(allocator, .{
        .chunk_type = .forward_tsn,
        .flags = encoded.items[1],
        .value = encoded.items[4..],
        .consumed = encoded.items.len,
    });
    defer empty_forward.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), empty_forward.skipped_streams.len);

    var skipped_messages = [_]sctp.SkippedMessage{
        .{ .stream_id = 1, .message_identifier = 7 },
        .{ .stream_id = 1, .message_identifier = 9 },
        .{ .stream_id = 1, .unordered = true, .message_identifier = 4 },
        .{ .stream_id = 2, .message_identifier = 3 },
    };
    encoded.clearRetainingCapacity();
    try sctp.writeIForwardTsnPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, .{
        .new_cumulative_tsn = 9100,
        .skipped_messages = &skipped_messages,
    });
    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var parsed_interleaved = try sctp.parsePacket(allocator, encoded.items, true);
    defer parsed_interleaved.deinit(allocator);
    try std.testing.expectEqual(sctp.ChunkType.i_forward_tsn, parsed_interleaved.chunks[0].chunk_type);
    var i_forward = try sctp.IForwardTsnChunk.parse(allocator, parsed_interleaved.chunks[0]);
    defer i_forward.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 9100), i_forward.new_cumulative_tsn);
    try std.testing.expectEqual(@as(usize, 3), i_forward.skipped_messages.len);
    try std.testing.expectEqual(@as(u16, 1), i_forward.skipped_messages[0].stream_id);
    try std.testing.expect(!i_forward.skipped_messages[0].unordered);
    try std.testing.expectEqual(@as(u32, 9), i_forward.skipped_messages[0].message_identifier);
    try std.testing.expect(i_forward.skipped_messages[1].unordered);

    encoded.items[23] = 0x02; // Reserved flags in the first I-FORWARD-TSN stream entry.
    std.mem.writeInt(u32, encoded.items[8..12], 0, .little);
    const repaired_checksum = try sctp.checksum(encoded.items);
    std.mem.writeInt(u32, encoded.items[8..12], repaired_checksum, .little);
    var invalid_interleaved = try sctp.parsePacket(allocator, encoded.items, true);
    defer invalid_interleaved.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.IForwardTsnChunk.parse(allocator, invalid_interleaved.chunks[0]));
}

test "SCTP RE-CONFIG stream reset request and response" {
    const allocator = std.testing.allocator;
    const streams = [_]u16{ 2, 4, 6 };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try sctp.writeReconfigPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{
        .{ .outgoing_ssn_reset_request = .{
            .request_sequence_number = 10,
            .response_sequence_number = 9,
            .sender_last_assigned_tsn = 1234,
            .stream_numbers = &streams,
        } },
        .{ .outgoing_ssn_reset_response = .{
            .response_sequence_number = 10,
            .result = .success_performed,
        } },
    });

    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var parsed = try sctp.parsePacket(allocator, encoded.items, true);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(sctp.ChunkType.reconfig, parsed.chunks[0].chunk_type);
    var reconfig = try sctp.ReconfigChunk.parse(allocator, parsed.chunks[0]);
    defer reconfig.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), reconfig.parameters.len);
    const request = reconfig.parameters[0].outgoing_ssn_reset_request;
    try std.testing.expectEqual(@as(u32, 10), request.request_sequence_number);
    try std.testing.expectEqual(@as(u32, 9), request.response_sequence_number);
    try std.testing.expectEqual(@as(u32, 1234), request.sender_last_assigned_tsn);
    try std.testing.expectEqualSlices(u16, &streams, request.stream_numbers);
    const response = reconfig.parameters[1].outgoing_ssn_reset_response;
    try std.testing.expectEqual(@as(u32, 10), response.response_sequence_number);
    try std.testing.expectEqual(sctp.ReconfigResult.success_performed, response.result);

    encoded.clearRetainingCapacity();
    try sctp.writeDataChannelResetPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, 7, 11, 10, 1235);
    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var reset_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer reset_packet.deinit(allocator);
    var reset_reconfig = try sctp.ReconfigChunk.parse(allocator, reset_packet.chunks[0]);
    defer reset_reconfig.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), reset_reconfig.parameters.len);
    const reset = reset_reconfig.parameters[0].outgoing_ssn_reset_request;
    try std.testing.expectEqual(@as(u32, 11), reset.request_sequence_number);
    try std.testing.expectEqual(@as(u32, 10), reset.response_sequence_number);
    try std.testing.expectEqual(@as(u32, 1235), reset.sender_last_assigned_tsn);
    try std.testing.expectEqualSlices(u16, &.{7}, reset.stream_numbers);

    encoded.clearRetainingCapacity();
    try sctp.writeDataChannelResetResponsePacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, 11, .success_performed);
    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var reset_response_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer reset_response_packet.deinit(allocator);
    var reset_response_reconfig = try sctp.ReconfigChunk.parse(allocator, reset_response_packet.chunks[0]);
    defer reset_response_reconfig.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), reset_response_reconfig.parameters.len);
    const reset_response = reset_response_reconfig.parameters[0].outgoing_ssn_reset_response;
    try std.testing.expectEqual(@as(u32, 11), reset_response.response_sequence_number);
    try std.testing.expectEqual(sctp.ReconfigResult.success_performed, reset_response.result);

    encoded.clearRetainingCapacity();
    try sctp.writeReconfigPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{
        .{ .unknown = .{ .param_type = @enumFromInt(@as(u16, 0x800d)), .value = "abc" } },
        .{ .outgoing_ssn_reset_response = .{
            .response_sequence_number = 44,
            .result = .success_nothing_to_do,
        } },
    });
    const first_param_len = 4 + "abc".len;
    const inter_param_padding_index = 12 + 4 + first_param_len;
    try std.testing.expectEqual(@as(u8, 0), encoded.items[inter_param_padding_index]);
    var two_param_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer two_param_packet.deinit(allocator);
    var two_param_reconfig = try sctp.ReconfigChunk.parse(allocator, two_param_packet.chunks[0]);
    defer two_param_reconfig.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), two_param_reconfig.parameters.len);
    try std.testing.expectEqual(@as(u32, 44), two_param_reconfig.parameters[0].outgoing_ssn_reset_response.response_sequence_number);

    encoded.items[inter_param_padding_index] = 0xff;
    std.mem.writeInt(u32, encoded.items[8..12], 0, .little);
    const repaired_inter_param_checksum = try sctp.checksum(encoded.items);
    std.mem.writeInt(u32, encoded.items[8..12], repaired_inter_param_checksum, .little);
    var bad_reconfig_padding = try sctp.parsePacket(allocator, encoded.items, true);
    defer bad_reconfig_padding.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.ReconfigChunk.parse(allocator, bad_reconfig_padding.chunks[0]));

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeReconfigChunk(&invalid, allocator, &.{}));

    invalid.clearRetainingCapacity();
    try wire.appendInt(&invalid, allocator, u16, 0x800d, .big); // unknown: skip and continue
    try wire.appendInt(&invalid, allocator, u16, 4, .big);
    try wire.appendInt(&invalid, allocator, u16, @intFromEnum(sctp.ReconfigParameterType.outgoing_ssn_reset_response), .big);
    try wire.appendInt(&invalid, allocator, u16, 12, .big);
    try wire.appendInt(&invalid, allocator, u32, 22, .big);
    try wire.appendInt(&invalid, allocator, u32, @intFromEnum(sctp.ReconfigResult.success_nothing_to_do), .big);
    var skipped_unknown = try sctp.ReconfigChunk.parse(allocator, .{
        .chunk_type = .reconfig,
        .flags = 0,
        .value = invalid.items,
        .consumed = 0,
    });
    defer skipped_unknown.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), skipped_unknown.parameters.len);
    try std.testing.expectEqual(@as(u32, 22), skipped_unknown.parameters[0].outgoing_ssn_reset_response.response_sequence_number);

    invalid.clearRetainingCapacity();
    try wire.appendInt(&invalid, allocator, u16, 0x0020, .big); // unknown: stop/report as error
    try wire.appendInt(&invalid, allocator, u16, 4, .big);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.ReconfigChunk.parse(allocator, .{
        .chunk_type = .reconfig,
        .flags = 0,
        .value = invalid.items,
        .consumed = 0,
    }));

    invalid.clearRetainingCapacity();
    try wire.appendInt(&invalid, allocator, u16, 0x800d, .big); // unknown: skip and continue
    try wire.appendInt(&invalid, allocator, u16, 5, .big);
    try invalid.append(allocator, 0xaa);
    try invalid.appendSlice(allocator, &.{ 0, 0, 0xff }); // invalid parameter padding
    try std.testing.expectError(error.InvalidSctpPacket, sctp.ReconfigChunk.parse(allocator, .{
        .chunk_type = .reconfig,
        .flags = 0,
        .value = invalid.items,
        .consumed = 0,
    }));
}

test "SCTP INIT cookie echo and cookie ack packets" {
    const allocator = std.testing.allocator;
    const cookie = "state-cookie";
    const extensions = [_]u8{ @intFromEnum(sctp.ChunkType.reconfig), @intFromEnum(sctp.ChunkType.forward_tsn) };
    var zero_checksum_param: std.ArrayList(u8) = .empty;
    defer zero_checksum_param.deinit(allocator);
    try sctp.writeZeroChecksumAcceptableParameter(&zero_checksum_param, allocator, sctp.dtls_error_detection_method);
    var params = [_]sctp.InitParameter{
        .{ .param_type = .state_cookie, .value = cookie },
        .{ .param_type = .supported_extensions, .value = &extensions },
        .{ .param_type = .zero_checksum_acceptable, .value = zero_checksum_param.items[4..] },
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try sctp.writeInitPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0,
    }, true, .{
        .initiate_tag = 0x01020304,
        .advertised_receiver_window_credit = 256 * 1024,
        .outbound_streams = 16,
        .inbound_streams = 16,
        .initial_tsn = 0x10203040,
        .parameters = &params,
    });
    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var parsed = try sctp.parsePacket(allocator, encoded.items, true);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(sctp.ChunkType.init_ack, parsed.chunks[0].chunk_type);
    var init_ack = try sctp.InitChunk.parse(allocator, parsed.chunks[0]);
    defer init_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x01020304), init_ack.initiate_tag);
    try std.testing.expectEqual(@as(u16, 16), init_ack.outbound_streams);
    try std.testing.expectEqual(@as(u32, 0x10203040), init_ack.initial_tsn);
    try std.testing.expectEqualStrings(cookie, init_ack.stateCookie().?);
    try std.testing.expectEqual(sctp.InitParameterType.supported_extensions, init_ack.parameters[1].param_type);
    try std.testing.expectEqual(sctp.InitParameterType.zero_checksum_acceptable, init_ack.parameters[2].param_type);
    try std.testing.expectEqual(@as(u32, sctp.dtls_error_detection_method), try sctp.parseZeroChecksumAcceptable(init_ack.parameters[2]));
    try std.testing.expect(try sctp.zeroChecksumAcceptsDtls(init_ack.parameters[2]));
    zero_checksum_param.clearRetainingCapacity();
    try sctp.writeZeroChecksumAcceptableParameter(&zero_checksum_param, allocator, 2);
    const non_dtls_zero_checksum = sctp.InitParameter{ .param_type = .zero_checksum_acceptable, .value = zero_checksum_param.items[4..] };
    try std.testing.expectEqual(@as(u32, 2), try sctp.parseZeroChecksumAcceptable(non_dtls_zero_checksum));
    try std.testing.expect(!(try sctp.zeroChecksumAcceptsDtls(non_dtls_zero_checksum)));
    const parsed_cookie = try allocator.dupe(u8, init_ack.stateCookie().?);
    defer allocator.free(parsed_cookie);
    var bundled_init = try encoded.clone(allocator);
    defer bundled_init.deinit(allocator);

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeInitPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, false, .{
        .initiate_tag = 0x01020304,
        .advertised_receiver_window_credit = 256 * 1024,
        .outbound_streams = 16,
        .inbound_streams = 16,
        .initial_tsn = 0x10203040,
    }));

    try sctp.writeShutdownAckChunk(&bundled_init, allocator);
    std.mem.writeInt(u32, bundled_init.items[8..12], 0, .little);
    const bundled_checksum = try sctp.checksum(bundled_init.items);
    std.mem.writeInt(u32, bundled_init.items[8..12], bundled_checksum, .little);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parsePacket(allocator, bundled_init.items, true));

    var odd_final_init: std.ArrayList(u8) = .empty;
    defer odd_final_init.deinit(allocator);
    const single_extension = [_]u8{@intFromEnum(sctp.ChunkType.reconfig)};
    var single_extension_param = [_]sctp.InitParameter{.{ .param_type = .supported_extensions, .value = &single_extension }};
    try sctp.writeInitPacket(&odd_final_init, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0,
    }, false, .{
        .initiate_tag = 0x01020304,
        .advertised_receiver_window_credit = 256 * 1024,
        .outbound_streams = 16,
        .inbound_streams = 16,
        .initial_tsn = 0x10203040,
        .parameters = &single_extension_param,
    });
    var odd_final_init_packet = try sctp.parsePacket(allocator, odd_final_init.items, true);
    defer odd_final_init_packet.deinit(allocator);
    // Pion/sctp omits final parameter padding from the INIT chunk length; the
    // packet-level chunk padding remains present and is validated by parsePacket.
    try std.testing.expectEqual(@as(usize, 16 + 4 + single_extension.len), odd_final_init_packet.chunks[0].value.len);
    var odd_final_init_chunk = try sctp.InitChunk.parse(allocator, odd_final_init_packet.chunks[0]);
    defer odd_final_init_chunk.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), odd_final_init_chunk.parameters.len);
    try std.testing.expectEqualSlices(u8, &single_extension, odd_final_init_chunk.parameters[0].value);

    var invalid_init: std.ArrayList(u8) = .empty;
    defer invalid_init.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeInitChunk(&invalid_init, allocator, .init, .{
        .initiate_tag = 0,
        .advertised_receiver_window_credit = 256 * 1024,
        .outbound_streams = 16,
        .inbound_streams = 16,
        .initial_tsn = 1,
    }));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeInitChunk(&invalid_init, allocator, .init, .{
        .initiate_tag = 1,
        .advertised_receiver_window_credit = 1499,
        .outbound_streams = 16,
        .inbound_streams = 16,
        .initial_tsn = 1,
    }));
    const invalid_init_chunk = sctp.Chunk{
        .chunk_type = .init,
        .flags = 0,
        .value = &.{ 0, 0, 0, 0, 0, 0, 0x05, 0xdc, 0, 1, 0, 1, 0, 0, 0, 1 },
        .consumed = 20,
    };
    try std.testing.expectError(error.InvalidSctpPacket, sctp.InitChunk.parse(allocator, invalid_init_chunk));

    invalid_init.clearRetainingCapacity();
    try wire.appendInt(&invalid_init, allocator, u32, 0x01020304, .big);
    try wire.appendInt(&invalid_init, allocator, u32, 256 * 1024, .big);
    try wire.appendInt(&invalid_init, allocator, u16, 16, .big);
    try wire.appendInt(&invalid_init, allocator, u16, 16, .big);
    try wire.appendInt(&invalid_init, allocator, u32, 0x10203040, .big);
    try wire.appendInt(&invalid_init, allocator, u16, @intFromEnum(sctp.InitParameterType.zero_checksum_acceptable), .big);
    try wire.appendInt(&invalid_init, allocator, u16, 6, .big);
    try invalid_init.appendSlice(allocator, &.{ 0, 1, 0, 0 });
    try std.testing.expectError(error.InvalidSctpPacket, sctp.InitChunk.parse(allocator, .{
        .chunk_type = .init,
        .flags = 0,
        .value = invalid_init.items,
        .consumed = 0,
    }));

    var skip_unknown_value: std.ArrayList(u8) = .empty;
    defer skip_unknown_value.deinit(allocator);
    try wire.appendInt(&skip_unknown_value, allocator, u32, 0x01020304, .big);
    try wire.appendInt(&skip_unknown_value, allocator, u32, 256 * 1024, .big);
    try wire.appendInt(&skip_unknown_value, allocator, u16, 16, .big);
    try wire.appendInt(&skip_unknown_value, allocator, u16, 16, .big);
    try wire.appendInt(&skip_unknown_value, allocator, u32, 0x10203040, .big);
    try wire.appendInt(&skip_unknown_value, allocator, u16, 0x800f, .big); // Unknown, skip and continue.
    try wire.appendInt(&skip_unknown_value, allocator, u16, 4, .big);
    try wire.appendInt(&skip_unknown_value, allocator, u16, @intFromEnum(sctp.InitParameterType.supported_extensions), .big);
    try wire.appendInt(&skip_unknown_value, allocator, u16, 5, .big);
    try skip_unknown_value.append(allocator, @intFromEnum(sctp.ChunkType.i_data));
    try skip_unknown_value.appendNTimes(allocator, 0, 3);
    var skip_unknown = try sctp.InitChunk.parse(allocator, .{
        .chunk_type = .init,
        .flags = 0,
        .value = skip_unknown_value.items,
        .consumed = 0,
    });
    defer skip_unknown.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), skip_unknown.parameters.len);
    try std.testing.expectEqual(sctp.InitParameterType.supported_extensions, skip_unknown.parameters[0].param_type);
    skip_unknown_value.items[skip_unknown_value.items.len - 1] = 0xff;
    try std.testing.expectError(error.InvalidSctpPacket, sctp.InitChunk.parse(allocator, .{
        .chunk_type = .init,
        .flags = 0,
        .value = skip_unknown_value.items,
        .consumed = 0,
    }));
    skip_unknown_value.items[skip_unknown_value.items.len - 1] = 0;

    var stop_unknown_value = try std.ArrayList(u8).initCapacity(allocator, skip_unknown_value.items.len);
    defer stop_unknown_value.deinit(allocator);
    try stop_unknown_value.appendSlice(allocator, skip_unknown_value.items);
    stop_unknown_value.items[16] = 0x00;
    stop_unknown_value.items[17] = 0x20; // Unknown, stop processing.
    try std.testing.expectError(error.InvalidSctpPacket, sctp.InitChunk.parse(allocator, .{
        .chunk_type = .init,
        .flags = 0,
        .value = stop_unknown_value.items,
        .consumed = 0,
    }));

    encoded.clearRetainingCapacity();
    try sctp.writeCookieEchoPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = init_ack.initiate_tag,
    }, parsed_cookie);
    var cookie_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer cookie_packet.deinit(allocator);
    try std.testing.expectEqual(sctp.ChunkType.cookie_echo, cookie_packet.chunks[0].chunk_type);
    try std.testing.expectEqualStrings(cookie, try sctp.cookieEchoValue(cookie_packet.chunks[0]));
    try std.testing.expect(sctp.packetRequiresChecksum(encoded.items));
    var zero_checksum_cookie = try encoded.clone(allocator);
    defer zero_checksum_cookie.deinit(allocator);
    std.mem.writeInt(u32, zero_checksum_cookie.items[8..12], 0, .little);
    try std.testing.expectError(error.BadSctpChecksum, sctp.parsePacket(allocator, zero_checksum_cookie.items, false));
    var misordered_cookie: std.ArrayList(u8) = .empty;
    defer misordered_cookie.deinit(allocator);
    try wire.appendInt(&misordered_cookie, allocator, u16, 5000, .big);
    try wire.appendInt(&misordered_cookie, allocator, u16, 5000, .big);
    try wire.appendInt(&misordered_cookie, allocator, u32, init_ack.initiate_tag, .big);
    try wire.appendInt(&misordered_cookie, allocator, u32, 0, .little);
    try sctp.writeHeartbeatChunk(&misordered_cookie, allocator, false, "probe-first");
    try sctp.writeCookieEchoChunk(&misordered_cookie, allocator, parsed_cookie);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parsePacket(allocator, misordered_cookie.items, false));

    encoded.clearRetainingCapacity();
    try sctp.writeDataPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = init_ack.initiate_tag,
    }, &.{.{
        .tsn = 1,
        .stream_id = 1,
        .payload_protocol_identifier = .webrtc_binary,
        .user_data = "zero-checksum-ok",
    }});
    try std.testing.expect(!sctp.packetRequiresChecksum(encoded.items));
    var stale_checksum_data = try encoded.clone(allocator);
    defer stale_checksum_data.deinit(allocator);
    stale_checksum_data.items[stale_checksum_data.items.len - 1] ^= 0xff;
    try std.testing.expectError(error.BadSctpChecksum, sctp.parsePacket(allocator, stale_checksum_data.items, false));
    std.mem.writeInt(u32, encoded.items[8..12], 0, .little);
    var zero_checksum_data = try sctp.parsePacket(allocator, encoded.items, false);
    zero_checksum_data.deinit(allocator);

    encoded.clearRetainingCapacity();
    try sctp.writeCookieAckPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = init_ack.initiate_tag,
    });
    var ack_packet = try sctp.parsePacket(allocator, encoded.items, true);
    defer ack_packet.deinit(allocator);
    try sctp.validateCookieAck(ack_packet.chunks[0]);

    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeCookieEchoChunk(&encoded, allocator, ""));
}

test "SCTP DATA reassembler handles fragmented messages" {
    const allocator = std.testing.allocator;
    var reassembler = sctp.Reassembler.init(allocator, 16);
    defer reassembler.deinit();

    try std.testing.expect((try reassembler.push(.{
        .tsn = 2,
        .stream_id = 1,
        .stream_sequence_number = 7,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = false,
        .ending = false,
        .user_data = "llo ",
    })) == null);

    try std.testing.expect((try reassembler.push(.{
        .tsn = 1,
        .stream_id = 1,
        .stream_sequence_number = 7,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = true,
        .ending = false,
        .user_data = "he",
    })) == null);

    var message = (try reassembler.push(.{
        .tsn = 3,
        .stream_id = 1,
        .stream_sequence_number = 7,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = false,
        .ending = true,
        .user_data = "world",
    })).?;
    defer message.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 1), message.stream_id);
    try std.testing.expectEqual(@as(u16, 7), message.stream_sequence_number);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string, message.payload_protocol_identifier);
    try std.testing.expectEqualStrings("hello world", message.data);
    try std.testing.expectEqual(@as(usize, 0), reassembler.buffered_bytes);

    var single = (try reassembler.push(.{
        .tsn = 4,
        .stream_id = 2,
        .stream_sequence_number = 0,
        .payload_protocol_identifier = .webrtc_binary,
        .beginning = true,
        .ending = true,
        .user_data = &.{ 1, 2, 3 },
    })).?;
    defer single.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, single.data);
    const single_payload = try single.dataChannelPayload();
    try std.testing.expectEqual(sctp.DataChannelPayloadKind.binary, single_payload.info.kind);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, single_payload.data);

    var empty = (try reassembler.push(.{
        .tsn = 8,
        .stream_id = 2,
        .stream_sequence_number = 1,
        .payload_protocol_identifier = .webrtc_string_empty,
        .beginning = true,
        .ending = true,
        .user_data = &.{0},
    })).?;
    defer empty.deinit(allocator);
    const empty_payload = try empty.dataChannelPayload();
    try std.testing.expect(empty_payload.info.is_string);
    try std.testing.expect(empty_payload.info.empty);
    try std.testing.expectEqual(@as(usize, 0), empty_payload.data.len);

    try std.testing.expect((try reassembler.push(.{
        .tsn = 5,
        .stream_id = 3,
        .stream_sequence_number = 1,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = true,
        .ending = false,
        .user_data = "12345",
    })) == null);
    try std.testing.expectError(error.InvalidSctpPacket, reassembler.push(.{
        .tsn = 6,
        .stream_id = 3,
        .stream_sequence_number = 1,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = false,
        .ending = false,
        .user_data = "too-large-for-window",
    }));

    var interleaved_packet: std.ArrayList(u8) = .empty;
    defer interleaved_packet.deinit(allocator);
    try sctp.writeDataPacket(&interleaved_packet, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{
        .{
            .interleaved = true,
            .tsn = 100,
            .stream_id = 4,
            .message_identifier = 9,
            .payload_protocol_identifier = .webrtc_string,
            .beginning = true,
            .ending = false,
            .user_data = "inter",
        },
        .{
            .interleaved = true,
            .tsn = 102,
            .stream_id = 4,
            .message_identifier = 9,
            .fragment_sequence_number = 2,
            .payload_protocol_identifier = @enumFromInt(@as(u32, 0)),
            .beginning = false,
            .ending = true,
            .user_data = "data",
        },
        .{
            .interleaved = true,
            .tsn = 101,
            .stream_id = 4,
            .message_identifier = 9,
            .fragment_sequence_number = 1,
            .payload_protocol_identifier = @enumFromInt(@as(u32, 0)),
            .beginning = false,
            .ending = false,
            .user_data = "leaved ",
        },
    });
    var parsed_interleaved = try sctp.parsePacket(allocator, interleaved_packet.items, true);
    defer parsed_interleaved.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed_interleaved.chunks.len);
    const i_begin = try sctp.DataChunk.parse(parsed_interleaved.chunks[0]);
    const i_end = try sctp.DataChunk.parse(parsed_interleaved.chunks[1]);
    const i_middle = try sctp.DataChunk.parse(parsed_interleaved.chunks[2]);
    try std.testing.expect(i_begin.interleaved);
    try std.testing.expectEqual(@as(u32, 9), i_begin.message_identifier);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string, i_begin.payload_protocol_identifier);
    try std.testing.expectEqual(@as(u32, 2), i_end.fragment_sequence_number);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.DataChunk.parse(.{
        .chunk_type = .i_data,
        .flags = 0x01, // End fragment without Begin; the fourth word is FSN and must not be zero.
        .value = &.{
            0, 0, 0, 1, // TSN
            0, 4, // Stream ID
            0, 0, // Reserved
            0, 0, 0, 9, // MID
            0, 0, 0, 0, // Invalid FSN for a non-beginning fragment
        },
        .consumed = 20,
    }));

    var i_reassembler = sctp.Reassembler.init(allocator, 64);
    defer i_reassembler.deinit();
    try std.testing.expect((try i_reassembler.push(i_end)) == null);
    try std.testing.expect((try i_reassembler.push(i_begin)) == null);
    var i_message = (try i_reassembler.push(i_middle)).?;
    defer i_message.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 4), i_message.stream_id);
    try std.testing.expectEqual(@as(u16, 9), i_message.stream_sequence_number);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string, i_message.payload_protocol_identifier);
    try std.testing.expectEqualStrings("interleaved data", i_message.data);
}

test "SCTP DATA reassembler handles Forward-TSN skips" {
    const allocator = std.testing.allocator;

    var ordered = sctp.Reassembler.init(allocator, 64);
    defer ordered.deinit();
    try std.testing.expect((try ordered.push(.{
        .tsn = 10,
        .stream_id = 1,
        .stream_sequence_number = 0,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = true,
        .ending = false,
        .user_data = "DROP",
    })) == null);
    try std.testing.expect((try ordered.push(.{
        .tsn = 11,
        .stream_id = 1,
        .stream_sequence_number = 2,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = true,
        .ending = false,
        .user_data = "NE",
    })) == null);
    try std.testing.expectEqual(@as(usize, 6), ordered.buffered_bytes);

    var skipped = [_]sctp.SkippedStream{.{ .stream_id = 1, .stream_sequence_number = 0 }};
    ordered.forwardTsn(.{ .new_cumulative_tsn = 10, .skipped_streams = &skipped });
    try std.testing.expectEqual(@as(usize, 2), ordered.buffered_bytes);

    var kept = (try ordered.push(.{
        .tsn = 12,
        .stream_id = 1,
        .stream_sequence_number = 2,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = false,
        .ending = true,
        .user_data = "XT",
    })).?;
    defer kept.deinit(allocator);
    try std.testing.expectEqualStrings("NEXT", kept.data);
    try std.testing.expectEqual(@as(usize, 0), ordered.buffered_bytes);

    var interleaved = sctp.Reassembler.init(allocator, 64);
    defer interleaved.deinit();
    try std.testing.expect((try interleaved.push(.{
        .interleaved = true,
        .unordered = true,
        .tsn = 20,
        .stream_id = 2,
        .message_identifier = 2,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = true,
        .ending = false,
        .user_data = "drop",
    })) == null);
    try std.testing.expect((try interleaved.push(.{
        .interleaved = true,
        .unordered = true,
        .tsn = 21,
        .stream_id = 2,
        .message_identifier = 5,
        .payload_protocol_identifier = .webrtc_string,
        .beginning = true,
        .ending = false,
        .user_data = "later",
    })) == null);
    try std.testing.expectEqual(@as(usize, 9), interleaved.buffered_bytes);

    var skipped_messages = [_]sctp.SkippedMessage{.{ .stream_id = 2, .unordered = true, .message_identifier = 2 }};
    interleaved.forwardIForwardTsn(.{ .new_cumulative_tsn = 20, .skipped_messages = &skipped_messages });
    try std.testing.expectEqual(@as(usize, 5), interleaved.buffered_bytes);

    var later = (try interleaved.push(.{
        .interleaved = true,
        .unordered = true,
        .tsn = 22,
        .stream_id = 2,
        .message_identifier = 5,
        .fragment_sequence_number = 1,
        .payload_protocol_identifier = @enumFromInt(@as(u32, 0)),
        .beginning = false,
        .ending = true,
        .user_data = "!",
    })).?;
    defer later.deinit(allocator);
    try std.testing.expectEqualStrings("later!", later.data);
    try std.testing.expectEqual(@as(usize, 0), interleaved.buffered_bytes);
}

test "SCTP SACK packet roundtrip" {
    const allocator = std.testing.allocator;
    var gaps = [_]sctp.GapAckBlock{
        .{ .start = 2, .end = 4 },
        .{ .start = 8, .end = 8 },
    };
    const duplicates = [_]u32{ 1005, 1006 };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try sctp.writeSackPacket(&encoded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x11223344,
    }, .{
        .cumulative_tsn_ack = 1000,
        .advertised_receiver_window_credit = 65_535,
        .gap_ack_blocks = &gaps,
        .duplicate_tsns = &duplicates,
    });

    try std.testing.expect(try sctp.validChecksum(encoded.items));
    var parsed = try sctp.parsePacket(allocator, encoded.items, true);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed.chunks.len);
    var sack = try sctp.SackChunk.parse(allocator, parsed.chunks[0]);
    defer sack.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1000), sack.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(u32, 65_535), sack.advertised_receiver_window_credit);
    try std.testing.expectEqual(@as(usize, 2), sack.gap_ack_blocks.len);
    try std.testing.expectEqual(@as(u16, 2), sack.gap_ack_blocks[0].start);
    try std.testing.expectEqual(@as(u16, 4), sack.gap_ack_blocks[0].end);
    try std.testing.expectEqualSlices(u32, &duplicates, sack.duplicate_tsns);

    var padded: std.ArrayList(u8) = .empty;
    defer padded.deinit(allocator);
    try sctp.writeHeartbeatPacket(&padded, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x11223344,
    }, false, &.{ 0xaa, 0xbb, 0xcc });
    try std.testing.expectEqual(@as(u8, 0), padded.items[padded.items.len - 1]);
    var parsed_padded = try sctp.parsePacket(allocator, padded.items, true);
    defer parsed_padded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed_padded.chunks.len);
    const padded_heartbeat = try sctp.HeartbeatChunk.parse(parsed_padded.chunks[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, padded_heartbeat.info);

    padded.items[padded.items.len - 1] = 0xff;
    std.mem.writeInt(u32, padded.items[8..12], 0, .little);
    const repaired_checksum = try sctp.checksum(padded.items);
    std.mem.writeInt(u32, padded.items[8..12], repaired_checksum, .little);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parsePacket(allocator, padded.items, true));

    var unknown: std.ArrayList(u8) = .empty;
    defer unknown.deinit(allocator);
    try wire.appendInt(&unknown, allocator, u16, 5000, .big);
    try wire.appendInt(&unknown, allocator, u16, 5000, .big);
    try wire.appendInt(&unknown, allocator, u32, 0x11223344, .big);
    try wire.appendInt(&unknown, allocator, u32, 0, .little);
    try unknown.appendSlice(allocator, &.{ 0x7f, 0x00, 0x00, 0x04 });
    const unknown_checksum = try sctp.checksum(unknown.items);
    std.mem.writeInt(u32, unknown.items[8..12], unknown_checksum, .little);
    try std.testing.expect(try sctp.validChecksum(unknown.items));
    var stopped_unknown = try sctp.parsePacket(allocator, unknown.items, true);
    defer stopped_unknown.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), stopped_unknown.chunks.len);

    var skip_unknown: std.ArrayList(u8) = .empty;
    defer skip_unknown.deinit(allocator);
    try wire.appendInt(&skip_unknown, allocator, u16, 5000, .big);
    try wire.appendInt(&skip_unknown, allocator, u16, 5000, .big);
    try wire.appendInt(&skip_unknown, allocator, u32, 0x11223344, .big);
    try wire.appendInt(&skip_unknown, allocator, u32, 0, .little);
    try skip_unknown.appendSlice(allocator, &.{ 0x80, 0x00, 0x00, 0x04 }); // unknown: skip and continue
    try skip_unknown.appendSlice(allocator, &.{ @intFromEnum(sctp.ChunkType.heartbeat), 0x00, 0x00, 0x04 });
    const skip_checksum = try sctp.checksum(skip_unknown.items);
    std.mem.writeInt(u32, skip_unknown.items[8..12], skip_checksum, .little);
    var skipped_unknown = try sctp.parsePacket(allocator, skip_unknown.items, true);
    defer skipped_unknown.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), skipped_unknown.chunks.len);
    try std.testing.expectEqual(sctp.ChunkType.heartbeat, skipped_unknown.chunks[0].chunk_type);

    var bad_gaps = [_]sctp.GapAckBlock{.{ .start = 3, .end = 2 }};
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeSackChunk(&invalid, allocator, .{
        .cumulative_tsn_ack = 1,
        .advertised_receiver_window_credit = 1,
        .gap_ack_blocks = &bad_gaps,
    }));
}

test "SCTP DATA packet and DCEP channel messages" {
    const allocator = std.testing.allocator;

    var dcep_open: std.ArrayList(u8) = .empty;
    defer dcep_open.deinit(allocator);
    try sctp.writeDcepOpen(&dcep_open, allocator, .{
        .channel_type = .partial_reliable_retransmit_unordered,
        .priority = 128,
        .reliability_parameter = 3,
        .label = "chat",
        .protocol = "json",
    });

    var packet_bytes: std.ArrayList(u8) = .empty;
    defer packet_bytes.deinit(allocator);
    try sctp.writeDataPacket(&packet_bytes, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{.{
        .tsn = 10,
        .stream_id = 2,
        .stream_sequence_number = 0,
        .payload_protocol_identifier = .webrtc_dcep,
        .user_data = dcep_open.items,
    }});

    try std.testing.expect(try sctp.validChecksum(packet_bytes.items));
    var parsed = try sctp.parsePacket(allocator, packet_bytes.items, true);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 5000), parsed.header.source_port);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.header.verification_tag);
    try std.testing.expectEqual(@as(usize, 1), parsed.chunks.len);

    const data = try sctp.DataChunk.parse(parsed.chunks[0]);
    try std.testing.expect(!data.unordered);
    try std.testing.expect(data.beginning);
    try std.testing.expect(data.ending);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_dcep, data.payload_protocol_identifier);
    const dcep = try sctp.parseDcepMessage(data.user_data);
    try std.testing.expectEqual(sctp.DataChannelType.partial_reliable_retransmit_unordered, dcep.open.channel_type);
    try std.testing.expectEqual(@as(u32, 3), dcep.open.reliability_parameter);
    try std.testing.expectEqualStrings("chat", dcep.open.label);
    try std.testing.expectEqualStrings("json", dcep.open.protocol);
    const dcep_reliability = try dcep.open.reliability();
    try std.testing.expect(dcep_reliability.unordered);
    try std.testing.expectEqual(sctp.DataChannelReliabilityMode.retransmit, dcep_reliability.mode);
    try std.testing.expectEqual(@as(u32, 3), dcep_reliability.parameter);
    var invalid_dcep_data: std.ArrayList(u8) = .empty;
    defer invalid_dcep_data.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeDataChunk(&invalid_dcep_data, allocator, .{
        .unordered = true,
        .tsn = 10,
        .stream_id = 2,
        .stream_sequence_number = 0,
        .payload_protocol_identifier = .webrtc_dcep,
        .user_data = dcep_open.items,
    }));
    var unordered_dcep_value = [_]u8{0} ** 12;
    std.mem.writeInt(u32, unordered_dcep_value[8..12], @intFromEnum(sctp.PayloadProtocolIdentifier.webrtc_dcep), .big);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.DataChunk.parse(.{
        .chunk_type = .data,
        .flags = 0x07,
        .value = &unordered_dcep_value,
        .consumed = 16,
    }));

    try std.testing.expectEqual(sctp.DataChannelReliability{
        .unordered = false,
        .mode = .reliable,
        .parameter = 0,
    }, try sctp.dataChannelReliability(.reliable, 0));
    try std.testing.expectEqual(sctp.DataChannelReliability{
        .unordered = true,
        .mode = .reliable,
        .parameter = 7,
    }, try sctp.dataChannelReliability(.reliable_unordered, 7));
    try std.testing.expectEqual(sctp.DataChannelReliability{
        .unordered = false,
        .mode = .timed,
        .parameter = 500,
    }, try sctp.dataChannelReliability(.partial_reliable_timed, 500));
    try std.testing.expectEqual(sctp.DataChannelReliability{
        .unordered = true,
        .mode = .timed,
        .parameter = 500,
    }, try sctp.dataChannelReliability(.partial_reliable_timed_unordered, 500));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.dataChannelReliability(@enumFromInt(0x7f), 0));
    try std.testing.expectEqual(@as(u16, 0), try sctp.nextDataChannelId(.dtls_client, &.{}, 16));
    try std.testing.expectEqual(@as(u16, 0), try sctp.nextDataChannelId(.dtls_client, &.{1}, 16));
    try std.testing.expectEqual(@as(u16, 2), try sctp.nextDataChannelId(.dtls_client, &.{0}, 16));
    try std.testing.expectEqual(@as(u16, 4), try sctp.nextDataChannelId(.dtls_client, &.{ 0, 2 }, 16));
    try std.testing.expectEqual(@as(u16, 2), try sctp.nextDataChannelId(.dtls_client, &.{ 0, 4 }, 16));
    try std.testing.expectEqual(@as(u16, 1), try sctp.nextDataChannelId(.dtls_server, &.{}, 16));
    try std.testing.expectEqual(@as(u16, 1), try sctp.nextDataChannelId(.dtls_server, &.{0}, 16));
    try std.testing.expectEqual(@as(u16, 3), try sctp.nextDataChannelId(.dtls_server, &.{1}, 16));
    try std.testing.expectEqual(@as(u16, 5), try sctp.nextDataChannelId(.dtls_server, &.{ 1, 3 }, 16));
    try std.testing.expectEqual(@as(u16, 3), try sctp.nextDataChannelId(.dtls_server, &.{ 1, 5 }, 16));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.nextDataChannelId(.dtls_client, &.{ 0, 2 }, 3));
    try std.testing.expectEqual(sctp.DataChannelIdRole.dtls_client, try sctp.dataChannelIdRoleFromDtlsRole(.client));
    try std.testing.expectEqual(sctp.DataChannelIdRole.dtls_server, try sctp.dataChannelIdRoleFromDtlsRole(.server));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.dataChannelIdRoleFromDtlsRole(.auto));
    try std.testing.expectEqual(@as(u16, 2), try sctp.nextDataChannelIdForDtlsRole(.client, &.{0}, 16));
    try std.testing.expectEqual(@as(u16, 3), try sctp.nextDataChannelIdForDtlsRole(.server, &.{1}, 16));
    var id_registry = try sctp.DataChannelIdRegistry.init(allocator, 8);
    defer id_registry.deinit();
    try std.testing.expectEqual(@as(u16, 0), try id_registry.allocate(.dtls_client));
    try std.testing.expectEqual(@as(u16, 2), try id_registry.allocate(.dtls_client));
    try std.testing.expectEqual(@as(u16, 1), try id_registry.allocate(.dtls_server));
    try std.testing.expect(id_registry.contains(2));
    try std.testing.expectError(error.InvalidSctpPacket, id_registry.reserve(2));
    id_registry.release(2);
    try std.testing.expect(!id_registry.contains(2));
    try std.testing.expectEqual(@as(u16, 2), try id_registry.allocate(.dtls_client));
    try id_registry.reserve(3);
    try id_registry.reserve(5);
    try id_registry.reserve(7);
    try std.testing.expectError(error.InvalidSctpPacket, id_registry.allocate(.dtls_server));
    id_registry.release(4);
    try std.testing.expectEqual(@as(u16, 4), try id_registry.allocateForDtlsRole(.client));
    try std.testing.expectError(error.InvalidSctpPacket, id_registry.allocateForDtlsRole(.auto));

    packet_bytes.clearRetainingCapacity();
    try sctp.writeDataPacket(&packet_bytes, allocator, .{
        .source_port = 5000,
        .destination_port = 5000,
        .verification_tag = 0x01020304,
    }, &.{.{
        .immediate_sack = true,
        .tsn = 11,
        .stream_id = 2,
        .stream_sequence_number = 1,
        .payload_protocol_identifier = .webrtc_string,
        .user_data = "immediate",
    }});
    var immediate_packet = try sctp.parsePacket(allocator, packet_bytes.items, true);
    defer immediate_packet.deinit(allocator);
    const immediate_data = try sctp.DataChunk.parse(immediate_packet.chunks[0]);
    try std.testing.expect(immediate_data.immediate_sack);
    try std.testing.expect(immediate_data.beginning);
    try std.testing.expect(immediate_data.ending);
    try std.testing.expectEqualStrings("immediate", immediate_data.user_data);

    var tampered = try allocator.dupe(u8, packet_bytes.items);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xff;
    try std.testing.expectError(error.BadSctpChecksum, sctp.parsePacket(allocator, tampered, true));

    var ack: std.ArrayList(u8) = .empty;
    defer ack.deinit(allocator);
    try sctp.writeDcepAck(&ack, allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0 }, ack.items);
    try std.testing.expect(try sctp.parseDcepMessage(ack.items) == .ack);
    try std.testing.expect(try sctp.parseDcepMessage(&.{0x02}) == .ack);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parseDcepMessage(&.{ 0x02, 0, 0, 1 }));
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string_empty, sctp.dataChannelPayloadProtocol(true, 0));
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_binary, sctp.dataChannelPayloadProtocol(false, 4));
    try std.testing.expectEqual(sctp.DataChannelPayloadInfo{
        .kind = .string,
        .is_string = true,
        .empty = true,
        .effective_len = 0,
    }, try sctp.dataChannelPayloadInfo(.webrtc_string_empty, 1));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.dataChannelPayloadInfo(.webrtc_string_empty, 0));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.dataChannelPayloadInfo(.webrtc_binary_empty, 2));
    try std.testing.expectEqual(sctp.DataChannelPayloadInfo{
        .kind = .binary,
        .empty = true,
        .effective_len = 0,
    }, try sctp.dataChannelPayloadInfo(.webrtc_binary_empty, 1));
    try std.testing.expectEqual(sctp.DataChannelPayloadInfo{
        .kind = .binary,
        .effective_len = 9,
    }, try sctp.dataChannelPayloadInfo(.webrtc_binary, 9));
    try std.testing.expectEqual(sctp.DataChannelPayloadInfo{
        .kind = .dcep,
        .effective_len = 4,
    }, try sctp.dataChannelPayloadInfo(.webrtc_dcep, 4));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.dataChannelPayloadInfo(@enumFromInt(@as(u32, 0)), 0));
    const empty_text_payload = try sctp.dataChannelPayload(.webrtc_string_empty, &.{0});
    try std.testing.expect(empty_text_payload.info.is_string);
    try std.testing.expect(empty_text_payload.info.empty);
    try std.testing.expectEqual(@as(usize, 0), empty_text_payload.data.len);
    const binary_payload = try sctp.dataChannelPayload(.webrtc_binary, "bytes");
    try std.testing.expect(!binary_payload.info.is_string);
    try std.testing.expectEqualStrings("bytes", binary_payload.data);
    const dcep_payload = try sctp.dataChannelPayload(.webrtc_dcep, ack.items);
    try std.testing.expectEqual(sctp.DataChannelPayloadKind.dcep, dcep_payload.info.kind);
    try std.testing.expectEqualSlices(u8, ack.items, dcep_payload.data);

    const unordered_reliability = try sctp.dataChannelReliability(.partial_reliable_retransmit_unordered, 3);
    const empty_text_chunk = sctp.dataChannelChunk(.{
        .tsn = 12,
        .stream_id = 2,
        .stream_sequence_number = 2,
        .reliability = unordered_reliability,
        .is_string = true,
    }, "");
    try std.testing.expect(empty_text_chunk.unordered);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string_empty, empty_text_chunk.payload_protocol_identifier);
    try std.testing.expectEqualSlices(u8, &.{0}, empty_text_chunk.user_data);
    const binary_chunk = sctp.dataChannelChunk(.{
        .tsn = 13,
        .stream_id = 2,
        .stream_sequence_number = 3,
        .reliability = unordered_reliability,
    }, "bin");
    try std.testing.expect(binary_chunk.unordered);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_binary, binary_chunk.payload_protocol_identifier);
    try std.testing.expectEqualStrings("bin", binary_chunk.user_data);
    const dcep_chunk = sctp.dataChannelDcepChunk(.{
        .tsn = 14,
        .stream_id = 2,
        .stream_sequence_number = 4,
        .reliability = unordered_reliability,
    }, ack.items);
    try std.testing.expect(!dcep_chunk.unordered);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_dcep, dcep_chunk.payload_protocol_identifier);
    try std.testing.expectEqualSlices(u8, ack.items, dcep_chunk.user_data);

    const fragments = try sctp.fragmentDataChannelMessage(allocator, .{
        .first_tsn = 20,
        .stream_id = 3,
        .stream_sequence_number = 9,
        .reliability = unordered_reliability,
        .max_payload_size = 4,
    }, "hello world");
    defer sctp.freeDataChannelFragments(allocator, fragments);
    try std.testing.expectEqual(@as(usize, 3), fragments.len);
    try std.testing.expect(fragments[0].unordered);
    try std.testing.expect(fragments[0].beginning);
    try std.testing.expect(!fragments[0].ending);
    try std.testing.expectEqual(@as(u32, 20), fragments[0].tsn);
    try std.testing.expectEqual(@as(u16, 9), fragments[0].stream_sequence_number);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_binary, fragments[0].payload_protocol_identifier);
    try std.testing.expectEqualStrings("hell", fragments[0].user_data);
    try std.testing.expect(!fragments[1].beginning);
    try std.testing.expect(!fragments[1].ending);
    try std.testing.expectEqual(@as(u32, 21), fragments[1].tsn);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_binary, fragments[1].payload_protocol_identifier);
    try std.testing.expectEqualStrings("o wo", fragments[1].user_data);
    try std.testing.expect(!fragments[2].beginning);
    try std.testing.expect(fragments[2].ending);
    try std.testing.expectEqualStrings("rld", fragments[2].user_data);

    const empty_fragments = try sctp.fragmentDataChannelMessage(allocator, .{
        .first_tsn = 30,
        .stream_id = 3,
        .stream_sequence_number = 10,
        .is_string = true,
        .max_payload_size = 8,
    }, "");
    defer sctp.freeDataChannelFragments(allocator, empty_fragments);
    try std.testing.expectEqual(@as(usize, 1), empty_fragments.len);
    try std.testing.expect(empty_fragments[0].beginning);
    try std.testing.expect(empty_fragments[0].ending);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string_empty, empty_fragments[0].payload_protocol_identifier);
    try std.testing.expectEqualSlices(u8, &.{0}, empty_fragments[0].user_data);

    const i_fragments = try sctp.fragmentDataChannelMessage(allocator, .{
        .first_tsn = 40,
        .stream_id = 4,
        .message_identifier = 0x0102_0304,
        .reliability = unordered_reliability,
        .interleaved = true,
        .is_string = true,
        .max_payload_size = 3,
    }, "abcdefg");
    defer sctp.freeDataChannelFragments(allocator, i_fragments);
    try std.testing.expectEqual(@as(usize, 3), i_fragments.len);
    try std.testing.expect(i_fragments[0].interleaved);
    try std.testing.expectEqual(@as(u16, 0x0304), i_fragments[0].stream_sequence_number);
    try std.testing.expectEqual(@as(u32, 0x0102_0304), i_fragments[0].message_identifier);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string, i_fragments[0].payload_protocol_identifier);
    try std.testing.expectEqual(@as(u32, 1), i_fragments[1].fragment_sequence_number);
    try std.testing.expectEqual(@as(u32, 2), i_fragments[2].fragment_sequence_number);
    try std.testing.expectEqual(@as(u32, 42), i_fragments[2].tsn);
    var invalid_i_data: std.ArrayList(u8) = .empty;
    defer invalid_i_data.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeDataChunk(&invalid_i_data, allocator, .{
        .interleaved = true,
        .tsn = 43,
        .stream_id = 7,
        .message_identifier = 0x0102_0304,
        .fragment_sequence_number = 0,
        .beginning = false,
        .ending = true,
        .payload_protocol_identifier = @enumFromInt(@as(u32, 0)),
        .user_data = "bad",
    }));

    const dcep_fragments = try sctp.fragmentDcepMessage(allocator, .{
        .first_tsn = 50,
        .stream_id = 2,
        .stream_sequence_number = 5,
        .reliability = unordered_reliability,
        .max_payload_size = 2,
    }, ack.items);
    defer sctp.freeDataChannelFragments(allocator, dcep_fragments);
    try std.testing.expectEqual(@as(usize, 2), dcep_fragments.len);
    try std.testing.expect(!dcep_fragments[0].unordered);
    try std.testing.expect(!dcep_fragments[1].unordered);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_dcep, dcep_fragments[0].payload_protocol_identifier);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_dcep, dcep_fragments[1].payload_protocol_identifier);

    var send_state = sctp.DataChannelSendState{ .next_tsn = 100 };
    const ordered_send = try send_state.fragmentMessage(allocator, 7, try sctp.dataChannelReliability(.reliable, 0), false, 3, false, "hello");
    defer sctp.freeDataChannelFragments(allocator, ordered_send);
    try std.testing.expectEqual(@as(usize, 2), ordered_send.len);
    try std.testing.expectEqual(@as(u32, 100), ordered_send[0].tsn);
    try std.testing.expectEqual(@as(u16, 0), ordered_send[0].stream_sequence_number);
    try std.testing.expectEqual(@as(u32, 102), send_state.next_tsn);
    try std.testing.expectEqual(@as(u16, 1), send_state.stream_sequence_number);

    const unordered_send = try send_state.fragmentMessage(allocator, 7, unordered_reliability, false, 8, false, "u");
    defer sctp.freeDataChannelFragments(allocator, unordered_send);
    try std.testing.expect(unordered_send[0].unordered);
    try std.testing.expectEqual(@as(u16, 1), unordered_send[0].stream_sequence_number);
    try std.testing.expectEqual(@as(u16, 1), send_state.stream_sequence_number);
    try std.testing.expectEqual(@as(u32, 103), send_state.next_tsn);

    const interleaved_unordered = try send_state.fragmentMessage(allocator, 7, unordered_reliability, true, 2, true, "abc");
    defer sctp.freeDataChannelFragments(allocator, interleaved_unordered);
    try std.testing.expectEqual(@as(u32, 0), interleaved_unordered[0].message_identifier);
    try std.testing.expectEqual(@as(u16, 0), interleaved_unordered[0].stream_sequence_number);
    try std.testing.expectEqual(@as(u32, 1), send_state.next_unordered_message_id);
    try std.testing.expectEqual(@as(u16, 1), send_state.stream_sequence_number);

    const interleaved_dcep = try send_state.fragmentDcep(allocator, 7, true, 2, ack.items);
    defer sctp.freeDataChannelFragments(allocator, interleaved_dcep);
    try std.testing.expect(!interleaved_dcep[0].unordered);
    try std.testing.expectEqual(@as(u32, 0), interleaved_dcep[0].message_identifier);
    try std.testing.expectEqual(@as(u32, 1), send_state.next_ordered_message_id);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_dcep, interleaved_dcep[0].payload_protocol_identifier);

    var invalid_dcep: std.ArrayList(u8) = .empty;
    defer invalid_dcep.deinit(allocator);
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeDcepOpen(&invalid_dcep, allocator, .{
        .label = "\xc0\x80",
    }));
    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeDcepOpen(&invalid_dcep, allocator, .{
        .channel_type = @enumFromInt(0x7f),
        .label = "bad-type",
    }));

    invalid_dcep.clearRetainingCapacity();
    try invalid_dcep.appendSlice(allocator, &.{
        0x03, // DATA_CHANNEL_OPEN
        @intFromEnum(sctp.DataChannelType.reliable),
        0x00, 0x00, // priority
        0x00, 0x00, 0x00, 0x00, // reliability
        0x00, 0x02, // label length
        0x00, 0x00, // protocol length
        0xc0, 0x80, // invalid UTF-8 label
    });
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parseDcepMessage(invalid_dcep.items));

    invalid_dcep.items[1] = 0x7f;
    invalid_dcep.items[12] = 'o';
    invalid_dcep.items[13] = 'k';
    try std.testing.expectError(error.InvalidSctpPacket, sctp.parseDcepMessage(invalid_dcep.items));
}

test {
    _ = runtime;
}
