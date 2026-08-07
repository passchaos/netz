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
        while (!attr_cursor.eof()) {
            const attr_type: AttributeType = @enumFromInt(try attr_cursor.readInt(u16, .big));
            const attr_len = try attr_cursor.readInt(u16, .big);
            const value = try attr_cursor.readSlice(attr_len);
            const padding = (@as(usize, 4) - (attr_len % 4)) % 4;
            try attr_cursor.skip(padding);
            if (seen_integrity and attr_type != .fingerprint) return error.InvalidStunAttribute;
            try attrs.append(allocator, .{ .attr_type = attr_type, .value = value });
            if (attr_type == .message_integrity) seen_integrity = true;
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

    pub const BindingRequestOptions = struct {
        transaction_id: [12]u8,
        username: []const u8,
        password: []const u8,
        priority: u32,
        role: IceRole,
        tie_breaker: u64,
        use_candidate: bool = false,
    };

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
    };

    pub const Transport = enum {
        udp,
        tcp,
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
        extensions: []const CandidateExtension = &.{},

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
            var it = std.mem.tokenizeScalar(u8, candidate_body, ' ');
            const foundation = it.next() orelse return error.InvalidIceCandidate;
            try validateIceFoundation(foundation);
            const component_s = it.next() orelse return error.InvalidIceCandidate;
            try validateDecimalToken(component_s, 5);
            const transport_s = it.next() orelse return error.InvalidIceCandidate;
            const priority_s = it.next() orelse return error.InvalidIceCandidate;
            try validateDecimalToken(priority_s, 10);
            const address = it.next() orelse return error.InvalidIceCandidate;
            try validateCandidateAddress(address);
            const port_s = it.next() orelse return error.InvalidIceCandidate;
            try validateDecimalToken(port_s, 5);
            const typ_label = it.next() orelse return error.InvalidIceCandidate;
            if (!std.mem.eql(u8, typ_label, "typ")) return error.InvalidIceCandidate;
            const typ_s = it.next() orelse return error.InvalidIceCandidate;

            var extensions: std.ArrayList(CandidateExtension) = .empty;
            errdefer if (allocator) |a| extensions.deinit(a);
            var candidate: Candidate = .{
                .foundation = foundation,
                .component = std.fmt.parseInt(u16, component_s, 10) catch return error.InvalidIceCandidate,
                .transport = if (std.ascii.eqlIgnoreCase(transport_s, "udp")) .udp else if (std.ascii.eqlIgnoreCase(transport_s, "tcp")) .tcp else return error.InvalidIceCandidate,
                .priority = std.fmt.parseInt(u32, priority_s, 10) catch return error.InvalidIceCandidate,
                .address = address,
                .port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidIceCandidate,
                .candidate_type = parseCandidateType(typ_s) orelse return error.UnknownIceCandidateType,
            };

            while (it.next()) |key| {
                try validateCandidateByteString(key);
                const value = it.next() orelse return error.InvalidIceCandidate;
                try validateCandidateByteString(value);
                if (std.mem.eql(u8, key, "raddr")) {
                    if (candidate.related_address != null or candidate.related_port != null) return error.InvalidIceCandidate;
                    try validateCandidateAddress(value);
                    candidate.related_address = value;
                    const rport_key = it.next() orelse return error.InvalidIceCandidate;
                    if (!std.mem.eql(u8, rport_key, "rport")) return error.InvalidIceCandidate;
                    const rport_value = it.next() orelse return error.InvalidIceCandidate;
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

        pub fn write(self: Candidate, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
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
    };

    fn parseCandidateType(value: []const u8) ?CandidateType {
        inline for (std.meta.fields(CandidateType)) |field| {
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

    fn validateCandidateAddress(value: []const u8) Error!void {
        try validateCandidateByteString(value);
        if (std.Io.net.IpAddress.parse(value, 0)) |_| {
            return;
        } else |_| {}
        try validateHostname(value);
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
        return std.mem.eql(u8, value, "active") or
            std.mem.eql(u8, value, "passive") or
            std.mem.eql(u8, value, "so");
    }
};

pub const sdp = struct {
    pub const Attribute = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const Media = struct {
        kind: []const u8,
        port: u16,
        protocol: []const u8,
        formats: []const u8,
        attributes: []Attribute,
    };

    const MediaHeader = struct {
        kind: []const u8,
        port: u16,
        protocol: []const u8,
        formats: []const u8,
    };

    pub const Session = struct {
        version: []const u8 = "0",
        origin: []const u8 = "- 0 0 IN IP4 127.0.0.1",
        name: []const u8 = "-",
        timing: []const u8 = "0 0",
        attributes: []Attribute,
        media: []Media,

        pub fn deinit(self: *Session, allocator: std.mem.Allocator) void {
            allocator.free(self.attributes);
            for (self.media) |media| allocator.free(media.attributes);
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

    pub const DtlsRole = enum {
        auto,
        client,
        server,
    };

    pub const RtcpFeedback = struct {
        typ: []const u8,
        parameter: []const u8 = "",
    };

    pub const RtpCodec = struct {
        payload_type: u8,
        mime_type: []const u8,
        clock_rate: u32,
        channels: u16 = 0,
        fmtp: []const u8 = "",
        rtcp_feedback: []RtcpFeedback = &.{},

        pub fn deinit(self: *RtpCodec, allocator: std.mem.Allocator) void {
            allocator.free(self.rtcp_feedback);
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

    pub const SctpParameters = struct {
        port: u16,
        max_message_size: u32 = 0,
        max_channels: ?u16 = null,
        protocol: []const u8 = "webrtc-datachannel",
    };

    pub const abs_send_time_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
    pub const transport_cc_uri = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
    pub const sdes_mid_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";
    pub const sdes_rtp_stream_id_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
    pub const sdes_repaired_rtp_stream_id_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";
    pub const audio_level_uri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

    pub const ExtMapDirection = enum {
        sendrecv,
        sendonly,
        recvonly,
        inactive,
    };

    pub const ExtMap = struct {
        id: u16,
        direction: ExtMapDirection = .sendrecv,
        uri: []const u8,
        extension_attributes: []const u8 = &.{},

        pub fn rtpId(self: ExtMap) Error!u8 {
            if (self.id == 0 or self.id > std.math.maxInt(u8)) return error.InvalidSdp;
            return @intCast(self.id);
        }
    };

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
        if (id == 0 or id > std.math.maxInt(u8)) return error.InvalidSdp;

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
            for (media_items.items) |media| allocator.free(media.attributes);
            media_items.deinit(allocator);
        }
        var current_attrs: std.ArrayList(Attribute) = .empty;
        defer current_attrs.deinit(allocator);
        var current_media: ?MediaHeader = null;
        var version: []const u8 = "0";
        var origin: []const u8 = "- 0 0 IN IP4 127.0.0.1";
        var name: []const u8 = "-";
        var timing: []const u8 = "0 0";

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
                't' => timing = value,
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
                            .protocol = media_header.protocol,
                            .formats = media_header.formats,
                            .attributes = try current_attrs.toOwnedSlice(allocator),
                        });
                        current_attrs = .empty;
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
                .protocol = media_header.protocol,
                .formats = media_header.formats,
                .attributes = try current_attrs.toOwnedSlice(allocator),
            });
            current_attrs = .empty;
        }

        return .{
            .version = version,
            .origin = origin,
            .name = name,
            .timing = timing,
            .attributes = try session_attrs.toOwnedSlice(allocator),
            .media = try media_items.toOwnedSlice(allocator),
        };
    }

    fn parseAttribute(value: []const u8) Attribute {
        if (std.mem.indexOfScalar(u8, value, ':')) |colon| return .{ .name = value[0..colon], .value = value[colon + 1 ..] };
        return .{ .name = value, .value = "" };
    }

    fn parseMediaLine(value: []const u8) Error!MediaHeader {
        var it = std.mem.splitScalar(u8, value, ' ');
        const kind = it.next() orelse return error.InvalidSdp;
        const port_s = it.next() orelse return error.InvalidSdp;
        const protocol = it.next() orelse return error.InvalidSdp;
        const formats = it.rest();
        return .{ .kind = kind, .port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidSdp, .protocol = protocol, .formats = formats };
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
        const session_ufrag = findAttr(session.attributes, "ice-ufrag");
        const session_password = findAttr(session.attributes, "ice-pwd");
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
                .ufrag = findAttr(selected.attributes, "ice-ufrag") orelse return error.MissingIceUfrag,
                .password = findAttr(selected.attributes, "ice-pwd") orelse return error.MissingIcePwd,
            };
        }

        return error.MissingIceUfrag;
    }

    pub fn extractIceCandidates(allocator: std.mem.Allocator, session: Session) Error![]IceCandidate {
        const media = candidateMediaWithIndex(session) orelse return allocator.alloc(IceCandidate, 0);
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
        if (protocol == null) {
            if (firstNonNumericFormat(media.formats)) |format| protocol = format;
        }

        return .{
            .port = port orelse return error.InvalidSdp,
            .max_message_size = try parseMaxMessageSize(findAttr(media.attributes, "max-message-size")),
            .max_channels = max_channels,
            .protocol = protocol orelse "webrtc-datachannel",
        };
    }

    pub fn extractRtpCodecs(allocator: std.mem.Allocator, media: Media) Error![]RtpCodec {
        var codecs: std.ArrayList(RtpCodec) = .empty;
        errdefer {
            for (codecs.items) |*codec| codec.deinit(allocator);
            codecs.deinit(allocator);
        }

        var payloads = std.mem.tokenizeAny(u8, media.formats, " \t");
        while (payloads.next()) |payload_token| {
            const payload_type = std.fmt.parseInt(u8, payload_token, 10) catch return error.InvalidSdp;
            const rtpmap = findPayloadAttribute(media.attributes, "rtpmap", payload_type) orelse return error.InvalidSdp;
            var codec = try parseRtpMap(payload_type, media.kind, rtpmap);
            errdefer codec.deinit(allocator);
            if (findPayloadAttribute(media.attributes, "fmtp", payload_type)) |fmtp| codec.fmtp = fmtp;
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

    pub fn findAttr(attrs: []const Attribute, name: []const u8) ?[]const u8 {
        for (attrs) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, name)) return attr.value;
        }
        return null;
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
        if (protocol.len == 0) return error.InvalidSdp;
        const max_channels_s = parts.next();
        if (parts.next() != null) return error.InvalidSdp;
        return .{
            .port = parseSctpPort(port_s) orelse return error.InvalidSdp,
            .protocol = protocol,
            .max_channels = if (max_channels_s) |value| std.fmt.parseInt(u16, value, 10) catch return error.InvalidSdp else null,
        };
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
            .mime_type = codec_name,
            .clock_rate = std.fmt.parseInt(u32, clock_s, 10) catch return error.InvalidSdp,
            .channels = if (channels_s) |channels| std.fmt.parseInt(u16, channels, 10) catch return error.InvalidSdp else defaultCodecChannels(media_kind),
        };
    }

    fn defaultCodecChannels(media_kind: []const u8) u16 {
        return if (std.ascii.eqlIgnoreCase(media_kind, "audio")) 1 else 0;
    }

    fn findPayloadAttribute(attrs: []const Attribute, name: []const u8, payload_type: u8) ?[]const u8 {
        for (attrs) |attr| {
            if (!std.ascii.eqlIgnoreCase(attr.name, name)) continue;
            var parts = std.mem.tokenizeAny(u8, attr.value, " \t");
            const payload_s = parts.next() orelse continue;
            const payload = std.fmt.parseInt(u8, payload_s, 10) catch continue;
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
                const payload = std.fmt.parseInt(u8, payload_s, 10) catch return error.InvalidSdp;
                if (payload != payload_type) continue;
            }
            const typ = parts.next() orelse return error.InvalidSdp;
            const parameter = parts.rest();
            try feedback.append(allocator, .{ .typ = typ, .parameter = std.mem.trim(u8, parameter, " \t") });
        }
        return feedback.toOwnedSlice(allocator);
    }

    fn parseMaxMessageSize(value: ?[]const u8) Error!u32 {
        const raw = value orelse return 0;
        if (raw.len == 0) return error.InvalidSdp;
        return std.fmt.parseInt(u32, raw, 10) catch return error.InvalidSdp;
    }

    fn dataChannelMedia(session: Session) ?Media {
        if (candidateMedia(session)) |media| {
            if (mediaLooksLikeDataChannel(media)) return media;
        }
        for (session.media) |media| {
            if (mediaLooksLikeDataChannel(media)) return media;
        }
        return null;
    }

    fn mediaLooksLikeDataChannel(media: Media) bool {
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

    fn firstNonNumericFormat(formats: []const u8) ?[]const u8 {
        var tokens = std.mem.tokenizeAny(u8, formats, " \t");
        while (tokens.next()) |token| {
            _ = std.fmt.parseInt(u16, token, 10) catch return token;
        }
        return null;
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
        const group = findAttr(session.attributes, "group") orelse return null;
        var parts = std.mem.tokenizeScalar(u8, group, ' ');
        const semantic = parts.next() orelse return null;
        if (!std.mem.eql(u8, semantic, "BUNDLE")) return null;
        return parts.next();
    }

    fn candidateMedia(session: Session) ?Media {
        if (candidateMediaWithIndex(session)) |indexed| return indexed.media;
        return null;
    }

    const IndexedMedia = struct {
        media: Media,
        index: u16,
    };

    fn candidateMediaWithIndex(session: Session) ?IndexedMedia {
        if (bundleId(session)) |bundle_id| {
            for (session.media, 0..) |media, index| {
                if (findAttr(media.attributes, "mid")) |mid| {
                    if (std.mem.eql(u8, mid, bundle_id)) return .{ .media = media, .index = @intCast(index) };
                }
            }
            return null;
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
};

pub const rtp = struct {
    pub const one_byte_header_extension_profile: u16 = 0xbede;
    pub const two_byte_header_extension_profile: u16 = 0x1000;

    pub const Extension = struct {
        profile: u16,
        data: []const u8,
    };

    pub const HeaderExtensionElement = struct {
        id: u8,
        data: []const u8,
    };

    pub const HeaderExtensionFormat = enum {
        one_byte,
        two_byte,
    };

    pub fn headerExtensionFormat(profile: u16) ?HeaderExtensionFormat {
        if (profile == one_byte_header_extension_profile) return .one_byte;
        if ((profile & 0xfff0) == two_byte_header_extension_profile) return .two_byte;
        return null;
    }

    pub fn parseHeaderExtensionElements(allocator: std.mem.Allocator, extension: Extension) Error![]HeaderExtensionElement {
        return switch (headerExtensionFormat(extension.profile) orelse return error.InvalidRtpPacket) {
            .one_byte => parseOneByteHeaderExtensions(allocator, extension.data),
            .two_byte => parseTwoByteHeaderExtensions(allocator, extension.data),
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
            const len = @as(usize, header & 0x0f) + 1;
            if (pos + len > data.len) return error.InvalidRtpPacket;
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
        if (value.len != 2) return error.InvalidRtpPacket;
        return std.mem.readInt(u16, value[0..2], .big);
    }

    pub fn absoluteSendTime24(elements: []const HeaderExtensionElement, id: u8) Error!?u24 {
        const value = findHeaderExtension(elements, id) orelse return null;
        if (value.len != 3) return error.InvalidRtpPacket;
        return (@as(u24, value[0]) << 16) | (@as(u24, value[1]) << 8) | value[2];
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
        _,
    };

    pub const transport_feedback_nack: u5 = 1;
    pub const transport_feedback_twcc: u5 = 15;
    pub const payload_feedback_pli: u5 = 1;
    pub const payload_feedback_fir: u5 = 4;
    pub const payload_feedback_remb: u5 = 15;
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
    };

    pub const SenderReport = struct {
        sender_ssrc: u32,
        ntp_timestamp_msw: u32,
        ntp_timestamp_lsw: u32,
        rtp_timestamp: u32,
        sender_packet_count: u32,
        sender_octet_count: u32,
        report_blocks: []ReportBlock = &.{},
    };

    pub const ReceiverReport = struct {
        sender_ssrc: u32,
        report_blocks: []ReportBlock = &.{},
    };

    pub const ReceiverEstimatedMaximumBitrate = struct {
        sender_ssrc: u32,
        bitrate: u64,
        ssrcs: []const u32 = &.{},

        pub fn deinit(self: *ReceiverEstimatedMaximumBitrate, allocator: std.mem.Allocator) void {
            allocator.free(@constCast(self.ssrcs));
            self.* = undefined;
        }
    };

    pub const Goodbye = struct {
        sources: []u32 = &.{},
        reason: []const u8 = &.{},

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
    };

    pub const SdesChunk = struct {
        ssrc: u32,
        items: []SdesItem,
    };

    pub const SourceDescription = struct {
        chunks: []SdesChunk,

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
    };

    pub const FirEntry = struct {
        ssrc: u32,
        sequence_number: u8,
    };

    pub const FullIntraRequest = struct {
        sender_ssrc: u32,
        media_ssrc: u32 = 0,
        entries: []FirEntry,

        pub fn deinit(self: *FullIntraRequest, allocator: std.mem.Allocator) void {
            allocator.free(self.entries);
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
    };

    pub const TransportLayerNack = struct {
        sender_ssrc: u32,
        media_ssrc: u32,
        pairs: []NackPair,
    };

    pub const TwccPacketStatus = enum(u2) {
        not_received = 0,
        small_delta = 1,
        large_delta = 2,
        reserved = 3,
    };

    pub const TwccPacketResult = struct {
        status: TwccPacketStatus,
        /// Raw delta units from the transport-cc wire format. One tick is
        /// 250 microseconds; keeping the raw tick preserves exact round-trips
        /// and lets congestion controllers choose their own time type.
        delta_ticks: i16 = 0,

        pub fn received(self: TwccPacketResult) bool {
            return self.status == .small_delta or self.status == .large_delta;
        }

        pub fn deltaMicros(self: TwccPacketResult) i32 {
            return @as(i32, self.delta_ticks) * 250;
        }
    };

    pub const TransportWideCc = struct {
        sender_ssrc: u32,
        media_ssrc: u32,
        base_sequence_number: u16,
        reference_time_64ms: u24,
        feedback_packet_count: u8,
        packets: []TwccPacketResult,

        pub fn deinit(self: *TransportWideCc, allocator: std.mem.Allocator) void {
            allocator.free(self.packets);
            self.* = undefined;
        }
    };

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

    pub const ReceiverStats = struct {
        ssrc: u32 = 0,
        clock_rate: u32 = 90_000,
        initialized: bool = false,
        base_seq: u16 = 0,
        max_seq: u16 = 0,
        cycles: u32 = 0,
        received: u32 = 0,
        expected_prior: u32 = 0,
        received_prior: u32 = 0,
        transit_prior: ?i64 = null,
        jitter_q4: u64 = 0,

        pub fn observe(self: *ReceiverStats, packet: rtp.Packet, arrival_time_ns: u64) void {
            const seq = packet.header.sequence_number;
            if (!self.initialized) {
                self.initialized = true;
                self.ssrc = packet.header.ssrc;
                self.base_seq = seq;
                self.max_seq = seq;
                self.received = 1;
                self.transit_prior = self.transit(packet.header.timestamp, arrival_time_ns);
                return;
            }

            if (seq < self.max_seq and self.max_seq - seq > 0x8000) self.cycles +%= 1;
            if (seqNewer(seq, self.max_seq)) self.max_seq = seq;
            self.received +|= 1;

            const transit_now = self.transit(packet.header.timestamp, arrival_time_ns);
            if (self.transit_prior) |prior| {
                const delta = @abs(transit_now - prior);
                if (delta > self.jitter_q4 >> 4) {
                    self.jitter_q4 += delta - (self.jitter_q4 >> 4);
                } else {
                    self.jitter_q4 -= (self.jitter_q4 >> 4) - delta;
                }
            }
            self.transit_prior = transit_now;
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

            const total_lost: i64 = @as(i64, expected) - @as(i64, self.received);
            const cumulative_lost: u24 = if (total_lost <= 0) 0 else @intCast(@min(@as(u64, std.math.maxInt(u24)), @as(u64, @intCast(total_lost))));
            return .{
                .ssrc = self.ssrc,
                .fraction_lost = fraction_lost,
                .cumulative_lost = cumulative_lost,
                .highest_sequence_number = self.extendedHighestSequenceNumber(),
                .interarrival_jitter = @intCast(@min(@as(u64, std.math.maxInt(u32)), self.jitter_q4 >> 4)),
            };
        }

        pub fn expectedPackets(self: ReceiverStats) u32 {
            if (!self.initialized) return 0;
            return self.extendedHighestSequenceNumber() - @as(u32, self.base_seq) + 1;
        }

        pub fn extendedHighestSequenceNumber(self: ReceiverStats) u32 {
            return self.cycles + @as(u32, self.max_seq);
        }

        fn transit(self: ReceiverStats, rtp_timestamp: u32, arrival_time_ns: u64) i64 {
            const arrival_rtp_units = (arrival_time_ns / std.time.ns_per_s) * self.clock_rate + ((arrival_time_ns % std.time.ns_per_s) * self.clock_rate) / std.time.ns_per_s;
            return @as(i64, @intCast(arrival_rtp_units)) - @as(i64, rtp_timestamp);
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

    pub const Unknown = struct {
        header: Header,
        payload: []const u8,
    };

    pub const Packet = union(enum) {
        sender_report: SenderReport,
        receiver_report: ReceiverReport,
        goodbye: Goodbye,
        source_description: SourceDescription,
        picture_loss_indication: PictureLossIndication,
        full_intra_request: FullIntraRequest,
        receiver_estimated_maximum_bitrate: ReceiverEstimatedMaximumBitrate,
        transport_layer_nack: TransportLayerNack,
        transport_wide_cc: TransportWideCc,
        unknown: Unknown,

        pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .sender_report => |report| allocator.free(report.report_blocks),
                .receiver_report => |report| allocator.free(report.report_blocks),
                .goodbye => |*goodbye| goodbye.deinit(allocator),
                .source_description => |*sdes| sdes.deinit(allocator),
                .full_intra_request => |*fir| fir.deinit(allocator),
                .receiver_estimated_maximum_bitrate => |*remb| remb.deinit(allocator),
                .transport_layer_nack => |nack| allocator.free(nack.pairs),
                .transport_wide_cc => |*twcc| twcc.deinit(allocator),
                else => {},
            }
            self.* = undefined;
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
            .payload_feedback => if (header.count_or_format == payload_feedback_pli)
                .{ .picture_loss_indication = try parsePictureLossIndication(payload) }
            else if (header.count_or_format == payload_feedback_fir)
                .{ .full_intra_request = try parseFullIntraRequest(allocator, payload) }
            else if (header.count_or_format == payload_feedback_remb)
                .{ .receiver_estimated_maximum_bitrate = try parseReceiverEstimatedMaximumBitrate(allocator, payload) }
            else
                .{ .unknown = .{ .header = header, .payload = payload } },
            .transport_feedback => if (header.count_or_format == transport_feedback_nack)
                .{ .transport_layer_nack = try parseTransportLayerNack(allocator, payload) }
            else if (header.count_or_format == transport_feedback_twcc)
                .{ .transport_wide_cc = try parseTransportWideCc(allocator, payload) }
            else
                .{ .unknown = .{ .header = header, .payload = payload } },
            else => .{ .unknown = .{ .header = header, .payload = payload } },
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
            .full_intra_request => |fir| try writeFullIntraRequest(list, allocator, fir),
            .receiver_estimated_maximum_bitrate => |remb| try writeReceiverEstimatedMaximumBitrate(list, allocator, remb),
            .transport_layer_nack => |nack| try writeTransportLayerNack(list, allocator, nack),
            .transport_wide_cc => |twcc| try writeTransportWideCc(list, allocator, twcc),
            .unknown => |unknown| {
                try writeHeader(list, allocator, unknown.header.count_or_format, unknown.header.packet_type, unknown.payload.len);
                try list.appendSlice(allocator, unknown.payload);
            },
        }
    }

    pub fn parseCompound(allocator: std.mem.Allocator, bytes: []const u8) Error![]Packet {
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
        try validateCompound(packets.items);
        return packets.toOwnedSlice(allocator);
    }

    pub fn freeCompound(allocator: std.mem.Allocator, packets: []Packet) void {
        for (packets) |*packet| packet.deinit(allocator);
        allocator.free(packets);
    }

    pub fn writeCompound(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packets: []const Packet) Error!void {
        try validateCompound(packets);
        for (packets) |packet| try writePacket(list, allocator, packet);
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
        if (payload.len != 24 + report_count * 24) return error.InvalidRtcpPacket;
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
        };
    }

    fn parseReceiverReport(allocator: std.mem.Allocator, header: Header, payload: []const u8) Error!ReceiverReport {
        const report_count = @as(usize, header.count_or_format);
        if (payload.len != 4 + report_count * 24) return error.InvalidRtcpPacket;
        var cursor = wire.Cursor.init(payload);
        const sender_ssrc = try cursor.readInt(u32, .big);
        return .{
            .sender_ssrc = sender_ssrc,
            .report_blocks = try parseReportBlocks(allocator, &cursor, report_count),
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

    fn parsePictureLossIndication(payload: []const u8) Error!PictureLossIndication {
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
        const bitrate = std.math.shlExact(u64, mantissa, exponent) catch return error.InvalidRtcpPacket;
        const ssrcs = try allocator.alloc(u32, num_ssrc);
        errdefer allocator.free(ssrcs);
        for (ssrcs) |*ssrc| ssrc.* = try cursor.readInt(u32, .big);
        return .{
            .sender_ssrc = sender_ssrc,
            .bitrate = bitrate,
            .ssrcs = ssrcs,
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
                .reserved => return error.InvalidRtcpPacket,
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
        try writeHeader(list, allocator, @intCast(report.report_blocks.len), .sender_report, 24 + report.report_blocks.len * 24);
        try wire.appendInt(list, allocator, u32, report.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, report.ntp_timestamp_msw, .big);
        try wire.appendInt(list, allocator, u32, report.ntp_timestamp_lsw, .big);
        try wire.appendInt(list, allocator, u32, report.rtp_timestamp, .big);
        try wire.appendInt(list, allocator, u32, report.sender_packet_count, .big);
        try wire.appendInt(list, allocator, u32, report.sender_octet_count, .big);
        for (report.report_blocks) |block| try writeReportBlock(list, allocator, block);
    }

    fn writeReceiverReport(list: *std.ArrayList(u8), allocator: std.mem.Allocator, report: ReceiverReport) Error!void {
        if (report.report_blocks.len > 31) return error.InvalidRtcpPacket;
        try writeHeader(list, allocator, @intCast(report.report_blocks.len), .receiver_report, 4 + report.report_blocks.len * 24);
        try wire.appendInt(list, allocator, u32, report.sender_ssrc, .big);
        for (report.report_blocks) |block| try writeReportBlock(list, allocator, block);
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

    fn writePictureLossIndication(list: *std.ArrayList(u8), allocator: std.mem.Allocator, pli: PictureLossIndication) Error!void {
        try writeHeader(list, allocator, payload_feedback_pli, .payload_feedback, 8);
        try wire.appendInt(list, allocator, u32, pli.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, pli.media_ssrc, .big);
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
        if (nack.pairs.len > (max_rtcp_payload_len - 8) / 4) return error.InvalidRtcpPacket;
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

        var run_status: ?TwccPacketStatus = null;
        var run_len: usize = 0;
        for (twcc.packets) |packet| {
            if (packet.status == .reserved) return error.InvalidRtcpPacket;
            if (run_status != null and packet.status == run_status.? and run_len < 0x1fff) {
                run_len += 1;
                continue;
            }
            if (run_status) |status| try writeTwccRunLengthChunk(&payload, allocator, status, run_len);
            run_status = packet.status;
            run_len = 1;
        }
        if (run_status) |status| try writeTwccRunLengthChunk(&payload, allocator, status, run_len);

        for (twcc.packets) |packet| {
            switch (packet.status) {
                .not_received => {},
                .small_delta => {
                    if (packet.delta_ticks < 0 or packet.delta_ticks > std.math.maxInt(u8)) return error.InvalidRtcpPacket;
                    try payload.append(allocator, @intCast(packet.delta_ticks));
                },
                .large_delta => try wire.appendInt(&payload, allocator, i16, packet.delta_ticks, .big),
                .reserved => unreachable,
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
        if ((payload_len % 4) != 0 or payload_len / 4 > std.math.maxInt(u16)) return error.InvalidRtcpPacket;
        try list.append(allocator, 0x80 | @as(u8, count_or_format));
        try list.append(allocator, @intFromEnum(packet_type));
        try wire.appendInt(list, allocator, u16, @intCast(payload_len / 4), .big);
    }

    fn appendTwccChunkStatuses(
        packets: *std.ArrayList(TwccPacketResult),
        allocator: std.mem.Allocator,
        chunk: u16,
        packet_status_count: usize,
    ) Error!void {
        if ((chunk & 0x8000) == 0) {
            const status: TwccPacketStatus = @enumFromInt((chunk >> 13) & 0x03);
            if (status == .reserved) return error.InvalidRtcpPacket;
            const run_len = chunk & 0x1fff;
            if (run_len == 0) return error.InvalidRtcpPacket;
            var i: usize = 0;
            while (i < run_len and packets.items.len < packet_status_count) : (i += 1) {
                try packets.append(allocator, .{ .status = status });
            }
            return;
        }

        const two_bit = (chunk & 0x4000) != 0;
        if (two_bit) {
            var i: usize = 0;
            while (i < 7 and packets.items.len < packet_status_count) : (i += 1) {
                const shift: u4 = @intCast(12 - 2 * i);
                const status: TwccPacketStatus = @enumFromInt((chunk >> shift) & 0x03);
                if (status == .reserved) return error.InvalidRtcpPacket;
                try packets.append(allocator, .{ .status = status });
            }
        } else {
            var i: usize = 0;
            while (i < 14 and packets.items.len < packet_status_count) : (i += 1) {
                const shift: u4 = @intCast(13 - i);
                const status: TwccPacketStatus = if (((chunk >> shift) & 0x01) != 0) .small_delta else .not_received;
                try packets.append(allocator, .{ .status = status });
            }
        }
    }

    fn writeTwccRunLengthChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, status: TwccPacketStatus, run_len: usize) Error!void {
        if (run_len == 0 or run_len > 0x1fff or status == .reserved) return error.InvalidRtcpPacket;
        const value = (@as(u16, @intFromEnum(status)) << 13) | @as(u16, @intCast(run_len));
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
            return .{
                .source_port = try cursor.readInt(u16, .big),
                .destination_port = try cursor.readInt(u16, .big),
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
                .data => .{
                    .immediate_sack = base.immediate_sack,
                    .unordered = base.unordered,
                    .beginning = base.beginning,
                    .ending = base.ending,
                    .tsn = base.tsn,
                    .stream_id = base.stream_id,
                    .stream_sequence_number = base.stream_sequence_number,
                    .payload_protocol_identifier = @enumFromInt(std.mem.readInt(u32, chunk.value[8..12], .big)),
                    .user_data = chunk.value[12..],
                },
                .i_data => blk: {
                    if (chunk.value.len < 16) return error.InvalidSctpPacket;
                    const mid = std.mem.readInt(u32, chunk.value[8..12], .big);
                    const ppid_or_fsn = std.mem.readInt(u32, chunk.value[12..16], .big);
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
                        .payload_protocol_identifier = if (base.beginning) @enumFromInt(ppid_or_fsn) else @enumFromInt(@as(u32, 0)),
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

    pub const HeartbeatChunk = struct {
        info: []const u8,

        pub fn parse(chunk: Chunk) Error!HeartbeatChunk {
            if ((chunk.chunk_type != .heartbeat and chunk.chunk_type != .heartbeat_ack) or chunk.flags != 0 or chunk.value.len == 0) return error.InvalidSctpPacket;
            return .{ .info = chunk.value };
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
                if (cursor.remaining() < 4) return error.InvalidSctpPacket;
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
                const padding = (4 - (len % 4)) % 4;
                if (cursor.remaining() < padding) return error.InvalidSctpPacket;
                try validateZeroPadding(cursor.buf[cursor.pos .. cursor.pos + padding]);
                try cursor.skip(padding);
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
    };

    pub const DataChannelOpen = struct {
        channel_type: DataChannelType = .reliable,
        priority: u16 = 0,
        reliability_parameter: u32 = 0,
        label: []const u8,
        protocol: []const u8 = &.{},
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
        if (verify_checksum and !try validChecksum(bytes)) return error.BadSctpChecksum;
        const header = try Header.parse(bytes[0..12]);

        var chunks: std.ArrayList(Chunk) = .empty;
        errdefer chunks.deinit(allocator);
        var pos: usize = 12;
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
        for (init.parameters) |parameter| try writeInitParameter(&value, allocator, parameter);
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
        if (info.len == 0) return error.InvalidSctpPacket;
        const chunk_len = 4 + info.len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(if (ack) ChunkType.heartbeat_ack else ChunkType.heartbeat));
        try list.append(allocator, 0);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
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

    pub fn writeReconfigChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, parameters: []const ReconfigParameter) Error!void {
        if (parameters.len == 0) return error.InvalidSctpPacket;
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(allocator);
        for (parameters) |parameter| try writeReconfigParameter(&value, allocator, parameter);
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
        try wire.appendInt(list, allocator, u16, options.source_port, .big);
        try wire.appendInt(list, allocator, u16, options.destination_port, .big);
        try wire.appendInt(list, allocator, u32, options.verification_tag, .big);
        try wire.appendInt(list, allocator, u32, 0, .little);
    }

    fn parseErrorCauses(allocator: std.mem.Allocator, bytes: []const u8) Error![]ErrorCause {
        var cursor = wire.Cursor.init(bytes);
        var causes: std.ArrayList(ErrorCause) = .empty;
        errdefer causes.deinit(allocator);
        while (!cursor.eof()) {
            if (cursor.remaining() < 4) return error.InvalidSctpPacket;
            const code: ErrorCauseCode = @enumFromInt(try cursor.readInt(u16, .big));
            const len = try cursor.readInt(u16, .big);
            if (len < 4 or cursor.remaining() < len - 4) return error.InvalidSctpPacket;
            const value = try cursor.readSlice(len - 4);
            try causes.append(allocator, .{ .code = code, .value = value });
            const padding = (4 - (len % 4)) % 4;
            if (cursor.remaining() < padding) return error.InvalidSctpPacket;
            try validateZeroPadding(cursor.buf[cursor.pos .. cursor.pos + padding]);
            try cursor.skip(padding);
        }
        return causes.toOwnedSlice(allocator);
    }

    fn writeErrorLikeChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunk_type: ChunkType, flags: u8, causes: []const ErrorCause) Error!void {
        if (chunk_type != .abort and chunk_type != .error_chunk) return error.InvalidSctpPacket;
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(allocator);
        for (causes) |cause| try writeErrorCause(&value, allocator, cause);
        const chunk_len = 4 + value.items.len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(chunk_type));
        try list.append(allocator, flags);
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try list.appendSlice(allocator, value.items);
        try list.appendNTimes(allocator, 0, align4(chunk_len) - chunk_len);
    }

    fn writeErrorCause(list: *std.ArrayList(u8), allocator: std.mem.Allocator, cause: ErrorCause) Error!void {
        const len = 4 + cause.value.len;
        if (len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try wire.appendInt(list, allocator, u16, @intFromEnum(cause.code), .big);
        try wire.appendInt(list, allocator, u16, @intCast(len), .big);
        try list.appendSlice(allocator, cause.value);
        try list.appendNTimes(allocator, 0, align4(len) - len);
    }

    fn parseInitParameters(allocator: std.mem.Allocator, bytes: []const u8) Error![]InitParameter {
        var cursor = wire.Cursor.init(bytes);
        var params: std.ArrayList(InitParameter) = .empty;
        errdefer params.deinit(allocator);
        while (!cursor.eof()) {
            if (cursor.remaining() < 4) return error.InvalidSctpPacket;
            const raw_type = try cursor.readInt(u16, .big);
            const param_type: InitParameterType = @enumFromInt(raw_type);
            const len = try cursor.readInt(u16, .big);
            if (len < 4 or cursor.remaining() < len - 4) return error.InvalidSctpPacket;
            const value = try cursor.readSlice(len - 4);
            if (knownInitParameter(param_type)) {
                try params.append(allocator, .{ .param_type = param_type, .value = value });
            } else {
                switch (raw_type & 0xc000) {
                    0x0000, 0x4000 => return error.InvalidSctpPacket,
                    0x8000, 0xc000 => {},
                    else => unreachable,
                }
            }
            const padding = (4 - (len % 4)) % 4;
            if (cursor.remaining() < padding) return error.InvalidSctpPacket;
            try validateZeroPadding(cursor.buf[cursor.pos .. cursor.pos + padding]);
            try cursor.skip(padding);
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

    fn writeInitParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, parameter: InitParameter) Error!void {
        const len = 4 + parameter.value.len;
        if (len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try wire.appendInt(list, allocator, u16, @intFromEnum(parameter.param_type), .big);
        try wire.appendInt(list, allocator, u16, @intCast(len), .big);
        try list.appendSlice(allocator, parameter.value);
        try list.appendNTimes(allocator, 0, align4(len) - len);
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

    fn writeReconfigParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, parameter: ReconfigParameter) Error!void {
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
        try list.appendNTimes(allocator, 0, align4(len) - len);
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

    fn validateZeroPadding(bytes: []const u8) Error!void {
        for (bytes) |byte| {
            if (byte != 0) return error.InvalidSctpPacket;
        }
    }

    pub fn dataChannelPayloadProtocol(is_string: bool, len: usize) PayloadProtocolIdentifier {
        if (is_string) return if (len == 0) .webrtc_string_empty else .webrtc_string;
        return if (len == 0) .webrtc_binary_empty else .webrtc_binary;
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
        try list.append(allocator, 0x02); // DATA_CHANNEL_ACK
    }

    pub fn parseDcepMessage(bytes: []const u8) Error!DataChannelMessage {
        if (bytes.len == 0) return error.InvalidSctpPacket;
        return switch (bytes[0]) {
            0x02 => blk: {
                if (bytes.len != 1) return error.InvalidSctpPacket;
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

fn appendFmt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    var tmp: [256]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&tmp, fmt, args);
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
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), try stun.attrU64(parsed, .ice_controlling));
    try std.testing.expect(stun.attrValue(parsed, .use_candidate) != null);

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
    const line = "candidate:1 1 UDP 2130706431 192.0.2.1 54400 typ host";
    const candidate = try ice.Candidate.parse(line);
    try std.testing.expectEqual(ice.CandidateType.host, candidate.candidate_type);
    try std.testing.expectEqual(@as(u16, 54400), candidate.port);

    const tcp = try ice.Candidate.parse("candidate:1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active");
    try std.testing.expectEqual(ice.Transport.tcp, tcp.transport);
    try std.testing.expectEqualStrings("active", tcp.tcp_type.?);

    const relay = try ice.Candidate.parse("candidate:848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 5001");
    try std.testing.expectEqual(ice.CandidateType.relay, relay.candidate_type);
    try std.testing.expectEqualStrings("192.168.0.1", relay.related_address.?);
    try std.testing.expectEqual(@as(u16, 5001), relay.related_port.?);

    var extended = try ice.Candidate.parseOwned(allocator, "candidate:4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10");
    defer extended.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), extended.extensions.len);
    try std.testing.expectEqualStrings("generation", extended.extensions[0].key);
    try std.testing.expectEqualStrings("0", extended.extensions[0].value);
    try std.testing.expectEqualStrings("network-cost", extended.extensions[2].key);
    try std.testing.expectEqualStrings("10", extended.extensions[2].value);
    var extended_line: std.ArrayList(u8) = .empty;
    defer extended_line.deinit(allocator);
    try extended.write(&extended_line, allocator);
    try std.testing.expectEqualStrings(
        "candidate:4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10",
        extended_line.items,
    );

    const mdns = try ice.Candidate.parse("candidate:1380287402 1 udp 2130706431 e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local 60542 typ host");
    try std.testing.expectEqualStrings("e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local", mdns.address);

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

    const text = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:0\r\n";
    var session = try sdp.parse(allocator, text);
    defer session.deinit(allocator);
    try std.testing.expectEqualStrings("BUNDLE 0", session.attributes[0].value);
    try std.testing.expectEqualStrings("application", session.media[0].kind);
    try std.testing.expectEqualStrings("mid", session.media[0].attributes[0].name);
}

test "SDP extracts DTLS fingerprint ICE credentials and RTP extmaps" {
    const allocator = std.testing.allocator;
    const text =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
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
        "a=fingerprint:sha-256 01:23:45:67:89:AB:CD:EF:FE:DC:BA:98:76:54:32:10:11:33:55:77:99:BB:DD:FF:00:22:44:66:88:AA:CC:EE\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=max-message-size:262144\r\n" ++
        "a=extmap-allow-mixed\r\n" ++
        "a=extmap:3/recvonly " ++ sdp.transport_cc_uri ++ " appdata\r\n" ++
        "a=extmap:4 " ++ sdp.sdes_mid_uri ++ "\r\n";
    var session = try sdp.parse(allocator, text);
    defer session.deinit(allocator);

    const fingerprint = try sdp.extractFingerprint(session);
    try std.testing.expectEqualStrings("sha-256", fingerprint.algorithm);
    try std.testing.expectEqualStrings("11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:10:20:30:40:50:60:70:80:90:A0:B0:C0:D0:E0:F0:01", fingerprint.value);

    const creds = try sdp.extractIceCredentials(session);
    try std.testing.expectEqualStrings("bundle-ufrag", creds.ufrag);
    try std.testing.expectEqualStrings("bundle-pwd", creds.password);

    try std.testing.expect(sdp.extMapAllowMixed(session));
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

    const parsed_extmap = try sdp.parseExtMapAttribute("7/inactive urn:example:ext attrs");
    try std.testing.expectEqual(@as(u16, 7), parsed_extmap.id);
    try std.testing.expectEqual(sdp.ExtMapDirection.inactive, parsed_extmap.direction);
    try std.testing.expectEqualStrings("urn:example:ext", parsed_extmap.uri);
    try std.testing.expectEqualStrings("attrs", parsed_extmap.extension_attributes);

    try std.testing.expectError(error.InvalidSdp, sdp.parseExtMapAttribute("0 " ++ sdp.sdes_mid_uri));

    const codec_text =
        "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n" ++
        "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
        "a=rtcp-fb:111 goog-remb\r\n" ++
        "a=rtcp-fb:111 ccm fir\r\n" ++
        "a=rtcp-fb:* nack\r\n";
    var codec_session = try sdp.parse(allocator, codec_text);
    defer codec_session.deinit(allocator);
    const codecs = try sdp.extractRtpCodecs(allocator, codec_session.media[0]);
    defer sdp.freeRtpCodecs(allocator, codecs);
    try std.testing.expectEqual(@as(usize, 1), codecs.len);
    try std.testing.expectEqual(@as(u8, 111), codecs[0].payload_type);
    try std.testing.expectEqualStrings("opus", codecs[0].mime_type);
    try std.testing.expectEqual(@as(u32, 48000), codecs[0].clock_rate);
    try std.testing.expectEqual(@as(u16, 2), codecs[0].channels);
    try std.testing.expectEqualStrings("minptime=10;useinbandfec=1", codecs[0].fmtp);
    try std.testing.expectEqual(@as(usize, 3), codecs[0].rtcp_feedback.len);
    try std.testing.expectEqualStrings("goog-remb", codecs[0].rtcp_feedback[0].typ);
    try std.testing.expectEqualStrings("", codecs[0].rtcp_feedback[0].parameter);
    try std.testing.expectEqualStrings("ccm", codecs[0].rtcp_feedback[1].typ);
    try std.testing.expectEqualStrings("fir", codecs[0].rtcp_feedback[1].parameter);
    try std.testing.expectEqualStrings("nack", codecs[0].rtcp_feedback[2].typ);

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
        "a=candidate:1 1 udp 2122162783 192.168.84.254 46492 typ host generation 0 network-id 2\r\n" ++
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
    try std.testing.expectEqual(@as(usize, 2), ice_details.candidates[0].candidate.extensions.len);
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
    try std.testing.expectEqual(@as(u32, 0), legacy_sctp.max_message_size);
    try std.testing.expectEqual(@as(?u16, 256), legacy_sctp.max_channels);
    try std.testing.expectEqualStrings("webrtc-datachannel", legacy_sctp.protocol);
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
}

test "RTP packet extension padding and writer" {
    const allocator = std.testing.allocator;
    var one_byte_extensions: std.ArrayList(u8) = .empty;
    defer one_byte_extensions.deinit(allocator);
    try rtp.writeOneByteHeaderExtensions(&one_byte_extensions, allocator, &.{
        .{ .id = 1, .data = "m" },
        .{ .id = 3, .data = &.{ 0x12, 0x34 } },
        .{ .id = 4, .data = &.{ 0x01, 0x02, 0x03 } },
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
    try std.testing.expectEqual(@as(?u24, 0x010203), try rtp.absoluteSendTime24(parsed_extensions, 4));
    try std.testing.expectEqualStrings("opus", packet.payload);
    try std.testing.expectEqual(@as(u8, 4), packet.padding_len);

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
    const parsed = try rtcp.parseCompound(allocator, encoded.items);
    defer rtcp.freeCompound(allocator, parsed);
    try std.testing.expectEqual(@as(usize, 4), parsed.len);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed[0].receiver_report.sender_ssrc);
    try std.testing.expectEqualStrings("alice@example.test", parsed[1].source_description.cname(0x01020304).?);
    try std.testing.expectEqual(@as(u32, 0x11121314), parsed[2].picture_loss_indication.media_ssrc);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed[3].goodbye.sources[0]);
    try std.testing.expectEqualStrings("done", parsed[3].goodbye.reason);

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
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writeCompound(&encoded, allocator, &.{
        .{ .picture_loss_indication = .{ .sender_ssrc = 1, .media_ssrc = 2 } },
    }));

    var no_cname_items = [_]rtcp.SdesItem{.{ .item_type = .name, .value = "alice" }};
    var no_cname_chunks = [_]rtcp.SdesChunk{.{ .ssrc = 0x01020304, .items = &no_cname_items }};
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writeCompound(&encoded, allocator, &.{
        .{ .receiver_report = .{ .sender_ssrc = 0x01020304 } },
        .{ .source_description = .{ .chunks = &no_cname_chunks } },
    }));

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
    } });
    var rr = try rtcp.parsePacket(allocator, encoded.items);
    defer rr.deinit(allocator);
    try std.testing.expectEqual(@as(usize, encoded.items.len), rr.consumed);
    try std.testing.expectEqual(@as(u32, 0x0a0b0c0d), rr.packet.receiver_report.sender_ssrc);
    try std.testing.expectEqual(@as(u24, 3), rr.packet.receiver_report.report_blocks[0].cumulative_lost);
    try std.testing.expectEqual(@as(u32, 44), rr.packet.receiver_report.report_blocks[0].interarrival_jitter);

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
    const too_many_nacks = try allocator.alloc(rtcp.NackPair, (((@as(usize, std.math.maxInt(u16)) * 4) - 8) / 4) + 1);
    defer allocator.free(too_many_nacks);
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.writePacket(&encoded, allocator, .{ .transport_layer_nack = .{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .pairs = too_many_nacks,
    } }));

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

    encoded.items[8] = 1; // REMB media SSRC must be zero.
    try std.testing.expectError(error.InvalidRtcpPacket, rtcp.parsePacket(allocator, encoded.items));
}

test "RTCP transport-wide congestion feedback" {
    const allocator = std.testing.allocator;
    var packet_results = [_]rtcp.TwccPacketResult{
        .{ .status = .small_delta, .delta_ticks = 4 },
        .{ .status = .not_received },
        .{ .status = .large_delta, .delta_ticks = -3 },
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
    try std.testing.expectEqual(@as(u8, 7), parsed.packet.transport_wide_cc.feedback_packet_count);
    try std.testing.expectEqual(@as(usize, 4), parsed.packet.transport_wide_cc.packets.len);
    try std.testing.expect(parsed.packet.transport_wide_cc.packets[0].received());
    try std.testing.expectEqual(@as(i32, 1000), parsed.packet.transport_wide_cc.packets[0].deltaMicros());
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, parsed.packet.transport_wide_cc.packets[1].status);
    try std.testing.expectEqual(@as(i16, -3), parsed.packet.transport_wide_cc.packets[2].delta_ticks);

    // Also parse a hand-built status-vector chunk.  The writer intentionally
    // emits simple run-length chunks for predictable output; receivers still
    // need to accept the more compact one-/two-bit vector chunks that browser
    // stacks and Pion's TWCC interceptor commonly generate.
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
    const two_bit_vector: u16 =
        0xc000 | // T=1 status-vector, S=1 two-bit symbols.
        (@as(u16, @intFromEnum(rtcp.TwccPacketStatus.small_delta)) << 12) |
        (@as(u16, @intFromEnum(rtcp.TwccPacketStatus.not_received)) << 10) |
        (@as(u16, @intFromEnum(rtcp.TwccPacketStatus.large_delta)) << 8) |
        (@as(u16, @intFromEnum(rtcp.TwccPacketStatus.small_delta)) << 6);
    try wire.appendInt(&vector_encoded, allocator, u16, two_bit_vector, .big);
    try vector_encoded.append(allocator, 8);
    try wire.appendInt(&vector_encoded, allocator, i16, -2, .big);
    try vector_encoded.append(allocator, 1);
    try vector_encoded.appendNTimes(allocator, 0, 2);

    var parsed_vector = try rtcp.parsePacket(allocator, vector_encoded.items);
    defer parsed_vector.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 700), parsed_vector.packet.transport_wide_cc.base_sequence_number);
    try std.testing.expectEqual(@as(usize, 4), parsed_vector.packet.transport_wide_cc.packets.len);
    try std.testing.expectEqual(@as(i16, 8), parsed_vector.packet.transport_wide_cc.packets[0].delta_ticks);
    try std.testing.expectEqual(rtcp.TwccPacketStatus.not_received, parsed_vector.packet.transport_wide_cc.packets[1].status);
    try std.testing.expectEqual(@as(i16, -2), parsed_vector.packet.transport_wide_cc.packets[2].delta_ticks);
    try std.testing.expectEqual(@as(i16, 1), parsed_vector.packet.transport_wide_cc.packets[3].delta_ticks);
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
}

test "RTCP NACK tracker detects RTP gaps and wraparound" {
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

    encoded.items[encoded.items.len - 1] = 0xff; // non-zero ERROR cause padding
    std.mem.writeInt(u32, encoded.items[8..12], 0, .little);
    const repaired_error_checksum = try sctp.checksum(encoded.items);
    std.mem.writeInt(u32, encoded.items[8..12], repaired_error_checksum, .little);
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

    try std.testing.expectError(error.InvalidSctpPacket, sctp.writeHeartbeatChunk(&encoded, allocator, false, ""));
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
    var params = [_]sctp.InitParameter{
        .{ .param_type = .state_cookie, .value = cookie },
        .{ .param_type = .supported_extensions, .value = &extensions },
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
    const parsed_cookie = try allocator.dupe(u8, init_ack.stateCookie().?);
    defer allocator.free(parsed_cookie);

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
    try std.testing.expectEqual(@as(usize, 3), parsed_padded.chunks[0].value.len);

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
        .unordered = true,
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
    try std.testing.expect(data.unordered);
    try std.testing.expect(data.beginning);
    try std.testing.expect(data.ending);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_dcep, data.payload_protocol_identifier);
    const dcep = try sctp.parseDcepMessage(data.user_data);
    try std.testing.expectEqual(sctp.DataChannelType.partial_reliable_retransmit_unordered, dcep.open.channel_type);
    try std.testing.expectEqual(@as(u32, 3), dcep.open.reliability_parameter);
    try std.testing.expectEqualStrings("chat", dcep.open.label);
    try std.testing.expectEqualStrings("json", dcep.open.protocol);

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
    try std.testing.expect(try sctp.parseDcepMessage(ack.items) == .ack);
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_string_empty, sctp.dataChannelPayloadProtocol(true, 0));
    try std.testing.expectEqual(sctp.PayloadProtocolIdentifier.webrtc_binary, sctp.dataChannelPayloadProtocol(false, 4));

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
