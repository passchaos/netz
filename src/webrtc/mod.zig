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
    InvalidSctpPacket,
    BadSctpChecksum,
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
        if (bytes.len < 20 + @as(usize, len)) return error.BufferTooShort;
        const decoded_type = decodeType(typ);
        var attr_cursor = wire.Cursor.init(bytes[20 .. 20 + @as(usize, len)]);
        var attrs: std.ArrayList(Attribute) = .empty;
        errdefer attrs.deinit(allocator);
        while (!attr_cursor.eof()) {
            const attr_type: AttributeType = @enumFromInt(try attr_cursor.readInt(u16, .big));
            const attr_len = try attr_cursor.readInt(u16, .big);
            const value = try attr_cursor.readSlice(attr_len);
            const padding = (@as(usize, 4) - (attr_len % 4)) % 4;
            try attr_cursor.skip(padding);
            try attrs.append(allocator, .{ .attr_type = attr_type, .value = value });
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
        for (attrs) |attr| {
            try wire.appendInt(&payload, allocator, u16, @intFromEnum(attr.attr_type), .big);
            try wire.appendInt(&payload, allocator, u16, @intCast(attr.value.len), .big);
            try payload.appendSlice(allocator, attr.value);
            const padding = (4 - (attr.value.len % 4)) % 4;
            try payload.appendNTimes(allocator, 0, padding);
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

    pub fn validateFingerprint(bytes: []const u8) Error!void {
        const located = (try findAttributeBytes(bytes, .fingerprint)) orelse return error.MissingStunAttribute;
        if (located.value.len != fingerprint_len) return error.InvalidStunAttribute;
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

        pub fn parse(line: []const u8) Error!Candidate {
            const prefix = "candidate:";
            const body = if (std.mem.startsWith(u8, line, "a=")) line[2..] else line;
            if (!std.mem.startsWith(u8, body, prefix)) return error.InvalidIceCandidate;
            var it = std.mem.tokenizeScalar(u8, body[prefix.len..], ' ');
            const foundation = it.next() orelse return error.InvalidIceCandidate;
            const component_s = it.next() orelse return error.InvalidIceCandidate;
            const transport_s = it.next() orelse return error.InvalidIceCandidate;
            const priority_s = it.next() orelse return error.InvalidIceCandidate;
            const address = it.next() orelse return error.InvalidIceCandidate;
            const port_s = it.next() orelse return error.InvalidIceCandidate;
            const typ_label = it.next() orelse return error.InvalidIceCandidate;
            if (!std.mem.eql(u8, typ_label, "typ")) return error.InvalidIceCandidate;
            const typ_s = it.next() orelse return error.InvalidIceCandidate;

            var candidate: Candidate = .{
                .foundation = foundation,
                .component = std.fmt.parseInt(u16, component_s, 10) catch return error.InvalidIceCandidate,
                .transport = if (std.ascii.eqlIgnoreCase(transport_s, "udp")) .udp else if (std.ascii.eqlIgnoreCase(transport_s, "tcp")) .tcp else return error.InvalidIceCandidate,
                .priority = std.fmt.parseInt(u32, priority_s, 10) catch return error.InvalidIceCandidate,
                .address = address,
                .port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidIceCandidate,
                .candidate_type = parseCandidateType(typ_s) orelse return error.InvalidIceCandidate,
            };

            while (it.next()) |key| {
                const value = it.next() orelse return error.InvalidIceCandidate;
                if (std.mem.eql(u8, key, "raddr")) candidate.related_address = value else if (std.mem.eql(u8, key, "rport")) candidate.related_port = std.fmt.parseInt(u16, value, 10) catch return error.InvalidIceCandidate else if (std.mem.eql(u8, key, "tcptype")) candidate.tcp_type = value;
            }
            return candidate;
        }

        pub fn write(self: Candidate, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
            try list.appendSlice(allocator, "candidate:");
            try list.appendSlice(allocator, self.foundation);
            try appendFmt(list, allocator, " {} {} {} {} {} typ {s}", .{
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
        }
    };

    fn parseCandidateType(value: []const u8) ?CandidateType {
        inline for (std.meta.fields(CandidateType)) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
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
        var ufrag = findAttr(session.attributes, "ice-ufrag");
        var password = findAttr(session.attributes, "ice-pwd");

        if (ufrag == null or password == null) {
            const media = candidateMedia(session);
            if (media) |selected| {
                if (ufrag == null) ufrag = findAttr(selected.attributes, "ice-ufrag");
                if (password == null) password = findAttr(selected.attributes, "ice-pwd");
            }
        }

        return .{
            .ufrag = ufrag orelse return error.MissingIceUfrag,
            .password = password orelse return error.MissingIcePwd,
        };
    }

    pub fn findAttr(attrs: []const Attribute, name: []const u8) ?[]const u8 {
        for (attrs) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, name)) return attr.value;
        }
        return null;
    }

    fn parseFingerprint(raw: []const u8) Error!Fingerprint {
        var parts = std.mem.splitScalar(u8, raw, ' ');
        const algorithm = parts.next() orelse return error.InvalidFingerprint;
        const value = parts.next() orelse return error.InvalidFingerprint;
        if (algorithm.len == 0 or value.len == 0 or parts.next() != null) return error.InvalidFingerprint;
        return .{ .algorithm = algorithm, .value = value };
    }

    fn bundleId(session: Session) ?[]const u8 {
        const group = findAttr(session.attributes, "group") orelse return null;
        var parts = std.mem.tokenizeScalar(u8, group, ' ');
        const semantic = parts.next() orelse return null;
        if (!std.mem.eql(u8, semantic, "BUNDLE")) return null;
        return parts.next();
    }

    fn candidateMedia(session: Session) ?Media {
        if (bundleId(session)) |bundle_id| {
            for (session.media) |media| {
                if (findAttr(media.attributes, "mid")) |mid| {
                    if (std.mem.eql(u8, mid, bundle_id)) return media;
                }
            }
            return null;
        }
        return if (session.media.len > 0) session.media[0] else null;
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
    pub const Extension = struct {
        profile: u16,
        data: []const u8,
    };

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
            try wire.appendInt(list, allocator, u16, extension.profile, .big);
            try wire.appendInt(list, allocator, u16, @intCast(extension.data.len / 4), .big);
            try list.appendSlice(allocator, extension.data);
        }
        try list.appendSlice(allocator, payload);
        if (options.padding_len > 0) {
            try list.appendNTimes(allocator, 0, options.padding_len - 1);
            try list.append(allocator, options.padding_len);
        }
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
    pub const payload_feedback_pli: u5 = 1;

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

    pub const PictureLossIndication = struct {
        sender_ssrc: u32,
        media_ssrc: u32,
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
        picture_loss_indication: PictureLossIndication,
        transport_layer_nack: TransportLayerNack,
        unknown: Unknown,

        pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .sender_report => |report| allocator.free(report.report_blocks),
                .receiver_report => |report| allocator.free(report.report_blocks),
                .transport_layer_nack => |nack| allocator.free(nack.pairs),
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
        const payload = bytes[4..packet_len];

        const packet: Packet = switch (header.packet_type) {
            .sender_report => .{ .sender_report = try parseSenderReport(allocator, header, payload) },
            .receiver_report => .{ .receiver_report = try parseReceiverReport(allocator, header, payload) },
            .payload_feedback => if (header.count_or_format == payload_feedback_pli)
                .{ .picture_loss_indication = try parsePictureLossIndication(payload) }
            else
                .{ .unknown = .{ .header = header, .payload = payload } },
            .transport_feedback => if (header.count_or_format == transport_feedback_nack)
                .{ .transport_layer_nack = try parseTransportLayerNack(allocator, payload) }
            else
                .{ .unknown = .{ .header = header, .payload = payload } },
            else => .{ .unknown = .{ .header = header, .payload = payload } },
        };
        return .{ .packet = packet, .consumed = packet_len };
    }

    pub fn writePacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet: Packet) Error!void {
        switch (packet) {
            .sender_report => |report| try writeSenderReport(list, allocator, report),
            .receiver_report => |report| try writeReceiverReport(list, allocator, report),
            .picture_loss_indication => |pli| try writePictureLossIndication(list, allocator, pli),
            .transport_layer_nack => |nack| try writeTransportLayerNack(list, allocator, nack),
            .unknown => |unknown| {
                try writeHeader(list, allocator, unknown.header.count_or_format, unknown.header.packet_type, unknown.payload.len);
                try list.appendSlice(allocator, unknown.payload);
            },
        }
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

    fn parsePictureLossIndication(payload: []const u8) Error!PictureLossIndication {
        if (payload.len != 8) return error.InvalidRtcpPacket;
        return .{
            .sender_ssrc = std.mem.readInt(u32, payload[0..4], .big),
            .media_ssrc = std.mem.readInt(u32, payload[4..8], .big),
        };
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

    fn writePictureLossIndication(list: *std.ArrayList(u8), allocator: std.mem.Allocator, pli: PictureLossIndication) Error!void {
        try writeHeader(list, allocator, payload_feedback_pli, .payload_feedback, 8);
        try wire.appendInt(list, allocator, u32, pli.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, pli.media_ssrc, .big);
    }

    fn writeTransportLayerNack(list: *std.ArrayList(u8), allocator: std.mem.Allocator, nack: TransportLayerNack) Error!void {
        try writeHeader(list, allocator, transport_feedback_nack, .transport_feedback, 8 + nack.pairs.len * 4);
        try wire.appendInt(list, allocator, u32, nack.sender_ssrc, .big);
        try wire.appendInt(list, allocator, u32, nack.media_ssrc, .big);
        for (nack.pairs) |pair| {
            try wire.appendInt(list, allocator, u16, pair.packet_id, .big);
            try wire.appendInt(list, allocator, u16, pair.lost_packet_bitmask, .big);
        }
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
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16,
        payload_protocol_identifier: PayloadProtocolIdentifier,
        user_data: []const u8,

        pub fn flags(self: DataChunk) u8 {
            return (if (self.unordered) @as(u8, 0x04) else 0) |
                (if (self.beginning) @as(u8, 0x02) else 0) |
                (if (self.ending) @as(u8, 0x01) else 0);
        }

        pub fn parse(chunk: Chunk) Error!DataChunk {
            if (chunk.chunk_type != .data) return error.InvalidSctpPacket;
            if ((chunk.flags & 0xf8) != 0 or chunk.value.len < 12) return error.InvalidSctpPacket;
            return .{
                .unordered = (chunk.flags & 0x04) != 0,
                .beginning = (chunk.flags & 0x02) != 0,
                .ending = (chunk.flags & 0x01) != 0,
                .tsn = std.mem.readInt(u32, chunk.value[0..4], .big),
                .stream_id = std.mem.readInt(u16, chunk.value[4..6], .big),
                .stream_sequence_number = std.mem.readInt(u16, chunk.value[6..8], .big),
                .payload_protocol_identifier = @enumFromInt(std.mem.readInt(u32, chunk.value[8..12], .big)),
                .user_data = chunk.value[12..],
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

    pub fn parsePacket(allocator: std.mem.Allocator, bytes: []const u8, verify_checksum: bool) Error!ParsedPacket {
        if (bytes.len < 12) return error.BufferTooShort;
        if (verify_checksum and !try validChecksum(bytes)) return error.BadSctpChecksum;
        const header = try Header.parse(bytes[0..12]);

        var chunks: std.ArrayList(Chunk) = .empty;
        errdefer chunks.deinit(allocator);
        var pos: usize = 12;
        while (pos < bytes.len) {
            if (bytes.len - pos < 4) return error.InvalidSctpPacket;
            const chunk_type: ChunkType = @enumFromInt(bytes[pos]);
            const flags = bytes[pos + 1];
            const len = std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big);
            if (len < 4 or bytes.len - pos < len) return error.InvalidSctpPacket;
            const padded_len = align4(len);
            if (bytes.len - pos < padded_len) return error.InvalidSctpPacket;
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

    pub fn writeDataPacket(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        options: PacketOptions,
        chunks: []const DataChunk,
    ) Error!void {
        if (chunks.len == 0) return error.InvalidSctpPacket;
        const start = list.items.len;
        try wire.appendInt(list, allocator, u16, options.source_port, .big);
        try wire.appendInt(list, allocator, u16, options.destination_port, .big);
        try wire.appendInt(list, allocator, u32, options.verification_tag, .big);
        try wire.appendInt(list, allocator, u32, 0, .little);
        for (chunks) |chunk| try writeDataChunk(list, allocator, chunk);

        // SCTP stores the CRC32C checksum in little-endian form and computes it
        // with the checksum field itself zeroed.  This mirrors the kernel SCTP
        // implementation's libcrc32c path and lets the codec catch corruption
        // before upper layers parse DCEP or user data.
        const value = try checksum(list.items[start..]);
        std.mem.writeInt(u32, list.items[start + 8 ..][0..4], value, .little);
    }

    pub fn writeDataChunk(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunk: DataChunk) Error!void {
        const value_len = 12 + chunk.user_data.len;
        const chunk_len = 4 + value_len;
        if (chunk_len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
        try list.append(allocator, @intFromEnum(ChunkType.data));
        try list.append(allocator, chunk.flags());
        try wire.appendInt(list, allocator, u16, @intCast(chunk_len), .big);
        try wire.appendInt(list, allocator, u32, chunk.tsn, .big);
        try wire.appendInt(list, allocator, u16, chunk.stream_id, .big);
        try wire.appendInt(list, allocator, u16, chunk.stream_sequence_number, .big);
        try wire.appendInt(list, allocator, u32, @intFromEnum(chunk.payload_protocol_identifier), .big);
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

    pub fn dataChannelPayloadProtocol(is_string: bool, len: usize) PayloadProtocolIdentifier {
        if (is_string) return if (len == 0) .webrtc_string_empty else .webrtc_string;
        return if (len == 0) .webrtc_binary_empty else .webrtc_binary;
    }

    pub fn writeDcepOpen(list: *std.ArrayList(u8), allocator: std.mem.Allocator, open: DataChannelOpen) Error!void {
        if (open.label.len > std.math.maxInt(u16) or open.protocol.len > std.math.maxInt(u16)) return error.InvalidSctpPacket;
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
                const priority = std.mem.readInt(u16, bytes[2..4], .big);
                const reliability_parameter = std.mem.readInt(u32, bytes[4..8], .big);
                const label_len = std.mem.readInt(u16, bytes[8..10], .big);
                const protocol_len = std.mem.readInt(u16, bytes[10..12], .big);
                const label_start: usize = 12;
                const protocol_start = label_start + @as(usize, label_len);
                const end = protocol_start + @as(usize, protocol_len);
                if (end != bytes.len) return error.InvalidSctpPacket;
                break :blk .{ .open = .{
                    .channel_type = channel_type,
                    .priority = priority,
                    .reliability_parameter = reliability_parameter,
                    .label = bytes[label_start..protocol_start],
                    .protocol = bytes[protocol_start..end],
                } };
            },
            else => error.InvalidSctpPacket,
        };
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

    encoded.items[encoded.items.len - 1] ^= 0xff;
    try std.testing.expectError(error.BadFingerprint, stun.validateFingerprint(encoded.items));
}

test "ICE candidate parser and SDP parser" {
    const allocator = std.testing.allocator;
    const line = "candidate:1 1 UDP 2130706431 192.0.2.1 54400 typ host";
    const candidate = try ice.Candidate.parse(line);
    try std.testing.expectEqual(ice.CandidateType.host, candidate.candidate_type);
    try std.testing.expectEqual(@as(u16, 54400), candidate.port);

    const text = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:0\r\n";
    var session = try sdp.parse(allocator, text);
    defer session.deinit(allocator);
    try std.testing.expectEqualStrings("BUNDLE 0", session.attributes[0].value);
    try std.testing.expectEqualStrings("application", session.media[0].kind);
    try std.testing.expectEqualStrings("mid", session.media[0].attributes[0].name);
}

test "SDP extracts DTLS fingerprint and ICE credentials" {
    const allocator = std.testing.allocator;
    const text =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=group:BUNDLE 1 0\r\n" ++
        "a=fingerprint:sha-256 SESSION-FINGERPRINT\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=mid:0\r\n" ++
        "a=ice-ufrag:wrong\r\n" ++
        "a=ice-pwd:wrong-pwd\r\n" ++
        "a=fingerprint:sha-256 AUDIO-FINGERPRINT\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=mid:1\r\n" ++
        "a=ice-ufrag:bundle-ufrag\r\n" ++
        "a=ice-pwd:bundle-pwd\r\n" ++
        "a=fingerprint:sha-256 BUNDLE-FINGERPRINT\r\n";
    var session = try sdp.parse(allocator, text);
    defer session.deinit(allocator);

    const fingerprint = try sdp.extractFingerprint(session);
    try std.testing.expectEqualStrings("sha-256", fingerprint.algorithm);
    try std.testing.expectEqualStrings("SESSION-FINGERPRINT", fingerprint.value);

    const creds = try sdp.extractIceCredentials(session);
    try std.testing.expectEqualStrings("bundle-ufrag", creds.ufrag);
    try std.testing.expectEqualStrings("bundle-pwd", creds.password);

    const media_only =
        "v=0\r\n" ++
        "o=- 0 0 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=mid:data\r\n" ++
        "a=ice-ufrag:media-ufrag\r\n" ++
        "a=ice-pwd:media-pwd\r\n" ++
        "a=fingerprint:sha-256 MEDIA-FINGERPRINT\r\n";
    var media_session = try sdp.parse(allocator, media_only);
    defer media_session.deinit(allocator);
    const media_fingerprint = try sdp.extractFingerprint(media_session);
    try std.testing.expectEqualStrings("MEDIA-FINGERPRINT", media_fingerprint.value);
    const media_creds = try sdp.extractIceCredentials(media_session);
    try std.testing.expectEqualStrings("media-ufrag", media_creds.ufrag);
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

    var missing_pwd = try sdp.parse(allocator, "v=0\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=ice-ufrag:ufrag\r\n");
    defer missing_pwd.deinit(allocator);
    try std.testing.expectError(error.MissingIcePwd, sdp.extractIceCredentials(missing_pwd));
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
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try rtp.writePacket(&encoded, allocator, .{
        .marker = true,
        .payload_type = 111,
        .sequence_number = 10,
        .timestamp = 99,
        .ssrc = 0x01020304,
        .extension = .{ .profile = 0xbede, .data = &.{ 0x10, 0x00, 0x00, 0x00 } },
        .padding_len = 4,
    }, "opus");

    var packet = try rtp.Packet.parse(allocator, encoded.items);
    defer packet.deinit(allocator);
    try std.testing.expect(packet.header.marker);
    try std.testing.expectEqual(@as(u7, 111), packet.header.payload_type);
    try std.testing.expectEqual(@as(u16, 0xbede), packet.extension.?.profile);
    try std.testing.expectEqualStrings("opus", packet.payload);
    try std.testing.expectEqual(@as(u8, 4), packet.padding_len);
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
}

test {
    _ = runtime;
}
