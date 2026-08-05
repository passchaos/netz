const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidStunMessage,
    InvalidStunAttribute,
    InvalidIceCandidate,
    InvalidSdp,
    InvalidDtlsRecord,
    InvalidRtpPacket,
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

pub const sctp = struct {
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
