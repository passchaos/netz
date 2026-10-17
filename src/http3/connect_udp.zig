//! RFC 9298 CONNECT-UDP protocol helpers.
//!
//! This module implements the standards-defined default URI Template,
//! Extended CONNECT metadata, Context ID framing, and a typed Context ID 0
//! session over Netz's generic HTTP Datagram association. Custom deployment
//! URI Templates remain an explicit application concern.

const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");
const capsule = @import("capsule.zig");
const capsule_session = @import("connect_udp/capsule_session.zig");
const session_module = @import("connect_udp/session.zig");
const template_module = @import("connect_udp/template.zig");

const net = std.Io.net;

pub fn Protocol(comptime Http3: type) type {
    return struct {
        pub const protocol = "connect-udp";
        pub const default_path_prefix = "/.well-known/masque/udp/";
        pub const udp_context_id: u62 = 0;
        pub const max_udp_payload_size: usize = 65_527;

        pub const Error = Http3.Error || wire.Error || template_module.Error || error{
            InvalidTarget,
            PayloadTooLarge,
            UnexpectedContextId,
        };
        pub const ContextDatagramError = wire.Error || error{
            PayloadTooLarge,
            UnexpectedContextId,
        };

        pub const UriTemplate = template_module.Template;
        pub const Variable = template_module.Variable;

        pub const Target = struct {
            host: []const u8,
            port: u16,

            pub fn validate(self: Target) error{InvalidTarget}!void {
                if (self.host.len == 0 or self.port == 0 or
                    std.mem.indexOfScalar(u8, self.host, '%') != null)
                {
                    return error.InvalidTarget;
                }
                if (std.mem.indexOfScalar(u8, self.host, ':') != null) {
                    _ = net.IpAddress.parseIp6(
                        self.host,
                        self.port,
                    ) catch return error.InvalidTarget;
                    return;
                }
                for (self.host) |byte| {
                    if (!isRegNameByte(byte)) return error.InvalidTarget;
                }
            }
        };

        pub const request_headers = [_]Http3.Qpack.HeaderField{
            .{ .name = ":protocol", .value = protocol },
            capsule.protocol_header,
        };

        pub const response_headers = [_]Http3.Qpack.HeaderField{
            capsule.protocol_header,
        };

        pub fn defaultPathLen(target: Target) Error!usize {
            try target.validate();
            var host_len: usize = 0;
            for (target.host) |byte| {
                host_len = std.math.add(
                    usize,
                    host_len,
                    if (isUnreserved(byte)) 1 else 3,
                ) catch return error.IntegerOverflow;
            }
            return std.math.add(
                usize,
                default_path_prefix.len + 2 + decimalLen(target.port),
                host_len,
            ) catch return error.IntegerOverflow;
        }

        /// Expand RFC 9298's default URI Template into caller storage.
        pub fn writeDefaultPath(
            out: []u8,
            target: Target,
        ) Error![]u8 {
            const needed = try defaultPathLen(target);
            if (out.len < needed) return error.BufferTooShort;
            @memcpy(out[0..default_path_prefix.len], default_path_prefix);
            var offset = default_path_prefix.len;
            const hex = "0123456789ABCDEF";
            for (target.host) |byte| {
                if (isUnreserved(byte)) {
                    out[offset] = byte;
                    offset += 1;
                } else {
                    out[offset] = '%';
                    out[offset + 1] = hex[byte >> 4];
                    out[offset + 2] = hex[byte & 0x0f];
                    offset += 3;
                }
            }
            out[offset] = '/';
            offset += 1;
            const port = std.fmt.bufPrint(out[offset..], "{d}", .{
                target.port,
            }) catch return error.BufferTooShort;
            offset += port.len;
            out[offset] = '/';
            offset += 1;
            std.debug.assert(offset == needed);
            return out[0..offset];
        }

        /// Parse a path produced by the RFC 9298 default URI Template.
        /// `Target.host` borrows `host_out`.
        pub fn parseDefaultPath(
            path: []const u8,
            host_out: []u8,
        ) error{ BufferTooShort, InvalidTarget }!Target {
            if (!std.mem.startsWith(u8, path, default_path_prefix) or
                path.len <= default_path_prefix.len + 2 or
                path[path.len - 1] != '/')
            {
                return error.InvalidTarget;
            }
            const value = path[default_path_prefix.len .. path.len - 1];
            const slash = std.mem.indexOfScalar(u8, value, '/') orelse
                return error.InvalidTarget;
            if (slash == 0 or slash + 1 >= value.len or
                std.mem.indexOfScalar(u8, value[slash + 1 ..], '/') != null)
            {
                return error.InvalidTarget;
            }
            const encoded_host = value[0..slash];
            var host_len: usize = 0;
            var index: usize = 0;
            while (index < encoded_host.len) {
                const decoded = if (encoded_host[index] == '%') blk: {
                    if (index + 2 >= encoded_host.len) {
                        return error.InvalidTarget;
                    }
                    const high = hexValue(encoded_host[index + 1]) orelse
                        return error.InvalidTarget;
                    const low = hexValue(encoded_host[index + 2]) orelse
                        return error.InvalidTarget;
                    index += 3;
                    break :blk (high << 4) | low;
                } else blk: {
                    const byte = encoded_host[index];
                    if (!isUnreserved(byte)) return error.InvalidTarget;
                    index += 1;
                    break :blk byte;
                };
                if (host_len >= host_out.len) return error.BufferTooShort;
                host_out[host_len] = decoded;
                host_len += 1;
            }
            const port_text = value[slash + 1 ..];
            for (port_text) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidTarget;
            }
            const port = std.fmt.parseUnsigned(u16, port_text, 10) catch
                return error.InvalidTarget;
            const target = Target{
                .host = host_out[0..host_len],
                .port = port,
            };
            try target.validate();
            return target;
        }

        pub fn requestInto(
            path_out: []u8,
            target: Target,
            authority: []const u8,
        ) Error!Http3.Request {
            const path = try writeDefaultPath(path_out, target);
            const request = Http3.Request{
                .method = "CONNECT",
                .path = path,
                .scheme = "https",
                .authority = authority,
                .headers = &request_headers,
            };
            try request.validateForContext(.direct);
            return request;
        }

        pub fn requestWithTemplateInto(
            path_out: []u8,
            template: UriTemplate,
            target: Target,
            variables: []const Variable,
        ) Error!Http3.Request {
            try target.validate();
            if (!std.mem.eql(u8, template.scheme, "https")) {
                return error.InvalidUriTemplate;
            }
            const path = try template.expandRequestTargetInto(
                path_out,
                target.host,
                target.port,
                variables,
            );
            const request = Http3.Request{
                .method = "CONNECT",
                .path = path,
                .scheme = template.scheme,
                .authority = template.authority,
                .headers = &request_headers,
            };
            try request.validateForContext(.direct);
            return request;
        }

        pub fn validateDefaultRequest(
            request: Http3.Request,
            host_out: []u8,
        ) Error!Target {
            try request.validateForContext(.direct);
            if (request.body.len != 0 or request.trailers.len != 0) {
                return error.InvalidHeader;
            }
            try validateRequestFields(
                request.method,
                request.path,
                request.scheme,
                request.authority,
                request.headers,
            );
            return parseDefaultPath(request.path, host_out);
        }

        pub fn validateDecodedDefaultRequest(
            request: Http3.DecodedRequestHead,
            host_out: []u8,
        ) Error!Target {
            if (request.content_length != null) return error.InvalidHeader;
            try validateDecodedRequest(request);
            return parseDefaultPath(request.path, host_out);
        }

        pub fn validateDecodedRequest(
            request: Http3.DecodedRequestHead,
        ) Error!void {
            if (request.content_length != null) return error.InvalidHeader;
            return validateRequestFields(
                request.method,
                request.path,
                request.scheme,
                request.authority,
                request.headers,
            );
        }

        pub fn validateRequestFields(
            method: []const u8,
            path: []const u8,
            scheme: []const u8,
            authority: ?[]const u8,
            headers: anytype,
        ) error{InvalidHeader}!void {
            if (!std.mem.eql(u8, method, "CONNECT") or
                !std.mem.eql(u8, scheme, "https") or
                path.len == 0 or path[0] != '/' or
                authority == null or authority.?.len == 0)
            {
                return error.InvalidHeader;
            }
            var protocols: usize = 0;
            for (headers) |header| {
                if (std.mem.eql(u8, header.name, ":protocol")) {
                    protocols += 1;
                    if (!std.mem.eql(u8, header.value, protocol)) {
                        return error.InvalidHeader;
                    }
                }
                if (std.ascii.eqlIgnoreCase(
                    header.name,
                    "content-length",
                )) return error.InvalidHeader;
            }
            if (protocols != 1 or
                !try capsule.protocolEnabled(headers))
            {
                return error.InvalidHeader;
            }
        }

        pub fn successResponse() Http3.Response {
            return .{
                .status = 200,
                .headers = &response_headers,
                .request_method = "CONNECT",
                .extended_connect = true,
            };
        }

        pub fn validateResponse(response: Http3.Response) Error!void {
            try validateResponseHead(response.status, response.headers);
            if (response.body.len != 0 or response.trailers.len != 0) {
                return error.InvalidContentLength;
            }
        }

        pub fn validateResponseHead(
            status: u16,
            headers: anytype,
        ) error{ InvalidHeader, InvalidStatus }!void {
            if (status < 200 or status >= 300) return error.InvalidStatus;
            if (!try capsule.protocolEnabled(headers)) {
                return error.InvalidHeader;
            }
            for (headers) |header| {
                if (std.ascii.eqlIgnoreCase(
                    header.name,
                    "content-length",
                )) return error.InvalidHeader;
            }
        }

        pub const ContextDatagram = struct {
            context_id: u62,
            payload: []const u8,

            pub fn parse(bytes: []const u8) ContextDatagramError!ContextDatagram {
                var cursor = wire.Cursor.init(bytes);
                const value = try quic.varint.decode(&cursor);
                const context_id: u62 = @intCast(value);
                const payload = bytes[cursor.pos..];
                if (context_id == udp_context_id and
                    payload.len > max_udp_payload_size)
                {
                    return error.PayloadTooLarge;
                }
                return .{ .context_id = context_id, .payload = payload };
            }

            pub fn encodedLen(self: ContextDatagram) ContextDatagramError!usize {
                if (self.context_id == udp_context_id and
                    self.payload.len > max_udp_payload_size)
                {
                    return error.PayloadTooLarge;
                }
                return std.math.add(
                    usize,
                    try quic.varint.length(self.context_id),
                    self.payload.len,
                ) catch return error.IntegerOverflow;
            }

            pub fn writeInto(
                self: ContextDatagram,
                out: []u8,
            ) ContextDatagramError![]u8 {
                const needed = try self.encodedLen();
                if (out.len < needed) return error.BufferTooShort;
                const prefix = try quic.varint.encodeInto(
                    out,
                    self.context_id,
                );
                @memcpy(
                    out[prefix.len..][0..self.payload.len],
                    self.payload,
                );
                return out[0..needed];
            }

            pub fn udpPayload(
                self: ContextDatagram,
            ) error{UnexpectedContextId}![]const u8 {
                if (self.context_id != udp_context_id) {
                    return error.UnexpectedContextId;
                }
                return self.payload;
            }
        };

        pub fn writeUdpPayloadInto(
            out: []u8,
            payload: []const u8,
        ) ContextDatagramError![]u8 {
            return (ContextDatagram{
                .context_id = udp_context_id,
                .payload = payload,
            }).writeInto(out);
        }

        pub fn maxUdpPayloadForHttpDatagram(
            maximum_http_datagram_payload: usize,
        ) ?usize {
            if (maximum_http_datagram_payload == 0) return null;
            return @min(
                maximum_http_datagram_payload - 1,
                max_udp_payload_size,
            );
        }

        pub const OwnedUdpPayload = struct {
            stream_id: u62,
            storage: []u8,
            payload: []const u8,

            pub fn deinit(
                self: *OwnedUdpPayload,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.storage);
                self.* = undefined;
            }
        };

        pub const ReceivedUdpPayload = struct {
            stream_id: u62,
            payload: []u8,
        };

        /// Typed Context ID 0 data plane over a detached CONNECT association.
        /// Unknown extension contexts are dropped as RFC 9298 permits.
        pub fn Session(comptime Transport: type) type {
            return session_module.Session(Http3, @This(), Transport);
        }

        pub const CapsuleSessionOptions = capsule_session.Options;

        pub fn CapsuleSession(
            comptime ResetCode: type,
            comptime Tunnel: type,
            comptime WriteProgress: type,
        ) type {
            return capsule_session.Session(
                ResetCode,
                capsule,
                @This(),
                Tunnel,
                WriteProgress,
            );
        }

        fn isUnreserved(byte: u8) bool {
            return std.ascii.isAlphanumeric(byte) or
                byte == '-' or byte == '.' or byte == '_' or byte == '~';
        }

        fn isRegNameByte(byte: u8) bool {
            if (isUnreserved(byte)) return true;
            return switch (byte) {
                '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
                else => false,
            };
        }

        fn hexValue(byte: u8) ?u8 {
            return switch (byte) {
                '0'...'9' => byte - '0',
                'a'...'f' => byte - 'a' + 10,
                'A'...'F' => byte - 'A' + 10,
                else => null,
            };
        }

        fn decimalLen(value: u16) usize {
            var current = value;
            var len: usize = 1;
            while (current >= 10) : (len += 1) current /= 10;
            return len;
        }

        test "CONNECT-UDP default target path round trips" {
            var path_storage: [160]u8 = undefined;
            const ipv6 = Target{ .host = "2001:db8::42", .port = 443 };
            const path = try writeDefaultPath(&path_storage, ipv6);
            try std.testing.expectEqualStrings(
                "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/",
                path,
            );
            var host_storage: [64]u8 = undefined;
            const parsed = try parseDefaultPath(path, &host_storage);
            try std.testing.expectEqualStrings(ipv6.host, parsed.host);
            try std.testing.expectEqual(ipv6.port, parsed.port);

            const ipv4 = try writeDefaultPath(
                &path_storage,
                .{ .host = "192.0.2.6", .port = 53 },
            );
            try std.testing.expectEqualStrings(
                "/.well-known/masque/udp/192.0.2.6/53/",
                ipv4,
            );
            const escaped_reg_name = try writeDefaultPath(
                &path_storage,
                .{ .host = "dns!edge.example", .port = 5353 },
            );
            try std.testing.expectEqualStrings(
                "/.well-known/masque/udp/dns%21edge.example/5353/",
                escaped_reg_name,
            );

            try std.testing.expectError(
                error.InvalidTarget,
                writeDefaultPath(&path_storage, .{
                    .host = "fe80::1%eth0",
                    .port = 443,
                }),
            );
            try std.testing.expectError(
                error.InvalidTarget,
                parseDefaultPath(
                    "/.well-known/masque/udp/2001:db8::1/443/",
                    &host_storage,
                ),
            );
            try std.testing.expectError(
                error.InvalidTarget,
                parseDefaultPath(
                    "/.well-known/masque/udp/dns%2Fescape/443/",
                    &host_storage,
                ),
            );
            var short_host: [2]u8 = undefined;
            try std.testing.expectError(
                error.BufferTooShort,
                parseDefaultPath(
                    "/.well-known/masque/udp/192.0.2.6/53/",
                    &short_host,
                ),
            );
            try std.testing.expectError(
                error.InvalidTarget,
                parseDefaultPath(
                    "/.well-known/masque/udp/example.com/0/",
                    &host_storage,
                ),
            );
        }

        test "CONNECT-UDP validates request response and Context ID zero" {
            var path_storage: [128]u8 = undefined;
            const request = try requestInto(
                &path_storage,
                .{ .host = "dns.example", .port = 53 },
                "proxy.example",
            );
            var host_storage: [64]u8 = undefined;
            const target = try validateDefaultRequest(
                request,
                &host_storage,
            );
            try std.testing.expectEqualStrings("dns.example", target.host);
            try std.testing.expectEqual(@as(u16, 53), target.port);
            try validateResponse(successResponse());
            try std.testing.expectError(
                error.InvalidHeader,
                validateResponse(.{ .status = 200 }),
            );
            try std.testing.expectError(
                error.InvalidStatus,
                validateResponse(.{
                    .status = 403,
                    .headers = &response_headers,
                }),
            );
            try std.testing.expectError(
                error.InvalidContentLength,
                validateResponse(.{
                    .status = 200,
                    .headers = &response_headers,
                    .body = "not-capsules",
                }),
            );

            var encoded: [32]u8 = undefined;
            const bytes = try writeUdpPayloadInto(&encoded, "dns-query");
            try std.testing.expectEqual(@as(u8, 0), bytes[0]);
            const datagram = try ContextDatagram.parse(bytes);
            try std.testing.expectEqualStrings(
                "dns-query",
                try datagram.udpPayload(),
            );

            const extension = ContextDatagram{
                .context_id = quic.varint.max_value,
                .payload = "extension",
            };
            const extension_bytes = try extension.writeInto(&encoded);
            const parsed_extension = try ContextDatagram.parse(
                extension_bytes,
            );
            try std.testing.expectEqual(
                quic.varint.max_value,
                parsed_extension.context_id,
            );
            try std.testing.expectError(
                error.UnexpectedContextId,
                parsed_extension.udpPayload(),
            );
            try std.testing.expectEqual(
                @as(?usize, 1199),
                maxUdpPayloadForHttpDatagram(1200),
            );
            try std.testing.expectEqual(
                @as(?usize, max_udp_payload_size),
                maxUdpPayloadForHttpDatagram(100_000),
            );

            var oversized = [_]u8{0} ** (max_udp_payload_size + 2);
            try std.testing.expectError(
                error.PayloadTooLarge,
                ContextDatagram.parse(&oversized),
            );
        }

        test "CONNECT-UDP malformed datagram aborts its request stream" {
            const allocator = std.testing.allocator;
            var threaded = std.Io.Threaded.init(allocator, .{});
            defer threaded.deinit();

            const Raw = struct {
                stream_id: u62,
                payload: []u8,

                pub fn deinit(
                    self: *@This(),
                    value_allocator: std.mem.Allocator,
                ) void {
                    value_allocator.free(self.payload);
                    self.* = undefined;
                }
            };
            const FakeTransport = struct {
                raw: ?Raw,
                canceled_code: ?u64 = null,

                pub fn receiveConnectDatagram(
                    self: *@This(),
                    _: u62,
                ) !Raw {
                    const raw = self.raw orelse return error.NothingAvailable;
                    self.raw = null;
                    return raw;
                }

                pub fn cancelRequest(
                    self: *@This(),
                    _: u62,
                    code: u64,
                ) !void {
                    self.canceled_code = code;
                }
            };
            var transport = FakeTransport{ .raw = .{
                .stream_id = 0,
                .payload = try allocator.alloc(u8, 0),
            } };
            var session = Session(FakeTransport).init(
                allocator,
                threaded.io(),
                &transport,
                0,
            );
            defer session.deinit();
            try std.testing.expectError(
                error.BufferTooShort,
                session.receive(),
            );
            try std.testing.expectEqual(
                @as(?u64, Http3.ApplicationErrorCode.message_error),
                transport.canceled_code,
            );
        }
    };
}
