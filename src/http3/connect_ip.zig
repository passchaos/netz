//! RFC 9484 CONNECT-IP protocol helpers.
//!
//! The transport-neutral core covers request scoping, MASQUE URI Templates,
//! HTTP negotiation metadata, IP-configuration Capsules, and Context ID 0 IP
//! packet framing. HTTP/1.1, HTTP/2, and HTTP/3 runtime adapters can share the
//! same strict codecs without owning address assignment or routing policy.

const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");
const capsule = @import("capsule.zig");
const config_capsules = @import("connect_ip/capsules.zig");
const capsule_session = @import("connect_udp/capsule_session.zig");
const configuration = @import("connect_ip/configuration.zig");
const packet_module = @import("connect_ip/packet.zig");
const session_module = @import("connect_udp/session.zig");
const scope_module = @import("connect_ip/scope.zig");
const template_module = @import("connect_ip/template.zig");

pub fn Protocol(comptime Http3: type) type {
    return struct {
        pub const protocol = "connect-ip";
        pub const default_path_prefix = scope_module.default_path_prefix;
        pub const ip_context_id: u62 = 0;
        pub const payload_context_id = ip_context_id;
        /// Maximum ordinary IPv6 packet size without RFC 2675 jumbograms.
        pub const max_ip_packet_size: usize = 65_575;
        pub const max_context_payload_size = max_ip_packet_size;

        pub const Error = Http3.Error || wire.Error || scope_module.Error ||
            template_module.Error || config_capsules.Error || error{
            UnexpectedContextId,
        };
        pub const ContextDatagramError = wire.Error || error{
            UnexpectedContextId,
        };

        pub const Scope = scope_module.Scope;
        pub const UriTemplate = template_module.Template;
        pub const Variable = template_module.Variable;
        pub const capsules = config_capsules;
        pub const ConfigurationState = configuration.State;
        pub const ConfigurationLimits = configuration.Limits;
        pub const ConfigurationApplyResult = configuration.ApplyResult;
        pub const packets = packet_module;
        pub const IpPacket = packet_module.View;
        pub const PacketError = packet_module.Error;

        pub fn parseIpPacket(packet: []const u8) PacketError!IpPacket {
            return packet_module.parse(packet);
        }

        pub const request_headers = [_]Http3.Qpack.HeaderField{
            .{ .name = ":protocol", .value = protocol },
            capsule.protocol_header,
        };

        pub const response_headers = [_]Http3.Qpack.HeaderField{
            capsule.protocol_header,
        };

        pub fn defaultPathLen(scope: Scope) scope_module.Error!usize {
            return scope_module.defaultPathLen(scope);
        }

        pub fn writeDefaultPath(
            out: []u8,
            scope: Scope,
        ) scope_module.Error![]u8 {
            return scope_module.writeDefaultPath(out, scope);
        }

        pub fn parseDefaultPath(
            path: []const u8,
            target_out: []u8,
        ) scope_module.Error!Scope {
            return scope_module.parseDefaultPath(path, target_out);
        }

        pub fn requestInto(
            path_out: []u8,
            scope: Scope,
            authority: []const u8,
        ) Error!Http3.Request {
            const path = try writeDefaultPath(path_out, scope);
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
            scope: Scope,
            variables: []const Variable,
        ) Error!Http3.Request {
            try scope.validate();
            if (!std.mem.eql(u8, template.scheme(), "https")) {
                return error.InvalidUriTemplate;
            }
            const path = try template.expandRequestTargetInto(
                path_out,
                scope,
                variables,
            );
            const request = Http3.Request{
                .method = "CONNECT",
                .path = path,
                .scheme = template.scheme(),
                .authority = template.authority(),
                .headers = &request_headers,
            };
            try request.validateForContext(.direct);
            return request;
        }

        pub fn validateDefaultRequest(
            request: Http3.Request,
            target_out: []u8,
        ) Error!Scope {
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
            return parseDefaultPath(request.path, target_out);
        }

        pub fn validateDecodedDefaultRequest(
            request: Http3.DecodedRequestHead,
            target_out: []u8,
        ) Error!Scope {
            if (request.content_length != null) return error.InvalidHeader;
            try validateDecodedRequest(request);
            return parseDefaultPath(request.path, target_out);
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
            if (protocols != 1 or !try capsule.protocolEnabled(headers)) {
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

            pub fn parse(
                bytes: []const u8,
            ) ContextDatagramError!ContextDatagram {
                var cursor = wire.Cursor.init(bytes);
                const context_id: u62 = @intCast(try quic.varint.decode(
                    &cursor,
                ));
                return .{
                    .context_id = context_id,
                    .payload = bytes[cursor.pos..],
                };
            }

            pub fn encodedLen(
                self: ContextDatagram,
            ) ContextDatagramError!usize {
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
                @memcpy(out[prefix.len..][0..self.payload.len], self.payload);
                return out[0..needed];
            }

            pub fn ipPacket(
                self: ContextDatagram,
            ) error{UnexpectedContextId}![]const u8 {
                if (self.context_id != ip_context_id) {
                    return error.UnexpectedContextId;
                }
                return self.payload;
            }
        };

        pub fn writeIpPacketInto(
            out: []u8,
            packet: []const u8,
        ) ContextDatagramError![]u8 {
            return (ContextDatagram{
                .context_id = ip_context_id,
                .payload = packet,
            }).writeInto(out);
        }

        pub fn maxIpPacketForHttpDatagram(
            maximum_http_datagram_payload: usize,
        ) ?usize {
            if (maximum_http_datagram_payload == 0) return null;
            return @min(
                maximum_http_datagram_payload - 1,
                max_ip_packet_size,
            );
        }

        pub const OwnedIpPayload = struct {
            stream_id: u62,
            storage: []u8,
            payload: []const u8,

            pub fn deinit(
                self: *OwnedIpPayload,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.storage);
                self.* = undefined;
            }
        };

        pub const ReceivedIpPayload = struct {
            stream_id: u62,
            payload: []u8,
        };

        pub const OwnedContextPayload = OwnedIpPayload;
        pub const ReceivedContextPayload = ReceivedIpPayload;

        pub fn maxContextPayloadForHttpDatagram(
            maximum_http_datagram_payload: usize,
        ) ?usize {
            return maxIpPacketForHttpDatagram(
                maximum_http_datagram_payload,
            );
        }

        /// Validate one reliable CONNECT-IP configuration Capsule value.
        /// Returns false for unknown extension Capsule types, which receivers
        /// skip while preserving every registered RFC 9484 configuration.
        pub fn validateConfigurationCapsule(
            capsule_type: u64,
            value: []const u8,
        ) Error!bool {
            switch (capsule_type) {
                capsules.address_assign_type => _ = try capsules.parseAddressAssign(value),
                capsules.address_request_type => _ = try capsules.parseAddressRequest(value),
                capsules.route_advertisement_type => _ = try capsules.parseRouteAdvertisement(value),
                else => return false,
            }
            return true;
        }

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
    };
}
