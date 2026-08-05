const std = @import("std");
const netz = @import("netz");

test "public modules are reachable" {
    try std.testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", netz.websocket.handshake_guid);
    try std.testing.expectEqual(@as(usize, 64 * 1024), (netz.http1.runtime.Limits{}).max_head_bytes);
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.websocket.runtime.Limits{}).max_frame_bytes);
    try std.testing.expectEqual(@as(u8, 0x40), netz.quic.varint.prefixForLength(2));
    try std.testing.expect(netz.http1.Method.GET.safe());
    try std.testing.expectEqual(@as(u64, 9), netz.http2.FrameHeader.encoded_len);
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.http2.runtime.Limits{}).max_body_bytes);
    try std.testing.expectEqual(@as(u64, 0x01), netz.http3.FrameType.headers);
    try std.testing.expectEqual(@as(u8, 5), netz.mqtt.ProtocolVersion.v5.byte());
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.mqtt.runtime.Limits{}).max_packet_size);
    try std.testing.expectEqual(@as(usize, 65_535), (netz.quic.runtime.Limits{}).max_datagram_size);
    try std.testing.expect(netz.webtransport.SessionId.init(0).isClientInitiatedBidirectional());
    try std.testing.expectEqual(@as(u32, 0x2112A442), netz.webrtc.stun.magic_cookie);
}
