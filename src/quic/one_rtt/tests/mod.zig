test {
    _ = @import("receive_target.zig");
    _ = @import("closed_streams.zig");
    _ = @import("datagram_queue.zig");
    _ = @import("datagram_receive.zig");
    _ = @import("datagram_send.zig");
    _ = @import("frame_traits.zig");
    _ = @import("basic.zig");
    _ = @import("crypto_path.zig");
    _ = @import("handshake_status.zig");
    _ = @import("lifecycle.zig");
    _ = @import("recovery_flow.zig");
    _ = @import("reliable_reset.zig");
    _ = @import("stream_cancel.zig");
    _ = @import("scratch.zig");
    _ = @import("stateless_reset_receive.zig");
}
