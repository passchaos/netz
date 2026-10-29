test {
    _ = @import("tests/multiplex.zig");
    _ = @import("tests/streaming.zig");
    _ = @import("tests/lifecycle.zig");
    _ = @import("tests/cancellation.zig");
    _ = @import("tests/resolution.zig");
    _ = @import("tests/rpc_shapes.zig");
    _ = @import("tests/terminal_deadline.zig");
}
