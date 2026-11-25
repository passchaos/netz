const shared = @import("../../../internal/testing/connection_race_storage.zig");

test "HTTP1 connection race storage keeps large contexts out of candidate allocations" {
    const Payload = [4096]u8;
    const Check = struct {
        fn valid(payload: *const Payload) bool {
            for (payload) |byte| if (byte != 0xa5) return false;
            return true;
        }
    };
    const payload: Payload = @splat(0xa5);
    try shared.compare(Payload, payload, Check.valid);
}

test "HTTP1 connection race storage retains large context through canceled result cleanup" {
    const Payload = [4096]u8;
    const Check = struct {
        fn valid(payload: *const Payload) bool {
            for (payload) |byte| if (byte != 0xa5) return false;
            return true;
        }
    };
    try shared.ownership(Payload, @splat(0xa5), Check.valid);
}
