//! xDS Load Reporting Service.
pub const codec = @import("lrs/codec.zig");
pub const path = @import("lrs/client.zig").path;
pub const Client = @import("lrs/client.zig").Client;
pub const Options = @import("lrs/client.zig").Options;
pub const Error = @import("lrs/client.zig").Error;
pub const Event = @import("lrs/client.zig").Event;
pub const integration = @import("lrs/integration.zig");
pub const Reporter = @import("lrs/reporter.zig").Reporter;
pub const ReporterOptions = @import("lrs/reporter.zig").Options;
pub const Scheduler = @import("lrs/scheduler.zig").Scheduler;
pub const Runner = @import("lrs/runner.zig").Runner;
pub const RunnerOptions = @import("lrs/runner.zig").Options;
test {
    _ = @import("lrs/tests.zig");
    _ = @import("lrs/transport_tests.zig");
    _ = @import("lrs/control_plane_tests.zig");
    _ = @import("lrs/scheduler_tests.zig");
    _ = @import("lrs/runner_tests.zig");
}
