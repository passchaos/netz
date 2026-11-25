//! Opt-in test-name progress using Zig's standard terminal runner.
const std = @import("std");

pub fn add(b: *std.Build, tests: *std.Build.Step.Compile, progress: bool) *std.Build.Step.Run {
    const run = b.addRunArtifact(tests);
    if (progress and tests.test_runner == null and run.stdio == .zig_test) {
        // Keep the producer, executor, seed and cache arguments installed by
        // addRunArtifact. Only the server-protocol switch selects terminal mode.
        const listen = run.argv.pop().?;
        std.debug.assert(listen == .bytes and std.mem.eql(u8, listen.bytes, "--listen=-"));
        run.stdio = .inherit;
    }
    return run;
}
