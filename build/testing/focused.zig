//! Independently compiled protocol roots with a real matching-test guard.

const std = @import("std");

const Scope = enum { proxy, proxy_queues, http, http1, http2, http3, quic, grpc, mqtt, websocket, webtransport, tls, vpn, mesh };

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    prototype: *std.Build.Module,
    filters: []const []const u8,
) void {
    const specs = .{
        .{ "test-proxy", Scope.proxy },
        .{ "test-proxy-queues", Scope.proxy_queues },
        .{ "test-http", Scope.http },
        .{ "test-http1", Scope.http1 },
        .{ "test-http2", Scope.http2 },
        .{ "test-http3", Scope.http3 },
        .{ "test-quic", Scope.quic },
        .{ "test-grpc", Scope.grpc },
        .{ "test-mqtt", Scope.mqtt },
        .{ "test-websocket", Scope.websocket },
        .{ "test-webtransport", Scope.webtransport },
        .{ "test-tls", Scope.tls },
        .{ "test-vpn", Scope.vpn },
        .{ "test-mesh", Scope.mesh },
    };
    inline for (specs) |spec| {
        const owned_prefix = if (spec[1] == .proxy_queues) "proxy.internal." else @tagName(spec[1]) ++ ".";
        const selected_filters: []const []const u8 = if (filters.len == 0) &.{owned_prefix} else filters;
        const options = b.addOptions();
        options.addOption(Scope, "scope", spec[1]);
        options.addOption([]const []const u8, "filters", filters);
        const module = b.createModule(.{
            .root_source_file = b.path("src/test_scope.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = prototype.link_libc,
        });
        var imports = prototype.import_table.iterator();
        while (imports.next()) |entry| module.addImport(entry.key_ptr.*, entry.value_ptr.*);
        module.addOptions("test_scope_options", options);
        const tests = b.addTest(.{ .root_module = module, .filters = selected_filters });
        b.step(b.fmt("{s}-compile", .{spec[0]}), "Compile one protocol's selected tests without running them").dependOn(&tests.step);
        const run = b.addRunArtifact(tests);
        b.step(spec[0], "Compile and run one protocol; reject filters with no matching protocol tests").dependOn(&run.step);
    }
}
