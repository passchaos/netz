//! gRPC interop and xDS verification steps.

const std = @import("std");

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    regexz_mod: *std.Build.Module,
    test_step: *std.Build.Step,
) void {
    const grpc_web_chrome_server = b.addExecutable(.{
        .name = "netz-grpc-web-chrome-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_web_chrome_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_web_chrome = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_web_chrome.py" });
    grpc_web_chrome.addArtifactArg(grpc_web_chrome_server);
    if (b.args) |args| grpc_web_chrome.addArgs(args);
    const grpc_web_chrome_step = b.step("interop-grpc-web-chrome", "Verify gRPC-Web/CORS with the official JS SDK in Chromium (--tls for HTTPS; --tls --http2 for HTTP/2)");
    grpc_web_chrome_step.dependOn(&grpc_web_chrome.step);

    const grpc_response_client = b.addExecutable(.{
        .name = "netz-grpc-response-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_response_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_response = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_response.py" });
    grpc_response.addArtifactArg(grpc_response_client);
    const grpc_response_step = b.step("interop-grpc-response", "Verify native gRPC response fallback with an independent HTTP/2 peer and official grpc-js");
    grpc_response_step.dependOn(&grpc_response.step);

    const grpc_ip_literals_client = b.addExecutable(.{
        .name = "netz-grpc-ip-literals-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_ip_literals/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_ip_literals = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_ip_literals/run.py" });
    grpc_ip_literals.addArtifactArg(grpc_ip_literals_client);
    if (b.args) |args| grpc_ip_literals.addArgs(args);
    const grpc_ip_literals_step = b.step("interop-grpc-ip-literals", "Verify numeric gRPC targets, HTTP/2 authority, TLS SNI and IP SAN identity with grpc-js/OpenSSL");
    grpc_ip_literals_step.dependOn(&grpc_ip_literals.step);

    const grpc_connection_race_client = b.addExecutable(.{
        .name = "netz-grpc-connection-race-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_connection_race/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_connection_race = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_connection_race/run.py" });
    grpc_connection_race.addArtifactArg(grpc_connection_race_client);
    if (b.args) |args| grpc_connection_race.addArgs(args);
    const grpc_connection_race_step = b.step("interop-grpc-connection-race", "Verify gRPC staggered endpoint selection and stalled handshake cleanup with grpc-js over h2c/TLS");
    grpc_connection_race_step.dependOn(&grpc_connection_race.step);

    const grpc_locality_client = b.addExecutable(.{
        .name = "netz-grpc-locality-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_locality/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_locality = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_locality/run.py" });
    grpc_locality.addArtifactArg(grpc_locality_client);
    if (b.args) |args| grpc_locality.addArgs(args);
    const grpc_locality_step = b.step("interop-grpc-locality", "Verify xDS locality generation with official grpc-js-xds and ordinary/shared routing with grpc-js");
    grpc_locality_step.dependOn(&grpc_locality.step);

    const grpc_cluster_manager_client = b.addExecutable(.{
        .name = "netz-grpc-cluster-manager-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_cluster_manager/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cluster_manager = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_cluster_manager/run.py" });
    grpc_cluster_manager.addArtifactArg(grpc_cluster_manager_client);
    if (b.args) |args| grpc_cluster_manager.addArgs(args);
    const grpc_cluster_manager_step = b.step("interop-grpc-cluster-manager", "Verify per-RPC cluster picking, failed-child isolation and config updates with official grpc-js-xds/grpc-js");
    grpc_cluster_manager_step.dependOn(&grpc_cluster_manager.step);

    const grpc_ads_client = b.addExecutable(.{
        .name = "netz-grpc-ads-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_ads/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_ads = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_ads/run.py" });
    grpc_ads.addArtifactArg(grpc_ads_client);
    if (b.args) |args| grpc_ads.addArgs(args);
    const grpc_ads_step = b.step("interop-grpc-ads", "Verify v3 ADS ACK/NACK subscriptions and stream reconnect with official discovery protobufs and grpc-js");
    grpc_ads_step.dependOn(&grpc_ads.step);

    const xds_regex_module = regexz_mod;
    const xds_regex_client = b.addExecutable(.{
        .name = "netz-grpc-xds-regex-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_xds_matching/regex_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "xds_regex", .module = xds_regex_module }},
        }),
    });
    const xds_regex = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_xds_matching/regex_run.py" });
    xds_regex.addArtifactArg(xds_regex_client);
    if (b.args) |args| xds_regex.addArgs(args);
    const xds_regex_step = b.step("interop-grpc-xds-regex", "Compare bounded native xDS safe-regex full matching against official RE2 WASM");
    xds_regex_step.dependOn(&xds_regex.step);

    const grpc_runtime_client = b.addExecutable(.{
        .name = "netz-grpc-xds-runtime-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_xds_runtime/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_runtime = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_xds_runtime/run.py" });
    grpc_runtime.addArtifactArg(grpc_runtime_client);
    if (b.args) |args| grpc_runtime.addArgs(args);
    const grpc_runtime_step = b.step("interop-grpc-xds-runtime", "Verify automatic LDS/RDS/CDS/EDS discovery and isolated cluster RPC admission");
    grpc_runtime_step.dependOn(&grpc_runtime.step);

    const grpc_delta_client = b.addExecutable(.{
        .name = "netz-grpc-delta-ads-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_delta_ads/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_delta = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_delta_ads/run.py" });
    grpc_delta.addArtifactArg(grpc_delta_client);
    if (b.args) |args| grpc_delta.addArgs(args);
    const grpc_delta_step = b.step("interop-grpc-delta-ads", "Verify delta ADS envelopes, diffs, NACK and reconnect against official Envoy protobuf schemas");
    grpc_delta_step.dependOn(&grpc_delta.step);

    const grpc_delta_runtime_client = b.addExecutable(.{
        .name = "netz-grpc-delta-runtime-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_delta_runtime/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_delta_runtime = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_delta_runtime/run.py" });
    grpc_delta_runtime.addArtifactArg(grpc_delta_runtime_client);
    if (b.args) |args| grpc_delta_runtime.addArgs(args);
    const grpc_delta_runtime_step = b.step("interop-grpc-delta-runtime", "Verify typed delta LDS/RDS/CDS/EDS publication and explicit removals with real RPCs");
    grpc_delta_runtime_step.dependOn(&grpc_delta_runtime.step);

    const grpc_lrs_client = b.addExecutable(.{
        .name = "netz-grpc-lrs-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_lrs/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_lrs = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_lrs/run.py" });
    grpc_lrs.addArtifactArg(grpc_lrs_client);
    if (b.args) |args| grpc_lrs.addArgs(args);
    const grpc_lrs_step = b.step("interop-grpc-lrs", "Verify Load Reporting Service envelopes and counters against official Envoy schemas");
    grpc_lrs_step.dependOn(&grpc_lrs.step);

    const grpc_lrs_automatic_client = b.addExecutable(.{
        .name = "netz-grpc-lrs-automatic-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_lrs_automatic/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_lrs_automatic = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_lrs_automatic/run.py" });
    grpc_lrs_automatic.addArtifactArg(grpc_lrs_automatic_client);
    if (b.args) |args| grpc_lrs_automatic.addArgs(args);
    b.step("interop-grpc-lrs-automatic", "Verify managed CDS LRS source provenance, migration and nonblocking reporting transport").dependOn(&grpc_lrs_automatic.step);

    const grpc_client_target_emitter = b.addExecutable(.{
        .name = "netz-grpc-client-target-emitter",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_client_target/emit.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step("build-grpc-client-target", "Build the bootstrap-derived xDS target emitter").dependOn(&b.addInstallArtifact(grpc_client_target_emitter, .{}).step);
    const grpc_client_target = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_client_target/run.py", "--native" });
    grpc_client_target.addArtifactArg(grpc_client_target_emitter);
    if (b.args) |args| grpc_client_target.addArgs(args);
    b.step("interop-grpc-client-target", "Verify xDS target templates and data authority with pinned C-Core (-- --reference-python PATH)").dependOn(&grpc_client_target.step);

    const grpc_federation_client = b.addExecutable(.{
        .name = "netz-grpc-federation-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_federation/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step("build-grpc-federation", "Build the managed federated xDS client").dependOn(&b.addInstallArtifact(grpc_federation_client, .{}).step);
    const grpc_federation = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_federation/run.py", "--native" });
    grpc_federation.addArtifactArg(grpc_federation_client);
    if (b.args) |args| grpc_federation.addArgs(args);
    b.step("interop-grpc-federation", "Verify managed cross-authority discovery, publication and LRS with independent peers").dependOn(&grpc_federation.step);

    const grpc_channelz_server = b.addExecutable(.{
        .name = "netz-grpc-channelz-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_channelz/server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_channelz = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_channelz/run.py" });
    grpc_channelz.addArtifactArg(grpc_channelz_server);
    if (b.args) |args| grpc_channelz.addArgs(args);
    b.step("interop-grpc-channelz", "Verify Channelz channels, subchannels, servers, sockets and traces with the official grpc-js client").dependOn(&grpc_channelz.step);

    const grpc_impl_client = b.addExecutable(.{
        .name = "netz-grpc-cluster-impl-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_cluster_impl/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_impl = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_cluster_impl/run.py" });
    grpc_impl.addArtifactArg(grpc_impl_client);
    if (b.args) |args| grpc_impl.addArgs(args);
    const grpc_impl_step = b.step("interop-grpc-cluster-impl", "Verify selected-cluster drop/circuit isolation with official grpc-js-xds and ordinary/shared RPCs");
    grpc_impl_step.dependOn(&grpc_impl.step);

    const grpc_lds_client = b.addExecutable(.{
        .name = "netz-grpc-lds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_lds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_lds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_lds/run.py" });
    grpc_lds.addArtifactArg(grpc_lds_client);
    if (b.args) |args| grpc_lds.addArgs(args);
    const grpc_lds_step = b.step("interop-grpc-lds", "Verify official client LDS/HCM through inline/dynamic RDS and immutable RPC timeout/routing publication");
    grpc_lds_step.dependOn(&grpc_lds.step);

    const grpc_hedging_commit_client = b.addExecutable(.{
        .name = "netz-grpc-hedging-commit-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_hedging_commit/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_hedging_commit = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_hedging_commit/run.py" });
    grpc_hedging_commit.addArtifactArg(grpc_hedging_commit_client);
    if (b.args) |args| grpc_hedging_commit.addArgs(args);
    b.step("interop-grpc-hedging-commit", "Verify A6 response-head commitment, immediate hedge cancellation and call-wide transparent recovery").dependOn(&grpc_hedging_commit.step);
    test_step.dependOn(&grpc_hedging_commit.step);

    const grpc_rds_client = b.addExecutable(.{
        .name = "netz-grpc-rds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_rds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_rds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_rds/run.py" });
    grpc_rds.addArtifactArg(grpc_rds_client);
    if (b.args) |args| grpc_rds.addArgs(args);
    const grpc_rds_step = b.step("interop-grpc-rds", "Verify official RDS resources through ADS, immutable selectors and automatic unary/stream cluster dispatch");
    grpc_rds_step.dependOn(&grpc_rds.step);

    const grpc_csds_emit = b.addExecutable(.{
        .name = "netz-grpc-csds-emit",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_csds/emit.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_csds = b.addSystemCommand(&.{ "node", "tools/interop/grpc_csds/run.js" });
    grpc_csds.addArtifactArg(grpc_csds_emit);
    const grpc_csds_step = b.step("interop-grpc-csds", "Decode a netz CSDS ClientStatusResponse with the official Envoy schema");
    grpc_csds_step.dependOn(&grpc_csds.step);

    const grpc_cds_client = b.addExecutable(.{
        .name = "netz-grpc-cds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_cds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_cds/run.py" });
    grpc_cds.addArtifactArg(grpc_cds_client);
    if (b.args) |args| grpc_cds.addArgs(args);
    const grpc_cds_step = b.step("interop-grpc-cds", "Verify official CDS policy/circuit decoding and transactional CDS/EDS ADS publication with grpc-js-xds/grpc-js");
    grpc_cds_step.dependOn(&grpc_cds.step);

    const grpc_eds_client = b.addExecutable(.{
        .name = "netz-grpc-eds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_eds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_eds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_eds/run.py" });
    grpc_eds.addArtifactArg(grpc_eds_client);
    if (b.args) |args| grpc_eds.addArgs(args);
    const grpc_eds_step = b.step("interop-grpc-eds", "Verify official EDS resources from ADS through typed validation, dynamic publication and priority/locality RPC routing");
    grpc_eds_step.dependOn(&grpc_eds.step);

    const grpc_eds_drop_client = b.addExecutable(.{
        .name = "netz-grpc-eds-drop-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_eds_drop/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_eds_drop = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_eds_drop/run.py" });
    grpc_eds_drop.addArtifactArg(grpc_eds_drop_client);
    if (b.args) |args| grpc_eds_drop.addArgs(args);
    const grpc_eds_drop_step = b.step("interop-grpc-eds-drop", "Verify EDS drop fractions, pre-wire RPC rejection, retry/hedging suppression and dynamic updates with official grpc-js-xds/grpc-js");
    grpc_eds_drop_step.dependOn(&grpc_eds_drop.step);

    const grpc_circuit_client = b.addExecutable(.{
        .name = "netz-grpc-circuit-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_circuit/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_circuit = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_circuit/run.py" });
    grpc_circuit.addArtifactArg(grpc_circuit_client);
    if (b.args) |args| grpc_circuit.addArgs(args);
    const grpc_circuit_step = b.step("interop-grpc-circuit", "Verify shared cluster/EDS circuit budgets, changed limits and RPC permits against official grpc-js-xds/grpc-js");
    grpc_circuit_step.dependOn(&grpc_circuit.step);
}
