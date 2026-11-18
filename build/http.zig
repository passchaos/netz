//! HTTP/1, HTTP/2, and HTTP/3 interop verification steps.

const std = @import("std");

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
) void {
    const h2spec_server = b.addExecutable(.{
        .name = "netz-h2spec-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_h2spec_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const h2spec = b.addSystemCommand(&.{
        "tools/interop/http2_h2spec.sh",
    });
    h2spec.addArtifactArg(h2spec_server);
    if (b.args) |args| h2spec.addArgs(args);
    const h2spec_step = b.step(
        "interop-http2-h2spec",
        "Run strict h2spec against h2c, TLS 1.3, or TLS 1.2 (--tls/--tls12)",
    );
    h2spec_step.dependOn(&h2spec.step);

    const http_external_client_server = b.addExecutable(.{
        .name = "netz-http-external-client-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_external_client_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_nghttpd_client = b.addExecutable(.{
        .name = "netz-http2-nghttpd-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_nghttpd_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_external_clients = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http_external_clients.py",
    });
    http_external_clients.addArtifactArg(http_external_client_server);
    http_external_clients.addArtifactArg(http2_nghttpd_client);
    const http_external_clients_step = b.step(
        "interop-http-external-clients",
        "Run independent curl/nghttp2 peers against Netz HTTP endpoints",
    );
    http_external_clients_step.dependOn(&http_external_clients.step);

    const http_cookie_jar_peer = b.addExecutable(.{
        .name = "netz-http-cookie-jar-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_cookie_jar_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_cookie_curl = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http_cookie_curl.py",
    });
    http_cookie_curl.addArtifactArg(http_cookie_jar_peer);
    const http_cookie_curl_step = b.step(
        "interop-http-cookie-curl",
        "Compare Netz CookieJar path/order behavior with curl",
    );
    http_cookie_curl_step.dependOn(&http_cookie_curl.step);

    const http2_hyper_client = b.addExecutable(.{
        .name = "netz-http2-hyper-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_hyper_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_hyper_server = b.addExecutable(.{
        .name = "netz-http2-hyper-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_hyper_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_hyper_interop = b.addSystemCommand(
        &.{"tools/interop/http2_hyper_client.sh"},
    );
    http2_hyper_interop.addArtifactArg(http2_hyper_client);
    http2_hyper_interop.addArtifactArg(http2_hyper_server);
    const http2_hyper_interop_step = b.step(
        "interop-http2-hyper-client",
        "Run bidirectional netz HTTP/2 interop with audited Hyper fixtures",
    );
    http2_hyper_interop_step.dependOn(&http2_hyper_interop.step);

    const connect_udp_hyper_peer = b.addExecutable(.{
        .name = "netz-connect-udp-hyper-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/connect_udp_hyper_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const connect_udp_hyper_interop = b.addSystemCommand(
        &.{"tools/interop/connect_udp_hyper.sh"},
    );
    connect_udp_hyper_interop.addArtifactArg(connect_udp_hyper_peer);
    const connect_udp_hyper_interop_step = b.step(
        "interop-connect-udp-hyper",
        "Run HTTP/1 and HTTP/2 CONNECT-UDP interop with Hyper",
    );
    connect_udp_hyper_interop_step.dependOn(
        &connect_udp_hyper_interop.step,
    );

    const connect_udp_h3_peer = b.addExecutable(.{
        .name = "netz-connect-udp-h3-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/connect_udp_h3_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const connect_udp_h3_interop = b.addSystemCommand(
        &.{"tools/interop/connect_udp_h3.sh"},
    );
    connect_udp_h3_interop.addArtifactArg(connect_udp_h3_peer);
    const connect_udp_h3_interop_step = b.step(
        "interop-connect-udp-h3",
        "Run bidirectional HTTP/3 CONNECT-UDP interop with h3/quinn",
    );
    connect_udp_h3_interop_step.dependOn(
        &connect_udp_h3_interop.step,
    );

    const connect_ip_h3_peer = b.addExecutable(.{
        .name = "netz-connect-ip-h3-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/connect_ip_h3_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const connect_ip_h3_interop = b.addSystemCommand(
        &.{"tools/interop/connect_ip_h3.sh"},
    );
    connect_ip_h3_interop.addArtifactArg(connect_ip_h3_peer);
    const connect_ip_h3_interop_step = b.step(
        "interop-connect-ip-h3",
        "Run bidirectional HTTP/3 CONNECT-IP interop with h3/quinn",
    );
    connect_ip_h3_interop_step.dependOn(
        &connect_ip_h3_interop.step,
    );

    const http_unified_hyper_client = b.addExecutable(.{
        .name = "netz-http-unified-hyper-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_unified_hyper_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_unified_hyper = b.addSystemCommand(
        &.{"tools/interop/http_unified_hyper.sh"},
    );
    http_unified_hyper.addArtifactArg(http_unified_hyper_client);
    const http_unified_hyper_step = b.step(
        "interop-http-unified-hyper",
        "Run unified netz HTTP pool ALPN/reuse interop with Hyper",
    );
    http_unified_hyper_step.dependOn(&http_unified_hyper.step);
}
