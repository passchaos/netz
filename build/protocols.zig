//! HTTP/3, TLS, WebSocket-over-H3, and protocol interop steps.

const std = @import("std");

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    test_step: *std.Build.Step,
    benchmark_counting_allocator_mod: *std.Build.Module,
) void {
    const http2_h2_push_client = b.addExecutable(.{
        .name = "netz-http2-h2-push-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_h2_push_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_h2_push_server = b.addExecutable(.{
        .name = "netz-http2-h2-push-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_h2_push_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_h2_push = b.addSystemCommand(
        &.{"tools/interop/http2_h2_push.sh"},
    );
    http2_h2_push.addArtifactArg(http2_h2_push_client);
    http2_h2_push.addArtifactArg(http2_h2_push_server);
    const http2_h2_push_step = b.step(
        "interop-http2-h2-push",
        "Run HTTP/2 push and informational interop with audited h2",
    );
    http2_h2_push_step.dependOn(&http2_h2_push.step);

    const http3_quic_go_client = b.addExecutable(.{
        .name = "netz-http3-quic-go-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_quic_go_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const http3_quic_go_server = b.addExecutable(.{
        .name = "netz-http3-quic-go-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_quic_go_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const http3_quic_go = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go.sh"},
    );
    http3_quic_go.addArtifactArg(http3_quic_go_client);
    http3_quic_go.addArtifactArg(http3_quic_go_server);
    const http3_quic_go_step = b.step(
        "interop-http3-quic-go",
        "Run bidirectional HTTP/3 body, trailer, cancellation, and informational interop with quic-go",
    );
    http3_quic_go_step.dependOn(&http3_quic_go.step);
    const http3_quic_go_handlers = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go_handlers.sh"},
    );
    http3_quic_go_handlers.addArtifactArg(http3_quic_go_server);
    const http3_quic_go_handlers_step = b.step(
        "interop-http3-quic-go-handlers",
        "Run bounded HTTP/3 handler supervisor interop with concurrent quic-go clients",
    );
    http3_quic_go_handlers_step.dependOn(
        &http3_quic_go_handlers.step,
    );
    const http3_quic_go_bench = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go.sh"},
    );
    http3_quic_go_bench.addArtifactArg(http3_quic_go_client);
    http3_quic_go_bench.addArtifactArg(http3_quic_go_server);
    http3_quic_go_bench.addArg("--bench");
    if (b.args) |args| http3_quic_go_bench.addArgs(args);
    const http3_quic_go_bench_step = b.step(
        "bench-http3-quic-go",
        "Compare verified HTTP/3 upload/download against quic-go, with optional kernel capture",
    );
    http3_quic_go_bench_step.dependOn(&http3_quic_go_bench.step);
    const http3_quic_go_multistream = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go_multistream.sh"},
    );
    http3_quic_go_multistream.addArtifactArg(http3_quic_go_client);
    http3_quic_go_multistream.addArtifactArg(http3_quic_go_server);
    if (b.args) |args| http3_quic_go_multistream.addArgs(args);
    const http3_quic_go_multistream_step = b.step(
        "bench-http3-quic-go-multistream",
        "Compare verified 4/16-stream HTTP/3 transfers against quic-go",
    );
    http3_quic_go_multistream_step.dependOn(
        &http3_quic_go_multistream.step,
    );

    const websocket_h3_quic_go_client = b.addExecutable(.{
        .name = "netz-websocket-h3-quic-go-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const websocket_h3_quic_go_server = b.addExecutable(.{
        .name = "netz-websocket-h3-quic-go-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const websocket_h3_quic_go = b.addSystemCommand(
        &.{"tools/interop/websocket_h3_quic_go.sh"},
    );
    websocket_h3_quic_go.addArtifactArg(websocket_h3_quic_go_client);
    websocket_h3_quic_go.addArtifactArg(websocket_h3_quic_go_server);
    const websocket_h3_quic_go_step = b.step(
        "interop-websocket-h3-quic-go",
        "Run bidirectional RFC 9220 interoperability with quic-go",
    );
    websocket_h3_quic_go_step.dependOn(&websocket_h3_quic_go.step);
    const websocket_h3_socks5 = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_h3_socks5.py",
    });
    websocket_h3_socks5.addArtifactArg(websocket_h3_quic_go_client);
    const websocket_h3_socks5_step = b.step(
        "interop-websocket-h3-socks5",
        "Run RFC 9220 through an independent SOCKS5 UDP relay",
    );
    websocket_h3_socks5_step.dependOn(&websocket_h3_socks5.step);
    test_step.dependOn(&websocket_h3_socks5.step);
    const websocket_h3_quic_go_bench = b.addSystemCommand(
        &.{"tools/interop/websocket_h3_quic_go.sh"},
    );
    websocket_h3_quic_go_bench.addArtifactArg(
        websocket_h3_quic_go_client,
    );
    websocket_h3_quic_go_bench.addArtifactArg(
        websocket_h3_quic_go_server,
    );
    websocket_h3_quic_go_bench.addArg("--bench");
    if (b.args) |args| websocket_h3_quic_go_bench.addArgs(args);
    const websocket_h3_quic_go_bench_step = b.step(
        "bench-websocket-h3-quic-go",
        "Compare persistent RFC 9220 echo against quic-go",
    );
    websocket_h3_quic_go_bench_step.dependOn(
        &websocket_h3_quic_go_bench.step,
    );

    const http3_tquic_client = b.addExecutable(.{
        .name = "netz-http3-tquic-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_tquic_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_tquic_server = b.addExecutable(.{
        .name = "netz-http3-tquic-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_tquic_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_tquic = b.addSystemCommand(
        &.{"tools/interop/http3_tquic.sh"},
    );
    http3_tquic.addArtifactArg(http3_tquic_client);
    http3_tquic.addArtifactArg(http3_tquic_server);
    const http3_tquic_step = b.step(
        "interop-http3-tquic",
        "Run bidirectional HTTP/3 interoperability with tquic",
    );
    http3_tquic_step.dependOn(&http3_tquic.step);

    const http3_qpack_peer = b.addExecutable(.{
        .name = "netz-http3-qpack-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_qpack_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_qpack_quic_zig = b.addSystemCommand(
        &.{"tools/interop/http3_qpack_quic_zig.sh"},
    );
    http3_qpack_quic_zig.addArtifactArg(http3_qpack_peer);
    const http3_qpack_quic_zig_step = b.step(
        "interop-http3-qpack-quic-zig",
        "Decode speculative netz QPACK with quic-zig",
    );
    http3_qpack_quic_zig_step.dependOn(
        &http3_qpack_quic_zig.step,
    );

    const websocket_hyper_h2_client = b.addExecutable(.{
        .name = "netz-websocket-hyper-h2-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_hyper_h2_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const websocket_hyper_h2 = b.addSystemCommand(
        &.{"tools/interop/websocket_hyper_h2.sh"},
    );
    websocket_hyper_h2.addArtifactArg(websocket_hyper_h2_client);
    const websocket_hyper_h2_step = b.step(
        "interop-websocket-hyper-h2",
        "Run netz RFC 8441 WebSocket interop with an audited Hyper server",
    );
    websocket_hyper_h2_step.dependOn(&websocket_hyper_h2.step);
    const websocket_hyper_h2_server = b.addExecutable(.{
        .name = "netz-websocket-hyper-h2-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_hyper_h2_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const websocket_hyper_h2_bench = b.addSystemCommand(
        &.{"tools/interop/websocket_hyper_h2_bench.sh"},
    );
    websocket_hyper_h2_bench.addArtifactArg(websocket_hyper_h2_client);
    websocket_hyper_h2_bench.addArtifactArg(websocket_hyper_h2_server);
    if (b.args) |args| websocket_hyper_h2_bench.addArgs(args);
    const websocket_hyper_h2_bench_step = b.step(
        "bench-websocket-hyper-h2",
        "Compare persistent RFC 8441 echo against Hyper",
    );
    websocket_hyper_h2_bench_step.dependOn(
        &websocket_hyper_h2_bench.step,
    );

    const http1_hyper_client = b.addExecutable(.{
        .name = "netz-http1-hyper-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http1_hyper_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http1_hyper_server = b.addExecutable(.{
        .name = "netz-http1-hyper-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http1_hyper_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http1_hyper_interop = b.addSystemCommand(
        &.{"tools/interop/http1_hyper.sh"},
    );
    http1_hyper_interop.addArtifactArg(http1_hyper_client);
    http1_hyper_interop.addArtifactArg(http1_hyper_server);
    const http1_hyper_interop_step = b.step(
        "interop-http1-hyper",
        "Run bidirectional HTTP/1 body, trailer, and Expect interop with Hyper",
    );
    http1_hyper_interop_step.dependOn(&http1_hyper_interop.step);

    const http1_ocsp_client = b.addExecutable(.{
        .name = "netz-http1-ocsp-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http1_ocsp_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http1_ocsp_interop = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http1_ocsp_client.py",
    });
    http1_ocsp_interop.addArtifactArg(http1_ocsp_client);
    const http1_ocsp_interop_step = b.step(
        "interop-http1-ocsp",
        "Require good OpenSSL TLS 1.2/1.3 OCSP staples from the HTTP/1 client",
    );
    http1_ocsp_interop_step.dependOn(&http1_ocsp_interop.step);
    test_step.dependOn(&http1_ocsp_interop.step);

    const tls12_ticket_server = b.addExecutable(.{
        .name = "netz-tls12-ticket-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/tls12_ticket_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const tls12_ticket_client = b.addExecutable(.{
        .name = "netz-tls12-ticket-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/tls12_ticket_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const tls12_ticket_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_ticket_openssl.sh"},
    );
    tls12_ticket_openssl.addArtifactArg(tls12_ticket_server);
    tls12_ticket_openssl.addArtifactArg(tls12_ticket_client);
    const tls12_ticket_openssl_step = b.step(
        "interop-tls12-ticket-openssl",
        "Verify bidirectional TLS 1.2 RFC 5077 resumption with OpenSSL",
    );
    tls12_ticket_openssl_step.dependOn(&tls12_ticket_openssl.step);
    test_step.dependOn(&tls12_ticket_openssl.step);

    const tls12_client_auth_client = b.addExecutable(.{
        .name = "netz-tls12-client-auth-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/tls12_client_auth_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const tls12_client_auth_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_client_auth_openssl.sh"},
    );
    tls12_client_auth_openssl.addArtifactArg(tls12_client_auth_client);
    tls12_client_auth_openssl.addArg("tls12");
    const tls12_client_auth_openssl_step = b.step(
        "interop-tls12-client-auth-openssl",
        "Verify matching/unmatched TLS 1.2 client identity selection against OpenSSL",
    );
    tls12_client_auth_openssl_step.dependOn(
        &tls12_client_auth_openssl.step,
    );
    test_step.dependOn(&tls12_client_auth_openssl.step);

    const tls13_client_auth_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_client_auth_openssl.sh"},
    );
    tls13_client_auth_openssl.addArtifactArg(tls12_client_auth_client);
    tls13_client_auth_openssl.addArg("tls13");
    const tls13_client_auth_openssl_step = b.step(
        "interop-tls13-client-auth-openssl",
        "Verify matching/unmatched TLS 1.3 client identity selection against OpenSSL",
    );
    tls13_client_auth_openssl_step.dependOn(
        &tls13_client_auth_openssl.step,
    );
    test_step.dependOn(&tls13_client_auth_openssl.step);

    const tls13_ticket_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_ticket_openssl.sh"},
    );
    tls13_ticket_openssl.addArtifactArg(tls12_ticket_server);
    tls13_ticket_openssl.addArtifactArg(tls12_ticket_client);
    tls13_ticket_openssl.addArg("tls13");
    const tls13_ticket_openssl_step = b.step(
        "interop-tls13-ticket-openssl",
        "Verify bidirectional TLS 1.3 session-ticket resumption with OpenSSL",
    );
    tls13_ticket_openssl_step.dependOn(&tls13_ticket_openssl.step);
    test_step.dependOn(&tls13_ticket_openssl.step);
}
