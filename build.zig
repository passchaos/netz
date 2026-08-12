const std = @import("std");
const builtin = @import("builtin");

const required_zig_version = "0.16.0";

pub fn build(b: *std.Build) void {
    comptime {
        if (!std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) {
            @compileError("netz requires Zig " ++ required_zig_version ++ "; found " ++ builtin.zig_version_string);
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const vail_dep = b.dependency("vail", .{
        .target = target,
        .optimize = optimize,
    });

    const netz_mod = b.addModule("netz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "vail", .module = vail_dep.module("vail") }},
    });

    const lib = b.addLibrary(.{
        .name = "netz",
        .root_module = netz_mod,
    });
    b.installArtifact(lib);

    const lib_tests = b.addTest(.{ .root_module = netz_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const package_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/package_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_package_tests = b.addRunArtifact(package_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_package_tests.step);

    const example_specs = [_]struct {
        exe_name: []const u8,
        path: []const u8,
        run_step: []const u8,
        description: []const u8,
    }{
        .{
            .exe_name = "netz-http1-hello",
            .path = "examples/http1_hello.zig",
            .run_step = "run-http1-hello",
            .description = "Run the HTTP/1 local client/server example",
        },
        .{
            .exe_name = "netz-http2-h2c",
            .path = "examples/http2_h2c.zig",
            .run_step = "run-http2-h2c",
            .description = "Run the HTTP/2 h2c local client/server example",
        },
        .{
            .exe_name = "netz-http3-handshake",
            .path = "examples/http3_handshake.zig",
            .run_step = "run-http3-handshake",
            .description = "Run the local HTTP/3 client/server handshake example",
        },
        .{
            .exe_name = "netz-websocket-echo",
            .path = "examples/websocket_echo.zig",
            .run_step = "run-websocket-echo",
            .description = "Run the WebSocket local echo example",
        },
        .{
            .exe_name = "netz-bench-mqtt-router",
            .path = "examples/bench_mqtt_router.zig",
            .run_step = "bench-mqtt-router",
            .description = "Benchmark MQTT router trie matching against a linear scan",
        },
        .{
            .exe_name = "netz-bench-http1-parse",
            .path = "examples/bench_http1_parse.zig",
            .run_step = "bench-http1-parse",
            .description = "Benchmark HTTP/1 borrowed head parsing against owned parsing",
        },
        .{
            .exe_name = "netz-bench-http2-hpack",
            .path = "examples/bench_http2_hpack.zig",
            .run_step = "bench-http2-hpack",
            .description = "Benchmark HTTP/2 HPACK stateful compression against stateless helpers",
        },
        .{
            .exe_name = "netz-bench-http2-h2c",
            .path = "examples/bench_http2_h2c.zig",
            .run_step = "bench-http2-h2c",
            .description = "Benchmark HTTP/2 h2c persistent request/response round trips",
        },
        .{
            .exe_name = "netz-bench-http3-dev",
            .path = "examples/bench_http3_dev.zig",
            .run_step = "bench-http3-dev",
            .description = "Benchmark HTTP/3 cleartext development request/response round trips",
        },
        .{
            .exe_name = "netz-bench-http3-handshake-transfer",
            .path = "examples/bench_http3_handshake_transfer.zig",
            .run_step = "bench-http3-handshake-transfer",
            .description = "Benchmark HTTP/3 real-handshake paced upload throughput",
        },
        .{
            .exe_name = "netz-http3-fetch",
            .path = "examples/http3_fetch.zig",
            .run_step = "run-http3-fetch",
            .description = "Fetch the default public endpoint over HTTP/3",
        },
        .{
            .exe_name = "netz-bench-http3-capsule",
            .path = "examples/bench_http3_capsule.zig",
            .run_step = "bench-http3-capsule",
            .description = "Benchmark HTTP/3 Capsule Protocol parsing and caller-buffer encoding",
        },
        .{
            .exe_name = "netz-bench-http3-qpack",
            .path = "examples/bench_http3_qpack.zig",
            .run_step = "bench-http3-qpack",
            .description = "Benchmark HTTP/3 QPACK dynamic field-section encoding",
        },
        .{
            .exe_name = "netz-bench-webtransport-datagram",
            .path = "examples/bench_webtransport_datagram.zig",
            .run_step = "bench-webtransport-datagram",
            .description = "Benchmark WebTransport datagram round trips over HTTP/3",
        },
        .{
            .exe_name = "netz-bench-quic-short-packet",
            .path = "examples/bench_quic_short_packet.zig",
            .run_step = "bench-quic-short-packet",
            .description = "Benchmark QUIC short packet in-place sealing against allocating sealing",
        },
        .{
            .exe_name = "netz-bench-quic-padding-parse",
            .path = "examples/bench_quic_padding_parse.zig",
            .run_step = "bench-quic-padding-parse",
            .description = "Benchmark long QUIC PADDING frame parsing",
        },
        .{
            .exe_name = "netz-bench-quic-lb",
            .path = "examples/bench_quic_lb.zig",
            .run_step = "bench-quic-lb",
            .description = "Benchmark draft-21 QUIC-LB encrypted server routing",
        },
        .{
            .exe_name = "netz-bench-quic-udp-batch",
            .path = "examples/bench_quic_udp_batch.zig",
            .run_step = "bench-quic-udp-batch",
            .description = "Benchmark QUIC UDP_SEGMENT batches against sendmmsg",
        },
        .{
            .exe_name = "netz-bench-quic-one-rtt-send",
            .path = "examples/bench_quic_one_rtt_send.zig",
            .run_step = "bench-quic-one-rtt-send",
            .description = "Benchmark QUIC 1-RTT batched protection and send",
        },
        .{
            .exe_name = "netz-bench-quic-one-rtt-receive",
            .path = "examples/bench_quic_one_rtt_receive.zig",
            .run_step = "bench-quic-one-rtt-receive",
            .description = "Benchmark QUIC 1-RTT UDP_GRO batch receive",
        },
        .{
            .exe_name = "netz-bench-quic-ack-ranges",
            .path = "examples/bench_quic_ack_ranges.zig",
            .run_step = "bench-quic-ack-ranges",
            .description = "Benchmark QUIC ACK range generation with caller storage",
        },
        .{
            .exe_name = "netz-bench-quic-stream-window",
            .path = "examples/bench_quic_stream_window.zig",
            .run_step = "bench-quic-stream-window",
            .description = "Benchmark bounded QUIC receive stream compaction",
        },
        .{
            .exe_name = "netz-bench-quic-ticket-keyring",
            .path = "examples/bench_quic_ticket_keyring.zig",
            .run_step = "bench-quic-ticket-keyring",
            .description = "Benchmark stateless QUIC session ticket seal/open",
        },
    };
    const linux_example_specs = [_]struct {
        exe_name: []const u8,
        path: []const u8,
        run_step: []const u8,
        description: []const u8,
    }{
        .{
            .exe_name = "netz-linux-io-uring-http1",
            .path = "examples/linux_io_uring_http1.zig",
            .run_step = "run-linux-io-uring-http1",
            .description = "Run the Linux io_uring HTTP/1 raw transport example",
        },
        .{
            .exe_name = "netz-linux-io-uring-http1-server",
            .path = "examples/linux_io_uring_http1_server.zig",
            .run_step = "run-linux-io-uring-http1-server",
            .description = "Run the Linux io_uring HTTP/1 server example",
        },
        .{
            .exe_name = "netz-linux-io-uring-websocket",
            .path = "examples/linux_io_uring_websocket.zig",
            .run_step = "run-linux-io-uring-websocket",
            .description = "Run the Linux io_uring WebSocket client example",
        },
    };

    const examples_step = b.step("examples", "Build all examples");
    const bench_step = b.step("bench", "Run all native protocol benchmarks");
    for (example_specs) |spec| {
        const exe = b.addExecutable(.{
            .name = spec.exe_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(spec.path),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "netz", .module = netz_mod }},
            }),
        });
        examples_step.dependOn(&exe.step);

        const run = b.addRunArtifact(exe);
        if (b.args) |args| run.addArgs(args);
        const run_step = b.step(spec.run_step, spec.description);
        run_step.dependOn(&run.step);
        if (std.mem.startsWith(u8, spec.run_step, "bench-")) {
            bench_step.dependOn(&run.step);
        }
    }
    if (target.result.os.tag == .linux) {
        for (linux_example_specs) |spec| {
            const exe = b.addExecutable(.{
                .name = spec.exe_name,
                .root_module = b.createModule(.{
                    .root_source_file = b.path(spec.path),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{.{ .name = "netz", .module = netz_mod }},
                }),
            });
            examples_step.dependOn(&exe.step);

            const run = b.addRunArtifact(exe);
            if (b.args) |args| run.addArgs(args);
            const run_step = b.step(spec.run_step, spec.description);
            run_step.dependOn(&run.step);
        }
    }
}
