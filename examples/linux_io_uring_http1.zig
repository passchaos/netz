const builtin = @import("builtin");
const std = @import("std");
const netz = @import("netz");

const linux = std.os.linux;
const posix = std.posix;

const UserData = enum(u64) {
    connect = 1,
    send = 2,
    recv = 3,
    close = 4,
};

pub fn main() !void {
    if (comptime builtin.os.tag != .linux) {
        std.debug.print("linux io_uring example is only available on Linux\n", .{});
        return;
    }

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http1.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.http1.runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            std.debug.print("io_uring example server received {s} {s}\n", .{
                request.request.method.string(),
                request.request.target,
            });

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "hello through linux io_uring",
                .request_method = request.request.method,
            });
        }
    };

    var ring = linux.IoUring.init(16, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => {
            std.debug.print("io_uring unavailable on this kernel/container: {s}\n", .{@errorName(err)});
            return;
        },
        else => |e| return e,
    };
    defer ring.deinit();

    const fd = try createTcpSocket();
    var fd_open = true;
    defer {
        if (fd_open) _ = linux.close(fd);
    }

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, server.address().ip4.port),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
    };
    _ = try ring.connect(@intFromEnum(UserData.connect), fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    _ = try submitOne(&ring, .connect);

    const request = try std.fmt.allocPrint(
        allocator,
        "GET /uring HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
        .{server.address().ip4.port},
    );
    defer allocator.free(request);
    try sendAll(&ring, fd, request);

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    var response = try receiveHttpResponse(&ring, allocator, &response_bytes, fd);
    defer response.deinit(allocator);

    _ = try ring.close(@intFromEnum(UserData.close), fd);
    _ = submitOne(&ring, .close) catch null;
    fd_open = false;

    thread.join();
    if (shared.err) |err| return err;
    std.debug.print("io_uring example client received {d}: {s}\n", .{ response.status, response.body });
}

fn createTcpSocket() !linux.fd_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM => error.SystemResources,
        .PROTONOSUPPORT => error.ProtocolUnsupportedBySystem,
        else => |errno| posix.unexpectedErrno(errno),
    };
}

fn submitOne(ring: *linux.IoUring, expected: UserData) !linux.io_uring_cqe {
    _ = try ring.submit_and_wait(1);
    const cqe = try ring.copy_cqe();
    if (cqe.user_data != @intFromEnum(expected)) return error.UnexpectedCompletion;
    if (cqe.err() != .SUCCESS) return error.IoUringOperationFailed;
    return cqe;
}

fn sendAll(ring: *linux.IoUring, fd: linux.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        _ = try ring.send(@intFromEnum(UserData.send), fd, bytes[offset..], 0);
        const cqe = try submitOne(ring, .send);
        if (cqe.res <= 0) return error.ConnectionClosed;
        offset += @intCast(cqe.res);
    }
}

fn receiveHttpResponse(
    ring: *linux.IoUring,
    allocator: std.mem.Allocator,
    response_bytes: *std.ArrayList(u8),
    fd: linux.fd_t,
) !netz.http1.Response {
    var buffer: [4096]u8 = undefined;
    while (true) {
        _ = try ring.recv(@intFromEnum(UserData.recv), fd, .{ .buffer = &buffer }, 0);
        const cqe = try submitOne(ring, .recv);
        if (cqe.res == 0) return error.ConnectionClosed;
        if (cqe.res < 0) return error.IoUringOperationFailed;
        try response_bytes.appendSlice(allocator, buffer[0..@intCast(cqe.res)]);

        return netz.http1.parseResponse(allocator, response_bytes.items, .{}) catch |err| switch (err) {
            error.BufferTooShort => continue,
            else => |e| return e,
        };
    }
}
