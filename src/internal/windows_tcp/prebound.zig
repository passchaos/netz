//! ConnectEx ownership for a socket whose source tuple was already installed.
const std = @import("std");
const zio = @import("zio");
const windows = std.os.windows;
const Encoded = @import("../socket_address/winsock.zig").Encoded;
const net = std.Io.net;
const Overlapped = extern struct {
    internal: usize = 0,
    internal_high: usize = 0,
    offset: u32 = 0,
    offset_high: u32 = 0,
    hEvent: ?windows.HANDLE = null,
};

const native = struct {
    extern "kernel32" fn CreateEventW(?*anyopaque, c_int, c_int, ?[*:0]const u16) callconv(.winapi) ?windows.HANDLE;
    extern "kernel32" fn CancelIoEx(windows.HANDLE, *Overlapped) callconv(.winapi) c_int;
    extern "kernel32" fn RegisterWaitForSingleObject(*windows.HANDLE, windows.HANDLE, *const fn (?*anyopaque, u8) callconv(.winapi) void, ?*anyopaque, u32, u32) callconv(.winapi) c_int;
    extern "kernel32" fn UnregisterWaitEx(windows.HANDLE, windows.HANDLE) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAIoctl(*opaque {}, u32, *const anyopaque, u32, *anyopaque, u32, *u32, ?*anyopaque, ?*anyopaque) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetOverlappedResult(*opaque {}, *Overlapped, *u32, c_int, *u32) callconv(.winapi) c_int;
    extern "ws2_32" fn setsockopt(*opaque {}, c_int, c_int, ?[*]const u8, c_int) callconv(.winapi) c_int;
};
const ConnectEx = *const fn (*opaque {}, *const anyopaque, c_int, ?*const anyopaque, u32, ?*u32, *Overlapped) callconv(.winapi) c_int;

const Wait = struct {
    io: std.Io,
    socket: net.Socket.Handle,
    overlapped: *Overlapped,
    done: std.Io.Event = .unset,
    result: net.IpAddress.ConnectError!void = error.Canceled,

    fn complete(context: ?*anyopaque, _: u8) callconv(.winapi) void {
        const state: *Wait = @ptrCast(@alignCast(context.?));
        var bytes: u32 = 0;
        var flags: u32 = 0;
        state.result = if (native.WSAGetOverlappedResult(@ptrCast(state.socket), state.overlapped, &bytes, 0, &flags) != 0) {} else wsaError(native.WSAGetLastError());
        state.done.set(state.io);
    }
};

pub fn connect(io: std.Io, socket: net.Socket.Handle, address: net.IpAddress, timeout: zio.Timeout) net.IpAddress.ConnectError!void {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    var guid: windows.GUID = .{ .Data1 = 0x25a207b9, .Data2 = 0xddf3, .Data3 = 0x4660, .Data4 = .{ 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e } };
    var connect_ex: ConnectEx = undefined;
    var returned: u32 = 0;
    if (native.WSAIoctl(@ptrCast(socket), 0xc8000006, &guid, @sizeOf(windows.GUID), @ptrCast(&connect_ex), @sizeOf(ConnectEx), &returned, null, null) != 0) return wsaError(native.WSAGetLastError());
    if (returned != @sizeOf(ConnectEx)) return error.Unexpected;
    const event = native.CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
    defer windows.CloseHandle(event);
    var overlapped: Overlapped = .{};
    // The low bit prevents a completion packet from entering zio's IOCP with
    // an OVERLAPPED that is owned by this independent operation.
    overlapped.hEvent = @ptrFromInt(@intFromPtr(event) | 1);
    var state: Wait = .{ .io = io, .socket = socket, .overlapped = &overlapped };
    var wait_handle: windows.HANDLE = undefined;
    if (native.RegisterWaitForSingleObject(&wait_handle, event, Wait.complete, &state, 0xffffffff, 0x00000008) == 0) return error.SystemResources;
    var issued = false;
    defer {
        if (issued and !state.done.isSet()) {
            _ = native.CancelIoEx(socket, &overlapped);
            // A canceled caller remains a cooperative waiter until the kernel
            // releases every reference to its OVERLAPPED and address storage.
            state.done.waitUncancelable(io);
        }
        _ = native.UnregisterWaitEx(wait_handle, @ptrFromInt(std.math.maxInt(usize)));
    }
    const encoded = Encoded.init(address);
    if (connect_ex(@ptrCast(socket), &encoded.bytes, @intCast(encoded.len), null, 0, null, &overlapped) == 0) {
        const err = native.WSAGetLastError();
        if (err != 997) return wsaError(err);
    }
    issued = true;
    switch (timeout.toDeadline()) {
        .none => try state.done.wait(io),
        .deadline => |deadline| try state.done.waitTimeout(io, .{ .deadline = .{ .clock = .awake, .raw = .{ .nanoseconds = @intCast(deadline.toNanoseconds()) } } }),
        .duration => unreachable,
    }
    try state.result;
    if (native.setsockopt(@ptrCast(socket), 0xffff, 0x7010, null, 0) != 0) return wsaError(native.WSAGetLastError());
}

fn wsaError(value: c_int) net.IpAddress.ConnectError {
    return switch (value) {
        995 => error.Canceled,
        10013 => error.AccessDenied,
        10047 => error.AddressFamilyUnsupported,
        10049 => error.AddressUnavailable,
        10051 => error.NetworkUnreachable,
        10054 => error.ConnectionResetByPeer,
        10055 => error.SystemResources,
        10060 => error.Timeout,
        10061 => error.ConnectionRefused,
        10065 => error.HostUnreachable,
        else => error.Unexpected,
    };
}
