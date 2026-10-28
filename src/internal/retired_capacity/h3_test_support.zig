//! Small endpoint-complete resource model for owning HTTP/3 pool cleanup.
const std = @import("std");
const real = @import("../../http3/runtime.zig");
const http3 = @import("../../http3/mod.zig");
const owning = @import("../../http3/runtime/handshake_client_pool.zig");
const budget_mod = @import("../connection_budget.zig");

pub const Client = struct {
    trace: *Trace,

    pub fn deinit(self: *Client) void {
        if (self.trace.drops == 0) {
            self.trace.dropped_before_budget_release = if (self.trace.budget) |budget| budget.connections == 1 else true;
        }
        self.trace.drops += 1;
    }

    pub fn isReusable(self: *const Client) bool {
        return self.trace.reusable;
    }
    pub fn peerOriginExcluded(_: *const Client, _: http3.Origin) bool {
        return false;
    }
    pub fn peerOriginSetAllows(_: *const Client, _: http3.Origin, _: http3.Origin) ?bool {
        return null;
    }
    pub fn peerCertificates(_: *const Client) ?[]const []const u8 {
        return null;
    }
};

pub const Runtime = struct {
    pub const HandshakeClient = Client;
    pub const Error = real.Error;
    pub const Limits = real.Limits;
    pub const HandshakeClientOptions = real.HandshakeClientOptions;
    pub const HandshakeServer = real.HandshakeServer;
    pub const EarlyRequestDisposition = real.EarlyRequestDisposition;
    pub const EarlyDataRetryReason = real.EarlyDataRetryReason;
    pub const PreparedEarlyRequest = real.PreparedEarlyRequest;
    pub const PreparedEarlyRequestOptions = real.PreparedEarlyRequestOptions;
    pub const UriRequestOptions = real.UriRequestOptions;
    pub const OwnedHandshakeResponse = real.OwnedHandshakeResponse;
    pub const RedirectedHandshakeResponse = real.RedirectedHandshakeResponse;
    pub const BatchHandshakeCancellationObserver = real.BatchHandshakeCancellationObserver;
    pub const BatchOwnedHandshakeResponseObserver = real.BatchOwnedHandshakeResponseObserver;
    pub const RedirectOptions = real.RedirectOptions;
    pub const RedirectError = real.RedirectError;
    pub const RedirectTimeoutError = real.RedirectTimeoutError;
    pub const ReceiveTimeoutError = real.ReceiveTimeoutError;
    pub const uriEndpoint = real.uriEndpoint;
    pub const uriRequestTargetAlloc = real.uriRequestTargetAlloc;
};

pub const Pool = owning.Pool(Runtime);

pub const Trace = struct {
    base: std.Io,
    reusable: bool = false,
    pool: ?*Pool = null,
    budget: ?*budget_mod.Budget = null,
    held_mutex: ?*std.Io.Mutex = null,
    close_during_connect: bool = false,
    failure: ?real.Error = null,
    called: bool = false,
    held: bool = false,
    drops: usize = 0,
    dropped_before_budget_release: bool = false,
    unbounded_waits: usize = 0,
    var active: ?*Trace = null;

    pub fn connector(self: *Trace) owning.Connector(Runtime) {
        return .{ .context = self, .client_identity_configured = false, .connect = connect };
    }

    fn connect(context: *anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.net.IpAddress, _: std.Uri, _: real.Limits) real.Error!Client {
        const self: *Trace = @ptrCast(@alignCast(context));
        self.called = true;
        if (self.close_during_connect) self.pool.?.close();
        if (self.held_mutex) |mutex| {
            mutex.lockUncancelable(self.base);
            self.held = true;
        }
        if (self.failure) |err| return err;
        return .{ .trace = self };
    }

    pub fn io(self: *Trace, table: *std.Io.VTable) std.Io {
        table.* = self.base.vtable.*;
        table.futexWaitUncancelable = waitUncancelable;
        active = self;
        return .{ .userdata = self.base.userdata, .vtable = table };
    }

    pub fn restore(self: *Trace) void {
        if (self.held) {
            _ = self.held_mutex.?.tryLock();
            self.held_mutex.?.unlock(self.base);
            self.held = false;
        }
        active = null;
    }

    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (self.held_mutex) |mutex| {
            const target: *const u32 = @ptrCast(&mutex.state.raw);
            if (pointer == target) {
                self.unbounded_waits += 1;
                mutex.state.store(.unlocked, .release);
                return;
            }
        }
        self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }
};
