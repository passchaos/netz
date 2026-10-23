//! Bridge Session admission's final Session Present/ClientID decision to one
//! owned CONNACK prepared before the Session commit.

const std = @import("std");
const runtime = @import("../runtime.zig");

pub const Preparation = struct {
    pending: *runtime.PendingAcceptedClient,
    options: runtime.AcceptOptions,
    prepared: ?runtime.PreparedAcceptance = null,

    pub fn prepare(self: *Preparation, session_present: bool, assigned_id: ?[]const u8) runtime.Error!void {
        std.debug.assert(self.prepared == null);
        var options = self.options;
        options.session_present = session_present;
        if (assigned_id) |id| options.assigned_client_identifier = id;
        self.prepared = try self.pending.prepareFinish(options);
    }

    pub fn validateDeadline(self: *Preparation) runtime.Error!void {
        try self.prepared.?.validateDeadline();
    }

    pub fn finish(self: *Preparation) runtime.Error!runtime.AcceptedClient {
        return self.pending.finishPrepared(&self.prepared.?);
    }

    pub fn deinit(self: *Preparation) void {
        if (self.prepared) |*prepared| prepared.deinit();
        self.* = undefined;
    }
};
