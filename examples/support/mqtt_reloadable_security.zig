//! Atomic password/ACL/CRL file reload for the Mosquitto-style broker example.
//!
//! Listener topology remains fixed for the process lifetime. A reload owns the
//! candidate password/ACL paths and parses every configured file into a
//! detached set before one write-locked swap. Callbacks hold the read lock
//! through password, ACL, CA, or CRL evaluation, so the previous generation is
//! destroyed only after all readers leave.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const Paths = struct {
    password_file: []const u8 = &.{},
    acl_file: []const u8 = &.{},
};

pub const ClientAuthPaths = struct {
    client_ca: ?*const netz.tls.client_ca_file.File = null,
    crl_file: []const u8 = &.{},
};

pub const PreparedReload = struct {
    security: *Security,
    paths: ?[]Paths,
    files: ?FileSet,
    client_crls: ?ClientCrlSet,

    pub fn deinit(self: *PreparedReload) void {
        if (self.files) |*files| files.deinit(self.security.allocator);
        if (self.client_crls) |*crls| crls.deinit(self.security.allocator);
        if (self.paths) |paths| deinitPaths(self.security.allocator, paths);
        self.paths = null;
        self.files = null;
        self.client_crls = null;
    }
};

pub const RetiredReload = struct {
    security: *Security,
    paths: []Paths,
    files: FileSet,
    client_crls: ?ClientCrlSet,

    /// Reauthorize a live connection against the replacement password files.
    /// Unchanged parsed credentials survive comments, ordering, and unrelated
    /// user edits; removed or modified credentials require a fresh CONNECT.
    pub fn stillAuthorizesConnection(
        context: *anyopaque,
        connection: mqtt.broker.ActiveConnectionAuthorization,
    ) bool {
        const self: *RetiredReload = @ptrCast(@alignCast(context));
        const listener_id = connection.listener_id orelse return true;
        const username = connection.username orelse return true;
        self.security.lock.lockSharedUncancelable(self.security.io);
        defer self.security.lock.unlockShared(self.security.io);

        for (self.security.listener_ids, 0..) |candidate, index| {
            if (@as(u64, candidate) != listener_id) continue;
            if (!self.security.listenerUsesPasswordAuthentication(index)) {
                continue;
            }
            // Listener IDs are caller-defined and need not be globally unique.
            // If any matching listener changed this user's credential, fail
            // closed rather than retaining a connection under ambiguous scope.
            if (!sameCredential(
                &self.files.passwords[
                    self.security.securityIndex(index)
                ],
                &self.security.files.passwords[
                    self.security.securityIndex(index)
                ],
                username,
            )) return false;
        }
        return true;
    }

    pub fn deinit(self: *RetiredReload) void {
        self.files.deinit(self.security.allocator);
        if (self.client_crls) |*crls| crls.deinit(self.security.allocator);
        deinitPaths(self.security.allocator, self.paths);
        self.* = undefined;
    }
};

fn sameCredential(
    previous: *const ?mqtt.password_file.File,
    current: *const ?mqtt.password_file.File,
    username: []const u8,
) bool {
    const old = if (previous.*) |*file| file else return current.* == null;
    const new = if (current.*) |*file| file else return false;
    return old.sameCredential(new, username);
}

const FileSet = struct {
    passwords: []?mqtt.password_file.File,
    acls: []?mqtt.acl_file.File,

    fn load(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: []const Paths,
    ) !FileSet {
        const passwords = try allocator.alloc(
            ?mqtt.password_file.File,
            paths.len,
        );
        errdefer allocator.free(passwords);
        @memset(passwords, null);
        var password_count: usize = 0;
        errdefer {
            for (passwords[0..password_count]) |*maybe_file| {
                if (maybe_file.*) |*file| file.deinit();
            }
        }
        const acls = try allocator.alloc(?mqtt.acl_file.File, paths.len);
        errdefer allocator.free(acls);
        @memset(acls, null);
        var acl_count: usize = 0;
        errdefer {
            for (acls[0..acl_count]) |*maybe_file| {
                if (maybe_file.*) |*file| file.deinit();
            }
        }

        for (paths, 0..) |entry, index| {
            if (entry.password_file.len != 0) {
                passwords[index] = try mqtt.password_file.load(
                    allocator,
                    io,
                    dir,
                    entry.password_file,
                );
            }
            password_count = index + 1;
            if (entry.acl_file.len != 0) {
                acls[index] = try mqtt.acl_file.load(
                    allocator,
                    io,
                    dir,
                    entry.acl_file,
                );
            }
            acl_count = index + 1;
        }
        return .{ .passwords = passwords, .acls = acls };
    }

    fn deinit(self: *FileSet, allocator: std.mem.Allocator) void {
        for (self.passwords) |*maybe_file| {
            if (maybe_file.*) |*file| file.deinit();
        }
        allocator.free(self.passwords);
        for (self.acls) |*maybe_file| {
            if (maybe_file.*) |*file| file.deinit();
        }
        allocator.free(self.acls);
        self.* = undefined;
    }
};

fn clonePaths(
    allocator: std.mem.Allocator,
    paths: []const Paths,
) std.mem.Allocator.Error![]Paths {
    const owned = try allocator.alloc(Paths, paths.len);
    @memset(owned, .{});
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |entry| {
            if (entry.password_file.len != 0) {
                allocator.free(@constCast(entry.password_file));
            }
            if (entry.acl_file.len != 0) {
                allocator.free(@constCast(entry.acl_file));
            }
        }
        allocator.free(owned);
    }
    for (paths, owned) |source, *destination| {
        destination.password_file = if (source.password_file.len == 0)
            &.{}
        else
            try allocator.dupe(u8, source.password_file);
        destination.acl_file = if (source.acl_file.len == 0)
            &.{}
        else
            allocator.dupe(u8, source.acl_file) catch |err| {
                if (destination.password_file.len != 0) {
                    allocator.free(@constCast(destination.password_file));
                    destination.password_file = &.{};
                }
                return err;
            };
        initialized += 1;
    }
    return owned;
}

fn deinitPaths(allocator: std.mem.Allocator, paths: []Paths) void {
    for (paths) |entry| {
        if (entry.password_file.len != 0) {
            allocator.free(@constCast(entry.password_file));
        }
        if (entry.acl_file.len != 0) {
            allocator.free(@constCast(entry.acl_file));
        }
    }
    allocator.free(paths);
}

const ClientCrlSet = struct {
    crls: []?netz.tls.client_crl_file.File,

    fn load(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: []const ClientAuthPaths,
    ) !ClientCrlSet {
        const crls = try allocator.alloc(
            ?netz.tls.client_crl_file.File,
            paths.len,
        );
        errdefer allocator.free(crls);
        @memset(crls, null);
        var initialized: usize = 0;
        errdefer for (crls[0..initialized]) |*maybe_crl| {
            if (maybe_crl.*) |*crl| crl.deinit();
        };

        for (paths, 0..) |entry, index| {
            if (entry.crl_file.len != 0) {
                const client_ca = entry.client_ca orelse
                    return error.CrlWithoutClientCa;
                crls[index] = try netz.tls.client_crl_file.load(
                    allocator,
                    io,
                    dir,
                    entry.crl_file,
                    client_ca,
                );
            }
            initialized = index + 1;
        }
        return .{ .crls = crls };
    }

    fn deinit(self: *ClientCrlSet, allocator: std.mem.Allocator) void {
        for (self.crls) |*maybe_crl| {
            if (maybe_crl.*) |*crl| crl.deinit();
        }
        allocator.free(self.crls);
        self.* = undefined;
    }
};

pub const Security = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    paths: []Paths,
    listener_ids: []const u64,
    per_listener_settings: bool,
    /// Per-listener eligibility for password authentication. The active file
    /// may appear or disappear across reload generations.
    password_authentication: []bool,
    allow_anonymous: []bool,
    admission_policies: []mqtt.broker.ListenerAdmissionSnapshot,
    files: FileSet,
    acl_enabled: []std.atomic.Value(bool),
    has_any_acl: std.atomic.Value(bool),
    client_auth_paths: []const ClientAuthPaths = &.{},
    client_crls: ?ClientCrlSet = null,
    lock: std.Io.RwLock = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: []const Paths,
        listener_ids: []const u64,
        per_listener_settings: bool,
    ) !Security {
        if (paths.len == 0 or listener_ids.len == 0 or
            (per_listener_settings and paths.len != listener_ids.len) or
            (!per_listener_settings and paths.len != 1))
        {
            return error.InvalidSecurityLayout;
        }
        const allow_anonymous = try allocator.alloc(bool, listener_ids.len);
        errdefer allocator.free(allow_anonymous);
        @memset(allow_anonymous, false);
        const password_authentication = try allocator.alloc(
            bool,
            listener_ids.len,
        );
        errdefer allocator.free(password_authentication);
        @memset(password_authentication, true);
        const admission_policies = try allocator.alloc(
            mqtt.broker.ListenerAdmissionSnapshot,
            listener_ids.len,
        );
        errdefer allocator.free(admission_policies);
        for (admission_policies) |*policy| {
            policy.* = mqtt.broker.ListenerAdmissionSnapshot.init(
                true,
                "netz-",
            ) catch unreachable;
        }
        const owned_paths = try clonePaths(allocator, paths);
        errdefer deinitPaths(allocator, owned_paths);
        const files = try FileSet.load(allocator, io, dir, owned_paths);
        errdefer {
            var owned_files = files;
            owned_files.deinit(allocator);
        }
        const acl_enabled = try allocator.alloc(
            std.atomic.Value(bool),
            files.acls.len,
        );
        errdefer allocator.free(acl_enabled);
        var has_any_acl = false;
        for (files.acls, acl_enabled) |maybe_acl, *enabled| {
            const present = maybe_acl != null;
            enabled.* = .init(present);
            has_any_acl = has_any_acl or present;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .paths = owned_paths,
            .listener_ids = listener_ids,
            .per_listener_settings = per_listener_settings,
            .password_authentication = password_authentication,
            .allow_anonymous = allow_anonymous,
            .admission_policies = admission_policies,
            .files = files,
            .acl_enabled = acl_enabled,
            .has_any_acl = .init(has_any_acl),
        };
    }

    pub fn deinit(self: *Security) void {
        if (self.client_crls) |*crls| crls.deinit(self.allocator);
        self.files.deinit(self.allocator);
        deinitPaths(self.allocator, self.paths);
        self.allocator.free(self.acl_enabled);
        self.allocator.free(self.password_authentication);
        self.allocator.free(self.allow_anonymous);
        self.allocator.free(self.admission_policies);
        self.* = undefined;
    }

    pub fn setPasswordAuthentication(
        self: *Security,
        enabled: []const bool,
    ) !void {
        if (enabled.len != self.listener_ids.len) {
            return error.InvalidSecurityLayout;
        }
        @memcpy(self.password_authentication, enabled);
    }

    pub fn setAllowAnonymous(
        self: *Security,
        enabled: []const bool,
    ) !void {
        if (enabled.len != self.listener_ids.len) {
            return error.InvalidSecurityLayout;
        }
        self.lock.lockUncancelable(self.io);
        self.setAllowAnonymousLocked(enabled);
        self.lock.unlock(self.io);
    }

    pub fn setAllowAnonymousLocked(
        self: *Security,
        enabled: []const bool,
    ) void {
        std.debug.assert(enabled.len == self.allow_anonymous.len);
        @memcpy(self.allow_anonymous, enabled);
    }

    pub fn setAdmissionPolicies(
        self: *Security,
        policies: []const mqtt.broker.ListenerAdmissionSnapshot,
    ) !void {
        if (policies.len != self.listener_ids.len) {
            return error.InvalidSecurityLayout;
        }
        self.lock.lockUncancelable(self.io);
        self.setAdmissionPoliciesLocked(policies);
        self.lock.unlock(self.io);
    }

    pub fn setAdmissionPoliciesLocked(
        self: *Security,
        policies: []const mqtt.broker.ListenerAdmissionSnapshot,
    ) void {
        std.debug.assert(policies.len == self.admission_policies.len);
        @memcpy(self.admission_policies, policies);
    }

    /// Attach the immutable client-CA topology and load every configured CRL
    /// before TLS listeners are opened. The paths and CA files must outlive
    /// this Security value.
    pub fn configureClientAuth(
        self: *Security,
        paths: []const ClientAuthPaths,
    ) !void {
        if (self.client_crls != null) return error.ClientAuthAlreadyConfigured;
        if (paths.len != self.listener_ids.len) {
            return error.InvalidClientAuthLayout;
        }
        self.client_crls = try ClientCrlSet.load(
            self.allocator,
            self.io,
            self.dir,
            paths,
        );
        self.client_auth_paths = paths;
    }

    /// Parse a detached replacement without changing the active policy. This
    /// lets the broker validate TLS identities and authorization files before
    /// committing either part of one SIGHUP transaction.
    pub fn prepareReload(self: *Security) !PreparedReload {
        return self.prepareReloadWithPaths(self.paths);
    }

    pub fn prepareReloadWithPaths(
        self: *Security,
        paths: []const Paths,
    ) !PreparedReload {
        if (paths.len != self.paths.len) return error.InvalidSecurityLayout;
        const owned_paths = try clonePaths(self.allocator, paths);
        errdefer deinitPaths(self.allocator, owned_paths);
        var files = try FileSet.load(
            self.allocator,
            self.io,
            self.dir,
            owned_paths,
        );
        errdefer files.deinit(self.allocator);
        const client_crls = if (self.client_crls != null)
            try ClientCrlSet.load(
                self.allocator,
                self.io,
                self.dir,
                self.client_auth_paths,
            )
        else
            null;
        return .{
            .security = self,
            .paths = owned_paths,
            .files = files,
            .client_crls = client_crls,
        };
    }

    pub fn commitReload(
        self: *Security,
        prepared: *PreparedReload,
    ) void {
        self.lock.lockUncancelable(self.io);
        var retired = self.swapPreparedReload(prepared);
        self.lock.unlock(self.io);
        retired.deinit();
    }

    /// Publish a prepared replacement while the caller holds `lock` for
    /// writing. The detached return value must be destroyed after unlocking.
    pub fn swapPreparedReload(
        self: *Security,
        prepared: *PreparedReload,
    ) RetiredReload {
        std.debug.assert(prepared.security == self);
        const replacement_paths = prepared.paths orelse unreachable;
        prepared.paths = null;
        const replacement = prepared.files orelse unreachable;
        prepared.files = null;
        const replacement_crls = prepared.client_crls;
        prepared.client_crls = null;
        const previous_paths = self.paths;
        self.paths = replacement_paths;
        const previous = self.files;
        self.files = replacement;
        var has_any_acl = false;
        for (self.files.acls, self.acl_enabled) |maybe_acl, *enabled| {
            const present = maybe_acl != null;
            enabled.store(present, .release);
            has_any_acl = has_any_acl or present;
        }
        self.has_any_acl.store(has_any_acl, .release);
        const previous_crls = self.client_crls;
        self.client_crls = replacement_crls;
        return .{
            .security = self,
            .paths = previous_paths,
            .files = previous,
            .client_crls = previous_crls,
        };
    }

    pub fn reload(self: *Security) !void {
        var prepared = try self.prepareReload();
        defer prepared.deinit();
        self.commitReload(&prepared);
    }

    pub fn listenerPolicy(
        self: *Security,
        listener_index: usize,
    ) ListenerPolicy {
        return .{
            .security = self,
            .listener_index = listener_index,
        };
    }

    pub fn clientAuthPolicy(
        self: *Security,
        listener_index: usize,
    ) ClientAuthPolicy {
        std.debug.assert(self.client_crls != null);
        std.debug.assert(listener_index < self.client_auth_paths.len);
        std.debug.assert(
            self.client_auth_paths[listener_index].client_ca != null,
        );
        return .{ .security = self, .listener_index = listener_index };
    }

    pub fn sourceAccessControl(
        self: *Security,
    ) ?mqtt.broker.AccessControlHandler {
        return .{
            .context = self,
            .authorize_publish = allowSourcePublish,
            .authorize_subscribe = allowSourceSubscribe,
            .authorize_will = authorizeSourceWill,
            .authorize_retained_source = authorizeRetainedSource,
        };
    }

    fn securityIndex(self: *const Security, listener_index: usize) usize {
        std.debug.assert(listener_index < self.listener_ids.len);
        return if (self.per_listener_settings) listener_index else 0;
    }

    fn listenerUsesPasswordAuthentication(
        self: *const Security,
        listener_index: usize,
    ) bool {
        return self.password_authentication[listener_index];
    }

    fn aclAllows(
        self: *Security,
        listener_index: usize,
        operation: mqtt.acl_file.Operation,
        identity: mqtt.acl_file.Identity,
        topic: []const u8,
    ) bool {
        const index = self.securityIndex(listener_index);
        if (!self.acl_enabled[index].load(.acquire)) return true;
        self.lock.lockSharedUncancelable(self.io);
        defer self.lock.unlockShared(self.io);
        const file = self.files.acls[index] orelse return true;
        return file.allows(operation, identity, topic);
    }

    fn sourceAclAllows(
        self: *Security,
        listener_id: ?u64,
        identity: mqtt.acl_file.Identity,
        topic: []const u8,
    ) bool {
        if (!self.has_any_acl.load(.acquire)) return true;
        self.lock.lockSharedUncancelable(self.io);
        defer self.lock.unlockShared(self.io);
        const index = if (!self.per_listener_settings)
            0
        else blk: {
            const id = listener_id orelse return false;
            var found: ?usize = null;
            for (self.listener_ids, 0..) |candidate, candidate_index| {
                if (candidate != id) continue;
                if (found != null) return false;
                found = candidate_index;
            }
            break :blk found orelse return false;
        };
        const file = self.files.acls[index] orelse return true;
        return file.allows(.write, identity, topic);
    }

    fn allowSourcePublish(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Publish,
    ) bool {
        return true;
    }

    fn allowSourceSubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Subscription,
    ) bool {
        return true;
    }

    fn authorizeSourceWill(
        context: *anyopaque,
        publication: mqtt.broker.WillAuthorization,
    ) bool {
        const self: *Security = @ptrCast(@alignCast(context));
        return self.sourceAclAllows(
            publication.listener_id,
            .{
                .client_id = publication.client_id,
                .username = publication.username,
            },
            publication.topic,
        );
    }

    fn authorizeRetainedSource(
        context: *anyopaque,
        publication: mqtt.broker.RetainedSourceAuthorization,
    ) bool {
        const self: *Security = @ptrCast(@alignCast(context));
        return self.sourceAclAllows(
            publication.listener_id,
            .{
                .client_id = publication.client_id,
                .username = publication.username,
            },
            publication.topic,
        );
    }
};

pub const ClientAuthPolicy = struct {
    security: *Security,
    listener_index: usize,

    pub fn clientVerifier(
        self: *ClientAuthPolicy,
    ) mqtt.tls_runtime.ClientCertificateVerifier {
        return .{
            .verify_trust = verifyTrust,
            .context = self,
        };
    }

    fn verifyTrust(
        context: ?*anyopaque,
        trust_context: netz.tls.ClientCertificateTrustContext,
    ) anyerror!void {
        const self: *ClientAuthPolicy = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        const security = self.security;
        security.lock.lockSharedUncancelable(security.io);
        defer security.lock.unlockShared(security.io);

        const paths = security.client_auth_paths[self.listener_index];
        const client_ca = paths.client_ca orelse return error.MissingClientCa;
        try client_ca.verifier(
            std.Io.Timestamp.now(security.io, .real).toSeconds(),
        ).verify(trust_context);
        const crls = security.client_crls orelse
            return error.MissingClientCrlSet;
        if (crls.crls[self.listener_index]) |crl| {
            if (trust_context.chain.len == 0) return error.CrlNotFound;
            try crl.verifyLeaf(trust_context.chain[0]);
        }
    }
};

pub const ListenerPolicy = struct {
    security: *Security,
    listener_index: usize,

    pub fn authorizeConnect(context: *anyopaque, connect: mqtt.Connect) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        self.security.lock.lockSharedUncancelable(self.security.io);
        defer self.security.lock.unlockShared(self.security.io);
        if (!self.security.listenerUsesPasswordAuthentication(
            self.listener_index,
        )) return true;
        const maybe_file = &self.security.files.passwords[
            self.security.securityIndex(self.listener_index)
        ];
        const file = if (maybe_file.*) |*value|
            value
        else
            return self.security.allow_anonymous[self.listener_index];
        const username = connect.username orelse
            return self.security.allow_anonymous[self.listener_index];
        const password = connect.password orelse return false;
        return file.verify(username, password);
    }

    pub fn admissionProvider(
        self: *ListenerPolicy,
    ) mqtt.broker.ListenerAdmissionProvider {
        return .{ .context = self, .snapshot = admissionSnapshot };
    }

    fn admissionSnapshot(
        context: *anyopaque,
    ) mqtt.broker.ListenerAdmissionSnapshot {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        self.security.lock.lockSharedUncancelable(self.security.io);
        defer self.security.lock.unlockShared(self.security.io);
        return self.security.admission_policies[self.listener_index];
    }

    pub fn accessControl(
        self: *ListenerPolicy,
    ) ?mqtt.broker.ListenerAccessControlHandler {
        return .{
            .context = self,
            .authorize_publish = authorizePublish,
            .authorize_subscribe = authorizeSubscribe,
            .authorize_unsubscribe = authorizeUnsubscribe,
            .authorize_delivery = authorizeDelivery,
            .authorize_will = authorizeWill,
        };
    }

    fn authorizePublish(
        context: *anyopaque,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        return self.security.aclAllows(
            self.listener_index,
            .write,
            identityForConnect(connect),
            publish.topic,
        );
    }

    fn authorizeSubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Subscription,
    ) bool {
        return true;
    }

    fn authorizeUnsubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: []const u8,
    ) bool {
        return true;
    }

    fn authorizeDelivery(
        context: *anyopaque,
        delivery: mqtt.broker.DeliveryAuthorization,
    ) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        return self.security.aclAllows(
            self.listener_index,
            .read,
            .{
                .client_id = delivery.client_id,
                .username = delivery.username,
            },
            delivery.topic,
        );
    }

    fn authorizeWill(
        context: *anyopaque,
        connect: mqtt.Connect,
        will: mqtt.LastWill,
    ) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        return self.security.aclAllows(
            self.listener_index,
            .write,
            identityForConnect(connect),
            will.topic,
        );
    }
};

fn identityForConnect(connect: mqtt.Connect) mqtt.acl_file.Identity {
    return .{ .client_id = connect.client_id, .username = connect.username };
}

const password_hash = "$7$1000$MDEyMzQ1Njc4OWFi$" ++
    "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+" ++
    "KMfRf9YJT//3a9+kZTXUdA==";

test "reloadable MQTT security swaps atomically and rolls back failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "old:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "acl",
        .data = "user old\ntopic write before/#\n",
    });
    const paths = [_]Paths{.{
        .password_file = "passwords",
        .acl_file = "acl",
    }};
    const listener_ids = [_]u64{1883};
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        false,
    );
    defer security.deinit();
    var policy = security.listenerPolicy(0);
    var connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = "client",
        .username = "old",
        .password = "password",
    };
    try std.testing.expectError(
        error.InvalidSecurityLayout,
        security.setAllowAnonymous(&.{ true, false }),
    );
    const authenticated_username = connect.username;
    const authenticated_password = connect.password;
    connect.username = null;
    connect.password = null;
    try std.testing.expect(!ListenerPolicy.authorizeConnect(&policy, connect));
    try security.setAllowAnonymous(&.{true});
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    try security.setAllowAnonymous(&.{false});
    try std.testing.expectError(
        error.InvalidSecurityLayout,
        security.setAdmissionPolicies(&.{
            try mqtt.broker.ListenerAdmissionSnapshot.init(true, "one-"),
            try mqtt.broker.ListenerAdmissionSnapshot.init(false, "two-"),
        }),
    );
    try security.setAdmissionPolicies(&.{
        try mqtt.broker.ListenerAdmissionSnapshot.init(false, "initial-"),
    });
    const admission = policy.admissionProvider();
    var snapshot = admission.snapshot(admission.context);
    try std.testing.expect(!snapshot.allow_zero_length_client_id);
    try std.testing.expectEqualStrings(
        "initial-",
        snapshot.autoClientIdPrefix(),
    );
    try security.setAdmissionPolicies(&.{
        try mqtt.broker.ListenerAdmissionSnapshot.initWithCapabilities(
            true,
            "reloaded-",
            .at_most_once,
            7,
            3,
            4,
            .{ .v3_1 = false, .v3_1_1 = true, .v5 = true },
        ),
    });
    snapshot = admission.snapshot(admission.context);
    try std.testing.expect(snapshot.allow_zero_length_client_id);
    try std.testing.expectEqualStrings(
        "reloaded-",
        snapshot.autoClientIdPrefix(),
    );
    try std.testing.expectEqual(mqtt.QoS.at_most_once, snapshot.maximum_qos.?);
    try std.testing.expectEqual(
        @as(?u16, 7),
        snapshot.maximum_keep_alive_seconds,
    );
    try std.testing.expectEqual(@as(u16, 3), snapshot.topic_alias_maximum);
    try std.testing.expectEqual(@as(u16, 4), snapshot.max_outgoing_topic_aliases);
    try std.testing.expect(!snapshot.accepted_protocol_versions.v3_1);
    connect.username = authenticated_username;
    connect.password = authenticated_password;
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    try std.testing.expect(ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "before/value",
            .packet_id = null,
            .payload = "value",
        },
    ));
    const source_access = security.sourceAccessControl().?;
    try std.testing.expect(source_access.authorize_retained_source.?(
        source_access.context,
        .{
            .client_id = "client",
            .username = "old",
            .listener_id = null,
            .topic = "before/value",
            .payload = "value",
            .qos = .at_most_once,
            .retain = true,
            .properties = &.{},
        },
    ));
    try std.testing.expect(!source_access.authorize_retained_source.?(
        source_access.context,
        .{
            .client_id = "client",
            .username = "old",
            .listener_id = 1883,
            .topic = "after/value",
            .payload = "value",
            .qos = .at_most_once,
            .retain = true,
            .properties = &.{},
        },
    ));

    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "new:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "acl",
        .data = "user old\ntopic write after/#\n" ++
            "user new\ntopic write after/#\n",
    });
    try security.reload();
    try std.testing.expect(!ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "new";
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "old";
    try std.testing.expect(!ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "before/value",
            .packet_id = null,
            .payload = "value",
        },
    ));
    try std.testing.expect(ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "after/value",
            .packet_id = null,
            .payload = "value",
        },
    ));

    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "third:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "acl",
        .data = "unsupported entry\n",
    });
    try std.testing.expectError(error.InvalidDirective, security.reload());
    connect.username = "new";
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "third";
    try std.testing.expect(!ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "old";
    try std.testing.expect(ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "after/value",
            .packet_id = null,
            .payload = "value",
        },
    ));
    try std.testing.expect(source_access.authorize_retained_source.?(
        source_access.context,
        .{
            .client_id = "client",
            .username = "old",
            .listener_id = 1883,
            .topic = "after/value",
            .payload = "value",
            .qos = .at_most_once,
            .retain = true,
            .properties = &.{},
        },
    ));
}

test "reloadable MQTT security adds and swaps per-listener file paths" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "first.passwords",
        .data = "first:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "second.passwords",
        .data = "second:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "first.acl",
        .data = "user first\ntopic write first/#\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "second.acl",
        .data = "user second\ntopic write second/#\n",
    });
    const initial_paths = [_]Paths{ .{}, .{} };
    const listener_ids = [_]u64{ 1883, 1884 };
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &initial_paths,
        &listener_ids,
        true,
    );
    defer security.deinit();
    try security.setAllowAnonymous(&.{ true, true });
    var first_policy = security.listenerPolicy(0);
    var second_policy = security.listenerPolicy(1);
    const first_access = first_policy.accessControl().?;
    const second_access = second_policy.accessControl().?;

    const candidate_paths = [_]Paths{
        .{
            .password_file = "first.passwords",
            .acl_file = "first.acl",
        },
        .{
            .password_file = "second.passwords",
            .acl_file = "second.acl",
        },
    };
    var prepared = try security.prepareReloadWithPaths(&candidate_paths);
    defer prepared.deinit();
    security.commitReload(&prepared);
    try security.setAllowAnonymous(&.{ false, false });

    const first_connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = "first-client",
        .username = "first",
        .password = "password",
    };
    const second_connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = "second-client",
        .username = "second",
        .password = "password",
    };
    try std.testing.expect(ListenerPolicy.authorizeConnect(
        &first_policy,
        first_connect,
    ));
    try std.testing.expect(!ListenerPolicy.authorizeConnect(
        &first_policy,
        second_connect,
    ));
    try std.testing.expect(ListenerPolicy.authorizeConnect(
        &second_policy,
        second_connect,
    ));
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "first/value",
        .packet_id = null,
        .payload = "value",
    };
    try std.testing.expect(first_access.authorize_publish.?(
        first_access.context,
        first_connect,
        publish,
    ));
    try std.testing.expect(!second_access.authorize_publish.?(
        second_access.context,
        second_connect,
        publish,
    ));

    const missing_paths = [_]Paths{
        .{ .password_file = "missing.passwords" },
        candidate_paths[1],
    };
    try std.testing.expectError(
        error.FileNotFound,
        security.prepareReloadWithPaths(&missing_paths),
    );
    try std.testing.expect(ListenerPolicy.authorizeConnect(
        &second_policy,
        second_connect,
    ));
}

test "reloadable MQTT security reauthorizes credentials per listener" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const changed_hash = "$6$MDEyMzQ1Njc4OWFi$" ++
        "QQ3PWSJ3IyGPP66YMDh3aUdVyS29efC2oPtFLnz5O/EXQO4dovrApaaZv32acQ3b" ++
        "0Lt02H8GBYcsYpkBYYcERg==";
    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "stable:" ++ password_hash ++ "\n" ++
            "changed:" ++ password_hash ++ "\n" ++
            "removed:" ++ password_hash ++ "\n",
    });
    const paths = [_]Paths{.{ .password_file = "passwords" }};
    const listener_ids = [_]u64{1883};
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        false,
    );
    defer security.deinit();

    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "changed:" ++ changed_hash ++ "\n" ++
            "stable:" ++ password_hash ++ "\n",
    });
    var prepared = try security.prepareReload();
    defer prepared.deinit();
    security.lock.lockUncancelable(io);
    var retired = security.swapPreparedReload(&prepared);
    security.lock.unlock(io);
    defer retired.deinit();

    try std.testing.expect(RetiredReload.stillAuthorizesConnection(
        &retired,
        .{ .username = "stable", .listener_id = 1883 },
    ));
    try std.testing.expect(!RetiredReload.stillAuthorizesConnection(
        &retired,
        .{ .username = "changed", .listener_id = 1883 },
    ));
    try std.testing.expect(!RetiredReload.stillAuthorizesConnection(
        &retired,
        .{ .username = "removed", .listener_id = 1883 },
    ));
    try std.testing.expect(RetiredReload.stillAuthorizesConnection(
        &retired,
        .{ .listener_id = 1883 },
    ));
    try std.testing.expect(RetiredReload.stillAuthorizesConnection(
        &retired,
        .{ .username = "changed", .listener_id = 2883 },
    ));
    try security.setPasswordAuthentication(&.{false});
    try std.testing.expect(RetiredReload.stillAuthorizesConnection(
        &retired,
        .{ .username = "changed", .listener_id = 1883 },
    ));
}

test "reloadable MQTT security selects unique retained source listener" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "first.acl",
        .data = "user writer\ntopic write first/#\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "second.acl",
        .data = "user writer\ntopic write second/#\n",
    });
    const paths = [_]Paths{
        .{ .acl_file = "first.acl" },
        .{ .acl_file = "second.acl" },
    };
    const listener_ids = [_]u64{ 1883, 1884 };
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        true,
    );
    defer security.deinit();
    const access = security.sourceAccessControl().?;
    try std.testing.expect(authorizeRetained(&access, 1883, "first/value"));
    try std.testing.expect(!authorizeRetained(&access, 1884, "first/value"));
    try std.testing.expect(!authorizeRetained(&access, null, "first/value"));
}

test "reloadable MQTT security rejects ambiguous retained source listener" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "first.acl",
        .data = "user writer\ntopic write allowed/#\n",
    });
    const paths = [_]Paths{
        .{ .acl_file = "first.acl" },
        .{},
    };
    const listener_ids = [_]u64{ 1883, 1883 };
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        true,
    );
    defer security.deinit();
    const access = security.sourceAccessControl().?;
    try std.testing.expect(!authorizeRetained(
        &access,
        1883,
        "allowed/value",
    ));
}

fn authorizeRetained(
    access: *const mqtt.broker.AccessControlHandler,
    listener_id: ?u64,
    topic: []const u8,
) bool {
    return access.authorize_retained_source.?(access.context, .{
        .client_id = "publisher",
        .username = "writer",
        .listener_id = listener_id,
        .topic = topic,
        .payload = "value",
        .qos = .at_most_once,
        .retain = true,
        .properties = &.{},
    });
}
