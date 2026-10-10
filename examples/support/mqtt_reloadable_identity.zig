//! Ref-counted TLS server identity generations for the configured MQTT broker.
//!
//! A reload parses every configured certificate/key pair before publishing the
//! replacement set. Handshakes lease one generation without holding the set's
//! lock across network I/O, so a stalled client cannot block SIGHUP rotation.

const std = @import("std");
const netz = @import("netz");

const Identity = netz.tls.server_identity_file.Identity;
const IdentityLease = netz.tls.stream.ServerIdentityLease;
const IdentityProvider = netz.tls.stream.ServerIdentityProvider;

pub const Paths = struct {
    certificate_file: []const u8 = &.{},
    private_key_file: []const u8 = &.{},

    fn configured(self: Paths) !bool {
        if ((self.certificate_file.len == 0) !=
            (self.private_key_file.len == 0))
        {
            return error.IncompleteServerIdentity;
        }
        return self.certificate_file.len != 0;
    }
};

const Generation = struct {
    allocator: std.mem.Allocator,
    identity: Identity,
    references: std.atomic.Value(usize) = .init(1),

    fn load(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: Paths,
    ) !*Generation {
        const generation = try allocator.create(Generation);
        errdefer allocator.destroy(generation);
        generation.* = .{
            .allocator = allocator,
            .identity = try netz.tls.server_identity_file.load(
                allocator,
                io,
                dir,
                paths.certificate_file,
                paths.private_key_file,
            ),
        };
        return generation;
    }

    fn retain(self: *Generation) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0 and previous != std.math.maxInt(usize));
    }

    fn release(self: *Generation) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        const allocator = self.allocator;
        self.identity.deinit();
        self.* = undefined;
        allocator.destroy(self);
    }
};

const ProviderContext = struct {
    shared: *Shared,
    listener_index: usize,
};

const Shared = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    paths: []const Paths,
    current: []?*Generation,
    initial: []?*Generation,
    providers: []ProviderContext,
    lock: *std.Io.RwLock,
};

pub const PreparedReload = struct {
    shared: *Shared,
    generations: []?*Generation,

    pub fn deinit(self: *PreparedReload) void {
        if (self.generations.len == 0) return;
        releaseGenerations(self.shared.allocator, self.generations);
        self.generations = &.{};
    }
};

pub const RetiredGenerations = struct {
    shared: *Shared,
    generations: []?*Generation,

    pub fn deinit(self: *RetiredGenerations) void {
        releaseGenerations(self.shared.allocator, self.generations);
        self.generations = &.{};
    }
};

pub const Set = struct {
    shared: *Shared,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: []const Paths,
        lock: *std.Io.RwLock,
    ) !Set {
        if (paths.len == 0) return error.EmptyServerIdentityLayout;
        const shared = try allocator.create(Shared);
        errdefer allocator.destroy(shared);
        const current = try loadGenerations(allocator, io, dir, paths);
        errdefer releaseGenerations(allocator, current);
        const initial = try allocator.dupe(?*Generation, current);
        errdefer allocator.free(initial);
        for (initial) |generation| {
            if (generation) |value| value.retain();
        }
        errdefer for (initial) |generation| {
            if (generation) |value| value.release();
        };
        const providers = try allocator.alloc(ProviderContext, paths.len);
        errdefer allocator.free(providers);
        shared.* = .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .paths = paths,
            .current = current,
            .initial = initial,
            .providers = providers,
            .lock = lock,
        };
        for (providers, 0..) |*provider_context, index| {
            provider_context.* = .{
                .shared = shared,
                .listener_index = index,
            };
        }
        return .{ .shared = shared };
    }

    pub fn deinit(self: *Set) void {
        const shared = self.shared;
        releaseGenerations(shared.allocator, shared.current);
        releaseGenerations(shared.allocator, shared.initial);
        shared.allocator.free(shared.providers);
        const allocator = shared.allocator;
        shared.* = undefined;
        allocator.destroy(shared);
        self.* = undefined;
    }

    pub fn hasReloadableFiles(self: Set) bool {
        for (self.shared.current) |generation| {
            if (generation != null) return true;
        }
        return false;
    }

    pub fn provider(
        self: *Set,
        listener_index: usize,
    ) ?IdentityProvider {
        if (self.shared.current[listener_index] == null) return null;
        return .{
            .context = &self.shared.providers[listener_index],
            .acquire_fn = acquire,
        };
    }

    /// Stable compatibility identity retained until the set is destroyed.
    /// The provider supersedes it once the listener starts accepting.
    pub fn initialIdentity(
        self: *const Set,
        listener_index: usize,
    ) ?netz.mqtt.tls_runtime.ServerIdentity {
        const generation = self.shared.initial[listener_index] orelse
            return null;
        return generation.identity.serverIdentity();
    }

    pub fn prepareReload(self: *Set) !PreparedReload {
        return .{
            .shared = self.shared,
            .generations = try loadGenerations(
                self.shared.allocator,
                self.shared.io,
                self.shared.dir,
                self.shared.paths,
            ),
        };
    }

    pub fn commitReload(self: *Set, prepared: *PreparedReload) void {
        self.shared.lock.lockUncancelable(self.shared.io);
        var retired = self.swapPreparedReload(prepared);
        self.shared.lock.unlock(self.shared.io);
        retired.deinit();
    }

    /// Publish a prepared identity set while the shared policy lock is held
    /// for writing. Retired generations remain valid through active leases.
    pub fn swapPreparedReload(
        self: *Set,
        prepared: *PreparedReload,
    ) RetiredGenerations {
        std.debug.assert(prepared.shared == self.shared);
        std.debug.assert(prepared.generations.len != 0);
        const previous = self.shared.current;
        self.shared.current = prepared.generations;
        prepared.generations = &.{};
        return .{ .shared = self.shared, .generations = previous };
    }

    pub fn reload(self: *Set) !void {
        var prepared = try self.prepareReload();
        defer prepared.deinit();
        self.commitReload(&prepared);
    }

    fn acquire(context: *anyopaque) IdentityLease {
        const provider_context: *ProviderContext = @ptrCast(@alignCast(context));
        const shared = provider_context.shared;
        shared.lock.lockSharedUncancelable(shared.io);
        const generation = shared.current[provider_context.listener_index] orelse
            unreachable;
        generation.retain();
        const identity = generation.identity.serverIdentity();
        shared.lock.unlockShared(shared.io);
        return .{
            .identity = identity,
            .context = generation,
            .release_fn = releaseLease,
        };
    }

    fn releaseLease(context: ?*anyopaque) void {
        const generation: *Generation = @ptrCast(@alignCast(
            context orelse unreachable,
        ));
        generation.release();
    }
};

fn loadGenerations(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    paths: []const Paths,
) ![]?*Generation {
    const generations = try allocator.alloc(?*Generation, paths.len);
    errdefer allocator.free(generations);
    @memset(generations, null);
    var initialized: usize = 0;
    errdefer for (generations[0..initialized]) |generation| {
        if (generation) |value| value.release();
    };
    for (paths, 0..) |entry, index| {
        if (try entry.configured()) {
            generations[index] = try Generation.load(
                allocator,
                io,
                dir,
                entry,
            );
        }
        initialized = index + 1;
    }
    return generations;
}

fn releaseGenerations(
    allocator: std.mem.Allocator,
    generations: []?*Generation,
) void {
    for (generations) |generation| {
        if (generation) |value| value.release();
    }
    allocator.free(generations);
}

const test_certificate_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2Nh
    \\bGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIw
    \\EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAA
    \\RawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65
    \\oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2Nh
    \\bGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wX
    \\gSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6s
    \\MvbrhNjKU=
    \\-----END CERTIFICATE-----
;

const test_private_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCASNFZ4mrze
    \\8SNFZ4mrze8SNFZ4mrze8SNFZ4mrze8SNA==
    \\-----END PRIVATE KEY-----
;

test "reloadable MQTT identities retain old handshakes and roll back failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "server.crt",
        .data = test_certificate_pem,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "server.key",
        .data = test_private_key_pem,
    });
    const paths = [_]Paths{.{
        .certificate_file = "server.crt",
        .private_key_file = "server.key",
    }};
    var lock: std.Io.RwLock = .init;
    var identities = try Set.init(allocator, io, tmp.dir, &paths, &lock);
    defer identities.deinit();
    const provider = identities.provider(0).?;

    var old_lease = provider.acquire();
    defer old_lease.deinit();
    try old_lease.identity.validate();
    const old_certificate = old_lease.identity.certificate_chain[0].ptr;

    var prepared = try identities.prepareReload();
    defer prepared.deinit();
    identities.commitReload(&prepared);
    var current_lease = provider.acquire();
    defer current_lease.deinit();
    try current_lease.identity.validate();
    try std.testing.expect(
        old_certificate != current_lease.identity.certificate_chain[0].ptr,
    );
    try old_lease.identity.validate();

    try tmp.dir.writeFile(io, .{
        .sub_path = "server.crt",
        .data = "not a certificate\n",
    });
    try std.testing.expectError(error.InvalidPem, identities.reload());
    var rollback_lease = provider.acquire();
    defer rollback_lease.deinit();
    try rollback_lease.identity.validate();
    try std.testing.expectEqual(
        current_lease.identity.certificate_chain[0].ptr,
        rollback_lease.identity.certificate_chain[0].ptr,
    );
}
