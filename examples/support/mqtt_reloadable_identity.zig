//! Ref-counted TLS policy generations for the configured MQTT broker.
//!
//! A reload parses every configured server identity, client CA, and CRL before
//! publishing the replacement set. Handshakes lease one complete generation
//! without holding the set's lock across network I/O, so a stalled client
//! cannot block SIGHUP rotation or observe mixed TLS policy.

const std = @import("std");
const netz = @import("netz");

const Identity = netz.tls.server_identity_file.Identity;
const IdentityLease = netz.tls.stream.ServerIdentityLease;
const IdentityProvider = netz.tls.stream.ServerIdentityProvider;
const ClientAuthPolicy = netz.mqtt.tls_runtime.ClientAuthPolicy;
const ClientAuthRequirement = netz.mqtt.tls_runtime.ClientAuthRequirement;

pub const Paths = struct {
    certificate_file: []const u8 = &.{},
    private_key_file: []const u8 = &.{},
    private_key_password_file: []const u8 = &.{},
    client_ca_file: []const u8 = &.{},
    client_ca_path: []const u8 = &.{},
    crl_file: []const u8 = &.{},
    require_client_certificate: bool = false,

    fn configured(self: Paths) !bool {
        if ((self.certificate_file.len == 0) !=
            (self.private_key_file.len == 0))
        {
            return error.IncompleteServerIdentity;
        }
        if (self.certificate_file.len == 0 and
            (self.client_ca_file.len != 0 or
                self.client_ca_path.len != 0 or
                self.crl_file.len != 0 or
                self.private_key_password_file.len != 0))
        {
            return error.ClientAuthenticationWithoutServerIdentity;
        }
        if (self.crl_file.len != 0 and
            self.client_ca_file.len == 0 and
            self.client_ca_path.len == 0)
        {
            return error.CrlWithoutClientCa;
        }
        return self.certificate_file.len != 0;
    }
};

const Generation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: Identity,
    client_ca: ?netz.tls.client_ca_file.File,
    client_crl: ?netz.tls.client_crl_file.File,
    client_auth_requirement: ClientAuthRequirement,
    references: std.atomic.Value(usize) = .init(1),

    fn load(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: Paths,
    ) !*Generation {
        const generation = try allocator.create(Generation);
        errdefer allocator.destroy(generation);
        var identity = if (paths.private_key_password_file.len != 0)
            try netz.tls.server_identity_file.loadWithPasswordFile(
                allocator,
                io,
                dir,
                paths.certificate_file,
                paths.private_key_file,
                paths.private_key_password_file,
            )
        else
            try netz.tls.server_identity_file.load(
                allocator,
                io,
                dir,
                paths.certificate_file,
                paths.private_key_file,
            );
        errdefer identity.deinit();
        var client_ca: ?netz.tls.client_ca_file.File =
            if (paths.client_ca_path.len != 0)
                try netz.tls.client_ca_dir.loadCombined(
                    allocator,
                    io,
                    dir,
                    if (paths.client_ca_file.len != 0)
                        paths.client_ca_file
                    else
                        null,
                    paths.client_ca_path,
                )
            else if (paths.client_ca_file.len != 0)
                try netz.tls.client_ca_file.load(
                    allocator,
                    io,
                    dir,
                    paths.client_ca_file,
                )
            else
                null;
        errdefer if (client_ca) |*ca| ca.deinit();
        var client_crl: ?netz.tls.client_crl_file.File = if (paths.crl_file.len != 0)
            try netz.tls.client_crl_file.load(
                allocator,
                io,
                dir,
                paths.crl_file,
                if (client_ca) |*ca|
                    ca
                else
                    return error.CrlWithoutClientCa,
            )
        else
            null;
        errdefer if (client_crl) |*crl| crl.deinit();
        generation.* = .{
            .allocator = allocator,
            .io = io,
            .identity = identity,
            .client_ca = client_ca,
            .client_crl = client_crl,
            .client_auth_requirement = if (paths.require_client_certificate)
                .required
            else
                .optional,
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
        if (self.client_crl) |*crl| crl.deinit();
        if (self.client_ca) |*ca| ca.deinit();
        self.identity.deinit();
        self.* = undefined;
        allocator.destroy(self);
    }

    fn clientAuthPolicy(self: *Generation) ?ClientAuthPolicy {
        const client_ca = if (self.client_ca) |*ca| ca else return null;
        return .{
            .verifier = .{
                .verify_trust = verifyClientTrust,
                .context = self,
            },
            .certificate_authorities = client_ca.authorities(),
            .requirement = self.client_auth_requirement,
        };
    }

    fn verifyClientTrust(
        context: ?*anyopaque,
        trust_context: netz.tls.ClientCertificateTrustContext,
    ) anyerror!void {
        const self: *Generation = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        const client_ca = if (self.client_ca) |*ca|
            ca
        else
            return error.MissingClientCa;
        try client_ca.verifier(
            std.Io.Timestamp.now(self.io, .real).toSeconds(),
        ).verify(trust_context);
        if (self.client_crl) |*crl| {
            if (trust_context.chain.len == 0) return error.CrlNotFound;
            try crl.verifyLeaf(trust_context.chain[0]);
        }
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

    pub fn initialClientAuth(
        self: *const Set,
        listener_index: usize,
    ) ?ClientAuthPolicy {
        const generation = self.shared.initial[listener_index] orelse
            return null;
        return generation.clientAuthPolicy();
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
            .client_auth = generation.clientAuthPolicy(),
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

const test_client_ca_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBVTCB/KADAgECAgkAs84+0pSp5UkwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
    \\cXVpYy16aWcgaW50ZXJvcCBDQTAeFw0yNjAzMTIwNDI1MDdaFw0zNjAzMDkwNDI1
    \\MDdaMB4xHDAaBgNVBAMME3F1aWMtemlnIGludGVyb3AgQ0EwWTATBgcqhkjOPQIB
    \\BggqhkjOPQMBBwNCAAS3jQ8iTpDTZ87j4sfrPztu4hr8d/Ep3m9Vt/+QmhVtVdrC
    \\uL+E7wLBHXKqkY7oBWt7WMjuTJHfsMzaQwNQvFm/oyMwITAPBgNVHRMBAf8EBTAD
    \\AQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiAbTTSRHrX8prIw
    \\4IJHkUCOEjBHCjflLVAlc3MnopJ/1AIhAIOQS3USGjl6TbHMGvRt2gZUNe+HXjq5
    \\64pxXZ9qM6nG
    \\-----END CERTIFICATE-----
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
    try tmp.dir.writeFile(io, .{
        .sub_path = "clients.pem",
        .data = test_client_ca_pem,
    });
    const paths = [_]Paths{.{
        .certificate_file = "server.crt",
        .private_key_file = "server.key",
        .client_ca_file = "clients.pem",
        .require_client_certificate = true,
    }};
    var lock: std.Io.RwLock = .init;
    var identities = try Set.init(allocator, io, tmp.dir, &paths, &lock);
    defer identities.deinit();
    const provider = identities.provider(0).?;

    var old_lease = provider.acquire();
    defer old_lease.deinit();
    try old_lease.identity.validate();
    const old_certificate = old_lease.identity.certificate_chain[0].ptr;
    const old_authorities = old_lease.client_auth.?.certificate_authorities;
    try std.testing.expectEqual(ClientAuthRequirement.required, old_lease.client_auth.?.requirement);
    try std.testing.expectEqual(@as(usize, 1), old_authorities.len);

    var prepared = try identities.prepareReload();
    defer prepared.deinit();
    identities.commitReload(&prepared);
    var current_lease = provider.acquire();
    defer current_lease.deinit();
    try current_lease.identity.validate();
    try std.testing.expect(
        old_certificate != current_lease.identity.certificate_chain[0].ptr,
    );
    try std.testing.expect(
        old_authorities[0].ptr !=
            current_lease.client_auth.?.certificate_authorities[0].ptr,
    );
    try old_lease.identity.validate();
    try std.testing.expectEqual(@as(u8, 0x30), old_authorities[0][0]);

    try tmp.dir.writeFile(io, .{
        .sub_path = "clients.pem",
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
