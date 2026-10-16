//! Owned RFC 6265 / RFC6265bis Cookie store for the unified HTTP client.
//!
//! The jar is intentionally explicit and single-owner. It consumes every
//! Set-Cookie field independently, deep-owns accepted state, and renders only
//! the Cookie field value into caller or allocator-owned storage. Applications
//! sharing one jar across tasks must serialize access at their ownership layer.

const std = @import("std");
const client_types = @import("../client/types.zig");
const http_method = @import("../../internal/http_method.zig");
const netscape = @import("netscape.zig");
const syntax = @import("syntax.zig");
const snapshot = @import("snapshot.zig");

const net = std.Io.net;

pub const maximum_cookie_bytes: usize = 4_096;
pub const maximum_partition_site_bytes: usize = net.HostName.max_len + 10;

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidUri,
    BufferTooShort,
    HeaderTooLarge,
    InvalidPartitionKey,
};
pub const SnapshotError = Error || snapshot.Error;
pub const SnapshotFileError = SnapshotError || snapshot.FileError;
pub const max_snapshot_bytes = snapshot.max_snapshot_bytes;
pub const NetscapeOptions = netscape.Options;
pub const NetscapeError = SnapshotError || netscape.Error;
pub const NetscapeFileError = NetscapeError || snapshot.FileError;

/// RFC6265bis Lax-by-default uses `.default`, including the bounded unsafe-
/// navigation compatibility window configured on the jar.
pub const SameSite = syntax.SameSite;

pub const SiteContext = enum { same_site, cross_site };

/// Caller-supplied browser/storage partition. `top_level_site` must be a
/// schemeful site serialization such as `https://example.com`, using a
/// caller-resolved registrable domain (or IP literal), with no port, path,
/// query, fragment, or userinfo. Netz validates and canonicalizes it but does
/// not bundle a potentially stale Public Suffix List.
pub const PartitionKey = struct {
    top_level_site: []const u8,
    /// Separate a same-site top-level document embedded below a cross-site
    /// ancestor from a genuinely same-site ancestor chain.
    has_cross_site_ancestor: bool = false,
};

pub const RequestContext = struct {
    site: SiteContext = .same_site,
    top_level_navigation: bool = false,
    method: []const u8 = "GET",
    /// False models a non-HTTP API and excludes HttpOnly cookies.
    http_api: bool = true,
    partition_key: ?PartitionKey = null,
};

pub const StoreContext = struct {
    site: SiteContext = .same_site,
    top_level_navigation: bool = false,
    http_api: bool = true,
    partition_key: ?PartitionKey = null,
};

pub const PublicSuffixChecker = struct {
    context: ?*anyopaque = null,
    is_public_suffix: *const fn (?*anyopaque, []const u8) bool,

    fn matches(self: PublicSuffixChecker, domain: []const u8) bool {
        return self.is_public_suffix(self.context, domain);
    }
};

/// Domain-cookie policy is explicit because an industry-grade public suffix
/// decision requires a regularly refreshed external dataset. URI hosts and
/// Domain attributes use canonical ASCII; callers must supply IDNA A-labels
/// for internationalized names.
pub const DomainPolicy = union(enum) {
    /// Secure default: reject every Set-Cookie carrying Domain.
    host_only,
    /// RFC domain matching without a public suffix database.
    unchecked,
    /// Apply RFC domain matching plus the caller's current PSL checker.
    checked: PublicSuffixChecker,
};

pub const Config = struct {
    max_cookies: usize = 3_000,
    max_cookies_per_domain: usize = 180,
    max_partitioned_cookies_per_domain: usize = 50,
    max_cookie_bytes: usize = maximum_cookie_bytes,
    max_header_bytes: usize = 16 * 1024,
    max_lifetime_seconds: u32 = 400 * std.time.s_per_day,
    domain_policy: DomainPolicy = .host_only,
    /// RFC6265bis optional Lax-allowing-unsafe compatibility window for a
    /// cookie whose SameSite attribute was omitted.
    lax_allowing_unsafe_seconds: u32 = 120,
};

pub const StoreResult = enum { stored, replaced, deleted, ignored };

pub const StoreSummary = struct {
    stored: usize = 0,
    replaced: usize = 0,
    deleted: usize = 0,
    ignored: usize = 0,

    fn add(self: *StoreSummary, result: StoreResult) void {
        switch (result) {
            .stored => self.stored += 1,
            .replaced => self.replaced += 1,
            .deleted => self.deleted += 1,
            .ignored => self.ignored += 1,
        }
    }
};

/// Validate that `uri_text` can be used as an HTTP or WebSocket Cookie scope
/// without reading or mutating a Jar. Connection-establishing adapters use
/// this preflight to reject invalid configuration before network I/O.
pub fn validateScopeUri(uri_text: []const u8) Error!void {
    var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
    _ = try parseOrigin(uri_text, &host_buffer);
}

const Cookie = struct {
    name: []u8,
    value: []u8,
    domain: []u8,
    path: []u8,
    expires_at: ?i64,
    secure: bool,
    http_only: bool,
    host_only: bool,
    partition_site: ?[]u8,
    partition_secure: bool,
    partition_cross_site_ancestor: bool,
    same_site: SameSite,
    created_at: i64,
    creation_order: u64,
    last_access_order: u64,

    fn deinit(self: *Cookie, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        allocator.free(self.domain);
        allocator.free(self.path);
        if (self.partition_site) |site| allocator.free(site);
        self.* = undefined;
    }
};

pub const Jar = struct {
    allocator: std.mem.Allocator,
    config: Config,
    cookies: std.ArrayList(Cookie) = .empty,
    sequence: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
    ) Error!Jar {
        if (config.max_cookies == 0 or
            config.max_cookies_per_domain == 0 or
            config.max_partitioned_cookies_per_domain == 0 or
            config.max_cookie_bytes == 0 or
            config.max_cookie_bytes > maximum_cookie_bytes or
            config.max_header_bytes == 0 or
            config.max_lifetime_seconds == 0)
        {
            return error.InvalidConfig;
        }
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Jar) void {
        self.clear();
        self.cookies.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Jar) void {
        for (self.cookies.items) |*cookie| cookie.deinit(self.allocator);
        self.cookies.clearRetainingCapacity();
    }

    pub fn count(self: *const Jar) usize {
        return self.cookies.items.len;
    }

    pub fn removeExpired(self: *Jar, now_unix_seconds: i64) usize {
        var removed: usize = 0;
        var index: usize = self.cookies.items.len;
        while (index != 0) {
            index -= 1;
            if (!expired(self.cookies.items[index], now_unix_seconds)) continue;
            self.removeAt(index);
            removed += 1;
        }
        return removed;
    }

    /// Remove every non-persistent cookie at the application's session
    /// boundary while retaining Max-Age/Expires state.
    pub fn endSession(self: *Jar) usize {
        var removed: usize = 0;
        var index: usize = self.cookies.items.len;
        while (index != 0) {
            index -= 1;
            if (self.cookies.items[index].expires_at != null) continue;
            self.removeAt(index);
            removed += 1;
        }
        return removed;
    }

    /// Encode persistent, non-expired cookies with full SameSite, host-only,
    /// creation, and access metadata. Session cookies are intentionally absent.
    pub fn encodeSnapshot(
        self: *const Jar,
        now_unix_seconds: i64,
        out: *std.ArrayList(u8),
    ) SnapshotError!void {
        return snapshot.encode(
            self.cookies.items,
            self.sequence,
            now_unix_seconds,
            out,
            self.allocator,
        );
    }

    /// Transactionally replace the jar from a complete validated snapshot.
    /// Any parse, policy, capacity, duplicate, or allocation failure leaves
    /// the active jar byte-for-byte unchanged.
    pub fn restoreSnapshot(
        self: *Jar,
        bytes: []const u8,
        now_unix_seconds: i64,
    ) SnapshotError!void {
        var decoded = try snapshot.decode(
            self.allocator,
            bytes,
            self.config.max_cookies,
        );
        defer decoded.deinit();
        try self.installDecoded(&decoded, now_unix_seconds);
    }

    pub fn saveSnapshotAtomic(
        self: *const Jar,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        now_unix_seconds: i64,
    ) SnapshotFileError!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try self.encodeSnapshot(now_unix_seconds, &encoded);
        try snapshot.saveAtomic(io, dir, sub_path, encoded.items);
    }

    pub fn loadSnapshot(
        self: *Jar,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        now_unix_seconds: i64,
    ) SnapshotFileError!void {
        const encoded = try snapshot.loadAlloc(
            self.allocator,
            io,
            dir,
            sub_path,
        );
        defer self.allocator.free(encoded);
        try self.restoreSnapshot(encoded, now_unix_seconds);
    }

    /// Export curl/Netscape cookies.txt after an explicit acknowledgement that
    /// SameSite and original creation/access metadata cannot be represented.
    pub fn encodeNetscapeLossy(
        self: *const Jar,
        now_unix_seconds: i64,
        options: NetscapeOptions,
        out: *std.ArrayList(u8),
    ) NetscapeError!void {
        return netscape.encode(
            self.cookies.items,
            now_unix_seconds,
            options,
            out,
            self.allocator,
        );
    }

    /// Transactionally replace the jar from curl/Netscape cookies.txt. Every
    /// imported SameSite value becomes Default and times are regenerated.
    pub fn restoreNetscapeLossy(
        self: *Jar,
        bytes: []const u8,
        now_unix_seconds: i64,
        options: NetscapeOptions,
    ) NetscapeError!void {
        var decoded = try netscape.decode(
            self.allocator,
            bytes,
            self.config.max_cookies,
            now_unix_seconds,
            options,
        );
        defer decoded.deinit();
        try self.installDecoded(&decoded, now_unix_seconds);
    }

    pub fn saveNetscapeAtomicLossy(
        self: *const Jar,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        now_unix_seconds: i64,
        options: NetscapeOptions,
    ) NetscapeFileError!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try self.encodeNetscapeLossy(now_unix_seconds, options, &encoded);
        try snapshot.saveAtomic(io, dir, sub_path, encoded.items);
    }

    pub fn loadNetscapeLossy(
        self: *Jar,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        now_unix_seconds: i64,
        options: NetscapeOptions,
    ) NetscapeFileError!void {
        const encoded = try snapshot.loadAlloc(
            self.allocator,
            io,
            dir,
            sub_path,
        );
        defer self.allocator.free(encoded);
        try self.restoreNetscapeLossy(encoded, now_unix_seconds, options);
    }

    fn installDecoded(
        self: *Jar,
        decoded: *snapshot.Decoded,
        now_unix_seconds: i64,
    ) SnapshotError!void {
        var replacement = try Jar.init(self.allocator, self.config);
        errdefer replacement.deinit();
        try replacement.cookies.ensureTotalCapacity(
            self.allocator,
            decoded.records.len,
        );
        var maximum_sequence = decoded.sequence;
        for (decoded.records) |*record| {
            if (record.expires_at) |deadline| {
                if (deadline <= now_unix_seconds) continue;
            }
            try validateSnapshotRecord(record.*, self.config);
            const record_partition_key: ?NormalizedPartitionKey =
                if (record.partitioned) .{
                    .site = record.partition_site,
                    .secure = record.partition_secure,
                    .has_cross_site_ancestor = record.partition_cross_site_ancestor,
                } else null;
            if (replacement.find(
                record.name,
                record.domain,
                record.path,
                record.host_only,
                record_partition_key,
            ) != null) return error.CorruptSnapshot;
            const maximum_expiry = std.math.add(
                i64,
                now_unix_seconds,
                @as(i64, self.config.max_lifetime_seconds),
            ) catch std.math.maxInt(i64);
            replacement.cookies.appendAssumeCapacity(.{
                .name = record.name,
                .value = record.value,
                .domain = record.domain,
                .path = record.path,
                .expires_at = if (record.expires_at) |deadline|
                    @min(deadline, maximum_expiry)
                else
                    null,
                .secure = record.secure,
                .http_only = record.http_only,
                .host_only = record.host_only,
                .partition_site = if (record.partitioned)
                    record.partition_site
                else
                    null,
                .partition_secure = record.partition_secure,
                .partition_cross_site_ancestor = record.partition_cross_site_ancestor,
                .same_site = @enumFromInt(record.same_site),
                .created_at = record.created_at,
                .creation_order = record.creation_order,
                .last_access_order = record.last_access_order,
            });
            if (!record.partitioned) {
                self.allocator.free(record.partition_site);
            }
            record.transferred = true;
            maximum_sequence = @max(
                maximum_sequence,
                @max(record.creation_order, record.last_access_order),
            );
            replacement.restoreRequestOrder(
                replacement.cookies.items.len - 1,
            );
            if (replacement.domainCount(
                record.domain,
                record_partition_key,
            ) > if (record.partitioned)
                self.config.max_partitioned_cookies_per_domain
            else
                self.config.max_cookies_per_domain)
            {
                return error.SnapshotLimitExceeded;
            }
        }
        replacement.sequence = maximum_sequence;
        var retired = self.*;
        self.* = replacement;
        retired.deinit();
    }

    pub fn storeSetCookie(
        self: *Jar,
        uri_text: []const u8,
        value: []const u8,
        now_unix_seconds: i64,
    ) Error!StoreResult {
        return self.storeSetCookieWithContext(
            uri_text,
            value,
            now_unix_seconds,
            .{},
        );
    }

    pub fn storeSetCookieWithContext(
        self: *Jar,
        uri_text: []const u8,
        value: []const u8,
        now_unix_seconds: i64,
        context: StoreContext,
    ) Error!StoreResult {
        var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const origin = try parseOrigin(uri_text, &host_buffer);
        var partition_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const partition_key = try normalizedPartitionKey(
            context.partition_key,
            &partition_buffer,
        );
        return self.storeForOrigin(
            origin,
            value,
            now_unix_seconds,
            context,
            partition_key,
        );
    }

    /// Consume every Set-Cookie field from a unified H1/H2/H3 response.
    /// Invalid individual fields are counted as ignored; an allocation error
    /// stops processing after earlier independent fields have committed.
    pub fn storeResponse(
        self: *Jar,
        response: client_types.OwnedResponse,
        uri_text: []const u8,
        now_unix_seconds: i64,
        context: StoreContext,
    ) Error!StoreSummary {
        var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const origin = try parseOrigin(uri_text, &host_buffer);
        var partition_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const partition_key = try normalizedPartitionKey(
            context.partition_key,
            &partition_buffer,
        );
        var summary: StoreSummary = .{};
        var values = response.headerValues("set-cookie");
        while (values.next()) |field| {
            summary.add(try self.storeForOrigin(
                origin,
                field.value,
                now_unix_seconds,
                context,
                partition_key,
            ));
        }
        return summary;
    }

    /// Store cookies against the final URI selected by a bounded redirect
    /// chain, never the initiating origin.
    pub fn storeRedirectedResponse(
        self: *Jar,
        response: client_types.RedirectedResponse,
        now_unix_seconds: i64,
        context: StoreContext,
    ) Error!StoreSummary {
        return self.storeResponse(
            response.response,
            response.final_uri,
            now_unix_seconds,
            context,
        );
    }

    /// Render the Cookie field value. Output is untouched on BufferTooShort.
    pub fn cookieHeaderValueInto(
        self: *Jar,
        uri_text: []const u8,
        now_unix_seconds: i64,
        context: RequestContext,
        out: []u8,
    ) Error![]u8 {
        var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const origin = try parseOrigin(uri_text, &host_buffer);
        var partition_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const partition_key = try normalizedPartitionKey(
            context.partition_key,
            &partition_buffer,
        );
        _ = self.removeExpired(now_unix_seconds);
        const needed = try self.headerValueLength(
            origin,
            now_unix_seconds,
            context,
            partition_key,
        );
        if (needed > out.len) return error.BufferTooShort;
        return self.writeHeaderValue(
            origin,
            now_unix_seconds,
            context,
            partition_key,
            out[0..needed],
        );
    }

    pub fn cookieHeaderValueAlloc(
        self: *Jar,
        allocator: std.mem.Allocator,
        uri_text: []const u8,
        now_unix_seconds: i64,
        context: RequestContext,
    ) Error![]u8 {
        var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const origin = try parseOrigin(uri_text, &host_buffer);
        var partition_buffer: [net.HostName.max_len + 2]u8 = undefined;
        const partition_key = try normalizedPartitionKey(
            context.partition_key,
            &partition_buffer,
        );
        _ = self.removeExpired(now_unix_seconds);
        const needed = try self.headerValueLength(
            origin,
            now_unix_seconds,
            context,
            partition_key,
        );
        const out = try allocator.alloc(u8, needed);
        errdefer allocator.free(out);
        return self.writeHeaderValue(
            origin,
            now_unix_seconds,
            context,
            partition_key,
            out,
        );
    }

    fn storeForOrigin(
        self: *Jar,
        origin: Origin,
        value: []const u8,
        now: i64,
        context: StoreContext,
        partition_key: ?NormalizedPartitionKey,
    ) Error!StoreResult {
        _ = self.removeExpired(now);
        var parsed = syntax.parse(
            value,
            self.config.max_cookie_bytes,
            now,
        ) orelse
            return .ignored;
        if (parsed.http_only and !context.http_api) return .ignored;
        if (parsed.secure and !origin.secure) return .ignored;
        if (parsed.same_site != .none and
            context.site == .cross_site and
            !context.top_level_navigation)
        {
            return .ignored;
        }
        if (parsed.same_site == .none and !parsed.secure) return .ignored;
        if (parsed.partitioned and !parsed.secure) return .ignored;
        const stored_partition_key = if (parsed.partitioned)
            partition_key orelse return .ignored
        else
            null;
        if (parsed.expires_at) |deadline| {
            const maximum = std.math.add(
                i64,
                now,
                @as(i64, self.config.max_lifetime_seconds),
            ) catch std.math.maxInt(i64);
            if (deadline > maximum) parsed.expires_at = maximum;
        }

        var domain = origin.host;
        var host_only = true;
        var domain_buffer: [net.HostName.max_len]u8 = undefined;
        if (parsed.domain) |raw_domain| {
            if (origin.is_ip) return .ignored;
            switch (self.config.domain_policy) {
                .host_only => return .ignored,
                else => {},
            }
            if (trim(raw_domain).len != 0) {
                const candidate_domain = normalizedDomain(
                    raw_domain,
                    &domain_buffer,
                ) orelse
                    return .ignored;
                if (!domainMatches(origin.host, candidate_domain)) {
                    return .ignored;
                }
                switch (self.config.domain_policy) {
                    .host_only => unreachable,
                    .unchecked => {
                        domain = candidate_domain;
                        host_only = false;
                    },
                    .checked => |checker| {
                        if (checker.matches(candidate_domain)) {
                            if (!std.ascii.eqlIgnoreCase(
                                origin.host,
                                candidate_domain,
                            )) return .ignored;
                        } else {
                            domain = candidate_domain;
                            host_only = false;
                        }
                    },
                }
            }
        }

        const path = if (parsed.path) |explicit|
            if (explicit.len != 0 and explicit[0] == '/') explicit else defaultPath(origin.path)
        else
            defaultPath(origin.path);
        const explicit_root_path = parsed.path != null and
            std.mem.eql(u8, parsed.path.?, "/");

        if (parsed.name.len == 0 and
            cookiePrefix(parsed.value) != .none) return .ignored;
        switch (cookiePrefix(parsed.name)) {
            .none => {},
            .secure => if (!origin.secure or !parsed.secure) return .ignored,
            .host => if (!origin.secure or !parsed.secure or !host_only or
                !explicit_root_path) return .ignored,
            .http => if (!origin.secure or !parsed.secure or
                !parsed.http_only) return .ignored,
            .host_http => if (!origin.secure or !parsed.secure or
                !parsed.http_only or !host_only or
                !explicit_root_path) return .ignored,
        }

        if (!origin.secure and !parsed.secure and
            self.overlaysSecure(
                parsed.name,
                domain,
                path,
                stored_partition_key,
            ))
        {
            return .ignored;
        }

        const existing_index = self.find(
            parsed.name,
            domain,
            path,
            host_only,
            stored_partition_key,
        );
        if (!context.http_api and existing_index != null and
            self.cookies.items[existing_index.?].http_only)
        {
            return .ignored;
        }
        if (parsed.expires_at) |deadline| {
            if (deadline <= now) {
                if (existing_index) |index| {
                    self.removeAt(index);
                    return .deleted;
                }
                return .ignored;
            }
        }

        const sequence = self.nextSequence();
        var candidate = try initCookie(
            self.allocator,
            parsed,
            domain,
            path,
            host_only,
            stored_partition_key,
            now,
            sequence,
        );
        errdefer candidate.deinit(self.allocator);

        if (existing_index) |index| {
            const creation_order = self.cookies.items[index].creation_order;
            const created_at = self.cookies.items[index].created_at;
            self.cookies.items[index].deinit(self.allocator);
            candidate.creation_order = creation_order;
            candidate.created_at = created_at;
            self.cookies.items[index] = candidate;
            return .replaced;
        }

        try self.cookies.ensureUnusedCapacity(self.allocator, 1);
        self.cookies.appendAssumeCapacity(candidate);
        self.restoreRequestOrder(self.cookies.items.len - 1);
        self.enforceDomainLimit(
            domain,
            stored_partition_key,
            if (stored_partition_key == null)
                self.config.max_cookies_per_domain
            else
                self.config.max_partitioned_cookies_per_domain,
        );
        self.enforceTotalLimit();
        return .stored;
    }

    fn find(
        self: *const Jar,
        name: []const u8,
        domain: []const u8,
        path: []const u8,
        host_only: bool,
        partition_key: ?NormalizedPartitionKey,
    ) ?usize {
        for (self.cookies.items, 0..) |cookie, index| {
            if (std.mem.eql(u8, cookie.name, name) and
                std.ascii.eqlIgnoreCase(cookie.domain, domain) and
                std.mem.eql(u8, cookie.path, path) and
                cookie.host_only == host_only and
                cookiePartitionEquals(cookie, partition_key)) return index;
        }
        return null;
    }

    fn overlaysSecure(
        self: *const Jar,
        name: []const u8,
        domain: []const u8,
        path: []const u8,
        partition_key: ?NormalizedPartitionKey,
    ) bool {
        for (self.cookies.items) |cookie| {
            if (!cookie.secure or !std.mem.eql(u8, cookie.name, name)) continue;
            if (!(domainMatches(domain, cookie.domain) or
                domainMatches(cookie.domain, domain))) continue;
            if (!cookiePartitionEquals(cookie, partition_key)) continue;
            if (pathMatches(path, cookie.path)) return true;
        }
        return false;
    }

    fn headerValueLength(
        self: *const Jar,
        origin: Origin,
        now: i64,
        context: RequestContext,
        partition_key: ?NormalizedPartitionKey,
    ) Error!usize {
        var result: usize = 0;
        var matched_count: usize = 0;
        for (self.cookies.items) |cookie| {
            if (!matches(
                cookie,
                origin,
                now,
                context,
                partition_key,
                self.config,
            )) continue;
            if (cookie.name.len != 0) {
                result = std.math.add(usize, result, cookie.name.len) catch
                    return error.HeaderTooLarge;
                result = std.math.add(usize, result, 1) catch
                    return error.HeaderTooLarge;
            }
            result = std.math.add(usize, result, cookie.value.len) catch
                return error.HeaderTooLarge;
            if (matched_count != 0) {
                result = std.math.add(usize, result, 2) catch
                    return error.HeaderTooLarge;
            }
            if (result > self.config.max_header_bytes) {
                return error.HeaderTooLarge;
            }
            matched_count += 1;
        }
        return result;
    }

    fn writeHeaderValue(
        self: *Jar,
        origin: Origin,
        now: i64,
        context: RequestContext,
        partition_key: ?NormalizedPartitionKey,
        out: []u8,
    ) []u8 {
        var offset: usize = 0;
        var matched_count: usize = 0;
        const access_order = self.nextSequence();
        for (self.cookies.items) |*cookie| {
            if (!matches(
                cookie.*,
                origin,
                now,
                context,
                partition_key,
                self.config,
            )) continue;
            if (matched_count != 0) {
                @memcpy(out[offset..][0..2], "; ");
                offset += 2;
            }
            if (cookie.name.len != 0) {
                @memcpy(out[offset..][0..cookie.name.len], cookie.name);
                offset += cookie.name.len;
                out[offset] = '=';
                offset += 1;
            }
            @memcpy(out[offset..][0..cookie.value.len], cookie.value);
            offset += cookie.value.len;
            cookie.last_access_order = access_order;
            matched_count += 1;
        }
        std.debug.assert(offset == out.len);
        return out;
    }

    fn enforceDomainLimit(
        self: *Jar,
        domain: []const u8,
        partition_key: ?NormalizedPartitionKey,
        limit: usize,
    ) void {
        while (self.domainCount(domain, partition_key) > limit) {
            const index = self.oldestPartitionAccessIndex(
                domain,
                partition_key,
                true,
            ) orelse self.oldestPartitionAccessIndex(
                domain,
                partition_key,
                false,
            ) orelse unreachable;
            self.removeAt(index);
        }
    }

    fn enforceTotalLimit(self: *Jar) void {
        while (self.cookies.items.len > self.config.max_cookies) {
            const index = self.oldestAccessIndex(null, false) orelse unreachable;
            self.removeAt(index);
        }
    }

    fn domainCount(
        self: *const Jar,
        domain: []const u8,
        partition_key: ?NormalizedPartitionKey,
    ) usize {
        var result: usize = 0;
        for (self.cookies.items) |cookie| {
            result += @intFromBool(
                std.ascii.eqlIgnoreCase(cookie.domain, domain) and
                    cookiePartitionEquals(cookie, partition_key),
            );
        }
        return result;
    }

    fn oldestPartitionAccessIndex(
        self: *const Jar,
        domain: []const u8,
        partition_key: ?NormalizedPartitionKey,
        only_non_secure: bool,
    ) ?usize {
        var result: ?usize = null;
        for (self.cookies.items, 0..) |cookie, index| {
            if (!std.ascii.eqlIgnoreCase(cookie.domain, domain) or
                !cookiePartitionEquals(cookie, partition_key) or
                (only_non_secure and cookie.secure)) continue;
            if (result == null or
                cookie.last_access_order <
                    self.cookies.items[result.?].last_access_order or
                (cookie.last_access_order ==
                    self.cookies.items[result.?].last_access_order and
                    cookie.creation_order <
                        self.cookies.items[result.?].creation_order))
            {
                result = index;
            }
        }
        return result;
    }

    fn oldestAccessIndex(
        self: *const Jar,
        domain: ?[]const u8,
        only_non_secure: bool,
    ) ?usize {
        var result: ?usize = null;
        for (self.cookies.items, 0..) |cookie, index| {
            if (domain) |required| {
                if (!std.ascii.eqlIgnoreCase(cookie.domain, required)) continue;
            }
            if (only_non_secure and cookie.secure) continue;
            if (result == null or
                cookie.last_access_order <
                    self.cookies.items[result.?].last_access_order or
                (cookie.last_access_order ==
                    self.cookies.items[result.?].last_access_order and
                    cookie.creation_order <
                        self.cookies.items[result.?].creation_order))
            {
                result = index;
            }
        }
        return result;
    }

    fn restoreRequestOrder(self: *Jar, start: usize) void {
        var index = start;
        while (index != 0 and requestOrderLess(
            self.cookies.items[index],
            self.cookies.items[index - 1],
        )) : (index -= 1) {
            std.mem.swap(
                Cookie,
                &self.cookies.items[index],
                &self.cookies.items[index - 1],
            );
        }
    }

    fn removeAt(self: *Jar, index: usize) void {
        var removed = self.cookies.orderedRemove(index);
        removed.deinit(self.allocator);
    }

    fn nextSequence(self: *Jar) u64 {
        self.sequence = std.math.add(u64, self.sequence, 1) catch
            std.math.maxInt(u64);
        return self.sequence;
    }
};

fn initCookie(
    allocator: std.mem.Allocator,
    parsed: syntax.ParsedCookie,
    domain: []const u8,
    path: []const u8,
    host_only: bool,
    partition_key: ?NormalizedPartitionKey,
    now: i64,
    sequence: u64,
) std.mem.Allocator.Error!Cookie {
    const name = try allocator.dupe(u8, parsed.name);
    errdefer allocator.free(name);
    const value = try allocator.dupe(u8, parsed.value);
    errdefer allocator.free(value);
    const owned_domain = try allocator.alloc(u8, domain.len);
    errdefer allocator.free(owned_domain);
    for (domain, owned_domain) |byte, *destination| {
        destination.* = std.ascii.toLower(byte);
    }
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    const owned_partition_site = if (partition_key) |key|
        try allocator.dupe(u8, key.site)
    else
        null;
    errdefer if (owned_partition_site) |site| allocator.free(site);
    return .{
        .name = name,
        .value = value,
        .domain = owned_domain,
        .path = owned_path,
        .expires_at = parsed.expires_at,
        .secure = parsed.secure,
        .http_only = parsed.http_only,
        .host_only = host_only,
        .partition_site = owned_partition_site,
        .partition_secure = if (partition_key) |key| key.secure else false,
        .partition_cross_site_ancestor = if (partition_key) |key|
            key.has_cross_site_ancestor
        else
            false,
        .same_site = parsed.same_site,
        .created_at = now,
        .creation_order = sequence,
        .last_access_order = sequence,
    };
}

fn validateSnapshotRecord(
    record: snapshot.Record,
    config: Config,
) SnapshotError!void {
    if (record.domain.len == 0 or record.path.len == 0 or
        record.path[0] != '/' or
        record.name.len > config.max_cookie_bytes or
        record.value.len > config.max_cookie_bytes - record.name.len or
        containsForbiddenStoredOctet(record.name) or
        containsForbiddenStoredOctet(record.value) or
        record.creation_order == 0 or record.last_access_order == 0)
    {
        return error.CorruptSnapshot;
    }
    if (!record.host_only and isIpLiteral(record.domain)) {
        return error.CorruptSnapshot;
    }
    if (!validStoredDomain(record.domain)) return error.CorruptSnapshot;
    if (record.partitioned != (record.partition_site.len != 0) or
        (!record.partitioned and
            (record.partition_secure or
                record.partition_cross_site_ancestor)) or
        (record.partitioned and
            (!record.secure or
                record.partition_site.len > net.HostName.max_len or
                !validStoredDomain(record.partition_site))))
    {
        return error.CorruptSnapshot;
    }
    if (!record.host_only) switch (config.domain_policy) {
        .host_only => return error.SnapshotPolicyMismatch,
        .unchecked => {},
        .checked => |checker| if (checker.matches(record.domain)) {
            return error.SnapshotPolicyMismatch;
        },
    };
    if (record.name.len == 0 and
        cookiePrefix(record.value) != .none) return error.CorruptSnapshot;
    switch (cookiePrefix(record.name)) {
        .none => {},
        .secure => if (!record.secure) return error.CorruptSnapshot,
        .host => if (!record.secure or !record.host_only or
            !std.mem.eql(u8, record.path, "/")) return error.CorruptSnapshot,
        .http => if (!record.secure or
            !record.http_only) return error.CorruptSnapshot,
        .host_http => if (!record.secure or !record.http_only or
            !record.host_only or
            !std.mem.eql(u8, record.path, "/")) return error.CorruptSnapshot,
    }
    if (record.same_site == @intFromEnum(SameSite.none) and !record.secure) {
        return error.CorruptSnapshot;
    }
}

const CookiePrefix = enum {
    none,
    secure,
    host,
    http,
    host_http,
};

fn cookiePrefix(value: []const u8) CookiePrefix {
    if (std.ascii.startsWithIgnoreCase(value, "__Host-Http-")) {
        return .host_http;
    }
    if (std.ascii.startsWithIgnoreCase(value, "__Secure-")) return .secure;
    if (std.ascii.startsWithIgnoreCase(value, "__Host-")) return .host;
    if (std.ascii.startsWithIgnoreCase(value, "__Http-")) return .http;
    return .none;
}

fn containsForbiddenStoredOctet(value: []const u8) bool {
    for (value) |byte| {
        if (byte <= 0x08 or (byte >= 0x0a and byte <= 0x1f) or
            byte == 0x7f or byte == ';') return true;
    }
    return false;
}

fn validStoredDomain(domain: []const u8) bool {
    if (isIpLiteral(domain)) return true;
    var buffer: [net.HostName.max_len]u8 = undefined;
    const normalized = normalizedDomain(domain, &buffer) orelse return false;
    return std.mem.eql(u8, normalized, domain);
}

const Origin = struct {
    host: []const u8,
    path: []const u8,
    secure: bool,
    is_ip: bool,
};

const NormalizedPartitionKey = struct {
    site: []const u8,
    secure: bool,
    has_cross_site_ancestor: bool,
};

fn normalizedPartitionKey(
    key: ?PartitionKey,
    host_buffer: *[net.HostName.max_len + 2]u8,
) Error!?NormalizedPartitionKey {
    const value = key orelse return null;
    if (value.top_level_site.len == 0 or
        value.top_level_site.len > maximum_partition_site_bytes)
    {
        return error.InvalidPartitionKey;
    }
    const uri = std.Uri.parse(value.top_level_site) catch
        return error.InvalidPartitionKey;
    if (uri.user != null or uri.password != null or uri.port != null or
        uri.query != null or uri.fragment != null)
    {
        return error.InvalidPartitionKey;
    }
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
    {
        return error.InvalidPartitionKey;
    }
    const path = componentBytes(uri.path);
    if (path.len != 0 and !std.mem.eql(u8, path, "/")) {
        return error.InvalidPartitionKey;
    }
    const origin = parseOrigin(value.top_level_site, host_buffer) catch
        return error.InvalidPartitionKey;
    return .{
        .site = origin.host,
        .secure = origin.secure,
        .has_cross_site_ancestor = value.has_cross_site_ancestor,
    };
}

fn cookiePartitionEquals(
    cookie: Cookie,
    key: ?NormalizedPartitionKey,
) bool {
    const site = cookie.partition_site orelse return key == null;
    const candidate = key orelse return false;
    return cookie.partition_secure == candidate.secure and
        cookie.partition_cross_site_ancestor ==
            candidate.has_cross_site_ancestor and
        std.mem.eql(u8, site, candidate.site);
}

fn cookiePartitionAvailable(
    cookie: Cookie,
    key: ?NormalizedPartitionKey,
) bool {
    if (cookie.partition_site == null) return true;
    return cookiePartitionEquals(cookie, key);
}

fn parseOrigin(
    uri_text: []const u8,
    host_buffer: *[net.HostName.max_len + 2]u8,
) Error!Origin {
    const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
    if (uri.user != null or uri.password != null) return error.InvalidUri;
    const secure = if (std.ascii.eqlIgnoreCase(uri.scheme, "https") or
        std.ascii.eqlIgnoreCase(uri.scheme, "wss"))
        true
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "http") or
        std.ascii.eqlIgnoreCase(uri.scheme, "ws"))
        false
    else
        return error.InvalidUri;
    const component = uri.host orelse return error.InvalidUri;
    const raw_host = component.toRaw(host_buffer) catch return error.InvalidUri;
    var host = raw_host;
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        host = host[1 .. host.len - 1];
    }
    if (host.len == 0 or host.len > net.HostName.max_len) {
        return error.InvalidUri;
    }
    if (host[host.len - 1] == '.') host = host[0 .. host.len - 1];
    if (host.len == 0) return error.InvalidUri;
    for (host, 0..) |byte, index| {
        if (!std.ascii.isAscii(byte)) return error.InvalidUri;
        host_buffer[index] = std.ascii.toLower(byte);
    }
    const canonical_host = host_buffer[0..host.len];
    const path_value = componentBytes(uri.path);
    const path = if (path_value.len == 0 or path_value[0] != '/')
        "/"
    else
        path_value;
    return .{
        .host = canonical_host,
        .path = path,
        .secure = secure,
        .is_ip = isIpLiteral(canonical_host),
    };
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |bytes| bytes,
    };
}

fn normalizedDomain(
    raw: []const u8,
    out: *[net.HostName.max_len]u8,
) ?[]const u8 {
    var domain = trim(raw);
    if (domain.len != 0 and domain[0] == '.') domain = domain[1..];
    if (domain.len == 0 or domain.len > out.len or
        domain[domain.len - 1] == '.') return null;
    var label_start: usize = 0;
    for (domain, 0..) |byte, index| {
        if (!std.ascii.isAscii(byte)) return null;
        if (byte == '.') {
            if (index == label_start or domain[index - 1] == '-') return null;
            out[index] = '.';
            label_start = index + 1;
            continue;
        }
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-')) return null;
        if (index == label_start and byte == '-') return null;
        out[index] = std.ascii.toLower(byte);
    }
    if (label_start == domain.len or domain[domain.len - 1] == '-') return null;
    return out[0..domain.len];
}

fn domainMatches(host: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, domain)) return true;
    if (host.len <= domain.len or isIpLiteral(host)) return false;
    const suffix_start = host.len - domain.len;
    return host[suffix_start - 1] == '.' and
        std.ascii.eqlIgnoreCase(host[suffix_start..], domain);
}

fn isIpLiteral(host: []const u8) bool {
    if (net.IpAddress.parseIp4(host, 0)) |_| return true else |_| {}
    if (net.IpAddress.parseIp6(host, 0)) |_| return true else |_| {}
    return false;
}

fn defaultPath(request_path: []const u8) []const u8 {
    if (request_path.len == 0 or request_path[0] != '/') return "/";
    const last_slash = std.mem.lastIndexOfScalar(u8, request_path, '/') orelse
        return "/";
    if (last_slash == 0) return "/";
    return request_path[0..last_slash];
}

fn pathMatches(request_path: []const u8, cookie_path: []const u8) bool {
    if (std.mem.eql(u8, request_path, cookie_path)) return true;
    if (!std.mem.startsWith(u8, request_path, cookie_path)) return false;
    return cookie_path[cookie_path.len - 1] == '/' or
        request_path[cookie_path.len] == '/';
}

fn matches(
    cookie: Cookie,
    origin: Origin,
    now: i64,
    context: RequestContext,
    partition_key: ?NormalizedPartitionKey,
    config: Config,
) bool {
    if (expired(cookie, now)) return false;
    if (!cookiePartitionAvailable(cookie, partition_key)) return false;
    if (cookie.host_only) {
        if (!std.ascii.eqlIgnoreCase(origin.host, cookie.domain)) return false;
    } else if (!domainMatches(origin.host, cookie.domain)) return false;
    if (!pathMatches(origin.path, cookie.path)) return false;
    if (cookie.secure and !origin.secure) return false;
    if (cookie.http_only and !context.http_api) return false;
    if (context.site == .same_site) return true;
    return switch (cookie.same_site) {
        .none => true,
        .strict => false,
        .lax => context.top_level_navigation and
            http_method.isSafe(context.method),
        .default => (context.top_level_navigation and
            http_method.isSafe(context.method)) or
            (context.top_level_navigation and
                now >= cookie.created_at and
                now - cookie.created_at <=
                    config.lax_allowing_unsafe_seconds),
    };
}

fn expired(cookie: Cookie, now: i64) bool {
    return if (cookie.expires_at) |deadline| deadline <= now else false;
}

fn requestOrderLess(left: Cookie, right: Cookie) bool {
    if (left.path.len != right.path.len) return left.path.len > right.path.len;
    return left.creation_order < right.creation_order;
}

fn trim(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

test {
    _ = netscape;
    _ = syntax;
    _ = @import("tests.zig");
    _ = @import("persistence_tests.zig");
}
