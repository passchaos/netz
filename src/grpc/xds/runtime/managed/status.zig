//! Source-correct CSDS views of the managed global desired resource graph.
const std = @import("std");
const csds = @import("../../csds.zig");
const names = @import("names.zig");
const raw_name = @import("../../raw_name.zig");
const lds = @import("../../lds.zig");
const rds = @import("../../rds.zig");
const cds = @import("../../cds.zig");
const eds = @import("../../eds.zig");
const sds = @import("../../sds.zig");
const storage = @import("status/ledger.zig");
pub const Options = storage.Options;
pub const Ledger = storage.Ledger;
pub const Prepared = storage.Prepared;

pub fn TimerClient(comptime Registry: type) type {
    return struct {
        sender: @import("../../../channel/shared.zig").Sender,
        subscriptions: struct {
            registry: *Registry,
            pub fn find(self: *const @This(), url: []const u8) ?struct { names: []const []const u8 } {
                for (self.registry.desired.items) |watch| if (isType(watch.type_url, url)) return .{ .names = watch.values };
                return null;
            }
        },
    };
}
/// Borrow current global watches, rather than SotW's retained last wire request.
pub fn timerClient(registry: anytype, session: anytype) TimerClient(@TypeOf(registry.*)) {
    return .{ .sender = session.client.sender, .subscriptions = .{ .registry = registry } };
}

pub fn timestamp(io: std.Io) csds.Timestamp {
    const ns = std.Io.Timestamp.now(io, .real).toNanoseconds();
    return .{ .seconds = @intCast(@divFloor(ns, std.time.ns_per_s)), .nanos = @intCast(@mod(ns, std.time.ns_per_s)) };
}
fn isType(url: []const u8, expected: []const u8) bool {
    return std.mem.eql(u8, url, expected);
}
fn resourceName(comptime mode: anytype, resource: anytype) ?[]const u8 {
    return if (mode == .sotw) raw_name.first(resource.value, 1) else resource.name;
}
fn payload(comptime mode: anytype, resource: anytype) ?[]const u8 {
    return if (mode == .sotw) resource.value else if (resource.resource) |value| value.value else null;
}
fn version(comptime mode: anytype, response: anytype, resource: anytype) []const u8 {
    return if (mode == .sotw) response.version else resource.version;
}
fn eligible(facade: anytype, authority: []const u8, url: []const u8, name: []const u8) bool {
    return names.belongs(name, authority) and storage.desired(&facade.registry, url, name);
}
fn present(comptime mode: anytype, response: anytype, name: []const u8) bool {
    for (response.resources) |resource| {
        const candidate = resourceName(mode, resource) orelse continue;
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

fn doesNotExist(prepared: *Prepared, url: []const u8, name: []const u8, failed_version: []const u8, now: csds.Timestamp, source: anytype, retain: bool) !void {
    var value: csds.Resource = if (retain) if (prepared.find(url, name)) |old| old.resource else .{ .type_url = url, .name = name } else .{ .type_url = url, .name = name };
    value.status = .does_not_exist;
    value.error_state = .{ .details = "does not exist", .version_info = failed_version, .last_update_attempt = now };
    try prepared.put(value, source.key);
}

pub fn prepareUpdate(comptime mode: anytype, facade: anytype, event: anytype) !Prepared {
    const update = (try event.result).update;
    const response = update.response.value;
    const url = response.type_url;
    const source = update.source.?;
    var prepared = try facade.status_history.prepare();
    errdefer prepared.deinit();
    for (response.resources) |resource| {
        const wire = payload(mode, resource) orelse continue; // Heartbeats preserve acceptance time.
        const name = resourceName(mode, resource) orelse continue;
        if (!eligible(facade, event.session.authority, url, name)) continue;
        try prepared.put(.{ .type_url = url, .name = name, .wire = wire, .version = version(mode, response, resource) }, source.key);
        prepared.tag(url, name, update.token);
    }
    const now = timestamp(facade.io);
    const retain = source.server.ignore_resource_deletion and (isType(url, lds.type_url) or isType(url, cds.type_url));
    if (mode == .sotw) {
        if (isType(url, lds.type_url) or isType(url, cds.type_url) or isType(url, sds.type_url)) {
            for (facade.status_history.records.items) |record| {
                const name = record.resource.name;
                if (!isType(record.resource.type_url, url) or !eligible(facade, event.session.authority, url, name) or present(mode, response, name)) continue;
                try doesNotExist(&prepared, url, name, response.version, now, source, retain);
            }
        }
    } else {
        for (response.removed) |name| {
            if (eligible(facade, event.session.authority, url, name)) try doesNotExist(&prepared, url, name, response.system_version, now, source, retain);
        }
    }
    try prepared.checkBudget();
    return prepared;
}

pub fn accepted(comptime mode: anytype, event: anytype) bool {
    const update = (event.result catch return false).update;
    const entry = event.session.client.subscriptions.find(update.response.value.type_url) orelse return false;
    const has_nack = if (mode == .sotw) entry.nack != null else entry.error_detail != null;
    return entry.pending_sequence == null and !has_nack and event.session.client.subscriptions.epoch == update.token.epoch;
}

pub fn commitUpdate(comptime mode: anytype, facade: anytype, prepared: *Prepared, event: anytype) void {
    const update = (event.result catch unreachable).update;
    const entry = event.session.client.subscriptions.find(update.response.value.type_url).?;
    for (prepared.records.items) |record| {
        if (facade.status_history.find(record.resource.type_url, record.resource.name) == record) continue;
        if (record.resource.status != .acked or record.resource.wire.len == 0) continue;
        const ns = if (mode == .sotw) entry.accepted_ns else blk: {
            for (entry.versions) |value| if (std.mem.eql(u8, value.name, record.resource.name)) break :blk value.accepted_ns;
            break :blk 0;
        };
        const accepted_time = if (ns == 0) timestamp(facade.io) else csds.Timestamp{
            .seconds = @intCast(@divFloor(ns, std.time.ns_per_s)),
            .nanos = @intCast(@mod(ns, std.time.ns_per_s)),
        };
        record.resource.last_updated_seconds = accepted_time.seconds;
        record.resource.last_updated_nanos = accepted_time.nanos;
    }
    prepared.prune(&facade.registry);
    prepared.commit();
}

pub fn cachedWire(controller: anytype, url: []const u8, name: []const u8) ?[]const u8 {
    if (isType(url, lds.type_url)) {
        const listener = controller.listener orelse return null;
        const value = listener.listener orelse return null;
        return if (std.mem.eql(u8, value.value.name, name)) value.wire else null;
    }
    if (isType(url, rds.type_url)) {
        const listener = controller.listener orelse return null;
        const value = listener.listener orelse return null;
        if (value.value.hcm.route_source != .rds or !listener.routes_accepted) return null;
        const routes = listener.routes orelse return null;
        return if (std.mem.eql(u8, routes.resource.value.name, name)) routes.resource.wire else null;
    }
    if (isType(url, sds.type_url)) return if (controller.sds_secrets.get(name)) |secret| secret.owned.wire else null;
    for (controller.entries.items) |entry| {
        const cluster = entry.cluster orelse continue;
        if (isType(url, cds.type_url) and entry.cds_seen and std.mem.eql(u8, entry.identity.name, name)) return cluster.resource.wire;
        if (isType(url, eds.type_url) and entry.eds_seen and std.mem.eql(u8, cluster.resource.value.edsName(), name)) {
            return if (entry.snapshot) |snapshot| snapshot.resource.wire else null;
        }
    }
    return null;
}

fn partialAcceptanceTime(comptime mode: anytype, event: anytype, resource: csds.Resource) ?csds.Timestamp {
    if (mode == .sotw) return null;
    const entry = event.session.client.subscriptions.find(resource.type_url) orelse return null;
    for (entry.versions) |value| {
        if (!std.mem.eql(u8, value.name, resource.name) or !std.mem.eql(u8, value.version, resource.version) or value.accepted_ns == 0) continue;
        return .{ .seconds = @intCast(@divFloor(value.accepted_ns, std.time.ns_per_s)), .nanos = @intCast(@mod(value.accepted_ns, std.time.ns_per_s)) };
    }
    return null;
}

pub fn commitPartial(comptime mode: anytype, facade: anytype, prepared: *Prepared, event: anytype, err: anyerror) void {
    const update = (event.result catch unreachable).update;
    if (!update.source.?.server.fail_on_data_errors) return;
    const detail = @errorName(err);
    // These failures occur before a valid partial-resource decision.
    if (err == error.OutOfMemory or err == error.Timeout or err == error.Canceled or
        err == error.InvalidDiscoveryMessage or err == error.StaleDiscoveryResponse or
        std.mem.startsWith(u8, detail, "Duplicate") or std.mem.endsWith(u8, detail, "LimitExceeded")) return;
    const now = timestamp(facade.io);
    var index: usize = 0;
    while (index < prepared.records.items.len) {
        const record = prepared.records.items[index];
        if (facade.status_history.find(record.resource.type_url, record.resource.name) == record) {
            index += 1;
            continue;
        }
        const current = cachedWire(facade.controller, record.resource.type_url, record.resource.name);
        if (record.resource.status == .acked and current != null and std.mem.eql(u8, current.?, record.resource.wire)) {
            const accepted_time = partialAcceptanceTime(mode, event, record.resource) orelse now;
            record.resource.last_updated_seconds = accepted_time.seconds;
            record.resource.last_updated_nanos = accepted_time.nanos;
        } else if (current == null and record.resource.status == .acked) {
            const failed_version = record.resource.version;
            record.discardWire();
            record.resource.version = "";
            record.resource.last_updated_seconds = null;
            record.resource.last_updated_nanos = null;
            record.resource.status = .nacked;
            record.resource.error_state = .{ .details = detail, .version_info = failed_version, .last_update_attempt = now };
        } else if (current != null and record.resource.status != .does_not_exist) {
            const previous_count = prepared.records.items.len;
            prepared.restore(record.resource.type_url, record.resource.name);
            if (prepared.records.items.len != previous_count) continue;
        }
        index += 1;
    }
    prepared.prune(&facade.registry);
    prepared.commit();
}

pub fn prepareReject(comptime mode: anytype, facade: anytype, event: anytype, message: []const u8) !Prepared {
    const update = (try event.result).update;
    const response = update.response.value;
    const source = update.source.?;
    const url = response.type_url;
    var prepared = try facade.status_history.prepare();
    errdefer prepared.deinit();
    const now = timestamp(facade.io);
    for (response.resources) |resource| {
        const name = resourceName(mode, resource) orelse continue;
        if (!eligible(facade, event.session.authority, url, name)) continue;
        const current = cachedWire(facade.controller, url, name);
        const incoming = payload(mode, resource);
        // A valid sibling already accepted during lenient handling keeps its
        // acceptance timestamp; sending the NACK is a separate decision.
        if (source.server.fail_on_data_errors and current != null and incoming != null and std.mem.eql(u8, current.?, incoming.?)) {
            if (prepared.find(url, name)) |old| {
                if (old.accepted_token) |token| {
                    if (old.resource.status == .acked and token.owner_id == update.token.owner_id and token.epoch == update.token.epoch and token.sequence == update.token.sequence) continue;
                }
            }
        }
        var value: csds.Resource = if (prepared.find(url, name)) |old| old.resource else .{ .type_url = url, .name = name };
        if (source.server.fail_on_data_errors and current == null) {
            value.wire = "";
            value.version = "";
            value.last_updated_seconds = null;
            value.last_updated_nanos = null;
        }
        value.status = .nacked;
        value.error_state = .{ .details = message, .version_info = version(mode, response, resource), .last_update_attempt = now };
        try prepared.put(value, source.key);
    }
    try prepared.checkBudget();
    return prepared;
}

pub fn rejected(comptime mode: anytype, event: anytype) bool {
    _ = mode;
    const update = (event.result catch return false).update;
    const token = event.session.client.last_rejected_token orelse return false;
    return token.owner_id == update.token.owner_id and token.epoch == update.token.epoch and token.sequence == update.token.sequence;
}

fn due(controller: anytype, resource: csds.Resource, now: std.Io.Clock.Timestamp) bool {
    if (isType(resource.type_url, lds.type_url) or isType(resource.type_url, rds.type_url)) {
        const listener = controller.listener orelse return false;
        const owned = listener.listener orelse return false;
        const name = if (isType(resource.type_url, lds.type_url)) owned.value.name else if (listener.routes) |routes| routes.resource.value.name else return false;
        if (!std.mem.eql(u8, name, resource.name)) return false;
        const expiry = if (isType(resource.type_url, lds.type_url)) listener.listener_deadline else listener.routes_deadline;
        return if (expiry) |value| value.raw.nanoseconds <= now.raw.nanoseconds else false;
    }
    if (isType(resource.type_url, sds.type_url)) {
        const secret = controller.sds_secrets.get(resource.name) orelse return false;
        return if (secret.deadline) |value| value.raw.nanoseconds <= now.raw.nanoseconds else false;
    }
    for (controller.entries.items) |entry| {
        const matches = if (isType(resource.type_url, cds.type_url))
            std.mem.eql(u8, entry.identity.name, resource.name)
        else if (entry.cluster) |cluster|
            isType(resource.type_url, eds.type_url) and std.mem.eql(u8, cluster.resource.value.edsName(), resource.name)
        else
            false;
        if (!matches) continue;
        const expiry = if (isType(resource.type_url, cds.type_url)) entry.cds_deadline else entry.eds_deadline;
        return if (expiry) |value| value.raw.nanoseconds <= now.raw.nanoseconds else false;
    }
    return false;
}

pub fn prepareExpiry(facade: anytype) !Prepared {
    var prepared = try facade.status_history.prepare();
    errdefer prepared.deinit();
    const now = std.Io.Clock.Timestamp.now(facade.io, .awake);
    for (facade.status_history.records.items) |record| {
        if (!due(facade.controller, record.resource, now)) continue;
        try prepared.put(.{
            .type_url = record.resource.type_url,
            .name = record.resource.name,
            .status = .does_not_exist,
            .error_state = .{ .details = "resource TTL expired", .version_info = record.resource.version, .last_update_attempt = timestamp(facade.io) },
        }, &record.source_key);
    }
    try prepared.checkBudget();
    return prepared;
}

pub fn commitExpiry(facade: anytype, prepared: *Prepared) void {
    for (prepared.records.items) |record| {
        const previous = facade.status_history.find(record.resource.type_url, record.resource.name);
        if (previous == record) continue;
        // Expiry commits per authority. A later failure must not invent an
        // expiry for an authority whose accepted version still survives.
        var version_present = false;
        for (facade.registry.sessions.items) |session| {
            if (!names.belongs(record.resource.name, session.authority)) continue;
            version_present = session.client.acceptedVersion(record.resource.type_url, record.resource.name) != null;
        }
        if (version_present) prepared.restore(record.resource.type_url, record.resource.name);
    }
    prepared.prune(&facade.registry);
    prepared.commit();
}

pub fn encode(facade: anytype, gpa: std.mem.Allocator, options: csds.Options) ![]u8 {
    _ = try facade.nextResourceTimerExpiry();
    var resources: std.ArrayList(csds.Resource) = .empty;
    defer resources.deinit(gpa);
    for (facade.registry.desired.items) |watch| for (watch.values) |name| {
        if (resources.items.len >= facade.status_history.options.max_resources) return error.XdsLimitExceeded;
        var resource: csds.Resource = if (facade.status_history.find(watch.type_url, name)) |record| record.resource else .{ .type_url = watch.type_url, .name = name, .status = .requested };
        if (resource.status == .requested) {
            const now = std.Io.Clock.Timestamp.now(facade.io, .awake);
            for (facade.controller.resource_timers.items) |timer| {
                if (!isType(timer.type_url, watch.type_url) or !std.mem.eql(u8, timer.name, name)) continue;
                if (timer.status == .timeout) resource.status = .timeout else if (timer.status == .does_not_exist) resource.status = .does_not_exist else if (timer.deadline.raw.nanoseconds <= now.raw.nanoseconds) {
                    var transient = false;
                    for (facade.registry.sessions.items) |session| {
                        if (!names.belongs(name, session.authority)) continue;
                        if (session.client.source) |source| transient = source.server.resource_timer_is_transient_error;
                    }
                    resource.status = if (transient) .timeout else .does_not_exist;
                }
                break;
            }
        }
        if (resource.status == .timeout and resource.error_state == null) {
            resource.error_state = .{ .details = "initial resource fetch timed out" };
        }
        try resources.append(gpa, resource);
    };
    var configured = options;
    if (configured.node.len == 0) if (facade.registry.bootstrap.adsNode()) |node| {
        const encoded_node = try @import("../../ads.zig").codec.encodeNode(gpa, node);
        defer gpa.free(encoded_node);
        configured.node = encoded_node;
        return csds.encodeResponse(gpa, resources.items, configured);
    };
    return csds.encodeResponse(gpa, resources.items, configured);
}

pub fn fetch(facade: anytype, gpa: std.mem.Allocator, request_bytes: []const u8, options: csds.Options) ![]u8 {
    const request = try csds.decodeRequest(request_bytes);
    var configured = options;
    configured.exclude_resource_contents = request.exclude_resource_contents;
    return encode(facade, gpa, configured);
}
