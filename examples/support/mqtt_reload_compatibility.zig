//! Classify configured-broker fields by their SIGHUP ownership boundary.
//!
//! A newly parsed field must never be silently ignored. The exhaustive
//! compile-time classification below forces every future `Config` field to be
//! assigned to a reload subsystem or to the restart-required snapshot.

const std = @import("std");
const netz = @import("netz");

const Config = netz.mqtt.broker_config.Config;

const FieldClass = enum {
    listener,
    bridge,
    admission,
    persistence_target,
    autosave,
    scheduling,
    delivery_policy,
    client_id_policy,
    restart_required,
};

fn fieldClass(comptime name: []const u8) FieldClass {
    if (std.mem.eql(u8, name, "listeners") or
        std.mem.eql(u8, name, "per_listener_settings") or
        std.mem.eql(u8, name, "password_file") or
        std.mem.eql(u8, name, "acl_file"))
    {
        return .listener;
    }
    if (std.mem.eql(u8, name, "bridges")) return .bridge;
    if (std.mem.eql(u8, name, "allow_zero_length_client_id") or
        std.mem.eql(u8, name, "auto_id_prefix") or
        std.mem.eql(u8, name, "retain_available"))
    {
        return .admission;
    }
    if (std.mem.eql(u8, name, "persistence") or
        std.mem.eql(u8, name, "persistence_location") or
        std.mem.eql(u8, name, "persistence_file"))
    {
        return .persistence_target;
    }
    if (std.mem.eql(u8, name, "autosave_interval") or
        std.mem.eql(u8, name, "autosave_on_changes"))
    {
        return .autosave;
    }
    if (std.mem.eql(u8, name, "retain_expiry_interval_seconds") or
        std.mem.eql(u8, name, "sys_interval_seconds"))
    {
        return .scheduling;
    }
    if (std.mem.eql(u8, name, "message_size_limit") or
        std.mem.eql(u8, name, "queue_qos0_messages") or
        std.mem.eql(u8, name, "upgrade_outgoing_qos") or
        std.mem.eql(u8, name, "check_retain_source") or
        std.mem.eql(u8, name, "persistent_client_expiration_seconds"))
    {
        return .delivery_policy;
    }
    if (std.mem.eql(u8, name, "client_id_prefixes")) {
        return .client_id_policy;
    }
    if (std.mem.eql(u8, name, "global_max_clients") or
        std.mem.eql(u8, name, "global_max_connections") or
        std.mem.eql(u8, name, "max_packet_size") or
        std.mem.eql(u8, name, "max_inflight_messages") or
        std.mem.eql(u8, name, "max_inflight_bytes") or
        std.mem.eql(u8, name, "max_queued_messages") or
        std.mem.eql(u8, name, "max_queued_bytes") or
        std.mem.eql(u8, name, "websocket_headers_size") or
        std.mem.eql(u8, name, "set_tcp_nodelay"))
    {
        return .restart_required;
    }
    @compileError("unclassified MQTT broker config field: " ++ name);
}

comptime {
    @setEvalBranchQuota(10_000);
    for (@typeInfo(Config).@"struct".fields) |field| {
        _ = fieldClass(field.name);
    }
}

/// Reject fields for which the running broker has no atomic runtime setter.
/// Other field classes are validated and committed by their owning subsystem.
pub fn validateRestartRequiredGlobals(
    initial: *const Config,
    candidate: *const Config,
) error{GlobalConfigurationRequiresRestart}!void {
    comptime @setEvalBranchQuota(10_000);
    inline for (@typeInfo(Config).@"struct".fields) |field| {
        if (comptime fieldClass(field.name) == .restart_required) {
            if (!fieldEqual(
                field.type,
                @field(initial.*, field.name),
                @field(candidate.*, field.name),
            )) {
                return error.GlobalConfigurationRequiresRestart;
            }
        }
    }
}

fn fieldEqual(comptime T: type, initial: T, candidate: T) bool {
    return switch (@typeInfo(T)) {
        .pointer => |pointer| if (pointer.size == .slice and
            pointer.child == u8)
            std.mem.eql(u8, initial, candidate)
        else
            @compileError("unsupported restart-required field type: " ++
                @typeName(T)),
        else => std.meta.eql(initial, candidate),
    };
}

test "restart-required MQTT globals reject every changed field" {
    var empty_listeners: [0]netz.mqtt.broker_config.Listener = .{};
    const initial = Config{ .listeners = &empty_listeners };

    var candidate = initial;
    candidate.global_max_clients += 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.global_max_connections += 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.max_packet_size -= 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.max_inflight_messages += 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.max_inflight_bytes = 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.max_queued_messages += 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.max_queued_bytes = 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.websocket_headers_size -= 1;
    try expectRestart(initial, candidate);
    candidate = initial;
    candidate.set_tcp_nodelay = !candidate.set_tcp_nodelay;
    try expectRestart(initial, candidate);
}

test "runtime-owned MQTT globals remain reload-compatible" {
    var empty_listeners: [0]netz.mqtt.broker_config.Listener = .{};
    const initial = Config{ .listeners = &empty_listeners };
    var candidate = initial;
    candidate.allow_zero_length_client_id = false;
    candidate.retain_available = false;
    candidate.auto_id_prefix = @constCast("dynamic-");
    candidate.autosave_interval = 7;
    candidate.autosave_on_changes = true;
    candidate.retain_expiry_interval_seconds = 60;
    candidate.sys_interval_seconds = 1;
    candidate.message_size_limit = 1;
    candidate.queue_qos0_messages = true;
    candidate.upgrade_outgoing_qos = true;
    candidate.check_retain_source = false;
    candidate.persistent_client_expiration_seconds = 1;
    candidate.client_id_prefixes = @constCast("dynamic-");

    try validateRestartRequiredGlobals(&initial, &candidate);
}

fn expectRestart(initial: Config, candidate: Config) !void {
    try std.testing.expectError(
        error.GlobalConfigurationRequiresRestart,
        validateRestartRequiredGlobals(&initial, &candidate),
    );
}
