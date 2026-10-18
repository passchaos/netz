//! RFC 9484 URI Template wrapper over the shared MASQUE scalar engine.

const std = @import("std");
const scope_module = @import("scope.zig");
const masque_template = @import("../connect_udp/template.zig");

pub const Error = masque_template.Error || error{InvalidScope};
pub const Variable = masque_template.Variable;

pub const Template = struct {
    inner: masque_template.Template,

    pub fn compile(source: []const u8) Error!Template {
        const inner = try masque_template.Template
            .compileWithRequiredVariables(source, &.{});
        return .{ .inner = inner };
    }

    pub fn scheme(self: Template) []const u8 {
        return self.inner.scheme;
    }

    pub fn authority(self: Template) []const u8 {
        return self.inner.authority;
    }

    pub fn expandedLen(
        self: Template,
        scope: scope_module.Scope,
        variables: []const Variable,
    ) Error!usize {
        try scope.validate();
        var protocol_storage: [3]u8 = undefined;
        const protocol = protocolText(scope.ip_protocol, &protocol_storage);
        return self.inner.expandedVariablesLen(&.{
            .{ .name = "target", .value = scope.target },
            .{ .name = "ipproto", .value = protocol },
        }, variables);
    }

    pub fn expandRequestTargetInto(
        self: Template,
        out: []u8,
        scope: scope_module.Scope,
        variables: []const Variable,
    ) Error![]u8 {
        try scope.validate();
        var protocol_storage: [3]u8 = undefined;
        const protocol = protocolText(scope.ip_protocol, &protocol_storage);
        return self.inner.expandVariablesRequestTargetInto(out, &.{
            .{ .name = "target", .value = scope.target },
            .{ .name = "ipproto", .value = protocol },
        }, variables);
    }

    pub fn expandUriInto(
        self: Template,
        out: []u8,
        scope: scope_module.Scope,
        variables: []const Variable,
    ) Error![]u8 {
        try scope.validate();
        var protocol_storage: [3]u8 = undefined;
        const protocol = protocolText(scope.ip_protocol, &protocol_storage);
        return self.inner.expandVariablesUriInto(out, &.{
            .{ .name = "target", .value = scope.target },
            .{ .name = "ipproto", .value = protocol },
        }, variables);
    }
};

fn protocolText(protocol: ?u8, storage: *[3]u8) []const u8 {
    if (protocol) |value| {
        return std.fmt.bufPrint(storage, "{d}", .{value}) catch unreachable;
    }
    return "*";
}
