//! RFC 9298 URI Template validation and scalar expansion.
//!
//! RFC 9298 permits Level-3 templates but explicitly excludes reserved,
//! fragment, label, path-segment, and path-parameter operators. Consequently
//! the supported surface is simple expansion plus form-query `?` and query
//! continuation `&`; Level-4 prefix/explode modifiers are rejected.

const std = @import("std");

const net = std.Io.net;

pub const Error = error{
    BufferTooShort,
    IntegerOverflow,
    InvalidTarget,
    InvalidUriTemplate,
    MissingTemplateVariable,
    DuplicateTemplateVariable,
    InvalidTemplateExpansion,
};

pub const Variable = struct {
    name: []const u8,
    value: []const u8,
};

pub const Template = struct {
    source: []const u8,
    scheme: []const u8,
    authority: []const u8,
    request_template: []const u8,

    pub fn compile(source: []const u8) Error!Template {
        if (source.len == 0) return error.InvalidUriTemplate;
        for (source, 0..) |byte, index| {
            if (byte < 0x21 or byte > 0x7e or byte == '#') {
                return error.InvalidUriTemplate;
            }
            if (byte == '%') {
                if (index + 2 >= source.len or
                    hexValue(source[index + 1]) == null or
                    hexValue(source[index + 2]) == null)
                {
                    return error.InvalidUriTemplate;
                }
            }
        }

        const scheme_end = std.mem.indexOf(u8, source, "://") orelse
            return error.InvalidUriTemplate;
        if (scheme_end == 0 or !std.ascii.isAlphabetic(source[0])) {
            return error.InvalidUriTemplate;
        }
        for (source[1..scheme_end]) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                byte != '+' and byte != '-' and byte != '.')
            {
                return error.InvalidUriTemplate;
            }
        }
        const authority_start = scheme_end + 3;
        const path_offset = std.mem.indexOfScalarPos(
            u8,
            source,
            authority_start,
            '/',
        ) orelse return error.InvalidUriTemplate;
        if (path_offset == authority_start or
            std.mem.indexOfAny(
                u8,
                source[0..path_offset],
                "{}?",
            ) != null)
        {
            return error.InvalidUriTemplate;
        }
        const request_template = source[path_offset..];
        if (request_template.len == 0 or request_template[0] != '/') {
            return error.InvalidUriTemplate;
        }

        var target_host_found = false;
        var target_port_found = false;
        var query_started = false;
        var index: usize = 0;
        while (index < request_template.len) {
            const byte = request_template[index];
            if (byte == '}') return error.InvalidUriTemplate;
            if (byte != '{') {
                if (byte == '?') {
                    if (query_started) return error.InvalidUriTemplate;
                    query_started = true;
                } else if (byte == '&' and !query_started) {
                    return error.InvalidUriTemplate;
                }
                index += 1;
                continue;
            }
            const end = std.mem.indexOfScalarPos(
                u8,
                request_template,
                index + 1,
                '}',
            ) orelse return error.InvalidUriTemplate;
            const expression = request_template[index + 1 .. end];
            if (expression.len == 0 or
                std.mem.indexOfScalar(u8, expression, '{') != null)
            {
                return error.InvalidUriTemplate;
            }
            const operator, const variables = try expressionParts(expression);
            switch (operator) {
                .simple => {},
                .query => {
                    if (query_started) return error.InvalidUriTemplate;
                    query_started = true;
                },
                .continuation => {
                    if (!query_started) return error.InvalidUriTemplate;
                },
            }
            var names = std.mem.splitScalar(u8, variables, ',');
            var count: usize = 0;
            while (names.next()) |name| {
                try validateVariableName(name);
                count += 1;
                target_host_found = target_host_found or
                    std.mem.eql(u8, name, "target_host");
                target_port_found = target_port_found or
                    std.mem.eql(u8, name, "target_port");
            }
            if (count == 0) return error.InvalidUriTemplate;
            index = end + 1;
        }
        if (!target_host_found or !target_port_found) {
            return error.MissingTemplateVariable;
        }
        return .{
            .source = source,
            .scheme = source[0..scheme_end],
            .authority = source[authority_start..path_offset],
            .request_template = request_template,
        };
    }

    pub fn expandedLen(
        self: Template,
        target_host: []const u8,
        target_port: u16,
        variables: []const Variable,
    ) Error!usize {
        return self.expandInternal(
            null,
            target_host,
            target_port,
            variables,
        );
    }

    /// Expand only the HTTP request target (path and optional query) into
    /// caller storage. The absolute template's scheme and authority remain
    /// available on `Template` for pseudo-header construction.
    pub fn expandRequestTargetInto(
        self: Template,
        out: []u8,
        target_host: []const u8,
        target_port: u16,
        variables: []const Variable,
    ) Error![]u8 {
        const needed = try self.expandedLen(
            target_host,
            target_port,
            variables,
        );
        if (out.len < needed) return error.BufferTooShort;
        const written = try self.expandInternal(
            out,
            target_host,
            target_port,
            variables,
        );
        std.debug.assert(written == needed);
        return out[0..written];
    }

    /// Expand the complete absolute URI for HTTP/1.x Upgrade requests.
    /// HTTP/2 and HTTP/3 carry these components in pseudo-header fields and
    /// should continue to use `expandRequestTargetInto` for `:path`.
    pub fn expandUriInto(
        self: Template,
        out: []u8,
        target_host: []const u8,
        target_port: u16,
        variables: []const Variable,
    ) Error![]u8 {
        const prefix_len = self.source.len - self.request_template.len;
        const request_target_len = try self.expandedLen(
            target_host,
            target_port,
            variables,
        );
        const needed = std.math.add(
            usize,
            prefix_len,
            request_target_len,
        ) catch return error.IntegerOverflow;
        if (out.len < needed) return error.BufferTooShort;
        @memcpy(out[0..prefix_len], self.source[0..prefix_len]);
        const request_target = try self.expandRequestTargetInto(
            out[prefix_len..needed],
            target_host,
            target_port,
            variables,
        );
        std.debug.assert(request_target.len == request_target_len);
        return out[0..needed];
    }

    fn expandInternal(
        self: Template,
        out: ?[]u8,
        target_host: []const u8,
        target_port: u16,
        variables: []const Variable,
    ) Error!usize {
        if (self.request_template.len == 0 or
            self.request_template[0] != '/')
        {
            return error.InvalidUriTemplate;
        }
        try validateTargetHost(target_host);
        if (target_port == 0) return error.InvalidTarget;
        try validateVariables(variables);
        var port_storage: [5]u8 = undefined;
        const port = std.fmt.bufPrint(&port_storage, "{d}", .{
            target_port,
        }) catch unreachable;

        var writer = Writer{ .out = out };
        var query_emitted = false;
        var index: usize = 0;
        while (index < self.request_template.len) {
            const byte = self.request_template[index];
            if (byte != '{') {
                try writer.byte(byte);
                if (byte == '?') query_emitted = true;
                index += 1;
                continue;
            }
            const end = std.mem.indexOfScalarPos(
                u8,
                self.request_template,
                index + 1,
                '}',
            ) orelse return error.InvalidUriTemplate;
            const expression = self.request_template[index + 1 .. end];
            if (expression.len == 0) return error.InvalidUriTemplate;
            const operator, const names_text = try expressionParts(expression);
            var names = std.mem.splitScalar(u8, names_text, ',');
            var emitted: usize = 0;
            while (names.next()) |name| {
                const value = variableValue(
                    name,
                    target_host,
                    port,
                    variables,
                ) orelse continue;
                switch (operator) {
                    .simple => {
                        if (emitted != 0) try writer.byte(',');
                    },
                    .query => {
                        try writer.byte(if (emitted == 0) '?' else '&');
                        query_emitted = true;
                        try writer.slice(name);
                        try writer.byte('=');
                    },
                    .continuation => {
                        if (!query_emitted) {
                            return error.InvalidTemplateExpansion;
                        }
                        try writer.byte('&');
                        try writer.slice(name);
                        try writer.byte('=');
                    },
                }
                try writer.encoded(value);
                emitted += 1;
            }
            index = end + 1;
        }
        return writer.len;
    }
};

const Operator = enum { simple, query, continuation };

fn expressionParts(expression: []const u8) Error!struct { Operator, []const u8 } {
    return switch (expression[0]) {
        '?' => .{ .query, expression[1..] },
        '&' => .{ .continuation, expression[1..] },
        '+', '#', '.', '/', ';' => error.InvalidUriTemplate,
        else => .{ .simple, expression },
    };
}

fn validateVariableName(name: []const u8) Error!void {
    if (name.len == 0 or
        std.mem.indexOfAny(u8, name, "*:") != null)
    {
        return error.InvalidUriTemplate;
    }
    var segment_len: usize = 0;
    var index: usize = 0;
    while (index < name.len) {
        const byte = name[index];
        if (byte == '.') {
            if (segment_len == 0) return error.InvalidUriTemplate;
            segment_len = 0;
            index += 1;
            continue;
        }
        if (byte == '%') {
            if (index + 2 >= name.len or
                hexValue(name[index + 1]) == null or
                hexValue(name[index + 2]) == null)
            {
                return error.InvalidUriTemplate;
            }
            index += 3;
            segment_len += 1;
            continue;
        }
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
            return error.InvalidUriTemplate;
        }
        index += 1;
        segment_len += 1;
    }
    if (segment_len == 0) return error.InvalidUriTemplate;
}

fn validateVariables(variables: []const Variable) Error!void {
    for (variables, 0..) |variable, index| {
        try validateVariableName(variable.name);
        if (std.mem.eql(u8, variable.name, "target_host") or
            std.mem.eql(u8, variable.name, "target_port"))
        {
            return error.DuplicateTemplateVariable;
        }
        for (variables[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, variable.name)) {
                return error.DuplicateTemplateVariable;
            }
        }
    }
}

fn variableValue(
    name: []const u8,
    target_host: []const u8,
    target_port: []const u8,
    variables: []const Variable,
) ?[]const u8 {
    if (std.mem.eql(u8, name, "target_host")) return target_host;
    if (std.mem.eql(u8, name, "target_port")) return target_port;
    for (variables) |variable| {
        if (std.mem.eql(u8, name, variable.name)) return variable.value;
    }
    return null;
}

fn validateTargetHost(host: []const u8) Error!void {
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, '%') != null) {
        return error.InvalidTarget;
    }
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        _ = net.IpAddress.parseIp6(host, 1) catch
            return error.InvalidTarget;
        return;
    }
    for (host) |byte| {
        if (!isRegNameByte(byte)) return error.InvalidTarget;
    }
}

const Writer = struct {
    out: ?[]u8,
    len: usize = 0,

    fn byte(self: *Writer, value: u8) Error!void {
        if (self.out) |out| out[self.len] = value;
        self.len = std.math.add(usize, self.len, 1) catch
            return error.IntegerOverflow;
    }

    fn slice(self: *Writer, value: []const u8) Error!void {
        const end = std.math.add(usize, self.len, value.len) catch
            return error.IntegerOverflow;
        if (self.out) |out| @memcpy(out[self.len..end], value);
        self.len = end;
    }

    fn encoded(self: *Writer, value: []const u8) Error!void {
        const hex = "0123456789ABCDEF";
        for (value) |raw| {
            if (isUnreserved(raw)) {
                try self.byte(raw);
            } else {
                try self.byte('%');
                try self.byte(hex[raw >> 4]);
                try self.byte(hex[raw & 0x0f]);
            }
        }
    }
};

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn isRegNameByte(byte: u8) bool {
    if (isUnreserved(byte)) return true;
    return switch (byte) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

test "CONNECT-UDP URI Template expands RFC 9298 examples" {
    const target_host = "2001:db8::42";
    const target_port: u16 = 443;
    var storage: [256]u8 = undefined;

    const path_template = try Template.compile(
        "https://example.org/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    try std.testing.expectEqualStrings("https", path_template.scheme);
    try std.testing.expectEqualStrings("example.org", path_template.authority);
    try std.testing.expectEqualStrings(
        "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/",
        try path_template.expandRequestTargetInto(
            &storage,
            target_host,
            target_port,
            &.{},
        ),
    );
    try std.testing.expectEqualStrings(
        "https://example.org/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/",
        try path_template.expandUriInto(
            &storage,
            target_host,
            target_port,
            &.{},
        ),
    );
    var short = [_]u8{0xaa} ** 8;
    try std.testing.expectError(
        error.BufferTooShort,
        path_template.expandRequestTargetInto(
            &short,
            target_host,
            target_port,
            &.{},
        ),
    );
    try std.testing.expectEqual([_]u8{0xaa} ** short.len, short);

    const literal_query = try Template.compile(
        "https://proxy.example.org:4443/masque?h={target_host}&p={target_port}",
    );
    try std.testing.expectEqualStrings(
        "/masque?h=2001%3Adb8%3A%3A42&p=443",
        try literal_query.expandRequestTargetInto(
            &storage,
            target_host,
            target_port,
            &.{},
        ),
    );

    const query_template = try Template.compile(
        "https://proxy.example.org:4443/masque{?target_host,target_port,token,missing}",
    );
    try std.testing.expectEqualStrings(
        "/masque?target_host=2001%3Adb8%3A%3A42&target_port=443&token=a%2Fb",
        try query_template.expandRequestTargetInto(
            &storage,
            target_host,
            target_port,
            &.{.{ .name = "token", .value = "a/b" }},
        ),
    );
}

test "CONNECT-UDP URI Template rejects forbidden and ambiguous forms" {
    inline for (.{
        "https://proxy.test/{+target_host}/{target_port}",
        "https://proxy.test/{#target_host}/{target_port}",
        "https://proxy.test/{.target_host}/{target_port}",
        "https://proxy.test/{/target_host}/{target_port}",
        "https://proxy.test/{;target_host}/{target_port}",
        "https://proxy.test/{target_host*}/{target_port}",
        "https://proxy.test/{target_host:4}/{target_port}",
        "https://{target_host}/{target_port}/",
        "https://proxy.test/{target_host}/",
    }) |invalid| {
        try std.testing.expectError(
            if (std.mem.endsWith(u8, invalid, "{target_host}/"))
                error.MissingTemplateVariable
            else
                error.InvalidUriTemplate,
            Template.compile(invalid),
        );
    }

    const continuation = try Template.compile(
        "https://proxy.test/masque{?optional}{&target_host,target_port}",
    );
    var storage = [_]u8{0xaa} ** 128;
    try std.testing.expectError(
        error.InvalidTemplateExpansion,
        continuation.expandRequestTargetInto(
            &storage,
            "dns.example",
            53,
            &.{},
        ),
    );
    try std.testing.expectEqual(@as(u8, 0xaa), storage[0]);
    try std.testing.expectError(
        error.DuplicateTemplateVariable,
        continuation.expandedLen(
            "dns.example",
            53,
            &.{
                .{ .name = "token", .value = "one" },
                .{ .name = "token", .value = "two" },
            },
        ),
    );
}
