//! Minimal schema-free reader for google.protobuf.FileDescriptorSet.
//!
//! The parser extracts only metadata needed by gRPC reflection while keeping
//! each original FileDescriptorProto byte string intact for wire responses.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    InvalidExtensionNumber,
    InvalidFieldNumber,
    InvalidUtf8,
    MalformedMessage,
    TruncatedMessage,
    VarintOverflow,
};

pub const Extension = struct {
    containing_type: []const u8,
    number: i32,
};

pub const File = struct {
    name: []const u8,
    descriptor: []const u8,
    dependencies: []const []const u8,
    message_types: []const []const u8,
    symbols: []const []const u8,
    services: []const []const u8,
    extensions: []const Extension,

    pub fn deinit(self: *File, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.descriptor);
        freeStrings(allocator, self.dependencies);
        freeStrings(allocator, self.message_types);
        freeStrings(allocator, self.symbols);
        freeStrings(allocator, self.services);
        for (self.extensions) |extension| {
            allocator.free(extension.containing_type);
        }
        allocator.free(self.extensions);
        self.* = undefined;
    }
};

pub const Set = struct {
    allocator: std.mem.Allocator,
    files: []File,

    pub fn deinit(self: *Set) void {
        for (self.files) |*file| file.deinit(self.allocator);
        self.allocator.free(self.files);
        self.* = undefined;
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!Set {
    var files: std.ArrayList(File) = .empty;
    errdefer {
        for (files.items) |*file| file.deinit(allocator);
        files.deinit(allocator);
    }
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            var file = try parseFile(allocator, try reader.bytesValue());
            errdefer file.deinit(allocator);
            try files.append(allocator, file);
        } else try reader.skip(field);
    }
    return .{
        .allocator = allocator,
        .files = try files.toOwnedSlice(allocator),
    };
}

const Builder = struct {
    allocator: std.mem.Allocator,
    descriptor: []const u8,
    name: ?[]const u8 = null,
    package: []const u8 = "",
    dependencies: std.ArrayList([]const u8) = .empty,
    message_types: std.ArrayList([]const u8) = .empty,
    symbols: std.ArrayList([]const u8) = .empty,
    services: std.ArrayList([]const u8) = .empty,
    extensions: std.ArrayList(Extension) = .empty,

    fn deinit(self: *Builder) void {
        deinitStringList(self.allocator, &self.dependencies);
        deinitStringList(self.allocator, &self.message_types);
        deinitStringList(self.allocator, &self.symbols);
        deinitStringList(self.allocator, &self.services);
        for (self.extensions.items) |extension| {
            self.allocator.free(extension.containing_type);
        }
        self.extensions.deinit(self.allocator);
    }

    fn appendBorrowed(
        self: *Builder,
        list: *std.ArrayList([]const u8),
        value: []const u8,
    ) Error!void {
        try validateString(value);
        const owned = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned);
        try list.append(self.allocator, owned);
    }

    fn appendQualified(
        self: *Builder,
        list: *std.ArrayList([]const u8),
        scope: []const u8,
        name: []const u8,
    ) Error!void {
        try validateNonEmptyString(name);
        const qualified = try qualifyAlloc(self.allocator, scope, name);
        errdefer self.allocator.free(qualified);
        try list.append(self.allocator, qualified);
    }

    fn appendSymbol(
        self: *Builder,
        scope: []const u8,
        name: []const u8,
    ) Error!void {
        return self.appendQualified(&self.symbols, scope, name);
    }

    fn appendMessageType(
        self: *Builder,
        scope: []const u8,
        name: []const u8,
    ) Error![]const u8 {
        try validateNonEmptyString(name);
        const qualified = try qualifyAlloc(self.allocator, scope, name);
        errdefer self.allocator.free(qualified);
        const symbol = try self.allocator.dupe(u8, qualified);
        errdefer self.allocator.free(symbol);
        try self.message_types.ensureUnusedCapacity(self.allocator, 1);
        try self.symbols.ensureUnusedCapacity(self.allocator, 1);
        self.message_types.appendAssumeCapacity(qualified);
        self.symbols.appendAssumeCapacity(symbol);
        return qualified;
    }

    fn appendService(
        self: *Builder,
        scope: []const u8,
        name: []const u8,
    ) Error![]const u8 {
        try validateNonEmptyString(name);
        const qualified = try qualifyAlloc(self.allocator, scope, name);
        errdefer self.allocator.free(qualified);
        const symbol = try self.allocator.dupe(u8, qualified);
        errdefer self.allocator.free(symbol);
        try self.services.ensureUnusedCapacity(self.allocator, 1);
        try self.symbols.ensureUnusedCapacity(self.allocator, 1);
        self.services.appendAssumeCapacity(qualified);
        self.symbols.appendAssumeCapacity(symbol);
        return qualified;
    }

    fn appendExtension(
        self: *Builder,
        scope: []const u8,
        bytes: []const u8,
    ) Error!void {
        const field = try parseField(bytes);
        try self.appendSymbol(scope, field.name);
        // Match protobuf's encoded descriptor database: relative extendees are
        // valid descriptor input but cannot be indexed without full type-name
        // resolution, so retain the file/symbol and omit only this lookup key.
        if (field.extendee.len == 0 or field.extendee[0] != '.') return;
        const containing_type = try normalizeTypeNameAlloc(
            self.allocator,
            scope,
            field.extendee,
        );
        errdefer self.allocator.free(containing_type);
        try validateExtensionNumber(field.number);
        try self.extensions.append(self.allocator, .{
            .containing_type = containing_type,
            .number = field.number,
        });
    }

    fn finish(self: *Builder) Error!File {
        const name_value = self.name orelse return error.MalformedMessage;
        try validateNonEmptyString(name_value);
        const name = try self.allocator.dupe(u8, name_value);
        errdefer self.allocator.free(name);
        const descriptor = try self.allocator.dupe(u8, self.descriptor);
        errdefer self.allocator.free(descriptor);
        const dependencies = try self.dependencies.toOwnedSlice(self.allocator);
        self.dependencies = .empty;
        errdefer freeStrings(self.allocator, dependencies);
        const message_types = try self.message_types.toOwnedSlice(self.allocator);
        self.message_types = .empty;
        errdefer freeStrings(self.allocator, message_types);
        const symbols = try self.symbols.toOwnedSlice(self.allocator);
        self.symbols = .empty;
        errdefer freeStrings(self.allocator, symbols);
        const services = try self.services.toOwnedSlice(self.allocator);
        self.services = .empty;
        errdefer freeStrings(self.allocator, services);
        const extensions = try self.extensions.toOwnedSlice(self.allocator);
        self.extensions = .empty;
        return .{
            .name = name,
            .descriptor = descriptor,
            .dependencies = dependencies,
            .message_types = message_types,
            .symbols = symbols,
            .services = services,
            .extensions = extensions,
        };
    }
};

fn parseFile(allocator: std.mem.Allocator, bytes: []const u8) Error!File {
    var builder = Builder{ .allocator = allocator, .descriptor = bytes };
    defer builder.deinit();

    // Package precedes declarations in protoc output, but protobuf field order
    // is unrestricted. First collect file identity/package/dependencies.
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 2) {
            builder.name = try reader.string();
        } else try reader.skip(field),
        2 => if (field.wire_type == 2) {
            builder.package = try reader.string();
        } else try reader.skip(field),
        3, 15 => if (field.wire_type == 2) {
            try builder.appendBorrowed(
                &builder.dependencies,
                try reader.string(),
            );
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    try validateString(builder.package);

    reader.cursor = 0;
    while (try reader.next()) |field| switch (field.number) {
        4 => if (field.wire_type == 2) {
            try parseMessage(&builder, builder.package, try reader.bytesValue());
        } else try reader.skip(field),
        5 => if (field.wire_type == 2) {
            try parseEnum(&builder, builder.package, try reader.bytesValue());
        } else try reader.skip(field),
        6 => if (field.wire_type == 2) {
            try parseService(&builder, builder.package, try reader.bytesValue());
        } else try reader.skip(field),
        7 => if (field.wire_type == 2) {
            try builder.appendExtension(
                builder.package,
                try reader.bytesValue(),
            );
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    return builder.finish();
}

fn parseMessage(
    builder: *Builder,
    parent_scope: []const u8,
    bytes: []const u8,
) Error!void {
    const name = try messageName(bytes);
    const scope = try builder.appendMessageType(parent_scope, name);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        2 => if (field.wire_type == 2) {
            const value = try parseField(try reader.bytesValue());
            try builder.appendSymbol(scope, value.name);
        } else try reader.skip(field),
        3 => if (field.wire_type == 2) {
            try parseMessage(builder, scope, try reader.bytesValue());
        } else try reader.skip(field),
        4 => if (field.wire_type == 2) {
            try parseEnum(builder, scope, try reader.bytesValue());
        } else try reader.skip(field),
        6 => if (field.wire_type == 2) {
            try builder.appendExtension(scope, try reader.bytesValue());
        } else try reader.skip(field),
        8 => if (field.wire_type == 2) {
            try builder.appendSymbol(
                scope,
                try namedMessageName(try reader.bytesValue()),
            );
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
}

fn parseEnum(
    builder: *Builder,
    parent_scope: []const u8,
    bytes: []const u8,
) Error!void {
    const name = try namedMessageName(bytes);
    try builder.appendSymbol(parent_scope, name);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 2 and field.wire_type == 2) {
            try builder.appendSymbol(
                parent_scope,
                try namedMessageName(try reader.bytesValue()),
            );
        } else try reader.skip(field);
    }
}

fn parseService(
    builder: *Builder,
    parent_scope: []const u8,
    bytes: []const u8,
) Error!void {
    const name = try namedMessageName(bytes);
    const scope = try builder.appendService(parent_scope, name);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 2 and field.wire_type == 2) {
            try builder.appendSymbol(
                scope,
                try namedMessageName(try reader.bytesValue()),
            );
        } else try reader.skip(field);
    }
}

fn messageName(bytes: []const u8) Error![]const u8 {
    return namedMessageName(bytes);
}

fn namedMessageName(bytes: []const u8) Error![]const u8 {
    var name: ?[]const u8 = null;
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            name = try reader.string();
        } else try reader.skip(field);
    }
    const value = name orelse return error.MalformedMessage;
    try validateNonEmptyString(value);
    return value;
}

const FieldDescriptor = struct {
    name: []const u8,
    extendee: []const u8,
    number: i32,
};

fn parseField(bytes: []const u8) Error!FieldDescriptor {
    var name: ?[]const u8 = null;
    var extendee: []const u8 = "";
    var number: i32 = 0;
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 2) {
            name = try reader.string();
        } else try reader.skip(field),
        2 => if (field.wire_type == 2) {
            extendee = try reader.string();
        } else try reader.skip(field),
        3 => if (field.wire_type == 0) {
            number = decodeInt32(try reader.varint());
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    const field_name = name orelse return error.MalformedMessage;
    try validateNonEmptyString(field_name);
    return .{
        .name = field_name,
        .extendee = extendee,
        .number = number,
    };
}

fn normalizeTypeNameAlloc(
    allocator: std.mem.Allocator,
    scope: []const u8,
    name: []const u8,
) Error![]const u8 {
    _ = scope;
    try validateNonEmptyString(name);
    if (name[0] == '.') return allocator.dupe(u8, name[1..]);
    unreachable;
}

fn qualifyAlloc(
    allocator: std.mem.Allocator,
    scope: []const u8,
    name: []const u8,
) Error![]const u8 {
    return if (scope.len == 0)
        allocator.dupe(u8, name)
    else
        std.fmt.allocPrint(allocator, "{s}.{s}", .{ scope, name });
}

fn freeStrings(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

fn deinitStringList(
    allocator: std.mem.Allocator,
    values: *std.ArrayList([]const u8),
) void {
    for (values.items) |value| allocator.free(value);
    values.deinit(allocator);
}

fn validateString(value: []const u8) Error!void {
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
}

fn validateNonEmptyString(value: []const u8) Error!void {
    try validateString(value);
    if (value.len == 0) return error.MalformedMessage;
}

fn validateExtensionNumber(number: i32) Error!void {
    if (number <= 0 or number > 536_870_911 or
        (number >= 19_000 and number <= 19_999))
    {
        return error.InvalidExtensionNumber;
    }
}

fn decodeInt32(value: u64) i32 {
    return @bitCast(@as(u32, @truncate(value)));
}

const Field = struct { number: u32, wire_type: u3 };

const Reader = struct {
    bytes: []const u8,
    cursor: usize = 0,

    fn next(self: *Reader) Error!?Field {
        if (self.cursor == self.bytes.len) return null;
        const key = try self.varint();
        const number = key >> 3;
        if (number == 0 or number > 0x1fffffff) {
            return error.InvalidFieldNumber;
        }
        return .{ .number = @intCast(number), .wire_type = @intCast(key & 7) };
    }

    fn varint(self: *Reader) Error!u64 {
        var value: u64 = 0;
        var shift: u6 = 0;
        for (0..10) |index| {
            if (self.cursor == self.bytes.len) return error.TruncatedMessage;
            const byte = self.bytes[self.cursor];
            self.cursor += 1;
            if (index == 9 and byte > 1) return error.VarintOverflow;
            value |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) return value;
            if (index != 9) shift += 7;
        }
        return error.VarintOverflow;
    }

    fn bytesValue(self: *Reader) Error![]const u8 {
        const raw_len = try self.varint();
        if (raw_len > std.math.maxInt(usize)) return error.TruncatedMessage;
        const len: usize = @intCast(raw_len);
        if (len > self.bytes.len - self.cursor) return error.TruncatedMessage;
        const value = self.bytes[self.cursor..][0..len];
        self.cursor += len;
        return value;
    }

    fn string(self: *Reader) Error![]const u8 {
        const value = try self.bytesValue();
        try validateString(value);
        return value;
    }

    fn skip(self: *Reader, field: Field) Error!void {
        return self.skipValue(field.number, field.wire_type, 0);
    }

    fn skipValue(
        self: *Reader,
        field_number: u32,
        wire_type: u3,
        depth: u8,
    ) Error!void {
        switch (wire_type) {
            0 => _ = try self.varint(),
            1 => try self.skipBytes(8),
            2 => _ = try self.bytesValue(),
            3 => {
                if (depth == 100) return error.MalformedMessage;
                while (try self.next()) |nested| {
                    if (nested.wire_type == 4) {
                        if (nested.number != field_number) {
                            return error.MalformedMessage;
                        }
                        return;
                    }
                    try self.skipValue(
                        nested.number,
                        nested.wire_type,
                        depth + 1,
                    );
                }
                return error.TruncatedMessage;
            },
            4, 6, 7 => return error.MalformedMessage,
            5 => try self.skipBytes(4),
        }
    }

    fn skipBytes(self: *Reader, len: usize) Error!void {
        if (len > self.bytes.len - self.cursor) {
            return error.TruncatedMessage;
        }
        self.cursor += len;
    }
};

fn appendTestVarint(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u64,
) !void {
    var remaining = value;
    while (remaining >= 0x80) {
        try out.append(allocator, @as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try out.append(allocator, @intCast(remaining));
}

fn appendTestBytes(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u32,
    value: []const u8,
) !void {
    try appendTestVarint(
        out,
        allocator,
        (@as(u64, field_number) << 3) | 2,
    );
    try appendTestVarint(out, allocator, value.len);
    try out.appendSlice(allocator, value);
}

fn appendTestInt32(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u32,
    value: i32,
) !void {
    try appendTestVarint(out, allocator, @as(u64, field_number) << 3);
    try appendTestVarint(out, allocator, @bitCast(@as(i64, value)));
}

test "reflection descriptor set extracts nested symbols and extensions" {
    const allocator = std.testing.allocator;
    var field: std.ArrayList(u8) = .empty;
    defer field.deinit(allocator);
    try appendTestBytes(&field, allocator, 1, "id");
    try appendTestInt32(&field, allocator, 3, 1);
    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(allocator);
    try appendTestBytes(&nested, allocator, 1, "Inner");
    var enum_value: std.ArrayList(u8) = .empty;
    defer enum_value.deinit(allocator);
    try appendTestBytes(&enum_value, allocator, 1, "READY");
    try appendTestInt32(&enum_value, allocator, 2, 0);
    var nested_enum: std.ArrayList(u8) = .empty;
    defer nested_enum.deinit(allocator);
    try appendTestBytes(&nested_enum, allocator, 1, "State");
    try appendTestBytes(&nested_enum, allocator, 2, enum_value.items);
    var oneof: std.ArrayList(u8) = .empty;
    defer oneof.deinit(allocator);
    try appendTestBytes(&oneof, allocator, 1, "choice");
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try appendTestBytes(&message, allocator, 1, "Common");
    try appendTestBytes(&message, allocator, 2, field.items);
    try appendTestBytes(&message, allocator, 3, nested.items);
    try appendTestBytes(&message, allocator, 4, nested_enum.items);
    try appendTestBytes(&message, allocator, 8, oneof.items);
    var method: std.ArrayList(u8) = .empty;
    defer method.deinit(allocator);
    try appendTestBytes(&method, allocator, 1, "Unary");
    var service: std.ArrayList(u8) = .empty;
    defer service.deinit(allocator);
    try appendTestBytes(&service, allocator, 1, "Echo");
    try appendTestBytes(&service, allocator, 2, method.items);
    var common: std.ArrayList(u8) = .empty;
    defer common.deinit(allocator);
    try appendTestBytes(&common, allocator, 1, "common.proto");
    try appendTestBytes(&common, allocator, 2, "demo");
    try appendTestBytes(&common, allocator, 4, message.items);
    try appendTestBytes(&common, allocator, 6, service.items);

    var extension: std.ArrayList(u8) = .empty;
    defer extension.deinit(allocator);
    try appendTestBytes(&extension, allocator, 1, "extra");
    try appendTestBytes(&extension, allocator, 2, ".demo.Common");
    try appendTestInt32(&extension, allocator, 3, 100);
    var application: std.ArrayList(u8) = .empty;
    defer application.deinit(allocator);
    // Deliberately emit declarations before package/name to verify arbitrary
    // protobuf field ordering.
    try appendTestBytes(&application, allocator, 7, extension.items);
    try appendTestBytes(&application, allocator, 3, "common.proto");
    try appendTestBytes(&application, allocator, 2, "demo");
    try appendTestBytes(&application, allocator, 1, "app.proto");

    var encoded_set: std.ArrayList(u8) = .empty;
    defer encoded_set.deinit(allocator);
    try appendTestBytes(&encoded_set, allocator, 1, common.items);
    try appendTestBytes(&encoded_set, allocator, 1, application.items);
    var decoded = try parse(allocator, encoded_set.items);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded.files.len);
    try std.testing.expectEqualSlices(
        u8,
        common.items,
        decoded.files[0].descriptor,
    );
    try std.testing.expectEqualStrings("common.proto", decoded.files[0].name);
    try std.testing.expectEqualStrings("demo.Common", decoded.files[0].message_types[0]);
    const expected_symbols = [_][]const u8{
        "demo.Common",
        "demo.Common.id",
        "demo.Common.Inner",
        "demo.Common.State",
        "demo.Common.READY",
        "demo.Common.choice",
        "demo.Echo",
        "demo.Echo.Unary",
    };
    try std.testing.expectEqual(expected_symbols.len, decoded.files[0].symbols.len);
    for (expected_symbols, decoded.files[0].symbols) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
    try std.testing.expectEqualStrings("demo.Echo", decoded.files[0].services[0]);
    try std.testing.expectEqualStrings("common.proto", decoded.files[1].dependencies[0]);
    try std.testing.expectEqualStrings(
        "demo.Common",
        decoded.files[1].extensions[0].containing_type,
    );
    try std.testing.expectEqual(@as(i32, 100), decoded.files[1].extensions[0].number);
    try std.testing.expectEqualStrings("demo.extra", decoded.files[1].symbols[0]);
}

test "reflection descriptor set rejects truncation and skips relative extendees" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.TruncatedMessage,
        parse(allocator, &.{ 0x0a, 0x02, 0x0a }),
    );

    var extension: std.ArrayList(u8) = .empty;
    defer extension.deinit(allocator);
    try appendTestBytes(&extension, allocator, 1, "extra");
    try appendTestBytes(&extension, allocator, 2, "Relative");
    try appendTestInt32(&extension, allocator, 3, 100);
    var file: std.ArrayList(u8) = .empty;
    defer file.deinit(allocator);
    try appendTestBytes(&file, allocator, 1, "bad.proto");
    try appendTestBytes(&file, allocator, 7, extension.items);
    var set: std.ArrayList(u8) = .empty;
    defer set.deinit(allocator);
    try appendTestBytes(&set, allocator, 1, file.items);
    var decoded = try parse(allocator, set.items);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.files.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.files[0].extensions.len);
    try std.testing.expectEqualStrings(
        "extra",
        decoded.files[0].symbols[0],
    );
}
