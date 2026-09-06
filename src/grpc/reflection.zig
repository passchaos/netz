//! Standard gRPC Server Reflection v1/v1alpha wire messages and registry.
//!
//! Descriptor protos remain opaque bytes. This keeps reflection independent
//! from a particular protobuf code generator while still providing all five
//! standard query shapes and transitive dependency expansion.

const std = @import("std");
const wire = @import("wire.zig");

pub const v1_path =
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
pub const v1alpha_path =
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

pub const Error = std.mem.Allocator.Error || error{
    DuplicateDescriptor,
    DuplicateExtension,
    DuplicateService,
    DuplicateSymbol,
    InvalidExtensionNumber,
    InvalidFieldNumber,
    InvalidUtf8,
    MalformedMessage,
    MissingDependency,
    TruncatedMessage,
    VarintOverflow,
};

pub const ExtensionRequest = struct {
    containing_type: []const u8 = "",
    extension_number: i32 = 0,
};

pub const Query = union(enum) {
    none,
    file_by_filename: []const u8,
    file_containing_symbol: []const u8,
    file_containing_extension: ExtensionRequest,
    all_extension_numbers_of_type: []const u8,
    list_services: []const u8,
};

pub const Request = struct {
    host: []const u8 = "",
    query: Query = .none,
};

pub const ExtensionNumbers = struct {
    base_type_name: []const u8,
    numbers: []const i32,
};

pub const Failure = struct {
    code: wire.Status,
    message: []const u8,
};

pub const Result = union(enum) {
    none,
    file_descriptors: []const []const u8,
    extension_numbers: ExtensionNumbers,
    services: []const []const u8,
    failure: Failure,
};

/// Parsed response whose result arrays are owned while all byte slices borrow
/// the encoded input. Keep the input alive until `deinit`.
pub const Response = struct {
    allocator: std.mem.Allocator,
    valid_host: []const u8 = "",
    original_request: []const u8 = &.{},
    result: Result = .none,

    pub fn deinit(self: *Response) void {
        freeResult(self.allocator, self.result);
        self.* = undefined;
    }
};

pub fn encodeRequestAlloc(
    allocator: std.mem.Allocator,
    request: Request,
) Error![]u8 {
    try validateString(request.host);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (request.host.len != 0) {
        try appendBytesField(&out, allocator, 1, request.host);
    }
    switch (request.query) {
        .none => {},
        .file_by_filename => |value| {
            try validateString(value);
            try appendBytesField(&out, allocator, 3, value);
        },
        .file_containing_symbol => |value| {
            try validateString(value);
            try appendBytesField(&out, allocator, 4, value);
        },
        .file_containing_extension => |value| {
            try validateString(value.containing_type);
            try validateExtensionNumber(value.extension_number);
            var nested: std.ArrayList(u8) = .empty;
            defer nested.deinit(allocator);
            if (value.containing_type.len != 0) {
                try appendBytesField(
                    &nested,
                    allocator,
                    1,
                    value.containing_type,
                );
            }
            if (value.extension_number != 0) {
                try appendInt32Field(
                    &nested,
                    allocator,
                    2,
                    value.extension_number,
                );
            }
            try appendBytesField(&out, allocator, 5, nested.items);
        },
        .all_extension_numbers_of_type => |value| {
            try validateString(value);
            try appendBytesField(&out, allocator, 6, value);
        },
        .list_services => |value| {
            try validateString(value);
            try appendBytesField(&out, allocator, 7, value);
        },
    }
    return out.toOwnedSlice(allocator);
}

pub fn decodeRequest(bytes: []const u8) Error!Request {
    var result: Request = .{};
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 2) {
            result.host = try reader.string();
        } else try reader.skip(field),
        3 => if (field.wire_type == 2) {
            result.query = .{ .file_by_filename = try reader.string() };
        } else try reader.skip(field),
        4 => if (field.wire_type == 2) {
            result.query = .{ .file_containing_symbol = try reader.string() };
        } else try reader.skip(field),
        5 => if (field.wire_type == 2) {
            result.query = .{ .file_containing_extension = try decodeExtensionRequest(try reader.bytesValue()) };
        } else try reader.skip(field),
        6 => if (field.wire_type == 2) {
            result.query = .{
                .all_extension_numbers_of_type = try reader.string(),
            };
        } else try reader.skip(field),
        7 => if (field.wire_type == 2) {
            result.query = .{ .list_services = try reader.string() };
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    return result;
}

pub fn encodeResponseAlloc(
    allocator: std.mem.Allocator,
    valid_host: []const u8,
    original_request: []const u8,
    result: Result,
) Error![]u8 {
    try validateString(valid_host);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (valid_host.len != 0) {
        try appendBytesField(&out, allocator, 1, valid_host);
    }
    try appendBytesField(&out, allocator, 2, original_request);

    var nested: std.ArrayList(u8) = .empty;
    defer nested.deinit(allocator);
    const result_field: u32 = switch (result) {
        .none => return out.toOwnedSlice(allocator),
        .file_descriptors => |descriptors| blk: {
            for (descriptors) |descriptor| {
                try appendBytesField(&nested, allocator, 1, descriptor);
            }
            break :blk 4;
        },
        .extension_numbers => |extensions| blk: {
            try validateString(extensions.base_type_name);
            if (extensions.base_type_name.len != 0) {
                try appendBytesField(
                    &nested,
                    allocator,
                    1,
                    extensions.base_type_name,
                );
            }
            if (extensions.numbers.len != 0) {
                var packed_values: std.ArrayList(u8) = .empty;
                defer packed_values.deinit(allocator);
                for (extensions.numbers) |number| {
                    try validateExtensionNumber(number);
                    try appendInt32(&packed_values, allocator, number);
                }
                try appendBytesField(
                    &nested,
                    allocator,
                    2,
                    packed_values.items,
                );
            }
            break :blk 5;
        },
        .services => |services| blk: {
            for (services) |service| {
                try validateString(service);
                var item: std.ArrayList(u8) = .empty;
                defer item.deinit(allocator);
                if (service.len != 0) {
                    try appendBytesField(&item, allocator, 1, service);
                }
                try appendBytesField(&nested, allocator, 1, item.items);
            }
            break :blk 6;
        },
        .failure => |failure| blk: {
            try appendInt32Field(
                &nested,
                allocator,
                1,
                @intFromEnum(failure.code),
            );
            try validateString(failure.message);
            if (failure.message.len != 0) {
                try appendBytesField(
                    &nested,
                    allocator,
                    2,
                    failure.message,
                );
            }
            break :blk 7;
        },
    };
    try appendBytesField(&out, allocator, result_field, nested.items);
    return out.toOwnedSlice(allocator);
}

pub fn decodeResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!Response {
    var response = Response{ .allocator = allocator };
    errdefer response.deinit();
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 2) {
            response.valid_host = try reader.string();
        } else try reader.skip(field),
        2 => if (field.wire_type == 2) {
            response.original_request = try reader.bytesValue();
        } else try reader.skip(field),
        4 => if (field.wire_type == 2) {
            const parsed = try decodeFileDescriptors(
                allocator,
                try reader.bytesValue(),
            );
            freeResult(allocator, response.result);
            response.result = .{ .file_descriptors = parsed };
        } else try reader.skip(field),
        5 => if (field.wire_type == 2) {
            const parsed = try decodeExtensionNumbers(
                allocator,
                try reader.bytesValue(),
            );
            freeResult(allocator, response.result);
            response.result = .{ .extension_numbers = parsed };
        } else try reader.skip(field),
        6 => if (field.wire_type == 2) {
            const parsed = try decodeServices(
                allocator,
                try reader.bytesValue(),
            );
            freeResult(allocator, response.result);
            response.result = .{ .services = parsed };
        } else try reader.skip(field),
        7 => if (field.wire_type == 2) {
            const parsed = try decodeFailure(try reader.bytesValue());
            freeResult(allocator, response.result);
            response.result = .{ .failure = parsed };
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    return response;
}

pub const Extension = struct {
    containing_type: []const u8,
    number: i32,
};

pub const File = struct {
    name: []const u8,
    descriptor: []const u8,
    dependencies: []const []const u8 = &.{},
    /// Fully-qualified message names declared by this file. These are kept
    /// separate from `symbols` so extension queries cannot mistake a service,
    /// method, or enum for an extendable message type.
    message_types: []const []const u8 = &.{},
    /// All fully-qualified declarations usable by file_containing_symbol.
    symbols: []const []const u8 = &.{},
    extensions: []const Extension = &.{},
};

const OwnedExtension = struct {
    containing_type: []const u8,
    number: i32,
};

const Entry = struct {
    name: []const u8,
    descriptor: []const u8,
    dependencies: []const []const u8,
    message_types: []const []const u8,
    symbols: []const []const u8,
    extensions: []const OwnedExtension,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.descriptor);
        freeStrings(allocator, self.dependencies);
        freeStrings(allocator, self.message_types);
        freeStrings(allocator, self.symbols);
        for (self.extensions) |extension| {
            allocator.free(extension.containing_type);
        }
        allocator.free(self.extensions);
        self.* = undefined;
    }
};

/// Concurrent registry of opaque serialized `FileDescriptorProto` values.
/// Files may be added in any order; missing dependency names are reported only
/// when the affected descriptor is queried.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    files: std.ArrayList(Entry) = .empty,
    services: std.ArrayList([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Registry {
        return .{ .allocator = allocator, .io = io };
    }

    pub fn deinit(self: *Registry) void {
        for (self.files.items) |*file| file.deinit(self.allocator);
        self.files.deinit(self.allocator);
        for (self.services.items) |service| self.allocator.free(service);
        self.services.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addService(self: *Registry, service: []const u8) Error!void {
        try validateNonEmptyString(service);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.services.items) |existing| {
            if (std.mem.eql(u8, existing, service)) {
                return error.DuplicateService;
            }
        }
        const owned = try self.allocator.dupe(u8, service);
        errdefer self.allocator.free(owned);
        try self.services.append(self.allocator, owned);
    }

    pub fn addFile(self: *Registry, file: File) Error!void {
        try validateNonEmptyString(file.name);
        for (file.dependencies) |name| try validateNonEmptyString(name);
        for (file.message_types) |name| try validateNonEmptyString(name);
        for (file.symbols) |symbol| try validateNonEmptyString(symbol);
        for (file.extensions) |extension| {
            try validateNonEmptyString(extension.containing_type);
            try validateExtensionNumber(extension.number);
        }
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.findFile(file.name) != null) return error.DuplicateDescriptor;
        for (file.symbols, 0..) |symbol, index| {
            if (self.findFileContainingSymbol(symbol) != null) {
                return error.DuplicateSymbol;
            }
            for (file.symbols[0..index]) |prior| {
                if (std.mem.eql(u8, prior, symbol)) {
                    return error.DuplicateSymbol;
                }
            }
        }
        for (file.message_types, 0..) |message_type, index| {
            if (self.hasMessageType(message_type)) {
                return error.DuplicateSymbol;
            }
            for (file.message_types[0..index]) |prior| {
                if (std.mem.eql(u8, prior, message_type)) {
                    return error.DuplicateSymbol;
                }
            }
        }
        for (file.extensions, 0..) |extension, index| {
            if (self.findFileContainingExtension(
                extension.containing_type,
                extension.number,
            ) != null) return error.DuplicateExtension;
            for (file.extensions[0..index]) |prior| {
                if (prior.number == extension.number and std.mem.eql(
                    u8,
                    prior.containing_type,
                    extension.containing_type,
                )) return error.DuplicateExtension;
            }
        }
        var owned = try cloneFile(self.allocator, file);
        errdefer owned.deinit(self.allocator);
        try self.files.append(self.allocator, owned);
    }

    /// Decode one reflection request and return its complete encoded response.
    pub fn respondAlloc(
        self: *Registry,
        allocator: std.mem.Allocator,
        request_bytes: []const u8,
    ) Error![]u8 {
        const request = try decodeRequest(request_bytes);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return switch (request.query) {
            .none => encodeResponseAlloc(
                allocator,
                request.host,
                request_bytes,
                .{ .failure = .{
                    .code = .unimplemented,
                    .message = "",
                } },
            ),
            .file_by_filename => |name| self.respondWithFile(
                allocator,
                request.host,
                request_bytes,
                self.findFile(name),
                "File not found.",
            ),
            .file_containing_symbol => |symbol| self.respondWithFile(
                allocator,
                request.host,
                request_bytes,
                self.findFileContainingSymbol(symbol),
                "Symbol not found.",
            ),
            .file_containing_extension => |extension| self.respondWithFile(
                allocator,
                request.host,
                request_bytes,
                if (self.hasMessageType(extension.containing_type))
                    self.findFileContainingExtension(
                        extension.containing_type,
                        extension.extension_number,
                    )
                else
                    null,
                if (self.hasMessageType(extension.containing_type))
                    "Extension not found."
                else
                    "Type not found.",
            ),
            .all_extension_numbers_of_type => |name| self.respondWithExtensionNumbers(
                allocator,
                request.host,
                request_bytes,
                name,
            ),
            .list_services => encodeResponseAlloc(
                allocator,
                request.host,
                request_bytes,
                .{ .services = self.services.items },
            ),
        };
    }

    fn respondWithFile(
        self: *Registry,
        allocator: std.mem.Allocator,
        host: []const u8,
        request_bytes: []const u8,
        file_index: ?usize,
        not_found_message: []const u8,
    ) Error![]u8 {
        const root = file_index orelse return encodeResponseAlloc(
            allocator,
            host,
            request_bytes,
            .{ .failure = .{
                .code = .not_found,
                .message = not_found_message,
            } },
        );
        var seen = try allocator.alloc(bool, self.files.items.len);
        defer allocator.free(seen);
        @memset(seen, false);
        var stack: std.ArrayList(usize) = .empty;
        defer stack.deinit(allocator);
        var descriptors: std.ArrayList([]const u8) = .empty;
        defer descriptors.deinit(allocator);
        try stack.append(allocator, root);
        while (stack.pop()) |index| {
            if (seen[index]) continue;
            seen[index] = true;
            const file = self.files.items[index];
            try descriptors.append(allocator, file.descriptor);
            var dependency = file.dependencies.len;
            while (dependency != 0) {
                dependency -= 1;
                const dependency_index = self.findFile(
                    file.dependencies[dependency],
                ) orelse return error.MissingDependency;
                if (!seen[dependency_index]) {
                    try stack.append(allocator, dependency_index);
                }
            }
        }
        return encodeResponseAlloc(
            allocator,
            host,
            request_bytes,
            .{ .file_descriptors = descriptors.items },
        );
    }

    fn respondWithExtensionNumbers(
        self: *Registry,
        allocator: std.mem.Allocator,
        host: []const u8,
        request_bytes: []const u8,
        containing_type: []const u8,
    ) Error![]u8 {
        if (!self.hasMessageType(containing_type)) {
            return encodeResponseAlloc(
                allocator,
                host,
                request_bytes,
                .{ .failure = .{
                    .code = .not_found,
                    .message = "Type not found.",
                } },
            );
        }
        var numbers: std.ArrayList(i32) = .empty;
        defer numbers.deinit(allocator);
        for (self.files.items) |file| {
            for (file.extensions) |extension| {
                if (std.mem.eql(
                    u8,
                    extension.containing_type,
                    containing_type,
                )) try numbers.append(allocator, extension.number);
            }
        }
        return encodeResponseAlloc(
            allocator,
            host,
            request_bytes,
            .{ .extension_numbers = .{
                .base_type_name = containing_type,
                .numbers = numbers.items,
            } },
        );
    }

    fn findFile(self: *const Registry, name: []const u8) ?usize {
        for (self.files.items, 0..) |file, index| {
            if (std.mem.eql(u8, file.name, name)) return index;
        }
        return null;
    }

    fn findFileContainingSymbol(
        self: *const Registry,
        symbol: []const u8,
    ) ?usize {
        for (self.files.items, 0..) |file, index| {
            for (file.symbols) |candidate| {
                if (std.mem.eql(u8, candidate, symbol)) return index;
            }
        }
        return null;
    }

    fn findFileContainingExtension(
        self: *const Registry,
        containing_type: []const u8,
        number: i32,
    ) ?usize {
        for (self.files.items, 0..) |file, index| {
            for (file.extensions) |extension| {
                if (extension.number == number and std.mem.eql(
                    u8,
                    extension.containing_type,
                    containing_type,
                )) return index;
            }
        }
        return null;
    }

    fn hasMessageType(
        self: *const Registry,
        containing_type: []const u8,
    ) bool {
        for (self.files.items) |file| {
            for (file.message_types) |message_type| {
                if (std.mem.eql(u8, message_type, containing_type)) return true;
            }
        }
        return false;
    }
};

fn cloneFile(allocator: std.mem.Allocator, file: File) Error!Entry {
    const name = try allocator.dupe(u8, file.name);
    errdefer allocator.free(name);
    const descriptor = try allocator.dupe(u8, file.descriptor);
    errdefer allocator.free(descriptor);
    const dependencies = try cloneStrings(allocator, file.dependencies);
    errdefer freeStrings(allocator, dependencies);
    const message_types = try cloneStrings(allocator, file.message_types);
    errdefer freeStrings(allocator, message_types);
    const symbols = try cloneStrings(allocator, file.symbols);
    errdefer freeStrings(allocator, symbols);
    const extensions = try allocator.alloc(OwnedExtension, file.extensions.len);
    var initialized: usize = 0;
    errdefer {
        for (extensions[0..initialized]) |extension| {
            allocator.free(extension.containing_type);
        }
        allocator.free(extensions);
    }
    for (file.extensions, 0..) |extension, index| {
        extensions[index] = .{
            .containing_type = try allocator.dupe(
                u8,
                extension.containing_type,
            ),
            .number = extension.number,
        };
        initialized += 1;
    }
    return .{
        .name = name,
        .descriptor = descriptor,
        .dependencies = dependencies,
        .message_types = message_types,
        .symbols = symbols,
        .extensions = extensions,
    };
}

fn cloneStrings(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) Error![]const []const u8 {
    const owned = try allocator.alloc([]const u8, values.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |value| allocator.free(value);
        allocator.free(owned);
    }
    for (values, 0..) |value, index| {
        owned[index] = try allocator.dupe(u8, value);
        initialized += 1;
    }
    return owned;
}

fn freeStrings(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

fn decodeExtensionRequest(bytes: []const u8) Error!ExtensionRequest {
    var result: ExtensionRequest = .{};
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 2) {
            result.containing_type = try reader.string();
        } else try reader.skip(field),
        2 => if (field.wire_type == 0) {
            result.extension_number = decodeInt32(try reader.varint());
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    try validateExtensionNumber(result.extension_number);
    return result;
}

fn decodeFileDescriptors(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error![]const []const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    errdefer result.deinit(allocator);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            try result.append(allocator, try reader.bytesValue());
        } else try reader.skip(field);
    }
    return result.toOwnedSlice(allocator);
}

fn decodeExtensionNumbers(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!ExtensionNumbers {
    var base_type_name: []const u8 = "";
    var numbers: std.ArrayList(i32) = .empty;
    errdefer numbers.deinit(allocator);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 2) {
            base_type_name = try reader.string();
        } else try reader.skip(field),
        2 => if (field.wire_type == 0) {
            const number = decodeInt32(try reader.varint());
            try validateExtensionNumber(number);
            try numbers.append(allocator, number);
        } else if (field.wire_type == 2) {
            var packed_values = Reader{ .bytes = try reader.bytesValue() };
            while (packed_values.cursor < packed_values.bytes.len) {
                const number = decodeInt32(try packed_values.varint());
                try validateExtensionNumber(number);
                try numbers.append(allocator, number);
            }
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    return .{
        .base_type_name = base_type_name,
        .numbers = try numbers.toOwnedSlice(allocator),
    };
}

fn decodeServices(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error![]const []const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    errdefer result.deinit(allocator);
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        var service_reader = Reader{ .bytes = try reader.bytesValue() };
        var name: []const u8 = "";
        while (try service_reader.next()) |service_field| {
            if (service_field.number == 1 and
                service_field.wire_type == 2)
            {
                name = try service_reader.string();
            } else try service_reader.skip(service_field);
        }
        try result.append(allocator, name);
    }
    return result.toOwnedSlice(allocator);
}

fn decodeFailure(bytes: []const u8) Error!Failure {
    var code: wire.Status = .ok;
    var message: []const u8 = "";
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => if (field.wire_type == 0) {
            const raw = decodeInt32(try reader.varint());
            if (raw < 0 or raw > std.math.maxInt(u8)) {
                return error.MalformedMessage;
            }
            code = std.enums.fromInt(wire.Status, @as(u8, @intCast(raw))) orelse
                return error.MalformedMessage;
        } else try reader.skip(field),
        2 => if (field.wire_type == 2) {
            message = try reader.string();
        } else try reader.skip(field),
        else => try reader.skip(field),
    };
    return .{ .code = code, .message = message };
}

fn freeResult(allocator: std.mem.Allocator, result: Result) void {
    switch (result) {
        .file_descriptors => |values| allocator.free(values),
        .extension_numbers => |value| allocator.free(value.numbers),
        .services => |values| allocator.free(values),
        .none, .failure => {},
    }
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
        return .{
            .number = @intCast(number),
            .wire_type = @intCast(key & 0x07),
        };
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

fn appendKey(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u32,
    wire_type: u3,
) Error!void {
    if (field_number == 0 or field_number > 0x1fffffff) {
        return error.InvalidFieldNumber;
    }
    try appendVarint(
        out,
        allocator,
        (@as(u64, field_number) << 3) | wire_type,
    );
}

fn appendBytesField(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u32,
    value: []const u8,
) Error!void {
    try appendKey(out, allocator, field_number, 2);
    try appendVarint(out, allocator, value.len);
    try out.appendSlice(allocator, value);
}

fn appendInt32Field(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    field_number: u32,
    value: i32,
) Error!void {
    try appendKey(out, allocator, field_number, 0);
    try appendInt32(out, allocator, value);
}

fn appendInt32(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: i32,
) Error!void {
    const encoded: u64 = @bitCast(@as(i64, value));
    try appendVarint(out, allocator, encoded);
}

fn appendVarint(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: anytype,
) Error!void {
    var remaining: u64 = @intCast(value);
    while (remaining >= 0x80) {
        try out.append(allocator, @as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try out.append(allocator, @intCast(remaining));
}

fn decodeInt32(value: u64) i32 {
    return @bitCast(@as(u32, @truncate(value)));
}

test "gRPC reflection request codecs cover every query kind" {
    const allocator = std.testing.allocator;
    const requests = [_]Request{
        .{ .host = "example.test", .query = .{
            .file_by_filename = "echo.proto",
        } },
        .{ .query = .{ .file_containing_symbol = "demo.Echo" } },
        .{ .query = .{ .file_containing_extension = .{
            .containing_type = "demo.Options",
            .extension_number = 123,
        } } },
        .{ .query = .{
            .all_extension_numbers_of_type = "demo.Options",
        } },
        .{ .query = .{ .list_services = "" } },
    };
    for (requests) |request| {
        const encoded = try encodeRequestAlloc(allocator, request);
        defer allocator.free(encoded);
        const decoded = try decodeRequest(encoded);
        try std.testing.expectEqualStrings(request.host, decoded.host);
        try std.testing.expectEqual(
            std.meta.activeTag(request.query),
            std.meta.activeTag(decoded.query),
        );
    }
    const filename = try encodeRequestAlloc(allocator, requests[0]);
    defer allocator.free(filename);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x0a, 0x0c, 'e',  'x',  'a', 'm', 'p', 'l', 'e', '.', 't', 'e',
            's',  't',  0x1a, 0x0a, 'e', 'c', 'h', 'o', '.', 'p', 'r', 'o',
            't',  'o',
        },
        filename,
    );
    const last_query_wins = try decodeRequest(&.{
        0x1a, 0x01, 'a',
        0x22, 0x01, 'b',
    });
    try std.testing.expectEqualStrings(
        "b",
        last_query_wins.query.file_containing_symbol,
    );
    try std.testing.expectError(
        error.InvalidExtensionNumber,
        decodeRequest(&.{ 0x2a, 0x02, 0x10, 0x00 }),
    );
    try std.testing.expectError(
        error.TruncatedMessage,
        decodeRequest(&.{ 0x1a, 0x02, 'x' }),
    );
}

test "gRPC reflection response codecs preserve result shapes" {
    const allocator = std.testing.allocator;
    const request = try encodeRequestAlloc(allocator, .{
        .host = "authority",
        .query = .{ .list_services = "" },
    });
    defer allocator.free(request);
    const cases = [_]Result{
        .{ .file_descriptors = &.{ "file-a", "file-b" } },
        .{ .extension_numbers = .{
            .base_type_name = "demo.Options",
            .numbers = &.{ 10, 100 },
        } },
        .{ .services = &.{ "demo.Echo", "grpc.health.v1.Health" } },
        .{ .failure = .{ .code = .not_found, .message = "missing" } },
    };
    for (cases) |expected| {
        const encoded = try encodeResponseAlloc(
            allocator,
            "authority",
            request,
            expected,
        );
        defer allocator.free(encoded);
        var decoded = try decodeResponse(allocator, encoded);
        defer decoded.deinit();
        try std.testing.expectEqualStrings(
            "authority",
            decoded.valid_host,
        );
        try std.testing.expectEqualSlices(
            u8,
            request,
            decoded.original_request,
        );
        try std.testing.expectEqual(
            std.meta.activeTag(expected),
            std.meta.activeTag(decoded.result),
        );
    }
}

test "gRPC reflection registry resolves files and transitive dependencies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var registry = Registry.init(allocator, threaded.io());
    defer registry.deinit();
    try registry.addFile(.{
        .name = "common.proto",
        .descriptor = "common-descriptor",
        .message_types = &.{"demo.Common"},
        .symbols = &.{"demo.Common"},
    });
    try registry.addFile(.{
        .name = "echo.proto",
        .descriptor = "echo-descriptor",
        .dependencies = &.{"common.proto"},
        .symbols = &.{ "demo.Echo", "demo.Echo.Unary" },
        .extensions = &.{.{
            .containing_type = "demo.Common",
            .number = 100,
        }},
    });
    try registry.addService("demo.Echo");

    inline for (.{
        Query{ .file_by_filename = "echo.proto" },
        Query{ .file_containing_symbol = "demo.Echo.Unary" },
        Query{ .file_containing_extension = .{
            .containing_type = "demo.Common",
            .extension_number = 100,
        } },
    }) |query| {
        const request = try encodeRequestAlloc(allocator, .{ .query = query });
        defer allocator.free(request);
        const encoded = try registry.respondAlloc(allocator, request);
        defer allocator.free(encoded);
        var response = try decodeResponse(allocator, encoded);
        defer response.deinit();
        try std.testing.expectEqual(@as(usize, 2), response.result.file_descriptors.len);
        try std.testing.expectEqualStrings(
            "echo-descriptor",
            response.result.file_descriptors[0],
        );
        try std.testing.expectEqualStrings(
            "common-descriptor",
            response.result.file_descriptors[1],
        );
    }
}

test "gRPC reflection registry lists services extensions and errors" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var registry = Registry.init(allocator, threaded.io());
    defer registry.deinit();
    try registry.addFile(.{
        .name = "options.proto",
        .descriptor = "options",
        .message_types = &.{"demo.Options"},
        .symbols = &.{"demo.Options"},
        .extensions = &.{
            .{ .containing_type = "demo.Options", .number = 100 },
            .{ .containing_type = "demo.Options", .number = 101 },
        },
    });
    try registry.addService("demo.Echo");
    try registry.addService("grpc.health.v1.Health");

    const extension_request = try encodeRequestAlloc(allocator, .{
        .query = .{ .all_extension_numbers_of_type = "demo.Options" },
    });
    defer allocator.free(extension_request);
    const extension_bytes = try registry.respondAlloc(
        allocator,
        extension_request,
    );
    defer allocator.free(extension_bytes);
    var extensions = try decodeResponse(allocator, extension_bytes);
    defer extensions.deinit();
    try std.testing.expectEqualSlices(
        i32,
        &.{ 100, 101 },
        extensions.result.extension_numbers.numbers,
    );

    const list_request = try encodeRequestAlloc(allocator, .{
        .query = .{ .list_services = "ignored" },
    });
    defer allocator.free(list_request);
    const list_bytes = try registry.respondAlloc(allocator, list_request);
    defer allocator.free(list_bytes);
    var list = try decodeResponse(allocator, list_bytes);
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 2), list.result.services.len);
    try std.testing.expectEqualStrings(
        "demo.Echo",
        list.result.services[0],
    );

    const missing_request = try encodeRequestAlloc(allocator, .{
        .host = "example.test",
        .query = .{ .file_containing_symbol = "demo.Missing" },
    });
    defer allocator.free(missing_request);
    const missing_bytes = try registry.respondAlloc(
        allocator,
        missing_request,
    );
    defer allocator.free(missing_bytes);
    var missing = try decodeResponse(allocator, missing_bytes);
    defer missing.deinit();
    try std.testing.expectEqual(wire.Status.not_found, missing.result.failure.code);
    try std.testing.expectEqualStrings(
        "Symbol not found.",
        missing.result.failure.message,
    );
    try std.testing.expectEqualStrings(
        "example.test",
        missing.valid_host,
    );
    try std.testing.expectEqualSlices(
        u8,
        missing_request,
        missing.original_request,
    );

    const empty_request = try encodeRequestAlloc(allocator, .{});
    defer allocator.free(empty_request);
    const empty_bytes = try registry.respondAlloc(allocator, empty_request);
    defer allocator.free(empty_bytes);
    var empty = try decodeResponse(allocator, empty_bytes);
    defer empty.deinit();
    try std.testing.expectEqual(
        wire.Status.unimplemented,
        empty.result.failure.code,
    );
    try std.testing.expectError(
        error.DuplicateService,
        registry.addService("demo.Echo"),
    );
    try std.testing.expectError(error.DuplicateSymbol, registry.addFile(.{
        .name = "duplicate.proto",
        .descriptor = "duplicate",
        .symbols = &.{"demo.Options"},
    }));
    try std.testing.expectError(error.DuplicateExtension, registry.addFile(.{
        .name = "duplicate-extension.proto",
        .descriptor = "duplicate-extension",
        .extensions = &.{.{
            .containing_type = "demo.Options",
            .number = 100,
        }},
    }));
}

test "gRPC reflection registry reports missing descriptor dependencies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var registry = Registry.init(allocator, threaded.io());
    defer registry.deinit();
    try registry.addFile(.{
        .name = "broken.proto",
        .descriptor = "broken",
        .dependencies = &.{"missing.proto"},
    });
    const request = try encodeRequestAlloc(allocator, .{
        .query = .{ .file_by_filename = "broken.proto" },
    });
    defer allocator.free(request);
    try std.testing.expectError(
        error.MissingDependency,
        registry.respondAlloc(allocator, request),
    );
}
