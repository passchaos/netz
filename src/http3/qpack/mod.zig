//! QPACK field compression for HTTP/3 (RFC 9204).
//!
//! This facade composes table state, encoder/decoder stream instructions,
//! and field-section codecs while dedicated modules own table data and Huffman.

const std = @import("std");
const wire = @import("../../internal/wire.zig");
const prefixed_integer = @import("integer.zig");
const encodePrefixedInteger = prefixed_integer.encode;
const encodePrefixedIntegerAssumeCapacity = prefixed_integer.encodeAssumeCapacity;
const decodePrefixedInteger = prefixed_integer.decode;

pub const Error = wire.Error || error{
    InvalidFrame,
    QpackDynamicTableUnsupported,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
    QpackDecompressionFailed,
    QpackBlocked,
    ExcessiveLoad,
} || std.mem.Allocator.Error;

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
    never_indexed: bool = false,
    /// Backing allocations owned by this decoded field. A storage slice may
    /// cover both name and value when they were materialized contiguously.
    /// Call `Qpack.freeDecodedFields` for decoder output; null storage means
    /// that component borrows static-table or encoded field-section bytes.
    name_storage: ?[]u8 = null,
    value_storage: ?[]u8 = null,
    /// Optional allocation shared by every name/value in a finalized HTTP/3
    /// field section. Only element zero owns this slice; per-field decoder
    /// storage remains represented by `name_storage`/`value_storage`.
    block_storage: ?[]u8 = null,
};

const dynamic = @import("dynamic_table.zig");
pub const dynamic_entry_overhead = dynamic.dynamic_entry_overhead;
pub const DynamicEntry = dynamic.DynamicEntry;
pub const DynamicTable = dynamic.DynamicTable;

pub const EncoderInstruction = union(enum) {
    insert_name_reference: struct {
        static: bool,
        name_index: u64,
        value: []const u8,
    },
    insert_literal: struct {
        name: []const u8,
        value: []const u8,
    },
    set_capacity: u64,
    duplicate: u64,
};

pub const DecodedEncoderInstruction = struct {
    instruction: EncoderInstruction,
    consumed: usize,
    name_storage: ?[]u8 = null,
    value_storage: ?[]u8 = null,

    pub fn deinit(self: *DecodedEncoderInstruction, allocator: std.mem.Allocator) void {
        if (self.name_storage) |storage| allocator.free(storage);
        if (self.value_storage) |storage| allocator.free(storage);
        self.* = undefined;
    }
};

pub fn writeEncoderInstruction(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    instruction: EncoderInstruction,
) !void {
    switch (instruction) {
        .insert_name_reference => |reference| {
            try encodePrefixedInteger(
                list,
                allocator,
                6,
                if (reference.static) 0xc0 else 0x80,
                reference.name_index,
            );
            try encodeString(list, allocator, reference.value);
        },
        .insert_literal => |literal| {
            try list.ensureUnusedCapacity(
                allocator,
                prefixed_integer.encodedLen(5, literal.name.len) +
                    literal.name.len,
            );
            encodePrefixedIntegerAssumeCapacity(list, 5, 0x40, literal.name.len);
            list.appendSliceAssumeCapacity(literal.name);
            try encodeString(list, allocator, literal.value);
        },
        .set_capacity => |capacity| try encodePrefixedInteger(list, allocator, 5, 0x20, capacity),
        .duplicate => |index| try encodePrefixedInteger(list, allocator, 5, 0x00, index),
    }
}

pub fn decodeEncoderInstruction(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !DecodedEncoderInstruction {
    var cursor = wire.Cursor.init(bytes);
    const first = try cursor.readByte();
    if ((first & 0x80) != 0) {
        const name_index = try decodePrefixedInteger(&cursor, 6, first);
        var value = try decodeString(allocator, &cursor);
        errdefer if (value.storage) |storage| allocator.free(storage);
        const result: DecodedEncoderInstruction = .{
            .instruction = .{ .insert_name_reference = .{
                .static = (first & 0x40) != 0,
                .name_index = name_index,
                .value = value.value,
            } },
            .consumed = cursor.pos,
            .value_storage = value.storage,
        };
        value.storage = null;
        return result;
    }
    if ((first & 0x40) != 0) {
        const name_len = try decodePrefixedInteger(&cursor, 5, first);
        var name = try decodeMaybeHuffman(
            allocator,
            try cursor.readSlice(name_len),
            (first & 0x20) != 0,
        );
        errdefer if (name.storage) |storage| allocator.free(storage);
        var value = try decodeString(allocator, &cursor);
        errdefer if (value.storage) |storage| allocator.free(storage);
        const result: DecodedEncoderInstruction = .{
            .instruction = .{ .insert_literal = .{
                .name = name.value,
                .value = value.value,
            } },
            .consumed = cursor.pos,
            .name_storage = name.storage,
            .value_storage = value.storage,
        };
        name.storage = null;
        value.storage = null;
        return result;
    }
    if ((first & 0x20) != 0) {
        return .{
            .instruction = .{ .set_capacity = try decodePrefixedInteger(&cursor, 5, first) },
            .consumed = cursor.pos,
        };
    }
    return .{
        .instruction = .{ .duplicate = try decodePrefixedInteger(&cursor, 5, first) },
        .consumed = cursor.pos,
    };
}

pub fn applyEncoderInstructions(
    table: *DynamicTable,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!usize {
    var offset: usize = 0;
    while (offset < bytes.len) {
        var decoded = decodeEncoderInstruction(allocator, bytes[offset..]) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return error.QpackEncoderStreamError,
        };
        defer decoded.deinit(allocator);
        switch (decoded.instruction) {
            .set_capacity => |capacity| {
                const cast = std.math.cast(usize, capacity) orelse return error.QpackEncoderStreamError;
                try table.setCapacity(cast);
            },
            .duplicate => |index| _ = try table.duplicate(index),
            .insert_literal => |literal| _ = try table.insert(literal.name, literal.value),
            .insert_name_reference => |reference| {
                const name = if (reference.static) blk: {
                    const entry = staticEntry(std.math.cast(usize, reference.name_index) orelse
                        return error.QpackEncoderStreamError) orelse
                        return error.QpackEncoderStreamError;
                    break :blk entry.name;
                } else blk: {
                    const entry = table.relative(reference.name_index) orelse
                        return error.QpackEncoderStreamError;
                    break :blk entry.name;
                };
                _ = try table.insert(name, reference.value);
            },
        }
        offset += decoded.consumed;
    }
    return offset;
}

pub fn encodeRequiredInsertCount(required_insert_count: u64, max_entries: u64) Error!u64 {
    if (required_insert_count == 0) return 0;
    if (max_entries == 0) return error.QpackDecompressionFailed;
    const full_range = std.math.mul(u64, 2, max_entries) catch return error.QpackDecompressionFailed;
    return (required_insert_count % full_range) + 1;
}

pub fn decodeRequiredInsertCount(
    encoded_insert_count: u64,
    max_entries: u64,
    total_number_of_inserts: u64,
) Error!u64 {
    if (encoded_insert_count == 0) return 0;
    if (max_entries == 0) return error.QpackDecompressionFailed;
    const full_range = std.math.mul(u64, 2, max_entries) catch return error.QpackDecompressionFailed;
    if (encoded_insert_count > full_range) return error.QpackDecompressionFailed;
    const max_value = std.math.add(u64, total_number_of_inserts, max_entries) catch
        return error.QpackDecompressionFailed;
    const max_wrapped = (max_value / full_range) * full_range;
    var required_insert_count = std.math.add(
        u64,
        max_wrapped,
        encoded_insert_count - 1,
    ) catch return error.QpackDecompressionFailed;
    if (required_insert_count > max_value) {
        if (required_insert_count <= full_range) return error.QpackDecompressionFailed;
        required_insert_count -= full_range;
    }
    if (required_insert_count == 0) return error.QpackDecompressionFailed;
    return required_insert_count;
}

pub const DecoderInstruction = union(enum) {
    section_acknowledgment: u64,
    stream_cancellation: u64,
    insert_count_increment: u64,
};

pub const DecodedDecoderInstruction = struct {
    instruction: DecoderInstruction,
    consumed: usize,
};

pub fn writeDecoderInstruction(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    instruction: DecoderInstruction,
) !void {
    switch (instruction) {
        .section_acknowledgment => |stream_id| try encodePrefixedInteger(
            list,
            allocator,
            7,
            0x80,
            stream_id,
        ),
        .stream_cancellation => |stream_id| try encodePrefixedInteger(
            list,
            allocator,
            6,
            0x40,
            stream_id,
        ),
        .insert_count_increment => |increment| {
            if (increment == 0) return error.QpackDecoderStreamError;
            try encodePrefixedInteger(list, allocator, 6, 0x00, increment);
        },
    }
}

pub fn decodeDecoderInstruction(bytes: []const u8) !DecodedDecoderInstruction {
    var cursor = wire.Cursor.init(bytes);
    const first = try cursor.readByte();
    if ((first & 0x80) != 0) {
        return .{
            .instruction = .{ .section_acknowledgment = try decodePrefixedInteger(&cursor, 7, first) },
            .consumed = cursor.pos,
        };
    }
    if ((first & 0x40) != 0) {
        return .{
            .instruction = .{ .stream_cancellation = try decodePrefixedInteger(&cursor, 6, first) },
            .consumed = cursor.pos,
        };
    }
    const increment = try decodePrefixedInteger(&cursor, 6, first);
    if (increment == 0) return error.QpackDecoderStreamError;
    return .{
        .instruction = .{ .insert_count_increment = increment },
        .consumed = cursor.pos,
    };
}

pub const DynamicBlockDecode = struct {
    fields: []HeaderField,
    required_insert_count: u64,
    base: u64,
};

pub const FieldSectionPrefix = struct {
    required_insert_count: u64,
    base: u64,
    consumed: usize,
};

/// Decode only the QPACK field-section prefix without allocating fields.
///
/// Runtimes use this to decide whether a complete HTTP message must wait
/// for encoder-stream inserts before attempting full semantic decoding.
pub fn decodeFieldSectionPrefix(
    block: []const u8,
    table: DynamicTable,
) Error!FieldSectionPrefix {
    var cursor = wire.Cursor.init(block);
    const encoded_insert_count = try decodePrefixedInteger(
        &cursor,
        8,
        try cursor.readByte(),
    );
    const required_insert_count = try decodeRequiredInsertCount(
        encoded_insert_count,
        table.maxEntries(),
        table.insert_count,
    );
    const delta_first = try cursor.readByte();
    const delta_base = try decodePrefixedInteger(&cursor, 7, delta_first);
    const base = if ((delta_first & 0x80) == 0)
        std.math.add(u64, required_insert_count, delta_base) catch
            return error.QpackDecompressionFailed
    else blk: {
        if (required_insert_count <= delta_base) {
            return error.QpackDecompressionFailed;
        }
        break :blk required_insert_count - delta_base - 1;
    };
    return .{
        .required_insert_count = required_insert_count,
        .base = base,
        .consumed = cursor.pos,
    };
}

pub fn encodeDynamicBlock(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const HeaderField,
    table: DynamicTable,
) !void {
    var ignored_references: std.ArrayList(u64) = .empty;
    defer ignored_references.deinit(allocator);
    try encodeDynamicBlockWithReferenceLimit(
        list,
        allocator,
        fields,
        table,
        table.insert_count,
        &ignored_references,
    );
}

/// Encode a non-blocking field section using only entries the decoder has
/// acknowledged. Absolute indexes actually referenced by the section are
/// appended to `references` for the encoder's eviction bookkeeping.
pub fn encodeDynamicBlockKnownReceived(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const HeaderField,
    table: DynamicTable,
    known_received_count: u64,
    references: *std.ArrayList(u64),
) !void {
    if (known_received_count > table.insert_count) {
        return error.QpackDecoderStreamError;
    }
    try encodeDynamicBlockWithReferenceLimit(
        list,
        allocator,
        fields,
        table,
        known_received_count,
        references,
    );
}

/// Encode using dynamic entries below an exclusive absolute-index limit.
///
/// Connection encoders pass Known Received Count for a non-blocking section,
/// or the current insertion count when the peer's blocked-stream budget allows
/// a speculative reference. The returned reference set lets that connection
/// retain entries until Section Acknowledgment or Stream Cancellation.
pub fn encodeDynamicBlockWithReferenceLimit(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const HeaderField,
    table: DynamicTable,
    reference_limit: u64,
    references: *std.ArrayList(u64),
) !void {
    const dynamic_references_possible =
        reference_limit != 0 and
        table.entryCount() != 0 and
        table.entries.items[table.head].absolute_index < reference_limit;
    const stack_match_capacity = 64;
    var stack_matches: [stack_match_capacity]?DynamicTable.Match =
        undefined;
    const dynamic_matches: []?DynamicTable.Match = if (!dynamic_references_possible)
        &.{}
    else if (fields.len <= stack_matches.len)
        stack_matches[0..fields.len]
    else
        try allocator.alloc(?DynamicTable.Match, fields.len);
    defer if (dynamic_references_possible and fields.len > stack_matches.len) {
        allocator.free(dynamic_matches);
    };

    var required_insert_count: u64 = 0;
    if (dynamic_references_possible) {
        for (fields, dynamic_matches) |field, *dynamic_match| {
            dynamic_match.* = table.findMatchBefore(
                field.name,
                field.value,
                reference_limit,
            );
            if (dynamic_match.*) |match| {
                if (usesDynamicMatch(field, match)) {
                    required_insert_count = @max(
                        required_insert_count,
                        match.absolute_index + 1,
                    );
                }
            }
        }
    }

    const encoded_insert_count = try encodeRequiredInsertCount(
        required_insert_count,
        table.maxEntries(),
    );
    // Every selected reference is below Required Insert Count, so choosing it
    // as Base makes Delta Base zero and minimizes every relative index. This
    // also keeps literal-only sections at the canonical zero/zero prefix even
    // after a long-lived connection has accumulated many unreferenced inserts.
    const base = required_insert_count;
    try encodePrefix(
        list,
        allocator,
        encoded_insert_count,
        0,
    );

    for (fields, 0..) |field, index| {
        const dynamic_match = if (dynamic_references_possible)
            dynamic_matches[index]
        else
            null;
        if (!field.never_indexed) {
            if (dynamic_match) |match| {
                if (match.full_match) {
                    const absolute_index = match.absolute_index;
                    try appendReferenceUnique(
                        references,
                        allocator,
                        absolute_index,
                    );
                    if (absolute_index < base) {
                        try encodePrefixedInteger(
                            list,
                            allocator,
                            6,
                            0x80,
                            base - absolute_index - 1,
                        );
                    } else {
                        try encodePrefixedInteger(
                            list,
                            allocator,
                            4,
                            0x10,
                            absolute_index - base,
                        );
                    }
                    continue;
                }
            }
        }

        if (static_table_module.findMatch(field.name, field.value)) |match| {
            if (match.full_match and !field.never_indexed) {
                try encodePrefixedInteger(list, allocator, 6, 0xc0, match.index);
            } else {
                try encodePrefixedInteger(
                    list,
                    allocator,
                    4,
                    0x50 | if (field.never_indexed) @as(u8, 0x20) else 0,
                    match.index,
                );
                try encodeString(list, allocator, field.value);
            }
            continue;
        }

        if (dynamic_match) |match| {
            const absolute_index = match.absolute_index;
            try appendReferenceUnique(references, allocator, absolute_index);
            if (absolute_index < base) {
                try encodePrefixedInteger(
                    list,
                    allocator,
                    4,
                    0x40 | if (field.never_indexed) @as(u8, 0x20) else 0,
                    base - absolute_index - 1,
                );
            } else {
                try encodePrefixedInteger(
                    list,
                    allocator,
                    3,
                    if (field.never_indexed) 0x08 else 0x00,
                    absolute_index - base,
                );
            }
            try encodeString(list, allocator, field.value);
            continue;
        }

        try list.ensureUnusedCapacity(
            allocator,
            prefixed_integer.encodedLen(3, field.name.len) + field.name.len,
        );
        encodePrefixedIntegerAssumeCapacity(
            list,
            3,
            0x20 | if (field.never_indexed) @as(u8, 0x10) else 0,
            field.name.len,
        );
        list.appendSliceAssumeCapacity(field.name);
        try encodeString(list, allocator, field.value);
    }
}

fn usesDynamicMatch(
    field: HeaderField,
    match: DynamicTable.Match,
) bool {
    // An exact dynamic entry is preferred unless Never Indexed forbids that
    // representation. A static name/full match otherwise wins before the
    // dynamic-name branch below. Keep prefix dependency calculation aligned
    // with those choices so the peer never acknowledges an unused entry.
    if (match.full_match and !field.never_indexed) return true;
    return static_table_module.findMatch(field.name, field.value) == null;
}

fn appendReferenceUnique(
    references: *std.ArrayList(u64),
    allocator: std.mem.Allocator,
    absolute_index: u64,
) !void {
    // Dynamic encoders often reference the same table entry for adjacent fields
    // (for example repeated trailers or benchmark blocks). Check the tail first
    // so that common duplicate case avoids scanning the whole reference set.
    if (references.items.len != 0 and
        references.items[references.items.len - 1] == absolute_index)
    {
        return;
    }
    for (references.items) |existing| {
        if (existing == absolute_index) return;
    }
    try references.append(allocator, absolute_index);
}

pub fn decodeDynamicBlock(
    allocator: std.mem.Allocator,
    block: []const u8,
    table: DynamicTable,
) !DynamicBlockDecode {
    return decodeDynamicBlockWithLimit(
        allocator,
        block,
        table,
        std.math.maxInt(u64),
    );
}

/// Decode a dynamic field section while enforcing RFC 9114's uncompressed
/// field-section size before materializing Huffman or table-backed strings.
pub fn decodeDynamicBlockWithLimit(
    allocator: std.mem.Allocator,
    block: []const u8,
    table: DynamicTable,
    max_field_section_size: u64,
) !DynamicBlockDecode {
    const prefix = try decodeFieldSectionPrefix(block, table);
    var cursor = wire.Cursor.init(block);
    cursor.pos = prefix.consumed;
    const required_insert_count = prefix.required_insert_count;
    const base = prefix.base;
    if (required_insert_count > table.insert_count) return error.QpackBlocked;
    var actual_required_insert_count: u64 = 0;
    var budget = FieldSectionBudget{ .max = max_field_section_size };

    var fields: std.ArrayList(HeaderField) = .empty;
    errdefer {
        freeFieldStorages(allocator, fields.items);
        fields.deinit(allocator);
    }
    while (!cursor.eof()) {
        const first = try cursor.readByte();
        var field: HeaderField = undefined;
        if ((first & 0x80) != 0) {
            const static = (first & 0x40) != 0;
            const index = try decodePrefixedInteger(&cursor, 6, first);
            if (static) {
                field = staticEntry(index) orelse return error.QpackDecompressionFailed;
                try budget.charge(field.name.len, field.value.len);
            } else {
                const entry = table.fieldRelativeToBase(base, index) orelse
                    return error.QpackDecompressionFailed;
                try noteDynamicReference(
                    &actual_required_insert_count,
                    required_insert_count,
                    entry,
                );
                try budget.charge(entry.name.len, entry.value.len);
                field = try ownedDynamicField(allocator, entry, entry.value, false);
            }
        } else if ((first & 0xf0) == 0x10) {
            const index = try decodePrefixedInteger(&cursor, 4, first);
            const entry = table.fieldPostBase(base, index) orelse
                return error.QpackDecompressionFailed;
            try noteDynamicReference(
                &actual_required_insert_count,
                required_insert_count,
                entry,
            );
            try budget.charge(entry.name.len, entry.value.len);
            field = try ownedDynamicField(allocator, entry, entry.value, false);
        } else if ((first & 0xc0) == 0x40) {
            const never_indexed = (first & 0x20) != 0;
            const static = (first & 0x10) != 0;
            const index = try decodePrefixedInteger(&cursor, 4, first);
            if (static) {
                const entry = staticEntry(index) orelse return error.QpackDecompressionFailed;
                const value_plan = try scanString(&cursor);
                try budget.charge(entry.name.len, value_plan.decoded_len);
                var value = try value_plan.decode(allocator);
                errdefer if (value.storage) |storage| allocator.free(storage);
                field = .{
                    .name = entry.name,
                    .value = value.value,
                    .never_indexed = never_indexed,
                    .value_storage = value.storage,
                };
                value.storage = null;
            } else {
                const entry = table.fieldRelativeToBase(base, index) orelse
                    return error.QpackDecompressionFailed;
                try noteDynamicReference(
                    &actual_required_insert_count,
                    required_insert_count,
                    entry,
                );
                const value_plan = try scanString(&cursor);
                try budget.charge(entry.name.len, value_plan.decoded_len);
                var value = try value_plan.decode(allocator);
                errdefer if (value.storage) |storage| allocator.free(storage);
                field = try ownedDynamicField(allocator, entry, value.value, never_indexed);
                if (value.storage) |storage| allocator.free(storage);
                value.storage = null;
            }
        } else if ((first & 0xf0) == 0x00) {
            const never_indexed = (first & 0x08) != 0;
            const index = try decodePrefixedInteger(&cursor, 3, first);
            const entry = table.fieldPostBase(base, index) orelse
                return error.QpackDecompressionFailed;
            try noteDynamicReference(
                &actual_required_insert_count,
                required_insert_count,
                entry,
            );
            const value_plan = try scanString(&cursor);
            try budget.charge(entry.name.len, value_plan.decoded_len);
            const value = try value_plan.decode(allocator);
            defer if (value.storage) |storage| allocator.free(storage);
            field = try ownedDynamicField(allocator, entry, value.value, never_indexed);
        } else if ((first & 0xe0) == 0x20) {
            const never_indexed = (first & 0x10) != 0;
            const name_len = try decodePrefixedInteger(&cursor, 3, first);
            const name_plan = try scanMaybeHuffman(
                try cursor.readSlice(name_len),
                (first & 0x08) != 0,
            );
            const value_plan = try scanString(&cursor);
            try budget.charge(name_plan.decoded_len, value_plan.decoded_len);
            var name = try name_plan.decode(allocator);
            errdefer if (name.storage) |storage| allocator.free(storage);
            var value = try value_plan.decode(allocator);
            errdefer if (value.storage) |storage| allocator.free(storage);
            field = .{
                .name = name.value,
                .value = value.value,
                .never_indexed = never_indexed,
                .name_storage = name.storage,
                .value_storage = value.storage,
            };
            name.storage = null;
            value.storage = null;
        } else {
            return error.QpackDecompressionFailed;
        }
        var appended = false;
        defer if (!appended) {
            if (field.name_storage) |storage| allocator.free(storage);
            if (field.value_storage) |storage| allocator.free(storage);
        };
        try fields.append(allocator, field);
        appended = true;
    }
    // RFC 9204 section 2.2 requires the smallest Insert Count that makes the
    // section decodable. Rejecting overstatement as well as the mandatory
    // under-reported case prevents phantom blocking and acknowledgments for
    // entries that the field lines never referenced.
    if (actual_required_insert_count != required_insert_count) {
        return error.QpackDecompressionFailed;
    }
    return .{
        .fields = try fields.toOwnedSlice(allocator),
        .required_insert_count = required_insert_count,
        .base = base,
    };
}

fn noteDynamicReference(
    actual_required_insert_count: *u64,
    declared_required_insert_count: u64,
    entry: DynamicEntry,
) Error!void {
    const referenced_insert_count = std.math.add(
        u64,
        entry.absolute_index,
        1,
    ) catch return error.QpackDecompressionFailed;
    // RFC 9204 section 2.2.3 makes references at or beyond the declared RIC a
    // connection error even if that entry happens to be present locally.
    if (referenced_insert_count > declared_required_insert_count) {
        return error.QpackDecompressionFailed;
    }
    actual_required_insert_count.* = @max(
        actual_required_insert_count.*,
        referenced_insert_count,
    );
}

pub fn freeDynamicBlock(allocator: std.mem.Allocator, decoded: *DynamicBlockDecode) void {
    freeDecodedFields(allocator, decoded.fields);
    decoded.* = undefined;
}

fn ownedDynamicField(
    allocator: std.mem.Allocator,
    entry: DynamicEntry,
    value: []const u8,
    never_indexed: bool,
) !HeaderField {
    const storage_len = std.math.add(usize, entry.name.len, value.len) catch
        return error.QpackDecompressionFailed;
    const storage = try allocator.alloc(u8, storage_len);
    @memcpy(storage[0..entry.name.len], entry.name);
    @memcpy(storage[entry.name.len..], value);
    return .{
        .name = storage[0..entry.name.len],
        .value = storage[entry.name.len..],
        .never_indexed = never_indexed,
        .name_storage = storage,
    };
}

const static_table_module = @import("static_table.zig");
pub const static_table = static_table_module.entries;

pub fn staticEntry(index: usize) ?HeaderField {
    const entry = static_table_module.get(index) orelse return null;
    return .{ .name = entry.name, .value = entry.value };
}

pub const findStaticName = static_table_module.findName;

/// Encode the two non-negative QPACK field-section prefix integers.
///
/// `encoded_insert_count` is the wrapped value returned by
/// `encodeRequiredInsertCount`; `delta_base` is used with a zero Sign bit.
/// These are RFC 9204 prefix integers, not QUIC variable-length integers:
/// values from 64 through 254 still occupy one byte in the 8-bit field.
pub fn encodePrefix(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    encoded_insert_count: u64,
    delta_base: u64,
) !void {
    try encodePrefixedInteger(
        list,
        allocator,
        8,
        0x00,
        encoded_insert_count,
    );
    try encodePrefixedInteger(
        list,
        allocator,
        7,
        0x00,
        delta_base,
    );
}

/// Stateless QPACK encoder for deterministic clients. It uses the static
/// table and literal fields only, so it remains safe with zero dynamic-table
/// capacity while interoperating with peers that expect common static refs.
pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
    try encodePrefix(list, allocator, 0, 0);
    for (fields) |field| {
        var lower_name_storage: ?[]u8 = null;
        defer if (lower_name_storage) |storage| allocator.free(storage);
        const name = try normalizedFieldName(allocator, field.name, &lower_name_storage);
        if (static_table_module.findMatch(name, field.value)) |match| {
            if (match.full_match) {
                try encodePrefixedInteger(list, allocator, 6, 0xc0, match.index);
            } else {
                try encodePrefixedInteger(list, allocator, 4, 0x50, match.index);
                try encodeString(list, allocator, field.value);
            }
        } else {
            try list.ensureUnusedCapacity(
                allocator,
                prefixed_integer.encodedLen(3, name.len) + name.len,
            );
            encodePrefixedIntegerAssumeCapacity(list, 3, 0x20, name.len);
            list.appendSliceAssumeCapacity(name);
            try encodeString(list, allocator, field.value);
        }
    }
}

fn normalizedFieldName(allocator: std.mem.Allocator, name: []const u8, storage: *?[]u8) ![]const u8 {
    for (name) |byte| {
        if (byte >= 'A' and byte <= 'Z') {
            const lowered = try allocator.dupe(u8, name);
            for (lowered) |*out| out.* = std.ascii.toLower(out.*);
            storage.* = lowered;
            return lowered;
        }
    }
    return name;
}

pub fn decodeLiteralBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
    return decodeLiteralBlockWithLimit(
        allocator,
        block,
        std.math.maxInt(u64),
    );
}

pub fn decodeLiteralBlockWithLimit(
    allocator: std.mem.Allocator,
    block: []const u8,
    max_field_section_size: u64,
) ![]HeaderField {
    var cursor = wire.Cursor.init(block);
    const required_insert_count = try decodePrefixedInteger(&cursor, 8, try cursor.readByte());
    const base = try decodePrefixedInteger(&cursor, 7, try cursor.readByte());
    if (required_insert_count != 0 or base != 0) return error.QpackDynamicTableUnsupported;
    var budget = FieldSectionBudget{ .max = max_field_section_size };

    var fields: std.ArrayList(HeaderField) = .empty;
    errdefer {
        freeFieldStorages(allocator, fields.items);
        fields.deinit(allocator);
    }
    while (!cursor.eof()) {
        const first = try cursor.readByte();
        if ((first & 0xc0) == 0xc0) {
            const index = try decodePrefixedInteger(&cursor, 6, first);
            const entry = staticEntry(index) orelse return error.InvalidFrame;
            try budget.charge(entry.name.len, entry.value.len);
            try fields.append(allocator, entry);
        } else if ((first & 0xc0) == 0x40) {
            const is_static = (first & 0x10) != 0;
            const index = try decodePrefixedInteger(&cursor, 4, first);
            if (!is_static) return error.QpackDynamicTableUnsupported;
            const entry = staticEntry(index) orelse return error.InvalidFrame;
            const value_plan = try scanString(&cursor);
            try budget.charge(entry.name.len, value_plan.decoded_len);
            var value = try value_plan.decode(allocator);
            errdefer if (value.storage) |storage| allocator.free(storage);
            try fields.append(allocator, .{ .name = entry.name, .value = value.value, .value_storage = value.storage });
            value.storage = null;
        } else if ((first & 0xe0) == 0x20) {
            const name_len = try decodePrefixedInteger(&cursor, 3, first);
            const name_plan = try scanMaybeHuffman(
                try cursor.readSlice(name_len),
                (first & 0x08) != 0,
            );
            const value_plan = try scanString(&cursor);
            try budget.charge(name_plan.decoded_len, value_plan.decoded_len);
            var name = try name_plan.decode(allocator);
            errdefer if (name.storage) |storage| allocator.free(storage);
            var value = try value_plan.decode(allocator);
            errdefer if (value.storage) |storage| allocator.free(storage);
            try fields.append(allocator, .{
                .name = name.value,
                .value = value.value,
                .name_storage = name.storage,
                .value_storage = value.storage,
            });
            name.storage = null;
            value.storage = null;
        } else {
            return error.QpackDynamicTableUnsupported;
        }
    }
    return fields.toOwnedSlice(allocator);
}

pub fn freeDecodedFields(allocator: std.mem.Allocator, fields: []HeaderField) void {
    freeFieldStorages(allocator, fields);
    allocator.free(fields);
}

fn freeFieldStorages(allocator: std.mem.Allocator, fields: []HeaderField) void {
    for (fields) |field| {
        if (field.name_storage) |storage| allocator.free(storage);
        if (field.value_storage) |storage| allocator.free(storage);
        if (field.block_storage) |storage| allocator.free(storage);
    }
}

fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    if (value.len == 0) {
        try list.ensureUnusedCapacity(allocator, 1);
        list.appendAssumeCapacity(0);
        return;
    }
    if (value.len <= 2) {
        try list.ensureUnusedCapacity(allocator, 1 + value.len);
        list.appendAssumeCapacity(@intCast(value.len));
        list.appendSliceAssumeCapacity(value);
        return;
    }
    const huffman_len = try huffmanEncodedLen(value);
    if (huffman_len >= value.len) {
        try list.ensureUnusedCapacity(allocator, prefixed_integer.encodedLen(7, value.len) + value.len);
        encodePrefixedIntegerAssumeCapacity(list, 7, 0x00, value.len);
        list.appendSliceAssumeCapacity(value);
        return;
    }
    try list.ensureUnusedCapacity(allocator, prefixed_integer.encodedLen(7, huffman_len) + huffman_len);
    encodePrefixedIntegerAssumeCapacity(list, 7, 0x80, huffman_len);
    appendHuffmanAssumeCapacity(list, value, huffman_len);
}

const DecodedString = struct {
    value: []const u8,
    storage: ?[]u8 = null,
};

const FieldSectionBudget = struct {
    max: u64,
    used: u64 = 0,

    fn charge(
        self: *FieldSectionBudget,
        name_len: usize,
        value_len: usize,
    ) Error!void {
        const field_size = std.math.add(
            u64,
            std.math.add(
                u64,
                std.math.cast(u64, name_len) orelse
                    return error.ExcessiveLoad,
                std.math.cast(u64, value_len) orelse
                    return error.ExcessiveLoad,
            ) catch return error.ExcessiveLoad,
            dynamic_entry_overhead,
        ) catch return error.ExcessiveLoad;
        self.used = std.math.add(u64, self.used, field_size) catch
            return error.ExcessiveLoad;
        if (self.used > self.max) return error.ExcessiveLoad;
    }
};

const EncodedString = struct {
    raw: []const u8,
    huffman: bool,
    decoded_len: usize,

    fn decode(
        self: EncodedString,
        allocator: std.mem.Allocator,
    ) !DecodedString {
        if (!self.huffman) return .{ .value = self.raw };
        if (self.decoded_len == 0) return .{ .value = &.{} };
        const decoded = try allocator.alloc(u8, self.decoded_len);
        errdefer allocator.free(decoded);
        try huffman_codec.decodeHuffmanInto(decoded, self.raw);
        return .{ .value = decoded, .storage = decoded };
    }
};

fn decodeString(allocator: std.mem.Allocator, cursor: *wire.Cursor) !DecodedString {
    const first = try cursor.readByte();
    const len = try decodePrefixedInteger(cursor, 7, first);
    const raw = try cursor.readSlice(len);
    return decodeMaybeHuffman(allocator, raw, (first & 0x80) != 0);
}

fn scanString(cursor: *wire.Cursor) !EncodedString {
    const first = try cursor.readByte();
    const len = try decodePrefixedInteger(cursor, 7, first);
    const raw = try cursor.readSlice(len);
    return scanMaybeHuffman(
        raw,
        (first & 0x80) != 0,
    );
}

fn decodeMaybeHuffman(allocator: std.mem.Allocator, raw: []const u8, huffman: bool) !DecodedString {
    if (!huffman) return .{ .value = raw };
    const decoded = try decodeHuffman(allocator, raw);
    return .{ .value = decoded, .storage = decoded };
}

fn scanMaybeHuffman(
    raw: []const u8,
    huffman: bool,
) !EncodedString {
    return .{
        .raw = raw,
        .huffman = huffman,
        .decoded_len = if (huffman) try huffmanDecodedLen(raw) else raw.len,
    };
}

const huffman_codec = @import("../../internal/hpack_huffman.zig");
pub const encodeHuffman = huffman_codec.encodeHuffman;
pub const decodeHuffman = huffman_codec.decodeHuffman;
pub const decodeHuffmanInto = huffman_codec.decodeHuffmanInto;
pub const huffmanEncodedLen = huffman_codec.encodedLen;
pub const huffmanDecodedLen = huffman_codec.decodedLen;
const appendHuffmanAssumeCapacity = huffman_codec.appendHuffmanAssumeCapacity;
