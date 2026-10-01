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
    /// field section. Only element zero owns this slice; it may also contain
    /// the field array itself. Per-field decoder storage remains represented
    /// by `name_storage`/`value_storage`.
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
            const value_plan = try encodedStringPlan(reference.value);
            const index_len = prefixed_integer.encodedLen(
                6,
                reference.name_index,
            );
            const instruction_len = std.math.add(
                usize,
                index_len,
                value_plan.wire_len,
            ) catch return error.IntegerOverflow;
            try list.ensureUnusedCapacity(allocator, instruction_len);
            encodePrefixedIntegerAssumeCapacity(
                list,
                6,
                if (reference.static) 0xc0 else 0x80,
                reference.name_index,
            );
            encodeStringAssumeCapacity(list, reference.value, value_plan);
        },
        .insert_literal => |literal| {
            const value_plan = try encodedStringPlan(literal.value);
            var instruction_len = std.math.add(
                usize,
                prefixed_integer.encodedLen(5, literal.name.len),
                literal.name.len,
            ) catch return error.IntegerOverflow;
            instruction_len = std.math.add(
                usize,
                instruction_len,
                value_plan.wire_len,
            ) catch return error.IntegerOverflow;
            try list.ensureUnusedCapacity(allocator, instruction_len);
            encodePrefixedIntegerAssumeCapacity(list, 5, 0x40, literal.name.len);
            list.appendSliceAssumeCapacity(literal.name);
            encodeStringAssumeCapacity(list, literal.value, value_plan);
        },
        .set_capacity => |capacity| {
            try list.ensureUnusedCapacity(
                allocator,
                prefixed_integer.encodedLen(5, capacity),
            );
            encodePrefixedIntegerAssumeCapacity(
                list,
                5,
                0x20,
                capacity,
            );
        },
        .duplicate => |index| {
            try list.ensureUnusedCapacity(
                allocator,
                prefixed_integer.encodedLen(5, index),
            );
            encodePrefixedIntegerAssumeCapacity(list, 5, 0x00, index);
        },
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

const owned_plan_stack_fields: usize = 32;

const OwnedFieldPlan = struct {
    name: EncodedString,
    value: EncodedString,
    never_indexed: bool,
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
    var stack_matches: [stack_match_capacity]?DynamicTable.Match = undefined;
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
    if (fields.len > stack_match_capacity and dynamic_references_possible) {
        return encodeLargeDynamicFields(
            list,
            allocator,
            fields,
            dynamic_matches,
            encoded_insert_count,
            base,
            table.entries.items[table.head].absolute_index,
            table.entryCount(),
            references,
        );
    }
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

fn encodeLargeDynamicFields(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const HeaderField,
    dynamic_matches: []const ?DynamicTable.Match,
    encoded_insert_count: u64,
    base: u64,
    oldest_absolute_index: u64,
    dynamic_entry_count: usize,
    references: *std.ArrayList(u64),
) !void {
    const bits_per_mask = @bitSizeOf(usize);
    // Live dynamic-table absolute indexes are contiguous. Indexing from the
    // oldest live entry therefore bounds scratch space by current table size,
    // not by the connection's lifetime insertion count.
    const mask_count = std.math.divCeil(
        usize,
        dynamic_entry_count,
        bits_per_mask,
    ) catch return error.OutOfMemory;
    const seen = try allocator.alloc(usize, mask_count);
    defer allocator.free(seen);
    @memset(seen, 0);
    for (references.items) |absolute_index| {
        if (absolute_index < oldest_absolute_index) continue;
        const offset = std.math.cast(
            usize,
            absolute_index - oldest_absolute_index,
        ) orelse continue;
        if (offset >= dynamic_entry_count) continue;
        setReferenceBit(seen, offset);
    }
    try references.ensureUnusedCapacity(allocator, fields.len);
    var exact_encoded_len = prefixed_integer.encodedLen(
        8,
        encoded_insert_count,
    ) + prefixed_integer.encodedLen(7, 0);
    for (fields, dynamic_matches) |field, dynamic_match| {
        if (field.never_indexed) break;
        const match = dynamic_match orelse break;
        if (!match.full_match) break;
        exact_encoded_len = std.math.add(
            usize,
            exact_encoded_len,
            if (match.absolute_index < base)
                prefixed_integer.encodedLen(
                    6,
                    base - match.absolute_index - 1,
                )
            else
                prefixed_integer.encodedLen(
                    4,
                    match.absolute_index - base,
                ),
        ) catch return error.OutOfMemory;
    } else {
        try list.ensureUnusedCapacity(allocator, exact_encoded_len);
        encodePrefixedIntegerAssumeCapacity(
            list,
            8,
            0x00,
            encoded_insert_count,
        );
        encodePrefixedIntegerAssumeCapacity(list, 7, 0x00, 0);
        for (dynamic_matches) |match| {
            const absolute_index = match.?.absolute_index;
            appendReferenceUniqueDense(
                references,
                absolute_index,
                oldest_absolute_index,
                seen,
            );
            if (absolute_index < base) {
                encodePrefixedIntegerAssumeCapacity(
                    list,
                    6,
                    0x80,
                    base - absolute_index - 1,
                );
            } else {
                encodePrefixedIntegerAssumeCapacity(
                    list,
                    4,
                    0x10,
                    absolute_index - base,
                );
            }
        }
        return;
    }
    try encodePrefix(list, allocator, encoded_insert_count, 0);

    for (fields, dynamic_matches) |field, dynamic_match| {
        if (!field.never_indexed) {
            if (dynamic_match) |match| {
                if (match.full_match) {
                    const absolute_index = match.absolute_index;
                    appendReferenceUniqueDense(
                        references,
                        absolute_index,
                        oldest_absolute_index,
                        seen,
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
            appendReferenceUniqueDense(
                references,
                absolute_index,
                oldest_absolute_index,
                seen,
            );
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
    if (references.items.len != 0) {
        if (references.items[references.items.len - 1] == absolute_index) {
            return;
        }
        for (references.items[0 .. references.items.len - 1]) |existing| {
            if (existing == absolute_index) return;
        }
    }
    try references.append(allocator, absolute_index);
}

inline fn appendReferenceUniqueDense(
    references: *std.ArrayList(u64),
    absolute_index: u64,
    oldest_absolute_index: u64,
    seen: []usize,
) void {
    const offset: usize = @intCast(absolute_index - oldest_absolute_index);
    const mask_index = offset / @bitSizeOf(usize);
    const bit = @as(usize, 1) << @as(std.math.Log2Int(usize), @truncate(offset));
    if ((seen[mask_index] & bit) != 0) return;
    seen[mask_index] |= bit;
    references.appendAssumeCapacity(absolute_index);
}

fn setReferenceBit(seen: []usize, offset: usize) void {
    const mask_index = offset / @bitSizeOf(usize);
    const bit = @as(usize, 1) << @as(std.math.Log2Int(usize), @truncate(offset));
    seen[mask_index] |= bit;
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
    return decodeDynamicBlockWithLimitInternal(
        allocator,
        block,
        table,
        max_field_section_size,
    ) catch |err| return normalizeFieldSectionDecodeError(err);
}

fn decodeDynamicBlockWithLimitInternal(
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

/// Decode a dynamic field section directly into one final allocation holding
/// both the field array and its shared name/value byte block.
pub fn decodeDynamicBlockOwnedWithLimit(
    allocator: std.mem.Allocator,
    block: []const u8,
    table: DynamicTable,
    max_field_section_size: u64,
) !DynamicBlockDecode {
    return decodeDynamicBlockOwnedWithLimitInternal(
        allocator,
        block,
        table,
        max_field_section_size,
    ) catch |err| return normalizeFieldSectionDecodeError(err);
}

fn decodeDynamicBlockOwnedWithLimitInternal(
    allocator: std.mem.Allocator,
    block: []const u8,
    table: DynamicTable,
    max_field_section_size: u64,
) !DynamicBlockDecode {
    const prefix = try decodeFieldSectionPrefix(block, table);
    if (prefix.required_insert_count > table.insert_count) {
        return error.QpackBlocked;
    }
    var cursor = wire.Cursor.init(block);
    cursor.pos = prefix.consumed;
    var actual_required_insert_count: u64 = 0;
    var budget = FieldSectionBudget{ .max = max_field_section_size };
    var plan_fallback = std.heap.stackFallback(
        owned_plan_stack_fields * @sizeOf(OwnedFieldPlan),
        allocator,
    );
    var builder = OwnedFieldBuilder.init(
        allocator,
        plan_fallback.get(),
    );
    defer builder.deinit();
    try builder.reservePlans(owned_plan_stack_fields);

    while (!cursor.eof()) {
        const first = try cursor.readByte();
        if ((first & 0x80) != 0) {
            const static = (first & 0x40) != 0;
            const index = try decodePrefixedInteger(&cursor, 6, first);
            const field = if (static)
                staticEntry(index) orelse return error.QpackDecompressionFailed
            else blk: {
                const entry = table.fieldRelativeToBase(prefix.base, index) orelse
                    return error.QpackDecompressionFailed;
                try noteDynamicReference(
                    &actual_required_insert_count,
                    prefix.required_insert_count,
                    entry,
                );
                break :blk HeaderField{
                    .name = entry.name,
                    .value = entry.value,
                };
            };
            try budget.charge(field.name.len, field.value.len);
            try builder.appendBorrowed(field.name, field.value, false);
        } else if ((first & 0xf0) == 0x10) {
            const entry = table.fieldPostBase(
                prefix.base,
                try decodePrefixedInteger(&cursor, 4, first),
            ) orelse return error.QpackDecompressionFailed;
            try noteDynamicReference(
                &actual_required_insert_count,
                prefix.required_insert_count,
                entry,
            );
            try budget.charge(entry.name.len, entry.value.len);
            try builder.appendBorrowed(entry.name, entry.value, false);
        } else if ((first & 0xc0) == 0x40) {
            const never_indexed = (first & 0x20) != 0;
            const static = (first & 0x10) != 0;
            const index = try decodePrefixedInteger(&cursor, 4, first);
            const name = if (static) blk: {
                const entry = staticEntry(index) orelse
                    return error.QpackDecompressionFailed;
                break :blk entry.name;
            } else blk: {
                const entry = table.fieldRelativeToBase(prefix.base, index) orelse
                    return error.QpackDecompressionFailed;
                try noteDynamicReference(
                    &actual_required_insert_count,
                    prefix.required_insert_count,
                    entry,
                );
                break :blk entry.name;
            };
            const value = try scanString(&cursor);
            try budget.charge(name.len, value.decoded_len);
            try builder.append(
                .{
                    .raw = name,
                    .huffman = false,
                    .decoded_len = name.len,
                },
                value,
                never_indexed,
            );
        } else if ((first & 0xf0) == 0x00) {
            const entry = table.fieldPostBase(
                prefix.base,
                try decodePrefixedInteger(&cursor, 3, first),
            ) orelse return error.QpackDecompressionFailed;
            try noteDynamicReference(
                &actual_required_insert_count,
                prefix.required_insert_count,
                entry,
            );
            const value = try scanString(&cursor);
            try budget.charge(entry.name.len, value.decoded_len);
            try builder.append(
                .{
                    .raw = entry.name,
                    .huffman = false,
                    .decoded_len = entry.name.len,
                },
                value,
                (first & 0x08) != 0,
            );
        } else if ((first & 0xe0) == 0x20) {
            const name = try scanMaybeHuffman(
                try cursor.readSlice(try decodePrefixedInteger(
                    &cursor,
                    3,
                    first,
                )),
                (first & 0x08) != 0,
            );
            const value = try scanString(&cursor);
            try budget.charge(name.decoded_len, value.decoded_len);
            try builder.append(name, value, (first & 0x10) != 0);
        } else {
            return error.QpackDecompressionFailed;
        }
    }
    if (actual_required_insert_count != prefix.required_insert_count) {
        return error.QpackDecompressionFailed;
    }
    return .{
        .fields = try builder.finish(),
        .required_insert_count = prefix.required_insert_count,
        .base = prefix.base,
    };
}

fn normalizeFieldSectionDecodeError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ExcessiveLoad => error.ExcessiveLoad,
        error.QpackBlocked => error.QpackBlocked,
        error.QpackDecompressionFailed => error.QpackDecompressionFailed,
        else => error.QpackDecompressionFailed,
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
    const wire_len = std.math.add(
        usize,
        prefixed_integer.encodedLen(8, encoded_insert_count),
        prefixed_integer.encodedLen(7, delta_base),
    ) catch return error.IntegerOverflow;
    try list.ensureUnusedCapacity(allocator, wire_len);
    encodePrefixedIntegerAssumeCapacity(
        list,
        8,
        0x00,
        encoded_insert_count,
    );
    encodePrefixedIntegerAssumeCapacity(list, 7, 0x00, delta_base);
}

/// Stateless QPACK encoder for deterministic clients. It uses the static
/// table and literal fields only, so it remains safe with zero dynamic-table
/// capacity while interoperating with peers that expect common static refs.
pub fn encodeLiteralBlock(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const HeaderField) !void {
    const stack_plan_capacity = 64;
    var stack_plans: [stack_plan_capacity]LiteralFieldPlan = undefined;
    const plans = if (fields.len <= stack_plans.len)
        stack_plans[0..fields.len]
    else
        try allocator.alloc(LiteralFieldPlan, fields.len);
    defer if (fields.len > stack_plans.len) allocator.free(plans);

    var block_len: usize = 2;
    for (fields, plans) |field, *plan| {
        plan.* = try planLiteralField(field);
        block_len = std.math.add(usize, block_len, plan.wire_len) catch
            return error.IntegerOverflow;
    }
    try list.ensureUnusedCapacity(allocator, block_len);
    encodePrefixedIntegerAssumeCapacity(list, 8, 0x00, 0);
    encodePrefixedIntegerAssumeCapacity(list, 7, 0x00, 0);
    for (fields, plans) |field, plan| {
        switch (plan.representation) {
            .indexed_static => |index| encodePrefixedIntegerAssumeCapacity(
                list,
                6,
                0xc0,
                index,
            ),
            .static_name => |static_name| {
                encodePrefixedIntegerAssumeCapacity(
                    list,
                    4,
                    0x50 | if (field.never_indexed) @as(u8, 0x20) else 0,
                    static_name.index,
                );
                encodeStringAssumeCapacity(
                    list,
                    field.value,
                    static_name.value,
                );
            },
            .literal_name => |value_plan| {
                encodePrefixedIntegerAssumeCapacity(
                    list,
                    3,
                    0x20 | if (field.never_indexed) @as(u8, 0x10) else 0,
                    field.name.len,
                );
                const name = list.addManyAsSliceAssumeCapacity(field.name.len);
                for (field.name, name) |byte, *out| {
                    out.* = std.ascii.toLower(byte);
                }
                encodeStringAssumeCapacity(list, field.value, value_plan);
            },
        }
    }
}

const LiteralFieldPlan = struct {
    representation: union(enum) {
        indexed_static: u64,
        static_name: struct {
            index: u64,
            value: EncodedStringPlan,
        },
        literal_name: EncodedStringPlan,
    },
    wire_len: usize,
};

fn planLiteralField(field: HeaderField) !LiteralFieldPlan {
    if (static_table_module.findMatchNormalizedName(
        field.name,
        field.value,
    )) |match| {
        if (match.full_match and !field.never_indexed) {
            return .{
                .representation = .{ .indexed_static = match.index },
                .wire_len = prefixed_integer.encodedLen(6, match.index),
            };
        }
        const value = try encodedStringPlan(field.value);
        return .{
            .representation = .{ .static_name = .{
                .index = match.index,
                .value = value,
            } },
            .wire_len = std.math.add(
                usize,
                prefixed_integer.encodedLen(4, match.index),
                value.wire_len,
            ) catch return error.IntegerOverflow,
        };
    }

    const value = try encodedStringPlan(field.value);
    var wire_len = std.math.add(
        usize,
        prefixed_integer.encodedLen(3, field.name.len),
        field.name.len,
    ) catch return error.IntegerOverflow;
    wire_len = std.math.add(usize, wire_len, value.wire_len) catch
        return error.IntegerOverflow;
    return .{
        .representation = .{ .literal_name = value },
        .wire_len = wire_len,
    };
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
            const never_indexed = (first & 0x20) != 0;
            const is_static = (first & 0x10) != 0;
            const index = try decodePrefixedInteger(&cursor, 4, first);
            if (!is_static) return error.QpackDynamicTableUnsupported;
            const entry = staticEntry(index) orelse return error.InvalidFrame;
            const value_plan = try scanString(&cursor);
            try budget.charge(entry.name.len, value_plan.decoded_len);
            var value = try value_plan.decode(allocator);
            errdefer if (value.storage) |storage| allocator.free(storage);
            try fields.append(allocator, .{
                .name = entry.name,
                .value = value.value,
                .never_indexed = never_indexed,
                .value_storage = value.storage,
            });
            value.storage = null;
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
            try fields.append(allocator, .{
                .name = name.value,
                .value = value.value,
                .never_indexed = never_indexed,
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

/// Literal-only counterpart of `decodeDynamicBlockOwnedWithLimit`.
pub fn decodeLiteralBlockOwnedWithLimit(
    allocator: std.mem.Allocator,
    block: []const u8,
    max_field_section_size: u64,
) ![]HeaderField {
    var cursor = wire.Cursor.init(block);
    const required_insert_count = try decodePrefixedInteger(
        &cursor,
        8,
        try cursor.readByte(),
    );
    const base = try decodePrefixedInteger(
        &cursor,
        7,
        try cursor.readByte(),
    );
    if (required_insert_count != 0 or base != 0) {
        return error.QpackDynamicTableUnsupported;
    }
    var budget = FieldSectionBudget{ .max = max_field_section_size };
    var plan_fallback = std.heap.stackFallback(
        owned_plan_stack_fields * @sizeOf(OwnedFieldPlan),
        allocator,
    );
    var builder = OwnedFieldBuilder.init(
        allocator,
        plan_fallback.get(),
    );
    defer builder.deinit();
    try builder.reservePlans(owned_plan_stack_fields);
    while (!cursor.eof()) {
        const first = try cursor.readByte();
        if ((first & 0xc0) == 0xc0) {
            const entry = staticEntry(try decodePrefixedInteger(
                &cursor,
                6,
                first,
            )) orelse return error.InvalidFrame;
            try budget.charge(entry.name.len, entry.value.len);
            try builder.appendBorrowed(entry.name, entry.value, false);
        } else if ((first & 0xc0) == 0x40) {
            if ((first & 0x10) == 0) {
                return error.QpackDynamicTableUnsupported;
            }
            const entry = staticEntry(try decodePrefixedInteger(
                &cursor,
                4,
                first,
            )) orelse return error.InvalidFrame;
            const value = try scanString(&cursor);
            try budget.charge(entry.name.len, value.decoded_len);
            try builder.append(
                .{
                    .raw = entry.name,
                    .huffman = false,
                    .decoded_len = entry.name.len,
                },
                value,
                (first & 0x20) != 0,
            );
        } else if ((first & 0xe0) == 0x20) {
            const name = try scanMaybeHuffman(
                try cursor.readSlice(try decodePrefixedInteger(
                    &cursor,
                    3,
                    first,
                )),
                (first & 0x08) != 0,
            );
            const value = try scanString(&cursor);
            try budget.charge(name.decoded_len, value.decoded_len);
            try builder.append(name, value, (first & 0x10) != 0);
        } else {
            return error.QpackDynamicTableUnsupported;
        }
    }
    return builder.finish();
}

const OwnedFieldBuilder = struct {
    allocator: std.mem.Allocator,
    plan_allocator: std.mem.Allocator,
    plans: std.ArrayList(OwnedFieldPlan) = .empty,
    string_bytes: usize = 0,

    fn init(
        allocator: std.mem.Allocator,
        plan_allocator: std.mem.Allocator,
    ) OwnedFieldBuilder {
        return .{
            .allocator = allocator,
            .plan_allocator = plan_allocator,
        };
    }

    fn deinit(self: *OwnedFieldBuilder) void {
        self.plans.deinit(self.plan_allocator);
    }

    fn reservePlans(self: *OwnedFieldBuilder, capacity: usize) !void {
        try self.plans.ensureTotalCapacityPrecise(
            self.plan_allocator,
            capacity,
        );
    }

    fn appendBorrowed(
        self: *OwnedFieldBuilder,
        name: []const u8,
        value: []const u8,
        never_indexed: bool,
    ) !void {
        return self.append(
            .{ .raw = name, .huffman = false, .decoded_len = name.len },
            .{ .raw = value, .huffman = false, .decoded_len = value.len },
            never_indexed,
        );
    }

    fn append(
        self: *OwnedFieldBuilder,
        name: EncodedString,
        value: EncodedString,
        never_indexed: bool,
    ) !void {
        try self.plans.ensureUnusedCapacity(self.plan_allocator, 1);
        const additional = std.math.add(
            usize,
            name.decoded_len,
            value.decoded_len,
        ) catch return error.ExcessiveLoad;
        const next_string_bytes = std.math.add(
            usize,
            self.string_bytes,
            additional,
        ) catch return error.ExcessiveLoad;
        self.plans.appendAssumeCapacity(.{
            .name = name,
            .value = value,
            .never_indexed = never_indexed,
        });
        self.string_bytes = next_string_bytes;
    }

    fn finish(self: *OwnedFieldBuilder) ![]HeaderField {
        if (self.plans.items.len == 0) {
            return self.allocator.alloc(HeaderField, 0);
        }
        const field_bytes = std.math.mul(
            usize,
            self.plans.items.len,
            @sizeOf(HeaderField),
        ) catch return error.OutOfMemory;
        const allocation_len = std.math.add(
            usize,
            field_bytes,
            self.string_bytes,
        ) catch return error.OutOfMemory;
        const allocation = try self.allocator.alignedAlloc(
            u8,
            .of(HeaderField),
            allocation_len,
        );
        errdefer self.allocator.free(allocation);
        const fields: []HeaderField = @as(
            [*]HeaderField,
            @ptrCast(allocation.ptr),
        )[0..self.plans.items.len];
        const strings = allocation[field_bytes..];
        var string_offset: usize = 0;
        for (self.plans.items, fields, 0..) |plan, *field, index| {
            const name = strings[string_offset..][0..plan.name.decoded_len];
            try plan.name.decodeInto(name);
            string_offset += name.len;
            const value = strings[string_offset..][0..plan.value.decoded_len];
            try plan.value.decodeInto(value);
            string_offset += value.len;
            field.* = .{
                .name = name,
                .value = value,
                .never_indexed = plan.never_indexed,
                .block_storage = if (index == 0) allocation else null,
            };
        }
        std.debug.assert(string_offset == strings.len);
        return fields;
    }
};

pub fn freeDecodedFields(allocator: std.mem.Allocator, fields: []HeaderField) void {
    if (fields.len != 0) {
        if (fields[0].block_storage) |storage| {
            if (@intFromPtr(fields.ptr) == @intFromPtr(storage.ptr)) {
                const allocation: []align(@alignOf(HeaderField)) u8 =
                    @alignCast(storage);
                allocator.free(allocation);
                return;
            }
        }
    }
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

const EncodedStringPlan = struct {
    payload_len: usize,
    wire_len: usize,
    huffman: bool,
};

fn encodedStringPlan(value: []const u8) !EncodedStringPlan {
    const huffman_len = if (value.len > 2)
        try huffmanEncodedLen(value)
    else
        value.len;
    const huffman = value.len > 2 and huffman_len < value.len;
    const payload_len = if (huffman) huffman_len else value.len;
    const wire_len = std.math.add(
        usize,
        prefixed_integer.encodedLen(7, payload_len),
        payload_len,
    ) catch return error.IntegerOverflow;
    return .{
        .payload_len = payload_len,
        .wire_len = wire_len,
        .huffman = huffman,
    };
}

fn encodeStringAssumeCapacity(
    list: *std.ArrayList(u8),
    value: []const u8,
    plan: EncodedStringPlan,
) void {
    encodePrefixedIntegerAssumeCapacity(
        list,
        7,
        if (plan.huffman) 0x80 else 0x00,
        plan.payload_len,
    );
    if (plan.huffman) {
        appendHuffmanAssumeCapacity(list, value, plan.payload_len);
    } else {
        list.appendSliceAssumeCapacity(value);
    }
}

fn encodeString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    const plan = try encodedStringPlan(value);
    try list.ensureUnusedCapacity(allocator, plan.wire_len);
    encodeStringAssumeCapacity(list, value, plan);
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

    fn decodeInto(self: EncodedString, output: []u8) !void {
        if (output.len != self.decoded_len) return error.InvalidEncoding;
        if (self.huffman) {
            return huffman_codec.decodeHuffmanInto(output, self.raw);
        }
        @memcpy(output, self.raw);
    }

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
