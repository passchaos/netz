//! Decode materialized HPACK fields with a per-field commit boundary.

const std = @import("std");

pub fn Decoder(comptime Context: type) type {
    return struct {
        pub fn decode(
            allocator: std.mem.Allocator,
            block: []const u8,
            dynamic_table: *Context.Table,
            max_dynamic_table_size: usize,
        ) ![]Context.Header {
            var cursor = Context.Cursor.init(block);
            var fields: std.ArrayList(Context.Header) = .empty;
            errdefer {
                Context.freeFields(allocator, fields.items);
                fields.deinit(allocator);
            }
            var saw_header = false;
            while (!cursor.eof()) {
                const first = try cursor.readByte();
                if ((first & 0x80) != 0) {
                    saw_header = true;
                    var field = try Context.copyField(allocator, dynamic_table, try Context.integer(first, &cursor, 7));
                    errdefer Context.freeFields(allocator, (&field)[0..1]);
                    try fields.append(allocator, field);
                    continue;
                }

                if ((first & 0xe0) == 0x20) {
                    if (saw_header) return error.InvalidEncoding;
                    const new_size = std.math.cast(usize, try Context.integer(first, &cursor, 5)) orelse return error.IntegerOverflow;
                    if (new_size > max_dynamic_table_size) return error.InvalidEncoding;
                    dynamic_table.setLimit(allocator, new_size);
                    continue;
                }

                saw_header = true;
                const indexed_literal = (first & 0x40) != 0;
                const name_index = if (indexed_literal)
                    try Context.integer(first, &cursor, 6)
                else
                    try Context.integer(first, &cursor, 4);
                // Incremental literals use bit 0x10 as part of the name index;
                // only the 0001xxxx representation marks Never Indexed.
                var field = Context.Header{
                    .name = undefined,
                    .value = undefined,
                    .never_index = !indexed_literal and (first & 0x10) != 0,
                };
                // The current field owns its strings until append succeeds.
                // Cleanup covers value decoding, table insertion and output
                // growth without touching independently retained table state.
                errdefer Context.freeFields(allocator, (&field)[0..1]);
                const name = if (name_index == 0)
                    try Context.string(allocator, &cursor)
                else
                    try Context.copyName(allocator, dynamic_table, name_index);
                field.name = name.value;
                field.name_storage = name.storage;
                const value = try Context.string(allocator, &cursor);
                field.value = value.value;
                field.value_storage = value.storage;
                if (indexed_literal) try dynamic_table.add(allocator, field.name, field.value);
                try fields.append(allocator, field);
            }
            return fields.toOwnedSlice(allocator);
        }
    };
}
