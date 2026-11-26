//! Complete callback forwarding for test observers with a stable local context.
//! Every callback reaches the delegate with its own userdata and token owners.
const std = @import("std");

/// Borrow an observer with a `delegate: std.Io` field and typed callback
/// overrides. The immutable table has static lifetime; the context and its
/// delegate must outlive every operation or task using the returned I/O.
/// Clock-remapping observers can use `table` with their own timeout mapping.
pub fn observer(context: anytype, comptime overrides: anytype) std.Io {
    const Context = @typeInfo(@TypeOf(context)).pointer.child;
    const Adapter = struct {
        fn from(userdata: ?*anyopaque) *Context {
            return @ptrCast(@alignCast(userdata.?));
        }
        fn baseIo(self: *Context) std.Io {
            return self.delegate;
        }
        fn preserveTimeout(_: *Context, timeout: std.Io.Timeout) std.Io.Timeout {
            return timeout;
        }
        const callbacks = blk: {
            var value = table(from, baseIo, preserveTimeout);
            for (@typeInfo(@TypeOf(overrides)).@"struct".fields) |field| {
                @field(value, field.name) = @field(overrides, field.name);
            }
            break :blk value;
        };
    };
    return .{ .userdata = context, .vtable = &Adapter.callbacks };
}

pub fn table(comptime from: anytype, comptime base_io: anytype, comptime map_timeout: anytype) std.Io.VTable {
    var result: std.Io.VTable = undefined;
    inline for (@typeInfo(std.Io.VTable).@"struct".fields) |field| {
        @field(result, field.name) = Forward(field.name, from, base_io, map_timeout).invoke;
    }
    return result;
}

fn Forward(comptime field: []const u8, comptime from: anytype, comptime base_io: anytype, comptime map_timeout: anytype) type {
    const Function = @typeInfo(@FieldType(std.Io.VTable, field)).pointer.child;
    const info = @typeInfo(Function).@"fn";
    const Args = std.meta.ArgsTuple(Function);
    const Result = info.return_type.?;
    const Call = struct {
        fn Arg(comptime index: usize) type {
            return info.params[index].type.?;
        }
        fn dispatch(original: Args) Result {
            const context = from(original[0]);
            const base = base_io(context);
            var args = original;
            args[0] = base.userdata;
            inline for (info.params, 0..) |parameter, index| {
                if (index != 0 and parameter.type.? == std.Io.Timeout) args[index] = map_timeout(context, original[index]);
            }
            return @call(.auto, @field(base.vtable, field), args);
        }
    };
    if (info.params.len == 0 or info.params[0].type.? != ?*anyopaque or info.is_var_args) @compileError("unsupported IO callback context");
    return switch (info.params.len) {
        1 => struct {
            pub fn invoke(p0: Call.Arg(0)) Result {
                return Call.dispatch(.{p0});
            }
        },
        2 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1)) Result {
                return Call.dispatch(.{ p0, p1 });
            }
        },
        3 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1), p2: Call.Arg(2)) Result {
                return Call.dispatch(.{ p0, p1, p2 });
            }
        },
        4 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1), p2: Call.Arg(2), p3: Call.Arg(3)) Result {
                return Call.dispatch(.{ p0, p1, p2, p3 });
            }
        },
        5 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1), p2: Call.Arg(2), p3: Call.Arg(3), p4: Call.Arg(4)) Result {
                return Call.dispatch(.{ p0, p1, p2, p3, p4 });
            }
        },
        6 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1), p2: Call.Arg(2), p3: Call.Arg(3), p4: Call.Arg(4), p5: Call.Arg(5)) Result {
                return Call.dispatch(.{ p0, p1, p2, p3, p4, p5 });
            }
        },
        7 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1), p2: Call.Arg(2), p3: Call.Arg(3), p4: Call.Arg(4), p5: Call.Arg(5), p6: Call.Arg(6)) Result {
                return Call.dispatch(.{ p0, p1, p2, p3, p4, p5, p6 });
            }
        },
        8 => struct {
            pub fn invoke(p0: Call.Arg(0), p1: Call.Arg(1), p2: Call.Arg(2), p3: Call.Arg(3), p4: Call.Arg(4), p5: Call.Arg(5), p6: Call.Arg(6), p7: Call.Arg(7)) Result {
                return Call.dispatch(.{ p0, p1, p2, p3, p4, p5, p6, p7 });
            }
        },
        else => @compileError("unsupported IO callback arity"),
    };
}
