const std = @import("std");

pub fn expectEnumEqual(comptime Enum: type, a: anytype, b: anytype) void {
    const valid_a = convert(Enum, a);
    const valid_b = convert(Enum, b);

    if (valid_a != valid_b) {
        std.debug.panic("expected {s}, found {s}\n", .{ @tagName(valid_a), @tagName(valid_b) });
    }
}

/// Converts a valid type to Enum type
fn convert(comptime Enum: type, i: anytype) Enum {
    return switch (@typeInfo(@TypeOf(i))) {
        .Int => @intToEnum(Enum, i),
        .Enum => switch (@TypeOf(i)) {
            Enum => i,
            else => @intToEnum(Enum, @enumToInt(i)),
        },
        else => @compileError("Unsupported type: " ++ @typeName(@TypeOf(i))),
    };
}
