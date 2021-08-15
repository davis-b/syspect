// Tested with Zig version 0.8
const std = @import("std");
const Builder = std.build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const examples = .{
        .{ "connect_redirector", "examples/connect_redirector/main.zig" },
        .{ "print_some_syscalls", "examples/print_some_syscalls.zig" },
        .{ "print_open2_pathnames", "examples/print_pathname.zig" },
    };

    inline for (examples) |i| {
        const exe = b.addExecutable(i[0], i[1]);
        exe.addPackagePath("syspect", "src/index.zig");
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.linkLibC();
        exe.install();
    }

    try @import("tests/build.zig").build(b, mode, target);
}
