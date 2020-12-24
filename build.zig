// Tested with Zig version 0.6
const std = @import("std");
const Builder = std.build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder) !void {
    const mode = b.standardReleaseOptions();

    const examples = .{
        .{ "redirector", "src/examples/connect_redirector/main.zig" },
        .{ "print_some_syscalls", "src/examples/print_some_syscalls.zig" },
        .{ "print_open2_pathnames", "src/examples/print_pathname.zig" },
    };

    inline for (examples) |i| {
        const exe = b.addExecutable(i[0], i[1]);
        exe.addPackagePath("syspect", "src/index.zig");
        exe.setBuildMode(mode);
        exe.linkLibC();
        exe.install();
    }

    try @import("tests/build.zig").build(b);
}
