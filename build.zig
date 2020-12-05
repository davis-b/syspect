const std = @import("std");
const Builder = std.build.Builder;
const Mode = @import("builtin").Mode;
const root = @import("root");

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    const examples = .{
        .{ "redirector", "src/examples/connect_redirector/main.zig" },
        .{ "print_some_syscalls", "src/examples/print_some_syscalls.zig" },
    };

    inline for (examples) |i| {
        const exe = b.addExecutable(i[0], i[1]);
        exe.addPackagePath("syspect", "src/index.zig");
        exe.setBuildMode(mode);
        exe.linkLibC();
        exe.install();
    }
}
