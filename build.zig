const Builder = @import("std").build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder) void {
    const mode = Mode.Debug;

    const examples = .{
        .{ "redirector", "src/examples/connect_redirector.zig" },
        .{ "mini-strace", "src/examples/print_some_syscalls.zig" },
    };

    inline for (examples) |i| {
        const exe = b.addExecutable(i[0], i[1]);
        exe.addPackagePath("syspect", "src/index.zig");
        exe.setBuildMode(mode);
        exe.linkLibC();
        exe.install();
    }

    // const test_step = b.step("test", "Run library tests");
    // var test_main = b.addTest("src/main.zig");
    // test_main.setBuildMode(mode);
    // test_step.dependOn(&test_main.step);
}
