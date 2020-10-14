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
    //     const exe = b.addExecutable("redirector", "src/examples/connect_redirector.zig");
    //     exe.addPackagePath("syspect", "src/index.zig");
    //     exe.setBuildMode(mode);
    //     exe.linkLibC();
    //     exe.install();

    //    const run_cmd = exe.run();
    //    run_cmd.step.dependOn(b.getInstallStep());
    //
    //    const run_step = b.step("run", "Run the app");
    //    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run library tests");

    var test_main = b.addTest("src/main.zig");
    // test_main.addPackagePath("maker", "src/maker.zig");
    test_main.setBuildMode(mode);
    test_step.dependOn(&test_main.step);
}
