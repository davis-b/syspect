const Builder = @import("std").build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder) void {
    const mode = Mode.Debug;

    const exe = b.addExecutable("redirector", "src/example_redirector.zig");
    exe.setBuildMode(mode);
    exe.linkLibC();
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run library tests");

    var test_main = b.addTest("src/main.zig");
    // test_main.addPackagePath("maker", "src/maker.zig");
    test_main.setBuildMode(mode);
    test_step.dependOn(&test_main.step);
}
