const std = @import("std");
const Builder = std.build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder, mode: std.builtin.Mode, target: std.zig.CrossTarget) !void {
    const tests = .{
        .{ "fork", "tests/src/fork.zig" },
        .{ "clone", "tests/src/clone.zig" },
        .{ "child signals", "tests/src/child_signals.zig" },
        .{ "modify_result", "tests/src/modify_result.zig" },
        .{ "nullify_syscall", "tests/src/nullify_syscall.zig" },
    };

    const testable_programs = .{
        .{ "testable-fork", "tests/testable-programs/fork.zig" },
        .{ "testable-clone", "tests/testable-programs/clone.zig" },
        .{ "testable-child_signals", "tests/testable-programs/child_signals.zig" },
        .{ "testable-modify_result", "tests/testable-programs/modify_result.zig" },
        .{ "testable-nullify_syscall", "tests/testable-programs/nullify_syscall.zig" },
    };

    try b.makePath("zig-cache/bin/tests/");

    const test_step = b.step("test", "Run library tests");
    inline for (testable_programs) |path| {
        const exe = b.addExecutable(path[0], path[1]);
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.setOutputDir("zig-cache/bin/tests/");
        // TODO
        // exe.install causes testable_programs to be installed in both bin/ and bin/tests/
        // We do not want them to be installed in bin/
        // Unsure how to fix this without the following workaround.
        const run_step = exe.run();
        run_step.addArg("do_end_early");
        run_step.step.dependOn(b.getInstallStep());
        test_step.dependOn(&run_step.step);
    }

    inline for (tests) |path| {
        var test_ = b.addTest(path[1]);
        test_.setTarget(target);
        test_.setBuildMode(mode);
        test_.addPackagePath("syspect", "src/index.zig");
        test_.linkLibC();
        test_step.dependOn(&test_.step);
    }
}
