const std = @import("std");
const Builder = std.build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder) !void {
    const mode = b.standardReleaseOptions();

    const tests = .{
        .{ "fork", "tests/src/fork.zig" },
        .{ "clone", "tests/src/clone.zig" },
    };

    const examples = .{
        .{ "example-fork", "tests/example-programs/fork.zig" },
        .{ "example-clone", "tests/example-programs/clone.zig" },
    };

    try b.makePath("zig-cache/bin/tests/");

    const test_step = b.step("test", "Run library tests");
    inline for (examples) |path| {
        const exe = b.addExecutable(path[0], path[1]);
        exe.setOutputDir("zig-cache/bin/tests/");
        // TODO
        // exe.install causes examples to be installed in both bin/ and bin/tests/
        // We do not want them to be installed in bin/
        // Unsure how to fix this without the following workaround.
        const test_cmd = exe.run();
        test_cmd.step.dependOn(b.getInstallStep());
        test_step.dependOn(&test_cmd.step);
    }

    // While we would prefer to simply run the tests using zig's builtin test keyword,
    // doing so is currently impossible.
    // For an unknown reason, waitpid constantly receives an exit signal on pid "-10" while using that method.
    inline for (tests) |path| {
        const exe = b.addExecutable(path[0], path[1]);
        exe.addPackagePath("syspect", "src/index.zig");
        exe.setBuildMode(mode);
        exe.linkLibC();
        exe.setOutputDir("zig-cache/bin/tests/");

        const test_cmd = exe.run();
        test_cmd.step.dependOn(b.getInstallStep());
        test_step.dependOn(&test_cmd.step);
        // std.debug.warn("test {}... ", .{path[0]});
    }
    // std.debug.warn("\n", .{});
}
