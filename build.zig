const std = @import("std");
const Builder = std.build.Builder;
const Mode = @import("builtin").Mode;

pub fn build(b: *Builder) void {
    const mode = Mode.Debug;

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

    const test_step = b.step("test", "Run library tests");

    const tests = [_][]const u8{
        "src/tests/test_events.zig",
    };

    inline for (tests) |path| {
        var t = b.addTest(path);
        addPackages(b, t);
        t.setBuildMode(mode);
        test_step.dependOn(&t.step);
    }
}

fn addPackages(b: *Builder, _test: *std.build.LibExeObjStep) void {
    _test.linkLibC();
    _test.addPackagePath("events", "src/events.zig");
    _test.addPackagePath("waitpid", "src/waitpid.zig");
}
