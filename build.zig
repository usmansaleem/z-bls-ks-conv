const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add dependencies
    const clap = b.dependency("clap", .{});
    const zg = b.dependency("zg", .{});

    // root module
    const mod = b.addModule("z-v4-converter", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "Normalize", .module = zg.module("Normalize") },
            .{ .name = "code_point", .module = zg.module("code_point") },
        },
    });

    // build zon module - to obtain the --version for cli
    const build_zig_zon = b.createModule(.{
        .root_source_file = b.path("build.zig.zon"),
        .target = target,
        .optimize = optimize,
    });

    // main executeable
    const exe = b.addExecutable(.{
        .name = "z-v4-converter",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "z-v4-converter", .module = mod },
                .{ .name = "build.zig.zon", .module = build_zig_zon },
                .{ .name = "zig-clap", .module = clap.module("clap") },
            },
        }),
    });

    b.installArtifact(exe);

    // Run step for main executeable
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| run_cmd.addArgs(args);

    // Test module for tests/all.zig
    const mod_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/all.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "z-v4-converter", .module = mod },
            },
        }),
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Test module for src/root.zig (to pickup all tests in src/)
    const root_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "z-v4-converter", .module = mod },
                .{ .name = "Normalize", .module = zg.module("Normalize") },
                .{ .name = "code_point", .module = zg.module("code_point") },
            },
        }),
    });

    const run_root_tests = b.addRunArtifact(root_tests);

    // Top-level test step that runs all tests
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_root_tests.step);
}
