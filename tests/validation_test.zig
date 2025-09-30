const std = @import("std");
const testing = std.testing;
const bls = @import("z-v4-converter");
const builtin = @import("builtin");

test "validateDestDir creates missing directory" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const dest_dir = try std.fmt.allocPrint(allocator, "{s}/dest/sub", .{tmp_path});
    defer allocator.free(dest_dir);

    try bls.validation.validateDestDir(allocator, dest_dir);

    // assert that dest dir war created
    var new_dest_dir = try std.fs.cwd().openDir(dest_dir, .{});
    new_dest_dir.close();
}

test "validateDestDir fails on read-only directory" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Compute full path for the read-only directory
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const readonly_path = try std.fmt.allocPrint(allocator, "{s}/readonly", .{tmp_path});
    defer allocator.free(readonly_path);

    // Create the directory
    try tmp.dir.makeDir("readonly");

    // Open the directory and make it read-only
    var ro_dir = try std.fs.openDirAbsolute(readonly_path, .{});
    defer ro_dir.close();
    try std.posix.fchmod(ro_dir.fd, 0o555);

    // Should fail
    try std.testing.expectError(error.AccessDenied, bls.validation.validateDestDir(allocator, readonly_path));
}

test "validateReadableDir fails on missing directory" {
    try std.testing.expectError(error.FileNotFound, bls.validation.validateReadableDir("/should/not/exists"));
}
