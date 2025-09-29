const std = @import("std");
const types = @import("types.zig");
const ConversionOptions = types.ConversionOptions;

/// Validate keystore, password and destination paths
pub fn validatePaths(allocator: std.mem.Allocator, options: ConversionOptions) !void {
    try validateReadableDir(options.src_dir);
    try validateReadableDir(options.password_dir);
    try validateDestDir(allocator, options.dest_dir);
}

pub fn validateReadableDir(path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });

    defer dir.close();
}

pub fn validateDestDir(allocator: std.mem.Allocator, dir_path: []const u8) !void {
    // Try to open the directory
    var dir = std.fs.cwd().openDir(dir_path, .{}) catch |err| switch (err) {
        error.FileNotFound => blk: {
            // Create directory path (with parents)
            std.log.info("Creating destination directory '{s}'", .{dir_path});
            try std.fs.cwd().makePath(dir_path);
            break :blk try std.fs.cwd().openDir(dir_path, .{});
        },
        else => return err,
    };
    defer dir.close();

    // Test write permissions using the dir handle
    const test_filename = try std.fmt.allocPrint(allocator, ".testfile_{d}_{d}.tmp", .{ std.time.milliTimestamp(), std.crypto.random.int(u32) });
    defer allocator.free(test_filename);

    const file = try dir.createFile(test_filename, .{ .exclusive = true });
    defer file.close();

    // Clean up using the dir handle
    dir.deleteFile(test_filename) catch |err| {
        std.log.warn("Could not clean up test file: {}", .{err});
    };
}
