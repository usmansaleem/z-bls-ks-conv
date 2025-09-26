const std = @import("std");
const builtin = @import("builtin");

pub const Mode = enum {
    WEB3SIGNER,
    NIMBUS,

    /// Returns the keystore file path for the given public key.
    /// Caller owns the returned memory and must free it.
    pub fn getKeystorePath(self: Mode, allocator: std.mem.Allocator, pk: []const u8) ![]u8 {
        return switch (self) {
            .WEB3SIGNER => try std.fmt.allocPrint(allocator, "{s}.json", .{pk}),
            .NIMBUS => try std.fmt.allocPrint(allocator, "{s}/keystore.json", .{pk}),
        };
    }

    pub fn getPasswordPath(self: Mode, allocator: std.mem.Allocator, pk: []const u8) ![]u8 {
        return switch (self) {
            .WEB3SIGNER => try std.fmt.allocPrint(allocator, "{s}.json", .{pk}),
            .NIMBUS => try allocator.dupe(u8, pk),
        };
    }
};

pub const KeystoreConfig = struct {
    pbkdf2_count: usize = 1,
    scrypt_n: usize = 2,
    scrypt_p: usize = 1,
    scrypt_r: usize = 8,
};

pub const ConversionOptions = struct {
    src_dir: []const u8,
    dest_dir: []const u8,
    password_dir: []const u8,
    mode: Mode,
    keystore_config: KeystoreConfig,
};

pub fn validatePaths(allocator: std.mem.Allocator, options: ConversionOptions) !void {
    try validateReadableDir(options.src_dir);
    try validateReadableDir(options.password_dir);
    try validateDestDir(allocator, options.dest_dir);
}

fn validateReadableDir(path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });

    defer dir.close();
}

fn validateDestDir(allocator: std.mem.Allocator, dir_path: []const u8) !void {
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

// unit tests
test "Mode.getKeystorePath for WEB3SIGNER" {
    const allocator = std.testing.allocator;
    const path = try Mode.WEB3SIGNER.getKeystorePath(allocator, "0x1234abcd");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("0x1234abcd.json", path);
}

test "Mode.getPasswordPath for NIMBUS" {
    const allocator = std.testing.allocator;
    const path = try Mode.NIMBUS.getPasswordPath(allocator, "0x1234abcd");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("0x1234abcd", "0x1234abcd");
}

test "validateDestDir creates missing directory" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const dest_dir = try std.fmt.allocPrint(allocator, "{s}/dest/sub", .{tmp_path});
    defer allocator.free(dest_dir);

    try validateDestDir(allocator, dest_dir);

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
    try std.testing.expectError(error.AccessDenied, validateDestDir(allocator, readonly_path));
}

test "validateReadableDir fails on missing directory" {
    try std.testing.expectError(error.FileNotFound, validateReadableDir("/should/not/exists"));
}
