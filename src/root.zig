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

/// Convert Keystores baed on provided conversion options
pub fn convertKeystores(allocator: std.mem.Allocator, options: ConversionOptions) !void {
    var src_dir = try std.fs.cwd().openDir(options.src_dir, .{ .iterate = true });
    defer src_dir.close();

    var iterator = src_dir.iterate();

    while (try iterator.next()) |entry| {
        switch (options.mode) {
            .WEB3SIGNER => try processWeb3SignerEntry(allocator, entry, src_dir, options),
            .NIMBUS => try processNimbusEntry(allocator, entry, src_dir, options),
        }
    }
}

/// Process a single Web3Signer keystore entry
fn processWeb3SignerEntry(allocator: std.mem.Allocator, entry: std.fs.Dir.Entry, src_dir: std.fs.Dir, options: ConversionOptions) !void {
    if (entry.kind != .file) return;

    if (!std.mem.endsWith(u8, entry.name, ".json")) return;

    // Extract public key (filename without .json extension)
    const pk = entry.name[0 .. entry.name.len - 5]; // Remove ".json"

    // Get keystore path (same as entry.name in this case)
    const keystore_path = try options.mode.getKeystorePath(allocator, pk);
    defer allocator.free(keystore_path);

    // Get password file path
    const password_path = try options.mode.getPasswordPath(allocator, pk);
    defer allocator.free(password_path);

    // Read keystore file
    const keystore_content = try src_dir.readFileAlloc(allocator, keystore_path, std.math.maxInt(usize));
    defer allocator.free(keystore_content);

    // Read password file (from password_dir)
    var password_dir = try std.fs.cwd().openDir(options.password_dir, .{});
    defer password_dir.close();

    const password_content = try password_dir.readFileAlloc(allocator, password_path, std.math.maxInt(usize));
    defer allocator.free(password_content);

    // TODO: Process keystore_content and password_content
    std.debug.print("Processing Web3Signer keystore for PK: {s}\n", .{pk});
    std.debug.print("  Keystore size: {} bytes\n", .{keystore_content.len});
    std.debug.print("  Password size: {} bytes\n", .{password_content.len});
}

/// Process a single Nimbus keystore entry
fn processNimbusEntry(allocator: std.mem.Allocator, entry: std.fs.Dir.Entry, src_dir: std.fs.Dir, options: ConversionOptions) !void {
    // Skip if not a directory
    if (entry.kind != .directory) return;

    // Directory name is the public key
    const pk = entry.name;

    // Get keystore path (pk/keystore.json)
    const keystore_path = try options.mode.getKeystorePath(allocator, pk);
    defer allocator.free(keystore_path);

    // Get password path (just pk in this case)
    const password_path = try options.mode.getPasswordPath(allocator, pk);
    defer allocator.free(password_path);

    // Read keystore file from subdirectory
    const keystore_content = try src_dir.readFileAlloc(allocator, keystore_path, std.math.maxInt(usize));
    defer allocator.free(keystore_content);

    // Read password file (from password_dir)
    var password_dir = try std.fs.cwd().openDir(options.password_dir, .{});
    defer password_dir.close();

    const password_content = try password_dir.readFileAlloc(allocator, password_path, std.math.maxInt(usize));
    defer allocator.free(password_content);

    // TODO: Process keystore_content and password_content
    std.debug.print("Processing Nimbus keystore for PK: {s}\n", .{pk});
    std.debug.print("  Keystore size: {} bytes\n", .{keystore_content.len});
    std.debug.print("  Password size: {} bytes\n", .{password_content.len});
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
