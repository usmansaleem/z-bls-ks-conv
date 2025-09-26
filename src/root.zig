const std = @import("std");

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

pub const PathValidationError = error{
    InvalidSourceDirectory,
    InvalidDestinationDirectory,
    InvalidPasswordDirectory,
    NoWritePermission,
    NoReadPermission,
    InsufficientSpace,
};

pub fn validatePaths(options: ConversionOptions) PathValidationError!void {
    try validateSourceDir(options.src_dir);
    try validateDestDir(options.dest_dir);
    try validatePasswordDir(options.password_dir);
}

fn validateSourceDir(path: []const u8) !void {
    var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch |err| {
        std.log.err("Cannot open source directory '{s}': {}", .{ path, err });
        return switch (err) {
            error.FileNotFound => error.InvalidSourceDirectory,
            error.AccessDenied, error.PermissionDenied => error.NoReadPermission,
            else => error.InvalidSourceDirectory,
        };
    };

    defer dir.close();

    // empty dir check
    var iter = dir.iterate();
    const has_files = (try iter.next()) != null;
    if (has_files) {
        std.log.warn("Source directory {s} is empty", .{path});
    }
}

fn validateDestDir(path: []const u8) !void {
    std.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => {}, //expected case
        error.AccessDenied => {
            std.log.err("Permission denied create dest dir '{s}': {}", .{ path, err });
            return error.InvalidDestinationDirectory;
        },
    };

    // open dir to verify access
    var dir = std.fs.openDirAbsolute(path, .{}) catch |err| {
        std.log.err("Cannot open destination directory '{s}': {}", .{ path, err });
        return switch (err) {
            error.AccessDenied => error.NoReadPermission,
            else => error.InvalidDestinationDirectory,
        };
    };
    defer dir.close();
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
