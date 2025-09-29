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
            .WEB3SIGNER => try std.fmt.allocPrint(allocator, "{s}.txt", .{pk}),
            .NIMBUS => try allocator.dupe(u8, pk), //password filename is same as pk
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

pub const KeystoreData = struct {
    keystore_content: []u8,
    password_content: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *KeystoreData) void {
        self.allocator.free(self.keystore_content);
        self.allocator.free(self.password_content);
    }
};

pub const ConversionContext = struct {
    src_dir: std.fs.Dir,
    dest_dir: std.fs.Dir,
    password_dir: std.fs.Dir,
    options: ConversionOptions,

    pub fn init(options: ConversionOptions) !ConversionContext {
        var src_dir = try std.fs.cwd().openDir(options.src_dir, .{ .iterate = true });
        errdefer src_dir.close();

        var password_dir = try std.fs.cwd().openDir(options.password_dir, .{});
        errdefer password_dir.close();

        // Create dest_dir if it doesn't exist, then open it
        try std.fs.cwd().makePath(options.dest_dir);
        var dest_dir = try std.fs.cwd().openDir(options.dest_dir, .{});
        errdefer dest_dir.close();

        return ConversionContext{
            .src_dir = src_dir,
            .dest_dir = dest_dir,
            .password_dir = password_dir,
            .options = options,
        };
    }

    pub fn deinit(self: *ConversionContext) void {
        self.src_dir.close();
        self.dest_dir.close();
        self.password_dir.close();
    }
};
