const std = @import("std");
const types = @import("types.zig");

/// Parsing-specific errors
pub const ParseError = error{
    UnsupportedKdfFunction,
    UnsupportedCipherFunction,
    UnsupportedChecksumFunction,
    UnsupportedKeystoreVersion,
    MissingKdfParams,
    MissingCipherParams,
};

/// Raw JSON representation for parsing (with flexible KDF params)
const KeystoreJson = struct {
    crypto: CryptoJson,
    description: ?[]const u8 = null,
    pubkey: []const u8,
    path: []const u8,
    uuid: []const u8,
    version: u32,

    const CryptoJson = struct {
        kdf: KdfJson,
        checksum: ChecksumJson,
        cipher: CipherJson,

        const KdfJson = struct {
            function: []const u8,
            params: std.json.Value,
            message: []const u8,
        };

        const ChecksumJson = struct {
            function: []const u8,
            params: std.json.Value,
            message: []const u8,
        };

        const CipherJson = struct {
            function: []const u8,
            params: std.json.Value,
            message: []const u8,
        };
    };
};
/// Parse keystore JSON content into Keystore structure
pub fn parseKeystore(allocator: std.mem.Allocator, json_content: []const u8) !types.Keystore {
    var parsed = try std.json.parseFromSlice(KeystoreJson, allocator, json_content, .{});
    defer parsed.deinit();

    const keystore_json = parsed.value;

    // Parse KDF parameters based on function type
    const kdf_params = try parseKdfParams(allocator, keystore_json.crypto.kdf.function, keystore_json.crypto.kdf.params);
    errdefer freeKdfParams(allocator, kdf_params);

    // Parse cipher parameters
    const cipher_params = try parseCipherParams(allocator, keystore_json.crypto.cipher.params);
    errdefer allocator.free(cipher_params.iv);

    // Validate checksum function
    if (!std.mem.eql(u8, keystore_json.crypto.checksum.function, "sha256")) {
        return ParseError.UnsupportedChecksumFunction;
    }

    return types.Keystore{
        .crypto = .{
            .kdf = .{
                .function = try allocator.dupe(u8, keystore_json.crypto.kdf.function),
                .params = kdf_params,
                .message = try allocator.dupe(u8, keystore_json.crypto.kdf.message),
            },
            .checksum = .{
                .function = try allocator.dupe(u8, keystore_json.crypto.checksum.function),
                .params = .{},
                .message = try allocator.dupe(u8, keystore_json.crypto.checksum.message),
            },
            .cipher = .{
                .function = try allocator.dupe(u8, keystore_json.crypto.cipher.function),
                .params = cipher_params,
                .message = try allocator.dupe(u8, keystore_json.crypto.cipher.message),
            },
        },
        .description = if (keystore_json.description) |desc| try allocator.dupe(u8, desc) else null,
        .pubkey = try allocator.dupe(u8, keystore_json.pubkey),
        .path = try allocator.dupe(u8, keystore_json.path),
        .uuid = try allocator.dupe(u8, keystore_json.uuid),
        .version = keystore_json.version,
    };
}

/// Parse and validate EIP-2335 keystore format
pub fn validateKeystoreFormat(keystore: *const types.Keystore) !void {
    // Validate version
    if (keystore.version != 4) {
        return ParseError.UnsupportedKeystoreVersion;
    }

    // Validate KDF function
    const is_valid_kdf = std.mem.eql(u8, keystore.crypto.kdf.function, "scrypt") or
        std.mem.eql(u8, keystore.crypto.kdf.function, "pbkdf2");
    if (!is_valid_kdf) {
        return ParseError.UnsupportedKdfFunction;
    }

    // Validate cipher function
    if (!std.mem.eql(u8, keystore.crypto.cipher.function, "aes-128-ctr")) {
        return ParseError.UnsupportedCipherFunction;
    }

    // Validate checksum function
    if (!std.mem.eql(u8, keystore.crypto.checksum.function, "sha256")) {
        return ParseError.UnsupportedChecksumFunction;
    }
}

/// Parse KDF parameters based on function type
fn parseKdfParams(allocator: std.mem.Allocator, function: []const u8, params_json: std.json.Value) !types.Keystore.Crypto.Kdf.KdfParams {
    const params_obj = switch (params_json) {
        .object => |obj| obj,
        else => return ParseError.MissingKdfParams,
    };

    if (std.mem.eql(u8, function, "scrypt")) {
        return .{ .scrypt = .{
            .dklen = @intCast((params_obj.get("dklen") orelse return ParseError.MissingKdfParams).integer),
            .n = @intCast((params_obj.get("n") orelse return ParseError.MissingKdfParams).integer),
            .r = @intCast((params_obj.get("r") orelse return ParseError.MissingKdfParams).integer),
            .p = @intCast((params_obj.get("p") orelse return ParseError.MissingKdfParams).integer),
            .salt = try allocator.dupe(u8, (params_obj.get("salt") orelse return ParseError.MissingKdfParams).string),
        } };
    } else if (std.mem.eql(u8, function, "pbkdf2")) {
        return .{ .pbkdf2 = .{
            .dklen = @intCast((params_obj.get("dklen") orelse return ParseError.MissingKdfParams).integer),
            .c = @intCast((params_obj.get("c") orelse return ParseError.MissingKdfParams).integer),
            .prf = try allocator.dupe(u8, (params_obj.get("prf") orelse return ParseError.MissingKdfParams).string),
            .salt = try allocator.dupe(u8, (params_obj.get("salt") orelse return ParseError.MissingKdfParams).string),
        } };
    } else {
        return ParseError.UnsupportedKdfFunction;
    }
}

/// Parse cipher parameters
fn parseCipherParams(allocator: std.mem.Allocator, params_json: std.json.Value) !types.Keystore.Crypto.Cipher.CipherParams {
    const params_obj = switch (params_json) {
        .object => |obj| obj,
        else => return ParseError.MissingCipherParams,
    };

    return .{
        .iv = try allocator.dupe(u8, (params_obj.get("iv") orelse return ParseError.MissingCipherParams).string),
    };
}

/// Helper function to free KDF parameters
fn freeKdfParams(allocator: std.mem.Allocator, params: types.Keystore.Crypto.Kdf.KdfParams) void {
    switch (params) {
        .scrypt => |scrypt_params| allocator.free(scrypt_params.salt),
        .pbkdf2 => |pbkdf2_params| {
            allocator.free(pbkdf2_params.salt);
            allocator.free(pbkdf2_params.prf);
        },
    }
}
