const std = @import("std");
const types = @import("types.zig");
const KdfParams = types.Keystore.Crypto.Kdf.KdfParams;
const crypto = std.crypto;
const pbkdf2 = crypto.pwhash.pbkdf2;
const testing = std.testing;

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

/// Derive Decryption Key
pub fn deriveKeyFromParams(
    allocator: std.mem.Allocator,
    password: []const u8,
    params: KdfParams,
) ![]u8 {
    switch (params) {
        .pbkdf2 => |p| {
            // Convert hex salt to bytes
            const salt_len = p.salt.len / 2;
            const salt_bytes = try allocator.alloc(u8, salt_len);
            defer allocator.free(salt_bytes);

            _ = try std.fmt.hexToBytes(salt_bytes, p.salt);

            // Allocate output buffer
            const derived_key = try allocator.alloc(u8, p.dklen);
            errdefer allocator.free(derived_key);

            // Derive key
            try pbkdf2(
                derived_key,
                password,
                salt_bytes,
                p.c,
                crypto.auth.hmac.sha2.HmacSha256,
            );

            return derived_key;
        },
        .scrypt => {
            // TODO: Implement scrypt
            return error.NotImplemented;
        },
    }
}

/// Verifies that the password is correct by checking the checksum
/// Returns true if the password is valid, false otherwise
pub fn isValidPassword(allocator: std.mem.Allocator, decryption_key: []const u8, keystore: types.Keystore) !bool {
    // Ensure decryption key is at least 32 bytes
    if (decryption_key.len < 32) return error.InvalidDecryptionKeyLength;

    const cipher_message = try hexToBytes(allocator, keystore.crypto.cipher.message);
    defer allocator.free(cipher_message);

    const checksum_message = try hexToBytes(allocator, keystore.crypto.checksum.message);
    defer allocator.free(checksum_message);

    // Ensure checksum message is 32 bytes (SHA256 output)
    if (checksum_message.len != 32) return error.InvalidChecksumLength;

    // Step 0: DK_slice = decryption_key[16:32]
    const dk_slice = decryption_key[16..32];

    // Step 1 & 2: Compute SHA256 of (DK_slice | cipher_message)
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(dk_slice);
    hasher.update(cipher_message);
    var checksum: [32]u8 = undefined;
    hasher.final(&checksum);

    // Step 3 & 4: Compare and return
    return std.mem.eql(u8, &checksum, checksum_message);
}

/// Parse KDF parameters based on function type
fn parseKdfParams(allocator: std.mem.Allocator, function: []const u8, params_json: std.json.Value) !KdfParams {
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
fn freeKdfParams(allocator: std.mem.Allocator, params: KdfParams) void {
    switch (params) {
        .scrypt => |scrypt_params| allocator.free(scrypt_params.salt),
        .pbkdf2 => |pbkdf2_params| {
            allocator.free(pbkdf2_params.salt);
            allocator.free(pbkdf2_params.prf);
        },
    }
}

/// Helper function to convert hex string to bytes
fn hexToBytes(allocator: std.mem.Allocator, hex_string: []const u8) ![]u8 {
    const byte_len = hex_string.len / 2;
    const bytes = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(bytes);

    _ = try std.fmt.hexToBytes(bytes, hex_string);
    return bytes;
}

test "PBKDF2 with hex salt" {
    const params = KdfParams{
        .pbkdf2 = .{
            .dklen = 32,
            .c = 262144,
            .prf = "hmac-sha256",
            .salt = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        },
    };

    const password = "mypassword";

    const key = try deriveKeyFromParams(
        testing.allocator,
        password,
        params,
    );
    defer testing.allocator.free(key);

    try testing.expectEqual(@as(usize, 32), key.len);
}
