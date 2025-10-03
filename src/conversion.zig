const std = @import("std");
const types = @import("types.zig");
const parsing = @import("parsing.zig");
const Normalize = @import("Normalize");
const code_point = @import("code_point");
const testing = std.testing;

const ConversionOptions = types.ConversionOptions;
const ConversionContext = types.ConversionContext;
const KeystoreData = types.KeystoreData;

/// Convert Keystores based on provided conversion options
pub fn convertKeystores(allocator: std.mem.Allocator, options: ConversionOptions) !void {
    var ctx = try ConversionContext.init(options);
    defer ctx.deinit();

    std.debug.print("Mode: {}\n", .{ctx.options.mode});
    var iterator = ctx.src_dir.iterate();
    while (try iterator.next()) |entry| {
        try processEntry(allocator, entry, &ctx);
    }
}

/// Process a single keystore entry
fn processEntry(allocator: std.mem.Allocator, entry: std.fs.Dir.Entry, ctx: *ConversionContext) !void {
    const pk = switch (ctx.options.mode) {
        .WEB3SIGNER => pk: {
            if (entry.kind != .file) return;
            if (!std.mem.endsWith(u8, entry.name, ".json")) return;
            break :pk entry.name[0 .. entry.name.len - 5];
        },
        .NIMBUS => pk: {
            if (entry.kind != .directory) return;
            break :pk entry.name; // directory name is pk for Nimbus
        },
    };

    var keystore_data = try readKeystoreAndPassword(allocator, pk, ctx);
    defer keystore_data.deinit();

    var keystore = try parsing.parseKeystore(allocator, keystore_data.keystore_content);
    defer keystore.deinit(allocator);

    // TODO: Process keystore_content and password_content
    std.debug.print("Keystore version: {d}\n", .{keystore.version});
    std.debug.print("Keystore public key:{s}\n", .{keystore.pubkey});
}

fn readKeystoreAndPassword(allocator: std.mem.Allocator, pk: []const u8, ctx: *ConversionContext) !KeystoreData {
    // Get keystore path
    const keystore_path = try ctx.options.mode.getKeystorePath(allocator, pk);
    defer allocator.free(keystore_path);

    // Read keystore file
    const keystore_file = try ctx.src_dir.openFile(keystore_path, .{});
    defer keystore_file.close();
    const keystore_content = try keystore_file.readToEndAlloc(allocator, try keystore_file.getEndPos());
    errdefer allocator.free(keystore_content);

    // Get password path
    const password_path = try ctx.options.mode.getPasswordPath(allocator, pk);
    defer allocator.free(password_path);

    const password_file = try ctx.password_dir.openFile(password_path, .{});
    defer password_file.close();

    const rawPassword = try password_file.readToEndAlloc(allocator, try password_file.getEndPos());
    defer allocator.free(rawPassword);

    const normalize_password = try normalizePassword(allocator, rawPassword);
    errdefer allocator.free(normalize_password);

    return KeystoreData{
        .keystore_content = keystore_content,
        .password_content = normalize_password,
        .allocator = allocator,
    };
}

fn normalizePassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    // Step 1: NFKD normalize
    var normalize = try Normalize.init(allocator);
    defer normalize.deinit(allocator);

    var nfkd_result = try normalize.nfkd(allocator, password);
    defer nfkd_result.deinit(allocator);

    // Step 2: Strip disallowed control codes
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    var it: code_point.Iterator = .init(nfkd_result.slice);
    while (it.next()) |cp| {
        if (isAllowedCodepoint(cp.code)) {
            // Encode codepoint back into UTF-8
            var tmp: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(cp.code, &tmp) catch continue;
            try buf.appendSlice(allocator, tmp[0..len]);
        }
    }

    // Step 3: Return owned slice (UTF-8 encoded)
    return buf.toOwnedSlice(allocator);
}

/// Only allow codepoints that are NOT C0, C1, or Delete (0x00–0x1F, 0x7F, 0x80–0x9F)
fn isAllowedCodepoint(cp: u21) bool {
    return !((cp <= 0x1F) or (cp == 0x7F) or (cp >= 0x80 and cp <= 0x9F));
}

test "normalizePassword produces correct output" {
    const allocator = std.testing.allocator;
    const password = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";

    const normalized = try normalizePassword(allocator, password);
    defer allocator.free(normalized);

    // Convert to hex string for comparison
    const hex_encoded = try std.fmt.allocPrint(allocator, "0x{x}", .{normalized});
    defer allocator.free(hex_encoded);

    try testing.expectEqualStrings(hex_encoded, "0x7465737470617373776f7264f09f9491");
}
