const std = @import("std");
const types = @import("types.zig");

const ConversionOptions = types.ConversionOptions;
const ConversionContext = types.ConversionContext;
const KeystoreData = types.KeystoreData;

/// Convert Keystores based on provided conversion options
pub fn convertKeystores(allocator: std.mem.Allocator, options: ConversionOptions) !void {
    var ctx = try ConversionContext.init(options);
    defer ctx.deinit();

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
    std.debug.print("Processing {} keystore for PK: {s}\n", .{ ctx.options.mode, pk });

    var keystore_data = try readKeystoreAndPassword(allocator, pk, ctx);
    defer keystore_data.deinit();

    // TODO: Process keystore_content and password_content
    std.debug.print("  Keystore size: {} bytes\n", .{keystore_data.keystore_content.len});
    std.debug.print("  Password size: {} bytes\n", .{keystore_data.password_content.len});
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
    const password_content = try password_file.readToEndAlloc(allocator, try password_file.getEndPos());
    errdefer allocator.free(password_content);

    return KeystoreData{
        .keystore_content = keystore_content,
        .password_content = password_content,
        .allocator = allocator,
    };
}
