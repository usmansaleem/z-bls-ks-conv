const std = @import("std");
const testing = std.testing;
const bls = @import("z-v4-converter");

test "convertKeystores - Web3Signer mode" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const options = bls.ConversionOptions{
        .src_dir = "tests/fixtures/web3signer/keystores",
        .dest_dir = tmp_path,
        .password_dir = "tests/fixtures/web3signer/passwords",
        .mode = .WEB3SIGNER,
        .keystore_config = .{}, // use defaults
    };

    try bls.convertKeystores(allocator, options);

    // TODO: Verify files are actually converted in dest!
    // var dest_dir = try tmp.dir.openDir(".", .{ .iterate = true });
    // defer dest_dir.close();
    // var iterator = dest_dir.iterate();
    // var file_count: u32 = 0;
    // while (try iterator.next()) |entry| {
    //     if (entry.kind == .file) file_count += 1;
    // }
    // try std.testing.expect(file_count > 0); // Ensure some files were created
}

test "convertKeystores - Nimbus mode" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const options = bls.ConversionOptions{
        .src_dir = "tests/fixtures/nimbus/keystores",
        .dest_dir = tmp_path,
        .password_dir = "tests/fixtures/nimbus/passwords",
        .mode = .NIMBUS,
        .keystore_config = .{}, // use defaults
    };

    try bls.convertKeystores(allocator, options);

    // TODO: Verify files are actually converted in dest!
    // var dest_dir = try tmp.dir.openDir(".", .{ .iterate = true });
    // defer dest_dir.close();
    // var iterator = dest_dir.iterate();
    // var file_count: u32 = 0;
    // while (try iterator.next()) |entry| {
    //     if (entry.kind == .file) file_count += 1;
    // }
    // try std.testing.expect(file_count > 0); // Ensure some files were created
}
