const std = @import("std");
const testing = std.testing;
const bls = @import("z-v4-converter");

test "Mode.getKeystorePath for WEB3SIGNER" {
    const allocator = std.testing.allocator;
    const path = try bls.types.Mode.WEB3SIGNER.getKeystorePath(allocator, "0x1234abcd");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("0x1234abcd.json", path);
}

test "Mode.getPasswordPath for NIMBUS" {
    const allocator = std.testing.allocator;
    const path = try bls.types.Mode.NIMBUS.getPasswordPath(allocator, "0x1234abcd");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("0x1234abcd", path);
}
