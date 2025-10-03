const std = @import("std");
const builtin = @import("builtin");

// Re-export public types and functions
pub const types = @import("types.zig");
pub const validation = @import("validation.zig");
pub const conversion = @import("conversion.zig");

// Re-export commonly used types for convenience
pub const Mode = types.Mode;
pub const ConversionOptions = types.ConversionOptions;
pub const KeystoreConfig = types.KeystoreConfig;
pub const KeystoreData = types.KeystoreData;

// Re-export main functions
pub const validatePaths = validation.validatePaths;
pub const convertKeystores = conversion.convertKeystores;

test {
    _ = @import("types.zig");
    _ = @import("validation.zig");
    _ = @import("conversion.zig");
    _ = @import("parsing.zig");
}
