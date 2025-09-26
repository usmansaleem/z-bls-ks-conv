const std = @import("std");
const builtin = @import("builtin");
const bls = @import("z_bls_ks_conv");
const clap = @import("zig-clap");

const native_os = builtin.os.tag;
var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

pub fn main() !void {
    // choose appropriate allocator based on release type
    const allocator, const is_debug = gpa: {
        if (native_os == .wasi) break :gpa .{ std.heap.wasm_allocator, false };
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{ debug_allocator.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        _ = debug_allocator.deinit();
    };

    // Parse command line arguments
    const params = comptime clap.parseParamsComptime(
        \\-h, --help                   Display help and exit.
        \\-v, --version                Display Version
        \\-s, --src          <PATH>    Source directory containing v4 keystores
        \\-d, --dest         <PATH>    Destination directory for converted v4 keystores 
        \\-w, --password_dir <PATH>    Path to the directory containing password files.
        \\-m, --mode         <MODE>    Keystores bulk-loading mode to specify how keystore and password file names are expected.
        \\                             Valid Values: [WEB3SIGNER, NIMBUS]. Defaults to: WEB3SIGNER.        
        \\                             WEB3SIGNER mode expects [<pk>.json | <pk>.txt]
        \\                             NIMBUS mode expects [<pk>/keystore.json | <pk>].
        \\-c                 <INTEGER>  PBKDF2 count parameter. Defaults to 1.
        \\-n                 <INTEGER>  SCRYPT CPU/memory cost parameter. Defaults to 2.
        \\-p                 <INTEGER>  SCRYPT Parallelization parameter. Defaults to 1.
        \\-r                 <INTEGER>  SCRYPT Block size parameter. Defaults to 8.
        \\ 
    );

    // parsers for zig-clap
    const parsers = comptime .{
        .PATH = clap.parsers.string,
        .MODE = clap.parsers.enumeration(bls.Mode),
        .INTEGER = clap.parsers.int(usize, 10),
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return err;
    };
    defer res.deinit();

    // Handle Help and Version flags
    if (res.args.help != 0) {
        return clap.helpToFile(.stderr(), clap.Help, &params, .{
            .markdown_lite = false,
            .description_on_new_line = true,
        });
    }

    if (res.args.version != 0) {
        std.debug.print("Version={s}\n", .{"1.0.0"});
        return;
    }

    // validate required arguments
    const src = res.args.src orelse {
        std.log.err("Missing required argument: --src", .{});
        return clap.usageToFile(.stderr(), clap.Help, &params);
    };

    const dest = res.args.dest orelse {
        std.log.err("Missing required argument: --dest", .{});
        return clap.usageToFile(.stderr(), clap.Help, &params);
    };

    const password_dir = res.args.password_dir orelse {
        std.log.err("Missing required argument: --password_dir", .{});
        return clap.usageToFile(.stderr(), clap.Help, &params);
    };

    // Build options from CLI arguments
    const options = bls.ConversionOptions{
        .src_dir = src,
        .dest_dir = dest,
        .password_dir = password_dir,
        .mode = res.args.mode orelse .WEB3SIGNER,
        .keystore_config = .{
            .pbkdf2_count = res.args.c orelse 1,
            .scrypt_n = res.args.n orelse 2,
            .scrypt_p = res.args.p orelse 1,
            .scrypt_r = res.args.r orelse 8,
        },
    };

    // Validate paths exists
    try bls.validatePaths(allocator, options);

    // Perform conversion
    // try bls.convertKeystores(allocator, options);

    std.log.info("Successfully converted keystores from '{s} to '{s}'", .{ src, dest });
}
