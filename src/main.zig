const std = @import("std");
const z_bls_ks_conv = @import("z_bls_ks_conv");
const clap = @import("zig-clap");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    // specify the paramaters that our program can take
    const params = comptime clap.parseParamsComptime(
        \\-h, --help                   Display help and exit.
        \\-v, --version                Display Version
        \\-s, --src          <PATH>    Source directory containing v4 keystores
        \\-d, --dest         <PATH>    Destination directory for converted v4 keystores 
        \\-p, --password-src <PATH>    Path to the directory containing password files.
        \\-m, --mode         <MODE>    Keystores bulk-loading mode to specify how keystore and password file names are expected.
        \\                             Valid Values: [WEB3SIGNER, NIMBUS]. Defaults to: WEB3SIGNER.        
        \\                             WEB3SIGNER mode expects [<pk>.json | <pk>.txt]
        \\                             NIMBUS mode expects [<pk>/keystore.json | <pk>].
        \\-c, --count        <INTEGER>  PBKDF2 count parameter. Defaults to 1.
        \\ 
    );

    // parsers for zig-clap
    const Mode = enum { WEB3SIGNER, NIMBUS };
    const parsers = comptime .{
        .PATH = clap.parsers.string,
        .MODE = clap.parsers.enumeration(Mode),
        .INTEGER = clap.parsers.int(usize, 10),
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = gpa.allocator(),
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        return clap.helpToFile(.stderr(), clap.Help, &params, .{
            .markdown_lite = false, // treat newlines literally
            .description_on_new_line = true, // description starts on a new line
        });
    }

    if (res.args.version != 0) {
        std.debug.print("Version={s}\n", .{"1.0.0"});
        return;
    }

    if (res.args.src) |src| {
        std.debug.print("Source directory: {s}\n", .{src});
    }

    // usage as default!
    std.debug.print("Usage: ", .{});
    return clap.usageToFile(.stderr(), clap.Help, &params);
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
