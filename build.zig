const std = @import("std");

/// Examples are registered here; each becomes a `run-<name>` step.
const examples: []const []const u8 = &.{
    "echo",
    "line_echo",
    "http_server",
    "http2_server",
    "http_client",
    "ws_echo",
    "ws_client",
    "redis_server",
    "udp_echo",
    "https_client",
    "tls13_client",
    "tls13_server",
    "http3_server",
    "dns_lookup",
    "http3_client",
    "readme_snippets",
};

/// Benchmarks are registered here; each becomes a `bench-<name>` step.
const benches: []const []const u8 = &.{
    "echo_bench",
    "http_bench",
    "tls_bench",
    "http2_bench",
    "http3_bench",
};

/// Which `std.Io` implementation the tests, examples and benchmarks run on.
///
/// The library itself never names one — it takes an `Io` as a parameter — so this
/// only selects the seam in `src/backend/`. `threaded` uses nothing but the
/// standard library; `zio` pulls in a third-party fiber runtime, and is the only
/// way to run on fibers at all while `std.Io.Evented` does not compile.
const Backend = enum { threaded, zio };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const backend = b.option(
        Backend,
        "io",
        "std.Io implementation for tests and examples (default: threaded)",
    ) orelse .threaded;

    const backend_module = b.createModule(.{
        .root_source_file = b.path(switch (backend) {
            .threaded => "src/backend/threaded.zig",
            .zio => "src/backend/zio.zig",
        }),
        .target = target,
        .optimize = optimize,
    });
    if (backend == .zio) {
        // Lazy, so a consumer that never selects this backend never downloads it.
        if (b.lazyDependency("zio", .{ .target = target, .optimize = optimize })) |dep| {
            backend_module.addImport("zio", dep.module("zio"));
        }
    }

    const zinet_module = b.addModule("zinet", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Attached unconditionally, so a downstream consumer of `zinet` gets a
    // working import too — pointing at the standard-library seam.
    zinet_module.addImport("backend", backend_module);

    // `zig build test`
    const test_step = b.step("test", "Run all unit tests");
    const unit_tests = b.addTest(.{ .root_module = zinet_module });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // `zig build fuzz` replays the fuzz corpora and the seeded stress loops.
    // The targets get their own module so a fuzzing run does not also have to
    // build and run the socket-backed integration tests.
    const fuzz_step = b.step("fuzz", "Run the fuzz targets");
    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "backend", .module = backend_module }},
        }),
    });
    const run_fuzz = b.addRunArtifact(fuzz_tests);
    run_fuzz.addPassthruArgs();
    fuzz_step.dependOn(&run_fuzz.step);

    // `zig build examples`, `zig build run-<name>`
    const examples_step = b.step("examples", "Build all examples");
    for (examples) |name| {
        const exe = addExecutable(b, name, "examples", target, optimize, zinet_module, backend_module);
        examples_step.dependOn(&b.addInstallArtifact(exe, .{}).step);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.addPassthruArgs();
        const run_step = b.step(
            b.fmt("run-{s}", .{name}),
            b.fmt("Run the {s} example", .{name}),
        );
        run_step.dependOn(&run_cmd.step);
    }

    // `zig build bench`, `zig build bench-<name>`
    const bench_step = b.step("bench", "Build all benchmarks");
    for (benches) |name| {
        const exe = addExecutable(b, name, "bench", target, .fast, zinet_module, backend_module);
        bench_step.dependOn(&b.addInstallArtifact(exe, .{}).step);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.addPassthruArgs();
        const run_step = b.step(
            b.fmt("bench-{s}", .{name}),
            b.fmt("Run the {s} benchmark", .{name}),
        );
        run_step.dependOn(&run_cmd.step);
    }

    // `zig build fmt` / `zig build fmt-check`
    const fmt_paths: []const std.Build.LazyPath = &.{
        b.path("build.zig"), b.path("src"), b.path("examples"), b.path("bench"),
    };
    const fmt = b.addFmt(.{ .paths = fmt_paths });
    b.step("fmt", "Format all source files").dependOn(&fmt.step);
    const fmt_check = b.addFmt(.{ .paths = fmt_paths, .check = true });
    b.step("fmt-check", "Check source formatting").dependOn(&fmt_check.step);

    // `zig build mutate` runs the mutation catalogue: break a rule on purpose, require the
    // suite to notice, put the file back. Its own step rather than part of `check`, because it
    // rebuilds and reruns the tests once per mutation and that is minutes rather than seconds —
    // a control worth having is not worth making every local build wait for.
    const mutate_step = b.step("mutate", "Break each rule in the catalogue and require a test to fail");
    const mutate_exe = b.addExecutable(.{
        .name = "mutate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/mutate.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_mutate = b.addRunArtifact(mutate_exe);
    // The compiler running this build, not whichever `zig` is on PATH: a mutation checked
    // against a different toolchain is not checked at all.
    run_mutate.addArg(b.graph.zig_exe);
    run_mutate.addPassthruArgs();
    // The tests it spawns must not race the build system's own writes.
    run_mutate.has_side_effects = true;
    mutate_step.dependOn(&run_mutate.step);

    // `zig build check` is the one that matches CI, step for step: formatting, tests, fuzz
    // targets, examples and benchmarks. It exists because the claim used to be attached to
    // the default step, which depends on tests and examples only — so "the checks that CI
    // performs" left out the fuzz targets and the benchmarks, and a change that broke either
    // passed locally and failed on push.
    const check_step = b.step("check", "Everything CI runs: fmt-check, test, fuzz, examples, bench");
    check_step.dependOn(&fmt_check.step);
    check_step.dependOn(test_step);
    check_step.dependOn(fuzz_step);
    check_step.dependOn(examples_step);
    check_step.dependOn(bench_step);

    // The default stays the fast pair rather than becoming `check`: the fuzz targets take
    // minutes, and a default that people avoid running is worse than a default that says
    // what it covers.
    b.getInstallStep().dependOn(test_step);
    b.getInstallStep().dependOn(examples_step);
}

fn addExecutable(
    b: *std.Build,
    name: []const u8,
    dir: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zinet_module: *std.Build.Module,
    backend_module: *std.Build.Module,
) *std.Build.Step.Compile {
    return b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(b.fmt("{s}/{s}.zig", .{ dir, name })),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zinet", .module = zinet_module },
                .{ .name = "backend", .module = backend_module },
            },
        }),
    });
}
