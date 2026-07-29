# `Allocator.free` rejects the `*[len]T` its own precondition permits

A report prepared against Zig `0.17.0-dev.1476+91a29d707`, written so it can be
checked rather than taken on trust. The suggested fix is in
[`std-allocator-free.patch`](std-allocator-free.patch), and it has been verified
here — see [Verification](#verification).

This is not a Zinet bug and fixing it does not unblock Zinet; it is written down
because it is what currently stops `std.Io.Evented` from compiling on macOS, which
is a claim the README makes and should be able to support.

## Symptom

Freeing a pointer-to-array fails to compile:

```zig
const plain = try gpa.alloc(u8, 8);
gpa.free(plain[0..8]);   // *[8]u8
```

```
lib/std/debug.zig:434:14: error: reached unreachable code
    if (!ok) unreachable; // assertion failure
lib/std/mem.zig:4711:11: note: called at comptime here
    assert(info.size == .slice);
lib/std/mem/Allocator.zig:452:63: note: generic function instantiated here
    const bytes: []u8 = @ptrCast(@constCast(mem.absorbSentinel(memory)));
```

## Root cause

`free` contains a check that deliberately admits a pointer-to-array, and says so
(`lib/std/mem/Allocator.zig:446-452`):

```zig
pub fn free(self: Allocator, memory: anytype) void {
    const slice_info = @typeInfo(@TypeOf(memory)).pointer;
    if (slice_info.size != .slice) {
        // slicing with comptime-known start and end results in *[len]T, which may be free'd
        comptime assert(slice_info.size == .one and @typeInfo(slice_info.child) == .array);
    }
    const bytes: []u8 = @ptrCast(@constCast(mem.absorbSentinel(memory)));
```

The next line then calls `absorbSentinel`, whose return-type helper asserts the
argument is a slice (`lib/std/mem.zig:4709-4712`):

```zig
fn AbsorbSentinelReturnType(comptime Slice: type) type {
    const info = @typeInfo(Slice).pointer;
    assert(info.size == .slice);
```

So the two lines contradict each other, and the case the first one permits is
unreachable in practice.

Where this bites in-tree: `Io/Dispatch.zig:583` frees
`main_loop_stack[0..main_loop_stack_size]`. `main_loop_stack` is a
`[*]align(N) u8`, and slicing a many-pointer with comptime-known bounds yields
`*[N]u8` — exactly the shape the comment describes. That single line is why
`std.Io.Evented` does not compile on macOS.

### The sentinel case needs handling too, not just permitting

`memory[0..]` is not enough on its own. For a `*[N:s]T`, slicing away the sentinel
gives N elements while `allocSentinel` reserved N+1, and `rawFree` is then told
the wrong length. Under `DebugAllocator` that surfaces as:

```
thread 8025923 panic: Invalid free
```

That was observed with a first attempt at this fix, which is why the patch derives
the length from the array's own type info rather than from a re-slice.

## Verification

With the patch applied and nothing else changed, all of these compile and run
clean under `DebugAllocator`, including its leak check:

| Shape | |
|---|---|
| `*[8]u8` | the case `Io/Dispatch.zig` needs |
| `*[5]u32` | element wider than a byte, so `@ptrCast` has to rescale the length |
| `*[16]u8 align(64)` | over-aligned, so the alignment attribute has to survive |
| `*[3:0]u32` | sentinel plus a wide element |
| zero length, both shapes | |
| `[]u8` and `[:0]u8` | slices, to confirm the existing path is untouched |

Without the patch, the same program produces four compile errors.

Beyond the shapes above, the patch was exercised by building and running a network
framework's whole test suite with the patched standard library: 272 tests, all of
them under a leak-checking allocator, unchanged in outcome.

And the line it was written for: with the patch, `std.Io.Evented` — `Io.Dispatch`
on macOS — compiles, initialises and tears down. (Its network operations are a
separate matter: `netListenIp`, `netAccept`, `netConnectIp` and `netSend` are all
wired to stubs returning `error.NetworkDown`, so a socket application still cannot
use it. That is not this bug.)

Environment: Zig `0.17.0-dev.1476+91a29d707`, macOS aarch64.
