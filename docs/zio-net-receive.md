# `net_receive` panics on a connected socket

A report prepared against [zio](https://github.com/lalinsky/zio) v0.16.0, written
so it can be checked rather than taken on trust. The fix appears to be one line,
and that line has been verified here — see [Verification](#verification).

## Symptom

Any `net_receive` on a **stream** socket panics:

```
thread 6298162 panic: reached unreachable code
zio/src/io.zig:1830:17: in zioIpToStdIo
        .from = zioIpToStdIo(storage.ip),
```

Deterministic in `Debug` and `ReleaseSafe`. In `ReleaseFast` there is no panic and
the caller silently receives a garbage peer address, which is the worse outcome.

A minimal reproducer is [`zio-net-receive-repro.zig`](zio-net-receive-repro.zig).

## Root cause

`recvmsg` fills `msg_name` only when the socket is *unconnected*. On a connected
socket the kernel sets `msg_namelen = 0` and leaves the buffer untouched.

`netReceiveImpl` declares that buffer `undefined`, passes `&addr_len` so the
kernel can report how much it wrote, then converts the buffer unconditionally and
discards `addr_len` (`src/io.zig:2332-2347`):

```zig
var storage: zio_net.Address = undefined;
var addr_len: os_net.socklen_t = @sizeOf(zio_net.Address);
...
message.* = .{
    .from = zioIpToStdIo(storage.ip),   // storage was never written
```

So `addr.any.family` is whatever was on the stack, and `zioIpToStdIo` reaches its
`else => unreachable` (`src/io.zig:1830`).

### Why this is zio-specific rather than inherent

`std.Io.Threaded` does the *same thing* with the storage — `var storage:
PosixAddress = undefined` at `std/Io/Threaded.zig:12897` — and is fine, because
its conversion defines the case away instead of asserting it cannot happen
(`std/Io/Threaded.zig:13977-13984`):

```zig
pub fn addressFromPosix(posix_address: *const PosixAddress) IpAddress {
    return switch (posix_address.any.family) {
        posix.AF.INET => ...,
        posix.AF.INET6 => ...,
        else => .{ .ip4 = .loopback(0) },
    };
}
```

An `Io` implementation that panics where the standard one returns a placeholder is
observably different through the same interface, which is what makes this a defect
rather than a choice.

### Two call sites, so the fix belongs in the conversion

`zioIpToStdIo` is reached from the receive path twice:

| Site | Path |
|---|---|
| `src/io.zig:2347` | `netReceiveImpl` — a direct `net_receive` |
| `src/io.zig:844` | `extractBatchResult` — `net_receive` inside a `Batch`, i.e. what `Io.Select` builds |

The second one matters because it is platform-independent and is on the path an
application takes when racing a receive against a timer — a natural way to give a
socket read a deadline. Guarding only `netReceiveImpl` would leave it broken.

Worth noting: zio's own `accept` path already does the defended thing, with a
comment reasoning about exactly this (`src/io.zig:1948-1953`):

```zig
.address = switch (peer_addr.any.family) {
    os_net.AF.INET, os_net.AF.INET6 => zioIpToStdIo(peer_addr.ip),
    // std.Io.net.Socket.address is an IpAddress; use an IPv4 loopback
    // placeholder for Unix peers, matching std.Io.UnixAddress.listen.
    else => .{ .ip4 = .loopback(0) },
},
```

So this is consistency with zio's own established handling, not a new pattern.

## Suggested fix

```diff
--- a/src/io.zig
+++ b/src/io.zig
@@ fn zioIpToStdIo
             .flow = addr.in6.flowinfo,
             .interface = .{ .index = addr.in6.scope_id },
         } },
-        else => unreachable,
+        // Matches std.Io.Threaded's addressFromPosix: recvmsg leaves msg_name
+        // untouched on a connected socket, so the family read back here can be
+        // whatever was on the stack.
+        else => .{ .ip4 = .loopback(0) },
     };
 }
```

Checking `addr_len == 0` in `netReceiveImpl` would be more precise about *why*
there is no address, and is worth doing as well; on its own it would not cover
`extractBatchResult`.

## Verification

Applied to a local v0.16.0 checkout, with no other change:

* Zinet — an event-driven networking framework whose connections put a deadline on
  every read, which is what makes `net_receive` load bearing for it — goes from 4
  skipped tests to **272/272 passing** on the zio backend, three consecutive runs.
* The two examples that panicked before now complete: a WebSocket client
  exchanging messages and a closing handshake with the third-party Python
  `websockets` library, and an HTTPS client fetching from OpenSSL's `s_server`
  (`status 200, 2048 bytes of body`).
* Reverting the one line restores the panic, so the line is the cause and not a
  coincidence.

Environment: Zig 0.16.0, macOS aarch64 (kqueue backend).

The patch is next to this file as
[`zio-net-receive.patch`](zio-net-receive.patch). It applies cleanly to tag
v0.16.0 and to the `zig-0.17` branch at commit `407427a`, which is what Zinet
depends on now; there the `unreachable` sits at `src/io.zig:1871`. Still present on
`main` as of commit `3566a3a`, and on all fifteen remote branches, so this is not
a report about something already fixed.

## Why this operation matters

`std.Io.Operation` is a closed union, and of its variants only
`file_read_streaming`, `file_write_streaming`, `device_io_control` and
`net_receive` apply to a socket. `net_receive` is therefore the **only** primitive
in the interface that can put a deadline on a socket read. Any framework that
wants a bounded read — for idle timeouts, for keepalives, for running queued work
between reads — has to go through it, on a stream socket, which is precisely the
case that panics.
