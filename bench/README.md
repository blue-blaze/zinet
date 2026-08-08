# Benchmarks

The server under test and the load generator run in **separate processes, on separate `Io`
instances**. That was not always so, and the change moved the numbers: sharing one process
meant the generator's connections competed with the server's for the same scheduler, and at
high connection counts the result was mostly a measurement of the harness. The clearest sign
was that the fiber backend — where a connection is supposed to be cheap — reported *worse*
throughput than thread-per-connection at every size, which is the opposite of what the design
predicts. Isolating the two recovered a third of the fiber backend's throughput at 32
connections and left a smaller difference that is a result rather than an artefact.

Both benchmarks still need no external tools, so they remain reproducible anywhere Zig
builds. The generator speaks the protocol over raw sockets, so the framework is in the
measurement path only on the serving side.

Every benchmark runs under `std.heap.DebugAllocator`. A leak makes the process exit non-zero,
so a green run is also a memory-safety result.

## Running

```
zig build bench                                   # build both
zig build bench -Dio=zio                          # ... against the fiber backend

./zig-out/bin/echo_bench [connections] [payload] [seconds] [loops]
./zig-out/bin/http_bench [connections] [seconds] [loops]
```

Defaults are 32 connections, a 1 KiB payload, 3 seconds and 4 worker loops. In that form the
benchmark spawns the server from its own executable and loads it; the roles can also be run
by hand, which is what a two-machine or a mixed-backend measurement needs:

```
./zig-out/bin/http_bench server <port> <seconds> <loops>
./zig-out/bin/http_bench client <port> <connections> <seconds>
```

Running the roles from two *differently built* binaries is how the table below attributes a
cost to one side or the other — a fiber server against a threaded client, and the reverse.

## What is measured

`echo_bench` sends a payload and reads it back, one round trip at a time per
connection. It measures the core path: read, one handler, write, flush.

`http_bench` issues keep-alive `GET` requests and reads the full response. It
adds the HTTP request decoder and response encoder to that path.

Both report the buffer pool hit rate, which is the check that recycling is
actually working: a low rate means inbound buffers are being freed to the
allocator instead of returning to the pool.

## Results

Apple M-series laptop, macOS 26, Zig 0.17.0-dev.1476, `ReleaseFast`, loopback, four worker
loops, three-second runs, server and generator in separate processes on the same machine.

**HTTP, both sides on `std.Io.Threaded`:**

| Connections | Throughput | Mean latency | Worst latency | Accepted / rejected |
|---|---|---|---|---|
| 8    | 38.7 k req/s | 206 µs | 3.0 ms | 9 / 0 |
| 64   | 41.2 k req/s | 1.5 ms | 7.6 ms | 65 / 0 |
| 512  | 38.8 k req/s | 13.0 ms | 49.9 ms | 513 / 0 |
| 1024 | 36.9 k req/s | — | 71 ms | 1024 / 0 |
| 2048 | 24.6 k req/s | — | 141 ms | 2048 / 0 |

**HTTP, the fiber backend (`-Dio=zio`), 512 connections, by which side runs on which:**

| Server | Generator | Throughput | Mean latency | Worst latency |
|---|---|---|---|---|
| threaded | threaded | 39.1 k req/s | 12.8 ms | 34 ms |
| threaded | fiber | 42.3 k req/s | 12.0 ms | 284 ms |
| fiber | threaded | 31.2 k req/s | 16.1 ms | **2742 ms** |

**Echo, both sides threaded**, 32 connections and a 1 KiB payload: 45.4 k round trips/s,
44.3 MiB/s each way, 704 µs mean, 4.6 ms worst, pool hit rate 100 %.

A ten second soak at 32 HTTP connections served 421 424 requests with zero failures and no
leaked bytes at exit.

Reading these numbers honestly:

* **Throughput is flat in the number of connections** — about 39–41 k req/s from 8 to 512 on
  threads — so the limit is per-operation cost, syscalls and scheduling, not bandwidth and not
  concurrency. Latency rises while throughput holds, which is what a saturated service looks
  like when it is not losing work.
* **The threaded backend does not fall over where the design says it should.** Two tasks per
  connection means 2048 connections is 4096 tasks, and that ran with **zero refusals** and a
  graceful throughput decline. The framework's own documentation has argued that the
  concurrency budget is its scarcest resource; on this platform, at these sizes, it was not
  the binding constraint. That does not make a bound unnecessary — a server that accepts 2048
  connections because nobody told it not to is still missing a limit — but it does mean the
  cost of threads here is throughput, not refusal.
* **The fiber backend is currently slower, and its tail is much worse.** Pairing a fiber
  server with a threaded generator — which the split roles exist to make possible — puts the
  cost on the server side: ~20 % less throughput and a **reproducible multi-second worst
  case** (2.74 s, 2.72 s, 2.78 s across three runs) where the threaded server stays under
  50 ms. A fiber generator against a threaded server shows a milder version of the same tail
  (284 ms), so the scheduler, not this framework's structure, is what is being observed.
* **This is a statement about one third-party fiber runtime on one operating system**, not
  about fibers. zio's `zig-0.17` branch on macOS is what was measured; Linux with io_uring is
  the comparison that has not been made, and the one that would matter most. Nothing in
  `src/` changes between the two backends, which is the point of injecting `Io` — and is also
  why this table can exist at all.
* These are loopback numbers with both processes competing for the same cores, so they
  understate throughput and overstate latency relative to a real deployment.
