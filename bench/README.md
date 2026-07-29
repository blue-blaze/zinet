# Benchmarks

Both benchmarks run the server and the load generator in one process, with no
external tools, so they are reproducible anywhere Zig builds. The generator
speaks the protocol over raw sockets, keeping the framework out of the
measurement path on the client side.

Every benchmark runs under `std.heap.DebugAllocator`. A leak makes the process
exit non-zero, so a green run is also a memory-safety result.

## Running

```
zig build bench                                   # build both

./zig-out/bin/echo_bench [connections] [payload] [seconds] [loops]
./zig-out/bin/http_bench [connections] [seconds] [loops]
```

Defaults are 32 connections, a 1 KiB payload, 3 seconds and 4 worker loops.

## What is measured

`echo_bench` sends a payload and reads it back, one round trip at a time per
connection. It measures the core path: read, one handler, write, flush.

`http_bench` issues keep-alive `GET` requests and reads the full response. It
adds the HTTP request decoder and response encoder to that path.

Both report the buffer pool hit rate, which is the check that recycling is
actually working: a low rate means inbound buffers are being freed to the
allocator instead of returning to the pool.

## Results

Apple M-series laptop, macOS 26, Zig 0.16.0, `ReleaseFast`, loopback:

| Benchmark | Connections | Payload | Throughput | Mean latency | Pool hits |
|-----------|-------------|---------|------------|--------------|-----------|
| echo      | 8           | 1 KiB   | 35 k round trips/s, 34 MiB/s | 226 µs | 100 % |
| echo      | 64          | 4 KiB   | 41 k round trips/s, 162 MiB/s | 1.5 ms | 99.9 % |
| echo      | 128         | 256 B   | 44 k round trips/s | 2.9 ms | 99.8 % |
| http      | 16          | 17 B    | 42 k req/s | 380 µs | 100 % |
| http      | 64          | 17 B    | 42 k req/s | 1.5 ms | 99.9 % |

A ten second soak at 32 HTTP connections served 421 424 requests with zero
failures and no leaked bytes at exit.

Reading these numbers honestly:

* Throughput plateaus near 42 k operations per second regardless of payload
  size, which says the limit is per-operation cost — syscalls and task
  scheduling — rather than bandwidth. Latency rises with connection count while
  throughput stays flat, the signature of a saturated scheduler.
* The `std.Io.Threaded` backend is what is being measured as much as Zinet:
  every read and write is a blocking syscall on a thread from its pool. An
  evented backend (io_uring, kqueue) is the interesting comparison, and both are
  still proof-of-concept in Zig 0.16. Nothing in Zinet needs to change to adopt
  one; the `Io` instance is injected.
* These are loopback numbers with the load generator competing for the same
  cores, so they understate what a real network deployment would show for
  throughput and overstate latency.
