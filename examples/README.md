# Examples

Each example is a complete, runnable server: it parses a port, installs a
`SIGINT`/`SIGTERM` handler, serves until interrupted, then shuts down
gracefully. All of them allocate through `std.heap.DebugAllocator`, so a clean
exit also proves nothing leaked.

| Example | Run | Try it with |
|---|---|---|
| [echo.zig](echo.zig) | `zig build run-echo -- 8007` | `nc localhost 8007` |
| [line_echo.zig](line_echo.zig) | `zig build run-line-echo -- 8008` | `nc localhost 8008`, then type lines; `quit` disconnects |
| [http_server.zig](http_server.zig) | `zig build run-http-server -- 8080` | `curl -v http://localhost:8080/echo -d hi` |
| [ws_echo.zig](ws_echo.zig) | `zig build run-ws-echo -- 8090` | `websocat ws://localhost:8090/` |

What each one demonstrates:

* **echo** — the smallest possible pipeline: one handler that writes back what
  it reads. Also shows a `BufferPool` shared by every connection.
* **line_echo** — a framing decoder in front of the application handler, so the
  handler only ever sees whole lines however the bytes arrived.
* **http_server** — the HTTP/1.1 codec with three routes, including a chunked
  streaming response, plus mapping decode failures onto status codes.
* **ws_echo** — a protocol upgrade at run time: the pipeline starts out speaking
  HTTP and rewrites itself to speak WebSocket once the handshake succeeds. Plain
  HTTP requests on the same port still get an HTTP response.

If `nc` seems to swallow the reply, it is closing as soon as its stdin ends. Use
an interactive session, or bash's own TCP support:

```bash
exec 3<>/dev/tcp/127.0.0.1/8008
printf 'hello\n' >&3
head -1 <&3
exec 3<&-; exec 3>&-
```
