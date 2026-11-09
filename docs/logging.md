# Logging

netz uses kron directly. Library code calls the process-wide
`kron.info`/`kron.warn`/`kron.err`/`kron.debug`/`kron.trace` functions with its
own scope; the application creates one `kron.Logging` and installs it at its
entry point. This is the Zig equivalent of Rust `tracing`: libraries only emit
events, the execution layer installs the subscriber once.

netz does not use `std.log`, does not ship its own logger facade, and does not
reimplement kron's level filtering or convenience methods.

## Execution-layer setup

```zig
const std = @import("std");
const kron = @import("kron");

pub fn main(init: std.process.Init) !void {
    const logging = try kron.Logging.create(init.gpa, init.io, .{
        .outputs = &.{.{
            .name = "netz",
            .target = .stderr,
            .mode = .asynchronous,
            .format = .json,
            .filter = "warn",
            .queue = .{ .memory = .{
                .capacity = 1024,
                .max_record_bytes = 4096,
            } },
            .overflow = .drop_newest,
        }},
    });
    defer logging.destroy();

    kron.setGlobalLogging(logging);
    defer kron.clearGlobalLogging();

    kron.info("netz", "started", .{ .version = "1.0" });
    kron.warn("netz.http1", "listener failed", .{ .err = "ConnectionRefused" });

    try logging.flush();
    try logging.shutdown();
}
```

`setGlobalLogging` must run before workers start. `clearGlobalLogging` must run
before `logging.destroy`; the `defer` order above does that. The global slot is
a convenience facade, not a replacement for kron's explicit `Logging`
lifecycle.

## Library-side use

The scope is chosen at each call site, so independent modules do not compete for
one process-wide scope:

```zig
const kron = @import("kron");

kron.warn("netz.http1", "handshake failed", .{ .err = @errorName(err) });
kron.info("netz.quic", "listener started", .{ .address = address });
```

If no global owner is installed, these calls are no-ops. Filtering, sampling,
formatting, and queueing are kron's own implementation; callers do not need to
check a level first.

For advanced kron APIs, use `kron.globalLogging()` or derive a scoped logger
with `kron.global.scoped(scope)`:

```zig
if (kron.global.scoped("netz.quic")) |log| {
    const traced = log.withTrace(trace_context);
    traced.debug("state", .{ .peer = peer });
    _ = try log.tryEmit(.warn, "queue pressure", .{ .pending = pending });
}
```

`kron.global.enabled(level, scope)` and kron's `Logger.enabled(level)` remain
available for call sites whose field values are expensive to construct.
`kron.logAt`/`kron.warnAt`/`kron.infoAt` and the other `*At` variants forward an
explicit source location when needed.

## Overhead rules

- Do not log per packet, per request, or per stream. Use the existing stats,
  metrics, qlog, and error returns for those paths.
- `kron.info`/`warn`/`err` add one global load and a null check, then derive a
  zero-allocation scoped frontend. Once an owner is installed, kron performs its
  normal level/sampling/filter checks and submits to a bounded queue.
- Use the bounded asynchronous Memory queue with `drop_newest` for servers.
  Logging must not become network backpressure.
- Keep the route filter at `warn` or `err` in production; `debug`/`trace` are
  for opt-in diagnostics.
- For repeated failures, use kron's route sampling or an application-level rate
  limit instead of one record per connection.

## HTTP/1 serve errors

`http1.runtime.logErrorObserver()` forwards serve-loop failures through
`kron.warn("netz.http1", ...)`:

```zig
const options = http1.runtime.ServeUntilOptions{
    .shutdown = &shutdown,
    .error_observer = http1.runtime.logErrorObserver(),
};
```

Without an installed global owner the observer is a no-op.
