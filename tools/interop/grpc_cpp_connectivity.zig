//! Exercise real channel transitions independently from RPC payload fixtures.
const std = @import("std");
const netz = @import("netz");
const Watch = netz.grpc.ChannelConnectivityWatch;
const Snapshot = netz.grpc.ChannelConnectivitySnapshot;

pub fn warm(client: *netz.grpc.runtime.Channel, io: std.Io) !Watch {
    var transitions = client.watchConnectivity();
    defer transitions.deinit();
    var readiness = client.watchConnectivity();
    defer readiness.deinit();
    if (transitions.snapshot().state != .idle) return error.UnexpectedConnectivity;
    const Await = struct {
        fn change(watch: *Watch) !Snapshot {
            return watch.nextWithTimeout(.fromSeconds(5));
        }
        fn ready(watch: *Watch) !void {
            return watch.waitForReadyWithTimeout(.fromSeconds(5));
        }
    };
    var change = io.async(Await.change, .{&transitions});
    defer _ = change.cancel(io) catch {};
    var ready = io.async(Await.ready, .{&readiness});
    defer ready.cancel(io) catch {};
    _ = try client.warmWithTimeout(.fromSeconds(5));
    const first = try change.await(io);
    if (first.generation == 0 or (first.state != .connecting and first.state != .ready)) return error.UnexpectedConnectivity;
    try ready.await(io);
    if (readiness.snapshot().state != .ready) return error.UnexpectedConnectivity;
    return client.watchConnectivity();
}

pub fn shutdown(watch: *Watch) !void {
    const terminal = try watch.nextWithTimeout(.zero);
    if (terminal.state != .shutdown) return error.UnexpectedConnectivity;
    if (watch.waitForReadyWithTimeout(.zero)) |_| return error.UnexpectedConnectivity else |err| {
        if (err != error.ChannelShutdown) return err;
    }
}
