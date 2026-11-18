const std = @import("std");
const mqtt = @import("netz").mqtt;
const Options = @import("options.zig").Options;

pub const topic = "bench/session-deadline";

pub const Peer = struct {
    server: *mqtt.runtime.Server,
    options: Options,
    payload: []const u8,
    expected_id: std.atomic.Value(u16) = .init(0),
    received: usize = 0,
    terminal: usize = 0,
    released: usize = 0,
    disconnected: bool = false,

    pub fn run(self: *Peer) !void {
        self.serve() catch |err| {
            std.debug.print("MQTT deadline benchmark peer failed: {s}\n", .{@errorName(err)});
            return err;
        };
    }

    fn serve(self: *Peer) !void {
        const alias = self.options.protocol == .v5 and self.options.topic_alias;
        var accepted = try self.server.acceptWithTimeout(.{ .protocol = self.options.protocol, .topic_alias_maximum = if (alias) 16 else 0 }, .fromSeconds(5));
        defer accepted.deinit(self.server.allocator);
        const connection = &accepted.connection;
        for (0..self.options.total()) |_| {
            var publish = try connection.readPublish();
            defer publish.deinit(self.server.allocator);
            const topic_alias = mqtt.topicAlias(publish.publish.properties);
            if (!std.mem.eql(u8, publish.publish.topic, topic) or
                !std.mem.eql(u8, publish.publish.payload, self.payload) or
                publish.publish.qos != self.options.qos or
                publish.publish.packet_id != self.expected_id.load(.acquire) or
                publish.publish.dup or publish.publish.retain or
                publish.publish.properties.len != @intFromBool(alias) or
                (alias and (topic_alias == null or topic_alias.? == 0 or topic_alias.? > 16)))
            {
                std.debug.print("invalid publish: index={d} topic={s} payload_equal={} qos={d} id={?d} expected_id={d} dup={} retain={} properties={d}\n", .{
                    self.received,                     publish.publish.topic,     std.mem.eql(u8, publish.publish.payload, self.payload),
                    @intFromEnum(publish.publish.qos), publish.publish.packet_id, self.expected_id.load(.acquire),
                    publish.publish.dup,               publish.publish.retain,    publish.publish.properties.len,
                });
                return error.InvalidBenchmarkPublish;
            }
            self.received += 1;
            const id = publish.publish.packet_id.?;
            switch (self.options.qos) {
                .at_least_once => try connection.writePubAck(id, 0),
                .exactly_once => {
                    try connection.writePubRec(id, 0);
                    var release = try connection.readPubRel();
                    defer release.deinit(self.server.allocator);
                    if (release.ack.packet_id != id or release.ack.reason_code != 0) return error.InvalidBenchmarkRelease;
                    self.released += 1;
                    try connection.writePubComp(id, 0);
                },
                .at_most_once => unreachable,
            }
            self.terminal += 1;
        }
        var disconnect = try connection.readDisconnect();
        defer disconnect.deinit(self.server.allocator);
        if (disconnect.disconnect.reason_code != 0) return error.InvalidBenchmarkDisconnect;
        self.disconnected = true;
    }
};
