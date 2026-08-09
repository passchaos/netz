//! Streaming qlog 0.4 JSON-SEQ encoder.
//!
//! Records use RFC 7464 framing (`RS JSON LF`) and are written directly to an
//! `std.Io.Writer`; packet frame lists and strings are never assembled in a
//! fixed temporary buffer. This makes large ACK range lists lossless and keeps
//! memory use independent of event size.

const std = @import("std");
const events = @import("events.zig");

const json_sequence_record_separator: u8 = 0x1e;

pub const Error = std.Io.Writer.Error || error{
    TimestampRegressed,
    TimestampBeforeReference,
    InvalidUtf8,
    InvalidAckRange,
};

pub const TimeFormat = enum {
    relative,
    absolute,
};

pub const Options = struct {
    time_format: TimeFormat = .relative,
    reference_time_ns: u64 = 0,
};

pub const Trace = struct {
    writer: *std.Io.Writer,
    options: Options,
    last_time_ns: ?u64 = null,

    pub fn init(writer: *std.Io.Writer, options: Options) Trace {
        return .{ .writer = writer, .options = options };
    }

    /// Write qlog's JSON-SEQ header record. The group ID is emitted as
    /// lowercase hexadecimal without allocating a temporary string.
    pub fn writeHeader(
        self: *Trace,
        vantage_point: events.VantagePoint,
        group_id: []const u8,
    ) std.Io.Writer.Error!void {
        try beginRecord(self.writer);
        var json: std.json.Stringify = .{
            .writer = self.writer,
            .options = .{},
        };
        try json.beginObject();
        try field(&json, "qlog_version", "0.4");
        try field(&json, "qlog_format", "JSON-SEQ");
        try field(&json, "serialization_format", "application/qlog+json-seq");
        try json.objectField("trace");
        try json.beginObject();
        try json.objectField("vantage_point");
        try json.beginObject();
        try field(&json, "type", vantagePointName(vantage_point));
        try json.endObject();
        try json.objectField("common_fields");
        try json.beginObject();
        try json.objectField("group_id");
        try writeHexString(&json, group_id);
        try json.objectField("protocol_type");
        try json.beginArray();
        try json.write("QUIC");
        try json.endArray();
        try field(&json, "time_format", timeFormatName(self.options.time_format));
        if (self.options.time_format == .relative) {
            try field(
                &json,
                "reference_time",
                nsToMilliseconds(self.options.reference_time_ns),
            );
        }
        try json.endObject();
        try json.endObject();
        try json.endObject();
        try endRecord(self.writer);
    }

    /// Write one timestamped event. Timestamps must be monotonic within a
    /// trace; rejecting regressions avoids qlog timelines whose ordering
    /// contradicts the serialized record order.
    pub fn writeEvent(
        self: *Trace,
        now_ns: u64,
        event: events.Event,
    ) Error!void {
        if (self.last_time_ns) |last| {
            if (now_ns < last) return error.TimestampRegressed;
        }
        if (self.options.time_format == .relative and
            now_ns < self.options.reference_time_ns)
        {
            return error.TimestampBeforeReference;
        }
        try validateEvent(event);

        try beginRecord(self.writer);
        var json: std.json.Stringify = .{
            .writer = self.writer,
            .options = .{},
        };
        try json.beginObject();
        try json.objectField("time");
        try json.write(timeMilliseconds(self.options, now_ns));
        try field(&json, "name", event.qlogName());
        try json.objectField("data");
        try writeEventData(&json, event);
        try json.endObject();
        try endRecord(self.writer);
        self.last_time_ns = now_ns;
    }
};

fn beginRecord(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeByte(json_sequence_record_separator);
}

fn endRecord(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeByte('\n');
}

fn field(json: *std.json.Stringify, name: []const u8, value: anytype) std.Io.Writer.Error!void {
    try json.objectField(name);
    try json.write(value);
}

fn writeEventData(json: *std.json.Stringify, event: events.Event) Error!void {
    try json.beginObject();
    switch (event) {
        .connection_started => |started| {
            if (started.src_ip) |value| try field(json, "src_ip", value);
            if (started.src_port) |value| try field(json, "src_port", value);
            if (started.dst_ip) |value| try field(json, "dst_ip", value);
            if (started.dst_port) |value| try field(json, "dst_port", value);
        },
        .connection_closed => |closed| {
            try field(json, "trigger", closed.trigger);
            if (closed.owner) |value| try field(json, "owner", ownerName(value));
            switch (closed.error_space) {
                .transport => try field(json, "connection_code", closed.error_code),
                .application => try field(json, "application_code", closed.error_code),
            }
            if (closed.reason.len != 0) try field(json, "reason", closed.reason);
        },
        .parameters_set => |parameters| {
            try field(json, "owner", ownerName(parameters.owner));
            if (parameters.max_idle_timeout_ms) |value| try field(json, "max_idle_timeout", value);
            if (parameters.max_udp_payload_size) |value| try field(json, "max_udp_payload_size", value);
            if (parameters.initial_max_data) |value| try field(json, "initial_max_data", value);
            if (parameters.initial_max_streams_bidi) |value| try field(json, "initial_max_streams_bidi", value);
            if (parameters.initial_max_streams_uni) |value| try field(json, "initial_max_streams_uni", value);
            if (parameters.disable_active_migration) |value| try field(json, "disable_active_migration", value);
        },
        .packet_sent => |packet| try writePacket(json, packet),
        .packet_received => |packet| try writePacket(json, packet),
        .packet_dropped => |dropped| {
            if (dropped.packet_type) |value| {
                try json.objectField("header");
                try json.beginObject();
                try field(json, "packet_type", value.qlogName());
                try json.endObject();
            }
            try field(json, "trigger", dropped.trigger);
            if (dropped.raw_length) |value| {
                try json.objectField("raw");
                try json.beginObject();
                try field(json, "length", value);
                try json.endObject();
            }
        },
        .metrics_updated => |metrics| try writeMetrics(json, metrics),
        .congestion_state_updated => |state| {
            if (state.old) |value| try field(json, "old", value);
            try field(json, "new", state.new);
            if (state.trigger) |value| try field(json, "trigger", value);
        },
        .packet_lost => |lost| {
            try json.objectField("header");
            try json.beginObject();
            try field(json, "packet_type", lost.packet_type.qlogName());
            try field(json, "packet_number", lost.packet_number);
            try json.endObject();
            try field(json, "trigger", lost.trigger);
        },
        .key_updated => |key| {
            try field(json, "trigger", key.trigger);
            try field(json, "key_type", key.key_type);
            if (key.generation) |value| try field(json, "generation", value);
        },
        .key_discarded => |key| {
            try field(json, "key_type", key.key_type);
            if (key.generation) |value| try field(json, "generation", value);
        },
    }
    try json.endObject();
}

fn writePacket(json: *std.json.Stringify, packet: events.Packet) Error!void {
    try json.objectField("header");
    try json.beginObject();
    try field(json, "packet_type", packet.packet_type.qlogName());
    if (packet.packet_number) |value| try field(json, "packet_number", value);
    try json.endObject();
    try json.objectField("raw");
    try json.beginObject();
    try field(json, "length", packet.length);
    try json.endObject();
    try json.objectField("frames");
    try json.beginArray();
    for (packet.frames) |frame_view| try writeFrame(json, frame_view);
    try json.endArray();
}

fn writeFrame(json: *std.json.Stringify, frame_view: events.Frame) Error!void {
    try json.beginObject();
    switch (frame_view) {
        .padding => |padding| {
            try field(json, "frame_type", "padding");
            try field(json, "length", padding.length);
        },
        .ping => try field(json, "frame_type", "ping"),
        .ack => |ack| try writeAck(json, ack),
        .reset_stream => |reset| {
            try field(json, "frame_type", "reset_stream");
            try field(json, "stream_id", reset.stream_id);
            try field(json, "error_code", reset.error_code);
            try field(json, "final_size", reset.final_size);
        },
        .stop_sending => |stop| {
            try field(json, "frame_type", "stop_sending");
            try field(json, "stream_id", stop.stream_id);
            try field(json, "error_code", stop.error_code);
        },
        .new_token => |token| {
            try field(json, "frame_type", "new_token");
            try field(json, "length", token.length);
        },
        .crypto => |crypto| {
            try field(json, "frame_type", "crypto");
            try field(json, "offset", crypto.offset);
            try field(json, "length", crypto.length);
        },
        .stream => |stream| {
            try field(json, "frame_type", "stream");
            try field(json, "stream_id", stream.stream_id);
            try field(json, "offset", stream.offset);
            try field(json, "length", stream.length);
            try field(json, "fin", stream.fin);
        },
        .max_data => |max_data| {
            try field(json, "frame_type", "max_data");
            try field(json, "maximum", max_data.maximum);
        },
        .max_stream_data => |max_data| {
            try field(json, "frame_type", "max_stream_data");
            try field(json, "stream_id", max_data.stream_id);
            try field(json, "maximum", max_data.maximum);
        },
        .max_streams => |max_streams| {
            try field(json, "frame_type", "max_streams");
            try field(json, "stream_type", streamTypeName(max_streams.stream_type));
            try field(json, "maximum", max_streams.maximum);
        },
        .data_blocked => |blocked| {
            try field(json, "frame_type", "data_blocked");
            try field(json, "limit", blocked.limit);
        },
        .stream_data_blocked => |blocked| {
            try field(json, "frame_type", "stream_data_blocked");
            try field(json, "stream_id", blocked.stream_id);
            try field(json, "limit", blocked.limit);
        },
        .streams_blocked => |blocked| {
            try field(json, "frame_type", "streams_blocked");
            try field(json, "stream_type", streamTypeName(blocked.stream_type));
            try field(json, "limit", blocked.limit);
        },
        .new_connection_id => |connection_id| {
            try field(json, "frame_type", "new_connection_id");
            try field(json, "sequence_number", connection_id.sequence_number);
            try field(json, "retire_prior_to", connection_id.retire_prior_to);
            try field(json, "connection_id_length", connection_id.connection_id_length);
        },
        .retire_connection_id => |connection_id| {
            try field(json, "frame_type", "retire_connection_id");
            try field(json, "sequence_number", connection_id.sequence_number);
        },
        .path_challenge => try field(json, "frame_type", "path_challenge"),
        .path_response => try field(json, "frame_type", "path_response"),
        .connection_close => |close| {
            try field(json, "frame_type", "connection_close");
            try field(json, "error_space", errorSpaceName(close.error_space));
            try field(json, "error_code", close.error_code);
            if (close.triggering_frame_type) |value| try field(json, "trigger_frame_type", value);
            if (close.reason.len != 0) try field(json, "reason", close.reason);
        },
        .handshake_done => try field(json, "frame_type", "handshake_done"),
        .immediate_ack => try field(json, "frame_type", "immediate_ack"),
        .datagram => |datagram| {
            try field(json, "frame_type", "datagram");
            try field(json, "length", datagram.length);
        },
        .ack_frequency => |frequency| {
            try field(json, "frame_type", "ack_frequency");
            try field(json, "sequence_number", frequency.sequence_number);
            try field(json, "packet_tolerance", frequency.packet_tolerance);
            try field(json, "max_ack_delay", frequency.max_ack_delay);
            try field(json, "reordering_threshold", frequency.reordering_threshold);
        },
    }
    try json.endObject();
}

fn writeAck(json: *std.json.Stringify, ack: events.Ack) Error!void {
    try field(json, "frame_type", "ack");
    try field(json, "ack_delay", ack.ack_delay_ms);
    try json.objectField("acked_ranges");
    try json.beginArray();

    var smallest = ack.largest_acknowledged - ack.first_ack_range;
    try writeRange(json, smallest, ack.largest_acknowledged);
    for (ack.ranges) |range| {
        const largest = smallest - (range.gap + 2);
        smallest = largest - range.ack_range_length;
        try writeRange(json, smallest, largest);
    }
    try json.endArray();
    if (ack.ecn_counts) |ecn| {
        try field(json, "ect0", ecn.ect0);
        try field(json, "ect1", ecn.ect1);
        try field(json, "ce", ecn.ce);
    }
}

fn writeRange(json: *std.json.Stringify, smallest: u64, largest: u64) std.Io.Writer.Error!void {
    try json.beginArray();
    try json.write(smallest);
    try json.write(largest);
    try json.endArray();
}

fn writeMetrics(json: *std.json.Stringify, metrics: events.RecoveryMetrics) std.Io.Writer.Error!void {
    if (metrics.min_rtt_ns) |value| try field(json, "min_rtt", nsToMilliseconds(value));
    if (metrics.smoothed_rtt_ns) |value| try field(json, "smoothed_rtt", nsToMilliseconds(value));
    if (metrics.latest_rtt_ns) |value| try field(json, "latest_rtt", nsToMilliseconds(value));
    if (metrics.rtt_variance_ns) |value| try field(json, "rtt_variance", nsToMilliseconds(value));
    try field(json, "congestion_window", metrics.congestion_window);
    try field(json, "bytes_in_flight", metrics.bytes_in_flight);
    if (metrics.pacing_rate_bps) |value| try field(json, "pacing_rate", value);
}

fn writeHexString(json: *std.json.Stringify, bytes: []const u8) std.Io.Writer.Error!void {
    const hex = "0123456789abcdef";
    try json.beginWriteRaw();
    try json.writer.writeByte('"');
    for (bytes) |byte| {
        try json.writer.writeByte(hex[byte >> 4]);
        try json.writer.writeByte(hex[byte & 0x0f]);
    }
    try json.writer.writeByte('"');
    json.endWriteRaw();
}

/// Validate all borrowed text and arithmetic before emitting a JSON-SEQ record.
/// Input errors therefore never leave a partial record in the sink.
fn validateEvent(event: events.Event) error{ InvalidUtf8, InvalidAckRange }!void {
    switch (event) {
        .connection_started => |started| {
            if (started.src_ip) |value| try validateString(value);
            if (started.dst_ip) |value| try validateString(value);
        },
        .connection_closed => |closed| {
            try validateString(closed.trigger);
            try validateString(closed.reason);
        },
        .parameters_set, .metrics_updated => {},
        .packet_sent => |packet| try validatePacket(packet),
        .packet_received => |packet| try validatePacket(packet),
        .packet_dropped => |dropped| try validateString(dropped.trigger),
        .congestion_state_updated => |state| {
            if (state.old) |value| try validateString(value);
            try validateString(state.new);
            if (state.trigger) |value| try validateString(value);
        },
        .packet_lost => |lost| try validateString(lost.trigger),
        .key_updated => |key| {
            try validateString(key.trigger);
            try validateString(key.key_type);
        },
        .key_discarded => |key| try validateString(key.key_type),
    }
}

fn validatePacket(packet: events.Packet) error{ InvalidUtf8, InvalidAckRange }!void {
    for (packet.frames) |frame_view| switch (frame_view) {
        .ack => |ack| try validateAck(ack),
        .connection_close => |close| try validateString(close.reason),
        else => {},
    };
}

fn validateAck(ack: events.Ack) error{InvalidAckRange}!void {
    if (ack.first_ack_range > ack.largest_acknowledged) {
        return error.InvalidAckRange;
    }
    var smallest = ack.largest_acknowledged - ack.first_ack_range;
    for (ack.ranges) |range| {
        const gap_distance = std.math.add(u64, range.gap, 2) catch
            return error.InvalidAckRange;
        if (gap_distance > smallest) return error.InvalidAckRange;
        const largest = smallest - gap_distance;
        if (range.ack_range_length > largest) return error.InvalidAckRange;
        smallest = largest - range.ack_range_length;
    }
}

fn validateString(value: []const u8) error{InvalidUtf8}!void {
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
}

fn timeMilliseconds(options: Options, now_ns: u64) f64 {
    return switch (options.time_format) {
        .relative => nsToMilliseconds(now_ns - options.reference_time_ns),
        .absolute => nsToMilliseconds(now_ns),
    };
}

fn nsToMilliseconds(value: u64) f64 {
    return @as(f64, @floatFromInt(value)) / @as(f64, std.time.ns_per_ms);
}

fn vantagePointName(value: events.VantagePoint) []const u8 {
    return switch (value) {
        .client => "client",
        .server => "server",
        .network => "network",
        .unknown => "unknown",
    };
}

fn timeFormatName(value: TimeFormat) []const u8 {
    return switch (value) {
        .relative => "relative",
        .absolute => "absolute",
    };
}

fn errorSpaceName(value: events.ErrorSpace) []const u8 {
    return switch (value) {
        .transport => "transport",
        .application => "application",
    };
}

fn ownerName(value: events.Owner) []const u8 {
    return switch (value) {
        .local => "local",
        .remote => "remote",
    };
}

fn streamTypeName(value: events.StreamType) []const u8 {
    return switch (value) {
        .bidirectional => "bidirectional",
        .unidirectional => "unidirectional",
    };
}
