#!/usr/bin/env bash
set -euo pipefail

emitter=${1:?netz QPACK emitter executable path}
quic_zig_root=${QUIC_ZIG_ROOT:-"$HOME/Work/quic-zig"}

if [[ ! -f "$quic_zig_root/src/h3/qpack.zig" ]]; then
  echo "quic-zig checkout not found under $quic_zig_root" >&2
  exit 127
fi

work=$(mktemp -d)
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/quic_zig_qpack_peer.zig" <<'EOF'
const std = @import("std");
const qpack = @import("qpack");

pub fn main(init: std.process.Init) !void {
    var reader_buffer: [4096]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(
        init.io,
        &reader_buffer,
    );
    const bytes = try reader.interface.allocRemaining(
        init.gpa,
        .limited(64 * 1024),
    );
    defer init.gpa.free(bytes);

    var decoder: qpack.QpackDecoder = .{};
    decoder.setCapacity(256);
    if (bytes.len < 4) return error.InvalidInput;
    const instruction_len = std.mem.readInt(u32, bytes[0..4], .big);
    const split = std.math.add(usize, 4, instruction_len) catch
        return error.InvalidInput;
    if (split > bytes.len) return error.InvalidInput;
    try decoder.processEncoderInstruction(bytes[4..split]);

    var fields: [16]qpack.Header = undefined;
    const count = try decoder.decode(bytes[split..], &fields, 4);
    if (count != 2 or
        !std.mem.eql(u8, fields[0].name, "x-peer") or
        !std.mem.eql(u8, fields[0].value, "speculative-value") or
        !std.mem.eql(u8, fields[1].name, "x-peer") or
        !std.mem.eql(u8, fields[1].value, "literal-tail"))
    {
        return error.UnexpectedFields;
    }
    if (decoder.getInstructions().len == 0) {
        return error.MissingSectionAcknowledgment;
    }
}
EOF

zig build-exe --dep qpack \
  -Mroot="$work/quic_zig_qpack_peer.zig" \
  -Mqpack="$quic_zig_root/src/h3/qpack.zig" \
  -OReleaseSafe -femit-bin="$work/quic-zig-qpack-peer"
"$emitter" | "$work/quic-zig-qpack-peer"
echo "quic-zig decoded netz speculative QPACK field section"
