# Channelz parser fuzz coverage

The bounded cross-protocol `fuzz-parsers` target now exercises the Channelz
decoders added with the server/client/socket admin surface:

- `decodeTopChannels`
- `decodeServers`
- `decodeChannelResponse`
- `decodeServerResponse`
- `decodeServerSockets`
- `decodeSocketResponse`

Every generated input is capped at 64 KiB and decoded under the leak-checking
test allocator. Structured Channelz channel and socket seeds are included in
both the `std.testing.fuzz` corpus and the deterministic truncation/bit-flip/
random mutation smoke list.

| Gate | Result | Evidence |
| --- | --- | --- |
| `fuzz-parsers` seed replay and deterministic mutation | 2/2 tests | `fuzz-parsers.Debug.log` |

Coverage-guided mode is not claimed by this record: the local Zig 0.16 coverage
cache currently reports `pcs_len was zero` for this target on this host. The
normal seed/mutation gate above passes and remains the committed evidence.

Reproduce with:

```sh
zig build fuzz-parsers --summary all
```
