# Trust roots: system, platform, or compiled-in Mozilla CA set

Netz clients default to the operating system root files. Three sources are
available:

```zig
const netz = @import("netz");

// Load the OS root bundle in Zig (the default).
.tls = .{ .root_source = .system }

// Delegate chain and hostname verification to the OS verifier.
// macOS: Security.framework; Windows: CryptoAPI/WinTrust.
.tls = .{ .root_source = .platform }

// Use the compiled-in Mozilla CCADB root snapshot.
.tls = .{ .root_source = .bundled }
```

`root_source = .bundled` uses the sibling `webpkiz` package. The data is a
snapshot of the Mozilla Included CA Certificate Report, including the
Mozilla-applied name constraints that are not encoded in the root certificates
themselves.

`root_source = .platform` is only available on macOS and Windows. Other targets
return `error.PlatformVerifierUnavailable`; use `.system` or `.bundled` there.

## Precedence

When multiple trust inputs are present, the first applicable source wins:

1. `server_verifier`
2. `ca_bundle`
3. `system_store`
4. `root_source`
5. `system_environ` (only refines `.system`)

This keeps explicit application trust material authoritative while letting
`root_source` select the default when nothing else is configured.

## Protocol surfaces

- HTTP/1 and HTTP/2 (`netz.http.Client`): `Options.tls.root_source`
- Direct HTTP/1 standard-library TLS: `http1.runtime.TlsClientOptions.root_source`
- Direct HTTP/1 Vail TLS: `http1.runtime.VailTlsClientOptions.root_source`
- MQTT: `ConnectOptions.tls.root_source`
- WebSocket/WSS: the embedded `http1.runtime.TlsClientOptions.root_source`
- QUIC and HTTP/3: `quic.handshake.ClientOptions.root_source`
- gRPC xDS TLS material: `grpc.xds.tls_material.Config.bundled_root_certs` or
  `Config.platform_root_certs`

The HTTP/1 standard-library TLS path cannot use `.platform` because Zig's
`std.crypto.tls.Client` accepts only a certificate bundle, not a verification
callback. Use the Vail-backed transport for platform verification.

## Reusing a bundled store

A per-handshake bundled store parses the root set each time. High-volume
clients should build one store and pass it through `system_store`:

```zig
const now = std.Io.Timestamp.now(io, .real);
var store = try netz.trust.initBundledStore(allocator, now);
defer store.deinit();

var client = try netz.http.Client.init(allocator, io, .{
    .tls = .{ .system_store = &store },
});
```

The caller owns the store and must keep it alive for the lifetime of
handshakes that reference it.

## HTTP/1 standard-library path

Zig's `std.crypto.Certificate.Bundle` cannot represent every root algorithm.
`netz.trust.initBundledBundle` skips those roots; the Vail-backed path
(`initBundledStore`) retains them through Vail's compatibility verifier. Use
the Vail TLS transport when complete Mozilla coverage is required.

## Limitations

- `.system` loads OS root files but does not inherit OS verification policy.
- `.platform` is macOS/Windows only and does not currently combine with
  stapled OCSP policy in the Vail TLS path.
- The bundled root set only updates when the application is rebuilt and
  redeployed.
- Bundled roots do not include enterprise CAs installed on the device.
- `webpkiz` currently stores full DER roots, not the compact webpki trust-anchor
  representation. This keeps it compatible with both Zig std and Vail.
