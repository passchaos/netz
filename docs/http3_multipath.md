# HTTP/3 multipath testing

netz implements QUIC connection migration and path validation. It does not
implement the `draft-ietf-quic-multipath` extension, so a single QUIC
connection cannot carry traffic over several local interfaces at once.

Application-level multipath is supported today: each owning HTTP/3 client binds
its own local UDP address, and the application schedules, races, or fails over
independent connections. `tools/interop/h3_multipath_probe.zig` exercises that
shape across hosts.

## Probe tool

```sh
zig build h3-multipath-probe
```

`serve` starts an HTTP/3 server and echoes the peer address it observed for
every request:

```sh
zig-out/bin/netz-h3-multipath-probe serve \
  --listen=0.0.0.0:4433 --sessions=2
```

`probe` opens one owning connection per `--bind` address and sends one request
on each path:

```sh
zig-out/bin/netz-h3-multipath-probe probe \
  --server=10.79.152.225:4433 \
  --bind=10.79.203.42:0 \
  --bind=10.79.239.233:0
```

The response body reports the server-observed peer, so a successful run proves
which source address each path used.

## Multi-NIC host recipe

The probe binary cross-compiles for Linux:

```sh
zig build h3-multipath-probe -Dtarget=x86_64-linux -Doptimize=ReleaseSafe \
  --prefix zig-out-linux
```

On a host with several interfaces, the kernel normally routes every destination
through the lowest-metric default route. To force one source address through a
different NIC without changing the global default, add a temporary source rule
and table (root required), then remove them after the test:

```sh
sudo ip route add default via <wifi-gateway> dev wlp0s20f3 table 100
sudo ip rule add from 10.79.239.233 lookup 100 priority 1000

# ... run the probe ...

sudo ip rule del from 10.79.239.233 lookup 100 priority 1000
sudo ip route flush table 100
```

## Verified run

A 2026-11-18 run used a macOS arm64 server on `10.79.152.225:4433` and the
Linux x86_64 probe on `10.79.203.42`:

```text
PATH local=10.79.203.42 -> 200 body=peer=10.79.203.42:57996 path=10.79.203.42
PATH local=10.79.239.233 -> 200 body=peer=10.79.239.233:54953 path=10.79.239.233
```

The server log reported the matching peers:

```text
SERVED 0 peer=10.79.203.42:57996 path=10.79.203.42
SERVED 1 peer=10.79.239.233:54953 path=10.79.239.233
```

The wired `enp3s0` path and the Wi-Fi `wlp0s20f3` path therefore completed
independent HTTP/3 exchanges against one server. This is application-level
multipath, not a claim of draft QUIC multipath support.

## Cross-compilation note

The Linux build also exposed a portability defect in the QUIC platform trust
path: the unsupported platform verifier's error set does not include
`OutOfMemory`, while the client mapped that error unconditionally. The mapping
now switches on `@as(anyerror, err)`, which preserves the distinction on
platforms that have a native verifier and still compiles where the verifier is
unsupported.
