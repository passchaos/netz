# xDS request matching

`grpc.xds.routing` supplies the request matching primitives used by typed route
configuration. Literal string matching supports exact, prefix, suffix and
contains, with ASCII case folding as in grpc-core. Safe regex uses RE2 full
matching semantics and a native bounded Thompson program.

```zig
var pattern = try netz.grpc.xds.routing.regex.Regex.init(
    allocator, "/demo\\.[A-Za-z]+/(Get|List)", .{},
);
defer pattern.deinit();
const matches = try pattern.matches(allocator, "/demo.Service/Get");
```

The regex parser supports alternation, captures/named groups as boolean
grouping, non-capturing groups, greedy/lazy repetition and counted bounds,
inline `i/m/s/U` flags and scoped flags, anchors and ASCII word boundaries,
literal quoting, Perl/POSIX classes, Unicode categories/scripts and simple
folding, hex/octal escapes and RE2's `\C` byte escape. Capture extraction and
replacement are separate work. Lookup data comes from pinned RE2 revision
`2da0056814cf180480a19f5cf811e7e1c054bf6d`; its BSD license and source hashes
are included beside endian-independent binary tables. The generation script
can reproduce and verify them with
`python3 tools/codegen/xds_unicode/generate.py --verify`.

Syntax construction bounds pattern bytes, group depth, AST nodes, character
ranges, repeat counts and emitted instructions. Concatenation/alternation trees
are balanced, so long literal sequences do not create unbounded compiler
recursion. Unsupported backreference/lookaround syntax fails compilation as in
RE2. Native matching deduplicates each instruction at each input byte position.
Five rotating position buckets allow UTF-8 rune transitions and `\C` byte
transitions to coexist, with workspace proportional to program size and work
bounded by program size times input length. Empty repetitions cannot spin an
epsilon closure forever. Invalid UTF-8 can be consumed only by explicit byte
escapes. `Workspace` can be reused across matches without new allocations.

Header matching sees request pseudo-headers, fixed `application/grpc` content
type and ASCII application metadata. Duplicate values are joined with commas,
including empty values, under a configured byte bound. Binary metadata is
absent from the routing view. Presence/absence predicates, inclusive/exclusive
int64 ranges and string/regex tests apply inversion using grpc-core's behavior:
a missing header fails a value predicate before inversion. Integer parsing
accepts an optional sign and surrounding ASCII whitespace, rejects underscores
and partial numbers, and checks overflow. This differs from grpc-js-xds's
missing-header inversion and its stricter canonical numeric strings.

Virtual-host lookup matches authority without case sensitivity. Exact domains
precede suffix wildcards, then prefix wildcards, then `*`; longer patterns win
within each group, and equal specificity keeps the first host. An edge wildcard
must consume at least one character. Empty patterns, interior wildcards and
multiple wildcards fail validation.

`zig build interop-grpc-xds-regex --summary all` compares generated operators,
Unicode, flags, syntax rejection and adversarial strings against actual RE2
WASM. The peer releases each compiled RE2 instance so its fixed WASM heap does
not turn later valid patterns into apparent syntax errors. The native runner
also checks the linear work bound for every vector. Adjacent tests cover
allocation rollback, reused workspace, malformed syntax, resource bounds,
negative folded classes, visible metadata, joined empty values, exact int64
ranges and virtual-host precedence. Evidence is stored in
`docs/evidence/grpc_xds_matching/2026-11-03.json`.

The matching engine also accepts an optional RPC budget, checking cancellation
and the original deadline during evaluation. [Typed RDS and immutable per-RPC
selector publication](grpc_rds.md) now use these primitives. Capture/hash
rewriting, HTTP filter overrides and full LDS/RDS/CDS resolver orchestration
remain follow-up work.
