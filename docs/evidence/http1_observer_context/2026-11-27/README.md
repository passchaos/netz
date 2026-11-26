# Complete HTTP/1 write-observer delegation

The source review finds 18 HTTP/1 writer/shutdown observer installations that
replace backend userdata while inheriting most of its callbacks. One partial
100 Continue fixture forwards a manually selected subset, leaving the rest
dependent on backend implementation details. These are context-contract source
findings; no separate failing native baseline is claimed for each observer.

All 18 installations now use the shared typed observer constructor. Each
observer retains its actual `delegate: std.Io`; only the original write or
shutdown injection is overridden. The partial Continue fixture removes its
manual forwarding methods. Its I/O is restored with `defer` before connection
cleanup on every return. The pooled partial-write fixture restores I/O inside
the observer's lexical scope before releasing the lease.

The nine repaired cases run on Threaded stream I/O, including Windows, and
the application backend. All original test names and 234 assertion statements
remain. They preserve wire shape, flatten/vectored equivalence, streaming
chunks, zero transport calls on allocation failure, terminal write failure,
exact accepted TCP prefix, no later write, shutdown count and empty pool state.

[validation.json](validation.json) records formatting, the 34-case scoped
native pass and same-scope Windows 8/8 compilation. Windows compilation remains
separate from native execution, and delivered native/complete acceptance remains
open.

This batch unifies test I/O construction and cleanup ownership. It does not
claim measured throughput or latency changes. The full HTTP-family goal still
includes remaining observer contexts, native/complete CI, fairness, performance
and public-interface usability.
