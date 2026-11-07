# Shared H2 cancellation header ownership diagnosis

The prebuilt Debug client reproduced the independent Hyper `h2-shared`
allocator abort. The confirmed failure is an invalid interior-pointer free in
the unified pool's `Exchange.deinit` header cleanup.

`gdb-header-owner-1794034806710316333/gdb.log` records two response fields in
the packed allocation at `0x37ac3c0`, with `block_storage` covering 219 bytes.
The first field's `:status` name starts at `0x37ac470`, 176 bytes inside that
allocation, and its `200` value starts at `0x37ac477`. The old custom destructor
freed those interior slices independently. The abort backtrace identifies
`Exchange.freeHeaders`, reached from canceled-command retirement.

The correction calls the existing public `http2.runtime.freeHeaderFields` for
both headers and trailers. That destructor recognizes packed `block_storage`
and also supports separately allocated fields. Header transfer into successful
owned responses and the stream/command/lease lifetimes remain unchanged.

The existing Threaded cancellation regression withheld the response head, so
the canceled exchange held no header allocation. Hyper sent the final response
head and retained the response body, exposing this missing case. A new
`Backend.initZio` regression receives a held head, then completes a later probe
on the same connection before cancellation. It explicitly checks packed HPACK
storage and retains the original sibling and later-reuse assertions.

The first gdb stop in `gdb-prebuilt-1794034387997861007` and the frame-size
capture in `gdb-sizes-1794034601224301964` were handled coroutine stack-growth
signals. Passing SIGSEGV to zio's installed handler reaches the real SIGABRT,
as retained in `gdb-abort-1794034675826942749`. The stack-growth stop is not the
allocator defect. No zio stack limits were increased.

The corrected source passed formatting, Zig AST checks, shell syntax and diff
checks. Failure cleanup was verified to retain logs without changing the
original exit status. Native rebuilding and the strict native/Hyper rerun are
assigned to the parent; this note does not claim those gates have passed.
