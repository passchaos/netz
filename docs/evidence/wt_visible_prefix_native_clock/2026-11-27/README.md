# Development stream visible prefix with a native deadline clock

Complete run 45877140272 aborts at 4898/7490,
`WebTransport development stream deadline isolates a visible prefix`.
An immutable worktree at `8b6b5f2a` reproduces a segmentation fault at 47/111
in Threaded task allocation. The sender replaces I/O userdata with its clock
observer while inheriting backend callbacks used by the deadline watcher.

The extracted fixture uses the complete native clock delegate. Awake time is
atomic; only an accepted datagram advances it by the original one second and
wakes the actual deadline wait. The original deadline remains one nanosecond
after initial time. The observer is removed in a lexical scope before the
healthy sibling uses the endpoint or the client is destroyed. The server peer
uses a concurrent Future with joined/canceled cleanup rather than an
unconditionally joined raw thread.

The original three development test names and 57 assertion statements remain
after normalizing atomic time/counter reads. They retain one visible send,
incomplete progress, prefix/reset state, an unusable failed send cursor,
no replay, and successful sibling completion after the datagram limit is
restored. The neighboring reverse-path/limits and peer-churn cursor cases are
included in the scoped verification.

[validation.json](validation.json) records the actual failing baseline,
current-source 116 native passes and Windows 8/8 compilation. The corrected
case runs on supported native datagram backends, including the Windows
application path. Windows compilation remains distinct from native execution.
Delivered native/complete acceptance, remaining contexts, fairness and
workload performance remain part of the active HTTP-family goal.
