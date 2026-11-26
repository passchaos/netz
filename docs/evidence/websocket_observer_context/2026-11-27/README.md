# WebSocket observer context and buffer lifetime

Two stream-adapter observers replace backend userdata while inheriting most
callbacks: the queued-writer futex probe and the header-expiry clock peer.
They now use complete delegate I/O. The mutex probe declares only its wait/wake
overrides, and the clock peer uses the native clock helper with atomic time,
timeout translation and real cancellation. Each returns to original I/O before
its context is destroyed.

The active-writer cleanup gate originally preserves backend userdata but
locates its state through a mutable global pointer. It now passes its own
instance to the typed observer constructor, forwards read/write calls with
the delegate's userdata, and restores I/O before connection cleanup. This
removes the global state dependency without changing the read/write gates.

All original test names and 70 assertion statements remain. The queued-writer
case checks a held Close versus text, slices and another Close under transport
success/failure. Header expiry retains the exact two-byte frame prefix, one
write and one close. Fatal receive cleanup verifies that an active compressed
writer keeps its buffers until joined completion, then releases them and clears
pending state.

Three cases run on Threaded stream I/O, including Windows with zero async
capacity, and the application backend with one executor. Formatting and the
78-case scoped native group pass; same-scope Windows compilation passes all
eight build steps. [validation.json](validation.json) records current source
hashes, original assertions and the actual check results. Source findings are
distinguished from separate native failing
baselines. Delivered native/complete qualification and the broader HTTP-family
architecture, fairness and performance goal remain active.
