# WebSocket H3 native deadline fixture ownership

Pinned revision fd016266 reaches test 4205/7472 before aborting in the WebSocket
80-header/1200-MTU paced admission fixture. Its clock observer replaced Threaded
userdata while inheriting Group.concurrent, causing an allocator access through
the wrong backend object. That fixture and seven same-family frame/control/message
fixtures now use Native observation with complete actual-backend forwarding.
Atomic clocks advance only after confirmed sends; pacing durations and actual
cancelable deadline watcher waits retain their independent semantics.

The eight original named tests remain, including header cardinality and MTU,
zero send/sleep admission, partial frame/FIN, one mask per transaction, exact
fragmented suffix and mismatch refusal. The admission observer is scoped to the
first failed accept attempt: its restore and deinit complete before Pending
transfers H3 ownership to the accepted connection. Selected peer tasks now support
cancellation and joined failure cleanup. POSIX runs Threaded and application
backends; native Windows uses the supported application backend for this UDP
scope. No pins, CI budgets or original combined commands are changed.

Deadline fixtures are extracted into a cohesive module, with the formal parent
test import and small shared header checks retained. [validation.json](validation.json)
records exact sources, 87 scoped native cases (eight focused, 79 imported support),
and matching Windows compilation. These checks do not claim complete acceptance.

Two existing H2 TLS peers now report their first failure stage. Their original
Threaded backend, KeyUpdate, capacity, reuse, close and payload assertions are
preserved. Their local scope passes 135 cases and Windows compilation passes 8/8
steps. New native Windows evidence is required to identify the first peer cause.
The source audit also found that Threaded Windows deviceIoControl can return
Canceled after joining a successful IO completion without returning its byte
count. This remains a backend-cancellation hypothesis until a native repro ties
it to the observed TLS failure; no speculative transport change is made.

The previous revision's Linux original/added protocol and send-deadline steps
passed. Both isolated and complete CA reload still fail before SIGHUP at roughly
160-162 ms. Full protocol correctness, structure, performance, documentation and
orthogonal public interface qualification remain part of the active goal.
