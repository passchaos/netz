# HTTP/2 individual batch cancellation wake

The individual response batch previously admitted its frame reader with
`Select.async`. With no asynchronous capacity, that call could enter a blocking
socket read before the cancellation waiter was submitted. The extracted frame
wake helper independently admits both tasks, drains joined reader results on
wake admission failure and caller cancellation, and delivers completed input
before interruption. Caller cancellation is rearmed after a successful late
read. A real reader timeout, protocol error or EOF is never replaced by a wake.

The real TCP regression waits for actual socket read entry before signaling
batch cancellation. It requires the batch to finish within 250 ms, reports one
canceled response, then sends HEADERS for stream 3 after a subsequent read has
entered on the original socket. Five helper cases cover failed second admission,
caller cancellation and late completion, unavailable initial admission, reader
errors during join, and wake-only joined cleanup. The formal HTTP/2 runtime
test root imports those cases directly.

[validation.json](validation.json) identifies the current sources and exact
scopes. Native macOS and Windows cross-compilation are separate from pinned
native Linux/Windows and complete acceptance. No CI budgets, dependency pins,
original combined native commands or IP-migration assertions are changed.
