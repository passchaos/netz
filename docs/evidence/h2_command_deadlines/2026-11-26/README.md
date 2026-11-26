# HTTP/2 command deadlines and completion ownership

An expired `startResponseWithBodyWithDeadline` could execute before the caller
observed its wait timeout. Inline handlers skipped deadline validation, and
queued response kinds other than informational heads discarded the timestamp
before socket output. Cancellation cleanup also retried a cancellable wait
on a command borrowed from the handler stack. Retrying a partially committed
compound response could repeat HEADERS or DATA.

The isolated f126f64c snapshot enables the existing inline handler mode in the
original two-stream informational fixture. It deterministically reports
`expected error.Timeout, found void`, followed by client `StreamReset`.
Adding only the shared awake-clock admission check to that snapshot makes the
same exchange pass 34 scoped tests. This isolates an admission defect that
produces the observed symptom; attribution of the earlier queued Linux CI
failure still requires delivered native qualification.

The implementation separates borrowed command lifetime from output dispatch.
Deadline/cancellation admission precedes queue allocation or inline output;
every owner execution and all head, DATA, trailer and reset writes retain the
original timestamp. A failed handler wait wakes the owner and joins command
release uncancelably. Fully committed output returns success and rearms an
actual consumed cancellation for the next cancellation point. The owner
retains its completed head and DATA cursor across backpressure and inbound
progress, preserving one HEADERS, the exact body and one FIN.

Direct server duplex buffered-response and reset methods have matching
deadline/timeout forms. Explicit terminal output applies the configured
cleanup cap without renewing the caller's timestamp; invalid admission leaves
stream ownership available for a valid retry.

Qualification drives actual Future cancellation/native timer waits, a separate
uncanceled owner and real TCP response frames. The completion case checks the
next actual cancellation point after success. Controlled refusal follows a
confirmed TCP DATA prefix to exercise both error and inbound-progress retries.
The original queued informational exchange remains, with a separate inline
case. Direct timeout variants verify zero-time admission, valid output and
terminal ownership on real sockets.

[validation.json](validation.json) records final-source commands, hashes and
scope. Stream fixtures include Threaded with zero async capacity and the
application backend on every platform, retaining Windows Threaded TCP
coverage. Windows compilation proves generated code, not native behavior.
Linux/Windows native and complete acceptance remain open; the continuous
optimization goal is active. Broader slow-writer fairness and performance
qualification remain separate work.
