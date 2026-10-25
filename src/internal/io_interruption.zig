//! Local interruptions preserve connection-owned incremental I/O progress.

/// These errors do not establish peer EOF, bad framing or authentication
/// failure. Timeout/cancellation retain accepted byte progress; executor
/// admission can fail before a read, write or timer task is scheduled.
pub fn retryable(err: anyerror) bool {
    return switch (err) {
        error.Timeout, error.Canceled, error.ConcurrencyUnavailable => true,
        else => false,
    };
}
