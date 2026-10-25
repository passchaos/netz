//! Local interruptions preserve the cursor of an incremental transport reader.

/// These errors do not establish peer EOF, bad framing or authentication
/// failure. Timeout/cancellation retain accepted byte progress; executor
/// admission can fail temporarily before the next read is scheduled.
pub fn retryable(err: anyerror) bool {
    return switch (err) {
        error.Timeout, error.Canceled, error.ConcurrencyUnavailable => true,
        else => false,
    };
}
