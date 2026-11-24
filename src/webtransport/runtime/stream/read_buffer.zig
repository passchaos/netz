//! Every incremental event consumer reserves receive storage before progress.
pub fn validate(output: []const u8) error{BufferTooShort}!void {
    if (output.len == 0) return error.BufferTooShort;
}
