//! Shared HTTP semantics independent of wire version.

pub const content_coding = @import("content_coding.zig");
pub const ContentCoding = content_coding.Coding;
pub const ContentCodingChain = content_coding.Chain;
pub const DecodedContent = content_coding.DecodedBody;

test {
    _ = content_coding;
}
