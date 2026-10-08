//! Shared HTTP semantics independent of wire version.

pub const content_coding = @import("content_coding.zig");
pub const ContentCoding = content_coding.Coding;
pub const ContentCodingChain = content_coding.Chain;
pub const DecodedContent = content_coding.DecodedBody;
pub const ContentStreamDecoder = content_coding.StreamDecoder;
pub const ContentStreamOptions = content_coding.StreamOptions;
pub const ContentStreamResult = content_coding.StreamResult;
pub const ContentStreamStatus = content_coding.StreamStatus;

test {
    _ = content_coding;
    _ = @import("content_coding/tests.zig");
}
