//! Shared HTTP semantics independent of wire version.

pub const content_coding = @import("content_coding.zig");
pub const ContentCoding = content_coding.Coding;
pub const ContentCodingChain = content_coding.Chain;
pub const DecodedContent = content_coding.DecodedBody;
pub const ContentStreamDecoder = content_coding.StreamDecoder;
pub const ContentStreamOptions = content_coding.StreamOptions;
pub const ContentStreamResult = content_coding.StreamResult;
pub const ContentStreamStatus = content_coding.StreamStatus;
pub const client = @import("client.zig");
pub const Client = client.Client;
pub const Connection = client.Connection;
pub const Protocol = client.Protocol;
pub const ProtocolPolicy = client.ProtocolPolicy;
pub const CleartextProtocol = client.CleartextProtocol;
pub const Header = client.Header;
pub const RequestOptions = client.RequestOptions;
pub const RedirectOptions = client.RedirectOptions;
pub const OwnedResponse = client.OwnedResponse;
pub const RedirectedResponse = client.RedirectedResponse;
pub const Error = client.Error;
pub const ResponseTimeoutError = client.ResponseTimeoutError;

test {
    _ = content_coding;
    _ = client;
    _ = @import("content_coding/tests.zig");
    _ = @import("client_tests.zig");
}
