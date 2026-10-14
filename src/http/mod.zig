//! Shared HTTP semantics independent of wire version.

pub const content_coding = @import("content_coding.zig");
pub const alt_svc_cache = @import("alt_svc_cache.zig");
pub const AltSvcCache = alt_svc_cache.Cache;
pub const AltSvcCacheConfig = alt_svc_cache.Config;
pub const AltSvcAlternative = alt_svc_cache.Alternative;
pub const AltSvcCacheStats = alt_svc_cache.Stats;
pub const ContentCoding = content_coding.Coding;
pub const ContentCodingChain = content_coding.Chain;
pub const DecodedContent = content_coding.DecodedBody;
pub const ContentStreamDecoder = content_coding.StreamDecoder;
pub const ContentStreamOptions = content_coding.StreamOptions;
pub const ContentStreamResult = content_coding.StreamResult;
pub const ContentStreamStatus = content_coding.StreamStatus;
pub const client = @import("client.zig");
pub const client_pool = @import("client_pool.zig");
pub const Client = client.Client;
pub const Connection = client.Connection;
pub const Pool = client_pool.Pool;
pub const Lease = client_pool.Lease;
pub const PoolOptions = client_pool.Options;
pub const PoolStats = client_pool.Stats;
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
pub const PoolError = client_pool.Error;
pub const PoolOperationError = client_pool.OperationError;

test {
    _ = content_coding;
    _ = alt_svc_cache;
    _ = client;
    _ = client_pool;
    _ = @import("content_coding/tests.zig");
    _ = @import("alt_svc_cache_tests.zig");
    _ = @import("client_tests.zig");
    _ = @import("client_pool_tests.zig");
}
