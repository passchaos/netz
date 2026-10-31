//! gRPC wire semantics plus unary, sequential, and full-duplex message streams
//! over the netz HTTP/2 runtime.
//!
//! Protobuf payloads remain opaque bytes at this layer. Applications can use
//! `pbz` or another codec without coupling HTTP/2 transport state to a schema
//! implementation.

pub const wire = @import("wire.zig");
pub const auth = @import("auth.zig");
pub const status_details = @import("status_details.zig");
pub const orca = @import("orca.zig");
pub const orca_oob = @import("orca/oob.zig");
pub const metadata = @import("metadata.zig");
pub const compression = @import("compression.zig");
pub const stream = @import("stream/mod.zig");
pub const call = @import("call.zig");
pub const web = @import("web.zig");
pub const runtime = @import("runtime.zig");
pub const health = @import("health.zig");
pub const reflection = @import("reflection.zig");
pub const service_config = @import("service_config.zig");
pub const pbz = @import("pbz.zig");

pub const Error = stream.Error;
pub const Status = wire.Status;
pub const Message = wire.Message;
pub const MessageIterator = wire.MessageIterator;
pub const TimeoutUnit = wire.TimeoutUnit;
pub const Timeout = wire.Timeout;
pub const encodedMessageLen = wire.encodedMessageLen;
pub const writeMessageInto = wire.writeMessageInto;
pub const writeMessage = wire.writeMessage;
pub const isContentType = wire.isContentType;
pub const encodeStatusMessageInto = wire.encodeStatusMessageInto;
pub const encodeStatusMessageAlloc = wire.encodeStatusMessageAlloc;
pub const decodeStatusMessageAlloc = wire.decodeStatusMessageAlloc;
pub const BinaryMetadata = metadata.BinaryMetadata;
pub const EncodedMetadataFields = metadata.EncodedFields;
pub const BinaryMetadataIterator = metadata.ValueIterator;
pub const isBinaryMetadataName = metadata.isBinaryName;
pub const encodeBinaryMetadataAlloc = metadata.encodeFieldsAlloc;
pub const binaryMetadataDecodedUpperBound = metadata.decodedUpperBound;
pub const binaryMetadataFieldsDecodedUpperBound =
    metadata.decodedFieldsUpperBound;
pub const CompressionAlgorithm = compression.Algorithm;
pub const CompressionAlgorithmSet = compression.AlgorithmSet;
pub const parseCompressionAcceptEncoding =
    compression.parseAcceptEncoding;
pub const parseCompressionAcceptEncodingFields =
    compression.parseAcceptEncodingFields;
pub const formatCompressionAcceptEncodingInto =
    compression.formatAcceptEncodingInto;
pub const compressMessageAlloc = compression.compressAlloc;
pub const decompressMessageAlloc = compression.decompressAlloc;
pub const StreamingMessage = stream.DecodedMessage;
pub const StreamingMessageOptions = stream.MessageOptions;
pub const MessageStreamDecoder = stream.Decoder;
pub const MessageStreamEncoder = stream.Encoder;
pub const StreamingRequestOptions = stream.RequestOptions;
pub const StreamingClientWriter = stream.ClientWriter;
pub const startStreamingCall = stream.startClient;
pub const StreamingResponse = stream.Response;
pub const StreamingRequest = stream.Request;
pub const readStreamingRequest = stream.readRequest;
pub const readStreamingRequestWithTimeout = stream.readRequestWithTimeout;
pub const readStreamingRequestWithDeadline = stream.readRequestWithDeadline;
pub const TerminalOptions = stream.TerminalOptions;
pub const StreamingResponseOptions = stream.ResponseOptions;
pub const StreamingServerWriter = stream.ServerWriter;
pub const startStreamingResponse = stream.startResponse;
pub const DuplexWriteResult = stream.WriteResult;
pub const DuplexMessageProgress = stream.MessageProgress;
pub const DuplexResponseHead = stream.DuplexResponseHead;
pub const DuplexResponse = stream.DuplexResponse;
pub const DuplexOwnedMessage = stream.DuplexOwnedMessage;
pub const ClientDuplexEvent = stream.ClientDuplexEvent;
pub const ClientDuplex = stream.ClientDuplex;
pub const startDuplex = stream.startDuplex;
pub const DuplexRequestTerminal = stream.DuplexRequestTerminal;
pub const ServerDuplexEvent = stream.ServerDuplexEvent;
pub const ServerRequestDrainResult = stream.ServerRequestDrainResult;
pub const ServerDuplex = stream.ServerDuplex;
pub const acceptDuplex = stream.acceptDuplex;
pub const acceptDuplexWithTimeout = stream.acceptDuplexWithTimeout;
pub const acceptDuplexWithDeadline = stream.acceptDuplexWithDeadline;

pub const UnaryRequest = call.UnaryRequest;
pub const UnaryCallOptions = call.UnaryCallOptions;
pub const RetryPolicy = call.RetryPolicy;
pub const HedgingPolicy = call.HedgingPolicy;
pub const HedgingStats = @import("channel/shared.zig").HedgingStats;
pub const RetryThrottler = call.RetryThrottler;
pub const ServiceConfig = service_config.ServiceConfig;
pub const ServiceConfigParseOptions = service_config.ParseOptions;
pub const MethodPolicy = service_config.MethodPolicy;
pub const LoadBalancingPolicy = service_config.LoadBalancingPolicy;
pub const LoadBalancingConfig = service_config.LoadBalancingConfig;
pub const LoadBalancingNode = service_config.LoadBalancingNode;
pub const LeastRequestConfig = service_config.LeastRequestConfig;
pub const RingHashConfig = service_config.RingHashConfig;
pub const ringHash = @import("channel/ring_hash.zig").hash;
pub const WeightedRoundRobinConfig = service_config.WeightedRoundRobinConfig;
pub const OutlierDetectionConfig = service_config.OutlierDetectionConfig;
pub const SuccessRateEjection = service_config.SuccessRateEjection;
pub const FailurePercentageEjection =
    service_config.FailurePercentageEjection;
pub const Channel = runtime.Channel;
pub const SharedChannel = @import("channel/shared.zig").SharedChannel;
pub const SharedChannelSender = @import("channel/shared.zig").Sender;
pub const SharedChannelOptions = @import("channel/shared.zig").Options;
pub const SharedChannelKeepAliveOptions =
    @import("channel/shared.zig").KeepAliveOptions;
pub const SharedChannelKeepAliveStats =
    @import("channel/shared.zig").KeepAliveStats;
pub const SharedChannelOrcaOobOptions =
    @import("channel/shared.zig").OrcaOobOptions;
pub const SharedChannelOrcaOobWatch =
    @import("channel/shared.zig").OrcaOobWatch;
pub const SharedChannelOrcaOobUpdate =
    @import("channel/shared.zig").OrcaOobUpdate;
pub const SharedChannelOrcaOobStatus =
    @import("channel/shared.zig").OrcaOobStatus;
pub const SharedClientDuplex = runtime.SharedClientDuplex;
pub const SharedStreamWriter = runtime.SharedStreamWriter;
pub const SharedStreamOwnedWriteMessage = runtime.SharedStreamOwnedWriteMessage;
pub const SharedStreamReader = runtime.SharedStreamReader;
pub const SharedStreamEvent = runtime.SharedStreamEvent;
pub const ChannelTarget = runtime.ChannelTarget;
pub const ChannelEndpoint = runtime.ChannelEndpoint;
pub const ChannelSelectionPolicy = runtime.ChannelSelectionPolicy;
pub const ChannelConnectivityState = runtime.ChannelConnectivityState;
pub const ChannelConnectivitySnapshot = runtime.ChannelConnectivitySnapshot;
pub const ChannelConnectivityWatch = runtime.ChannelConnectivityWatch;
pub const ChannelAddressResolver = runtime.ChannelAddressResolver;
pub const ChannelOptions = runtime.ChannelOptions;
pub const ChannelBackoffPolicy = runtime.ChannelBackoffPolicy;
pub const ChannelCustomConnector = runtime.ChannelCustomConnector;
pub const ChannelHttpConnectProxy = runtime.ChannelHttpConnectProxy;
pub const ChannelSocks5Proxy = runtime.ChannelSocks5Proxy;
pub const ChannelProxyEnvironment = runtime.ChannelProxyEnvironment;
pub const ChannelProxyPolicy = runtime.ChannelProxyPolicy;
pub const ChannelProxyDecision = runtime.ChannelProxyDecision;
pub const ChannelProxySource = runtime.ChannelProxySource;
pub const ChannelProxyBypassSource = runtime.ChannelProxyBypassSource;
pub const ChannelProxyDirectReason = runtime.ChannelProxyDirectReason;
pub const ChannelTlsHostProxyTarget = runtime.ChannelTlsHostProxyTarget;
pub const CleartextServerOptions = runtime.CleartextServerOptions;
pub const ServerKeepAliveEnforcementPolicy =
    runtime.ServerKeepAliveEnforcementPolicy;
pub const UnaryResponse = call.UnaryResponse;
pub const UnaryResponseOptions = call.UnaryResponseOptions;
pub const parseUnaryRequest = call.parseUnaryRequest;
pub const unaryCall = call.unaryCall;
pub const unaryCallWithRetry = call.unaryCallWithRetry;
pub const writeUnaryResponse = call.writeUnaryResponse;
pub const statusFromHttp = call.statusFromHttp;
pub const statusFromHttp2Error = call.statusFromHttp2Error;
pub const validateCustomMetadata = call.validateCustomMetadata;
pub const validateCustomBinaryMetadata =
    call.validateCustomBinaryMetadata;
pub const validateMessageEncoding = call.validateMessageEncoding;
pub const parseBearerToken = auth.parseBearerToken;
pub const bearerTokenMatches = auth.bearerTokenMatches;
pub const bearerAuthorizationValueLen = auth.bearerAuthorizationValueLen;
pub const bearerAuthorizationInto = auth.bearerAuthorizationInto;

test {
    _ = @import("channel/connectivity.zig");
    _ = @import("channel/shared.zig");
    _ = compression;
    _ = @import("compression/negotiation_runtime_tests.zig");
    _ = status_details;
    _ = orca;
    _ = orca_oob;
    _ = @import("response_metadata.zig");
    _ = auth;
    _ = web;
    _ = @import("tests.zig");
    _ = @import("runtime_tests.zig");
    _ = @import("server_ping_enforcement_tests.zig");
    _ = @import("call/output_deadline_tests.zig");
    _ = @import("call/early_response_tests.zig");
    _ = @import("call/refused_retry_tests.zig");
    _ = @import("call/retry_lifecycle_tests.zig");
    _ = @import("call/per_attempt_timeout_tests.zig");
    _ = @import("channel_tests.zig");
    _ = @import("channel/outlier_detection_tests.zig");
    _ = @import("channel/weighted_round_robin_tests.zig");
    _ = @import("channel/least_request_channel_tests.zig");
    _ = @import("channel/ring_hash_tests.zig");
    _ = @import("channel/proxy_tests.zig");
    _ = @import("channel/proxy_policy_tests.zig");
    _ = @import("channel/socks5_tests.zig");
    _ = @import("service_config/least_request_tests.zig");
    _ = @import("service_config/ring_hash_tests.zig");
    _ = @import("service_config/hedging_tests.zig");
    _ = @import("channel/host_tests.zig");
    _ = @import("channel/connect_race.zig");
    _ = @import("channel/connect_race/tests.zig");
    _ = @import("channel/connect_race/ownership_tests.zig");
    _ = runtime;
    _ = stream;
    _ = health;
    _ = reflection;
    _ = service_config;
    _ = pbz;
}
