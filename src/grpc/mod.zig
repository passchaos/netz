//! gRPC wire semantics plus unary, sequential, and full-duplex message streams
//! over the netz HTTP/2 runtime.
//!
//! Protobuf payloads remain opaque bytes at this layer. Applications can use
//! `pbz` or another codec without coupling HTTP/2 transport state to a schema
//! implementation.

pub const wire = @import("wire.zig");
pub const auth = @import("auth.zig");
pub const status_details = @import("status_details.zig");
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
pub const RetryThrottler = call.RetryThrottler;
pub const ServiceConfig = service_config.ServiceConfig;
pub const MethodPolicy = service_config.MethodPolicy;
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
    _ = compression;
    _ = @import("compression/negotiation_runtime_tests.zig");
    _ = status_details;
    _ = @import("response_metadata.zig");
    _ = auth;
    _ = web;
    _ = @import("tests.zig");
    _ = @import("runtime_tests.zig");
    _ = @import("call/output_deadline_tests.zig");
    _ = @import("call/early_response_tests.zig");
    _ = @import("call/refused_retry_tests.zig");
    _ = @import("call/retry_lifecycle_tests.zig");
    _ = runtime;
    _ = stream;
    _ = health;
    _ = reflection;
    _ = service_config;
    _ = pbz;
}
