//! gRPC wire semantics and unary calls over the netz HTTP/2 runtime.
//!
//! Protobuf payloads remain opaque bytes at this layer. Applications can use
//! `pbz` or another codec without coupling HTTP/2 transport state to a schema
//! implementation.

pub const wire = @import("wire.zig");
pub const metadata = @import("metadata.zig");
pub const call = @import("call.zig");

pub const Error = call.Error;
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

pub const UnaryRequest = call.UnaryRequest;
pub const UnaryCallOptions = call.UnaryCallOptions;
pub const UnaryResponse = call.UnaryResponse;
pub const UnaryResponseOptions = call.UnaryResponseOptions;
pub const parseUnaryRequest = call.parseUnaryRequest;
pub const unaryCall = call.unaryCall;
pub const writeUnaryResponse = call.writeUnaryResponse;
pub const statusFromHttp = call.statusFromHttp;
pub const validateCustomMetadata = call.validateCustomMetadata;
pub const validateCustomBinaryMetadata =
    call.validateCustomBinaryMetadata;
pub const validateMessageEncoding = call.validateMessageEncoding;

test {
    _ = @import("tests.zig");
}
