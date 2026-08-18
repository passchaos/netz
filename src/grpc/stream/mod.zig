//! gRPC message streaming over the netz HTTP/2 incremental runtime.

pub const codec = @import("codec.zig");
pub const runtime = @import("runtime.zig");

pub const Error = runtime.Error;
pub const DecodedMessage = codec.DecodedMessage;
pub const Decoder = codec.Decoder;
pub const Encoder = codec.Encoder;
pub const RequestOptions = runtime.RequestOptions;
pub const ClientWriter = runtime.ClientWriter;
pub const startClient = runtime.startClient;
pub const Response = runtime.Response;
pub const Request = runtime.Request;
pub const readRequest = runtime.readRequest;
pub const ResponseOptions = runtime.ResponseOptions;
pub const ServerWriter = runtime.ServerWriter;
pub const startResponse = runtime.startResponse;

test {
    _ = @import("tests.zig");
}
