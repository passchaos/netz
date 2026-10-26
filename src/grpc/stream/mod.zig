//! gRPC message streaming over the netz HTTP/2 incremental runtime.

pub const codec = @import("codec.zig");
pub const runtime = @import("runtime.zig");
pub const duplex = @import("duplex.zig");

pub const Error = runtime.Error;
pub const DecodedMessage = codec.DecodedMessage;
pub const MessageOptions = codec.MessageOptions;
pub const Decoder = codec.Decoder;
pub const Encoder = codec.Encoder;
pub const RequestOptions = runtime.RequestOptions;
pub const ClientWriter = runtime.ClientWriter;
pub const startClient = runtime.startClient;
pub const Response = runtime.Response;
pub const Request = runtime.Request;
pub const readRequest = runtime.readRequest;
pub const TerminalOptions = runtime.TerminalOptions;
pub const ResponseOptions = runtime.ResponseOptions;
pub const ServerWriter = runtime.ServerWriter;
pub const startResponse = runtime.startResponse;
pub const WriteResult = duplex.WriteResult;
pub const MessageProgress = duplex.MessageProgress;
pub const DuplexResponseHead = duplex.ResponseHead;
pub const DuplexResponse = duplex.Response;
pub const ClientDuplexEvent = duplex.ClientEvent;
pub const ClientDuplex = duplex.ClientDuplex;
pub const startDuplex = duplex.startDuplex;
pub const DuplexRequestTerminal = duplex.RequestTerminal;
pub const ServerDuplexEvent = duplex.ServerEvent;
pub const ServerRequestDrainResult = duplex.RequestDrainResult;
pub const ServerDuplex = duplex.ServerDuplex;
pub const acceptDuplex = duplex.acceptDuplex;
pub const acceptDuplexWithTimeout = duplex.acceptDuplexWithTimeout;
pub const acceptDuplexWithDeadline = duplex.acceptDuplexWithDeadline;

test {
    _ = @import("tests.zig");
    _ = @import("terminal.zig");
}
