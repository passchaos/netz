//! Stable cross-protocol streaming request-body surface.
//!
//! These aliases intentionally point at the runtime types that already own the
//! frame readers, flow control and bounded buffers. They are re-exported here
//! so applications such as weft do not depend on internal module paths.
//!
//! Body bytes are always bounded by the protocol `Limits.max_body_bytes`.
//! HTTP/1 uses a push callback: the handler consumes slices before returning
//! and writes its response afterwards. HTTP/2 exposes both push callbacks and
//! an independent step-driven `Stream` handle. HTTP/3 exposes multiplexed
//! `RequestEvent` values carrying peer and stream identity.

pub const http1 = struct {
    /// Returned after `Connection.readRequestStreaming*` has delivered every
    /// body chunk through the caller's `consume` callback. The callback runs
    /// while the request is still being parsed; the response may be written
    /// after it returns.
    pub const Request = @import("../http1/runtime.zig").StreamingRequest;
    pub const RequestHead = @import("../http1/runtime.zig").StreamingRequestHead;
    /// Pull-style body reader from `Connection.readRequestBody*`. `next`
    /// returns the next chunk (borrowed until the following call); `takeRequest`
    /// returns the completed metadata and trailers.
    pub const BodyReader = @import("../http1/runtime.zig").RequestBodyReader;
    pub const BodyHead = @import("../http1/runtime.zig").RequestBodyHead;
    pub const Connection = @import("../http1/runtime.zig").Connection;
};

pub const http2 = struct {
    /// Returned after `Connection.readRequestStreaming*` delivered DATA through
    /// per-stream callbacks.
    pub const Request = @import("../http2/runtime.zig").StreamingRequest;
    pub const RequestHead = @import("../http2/runtime.zig").StreamingRequestHead;
    /// Independent step-driven server stream handle from
    /// `Connection.acceptDuplexRequest*`. It owns its request event stream and
    /// response half; one connection frame reader must be driven by one task at
    /// a time.
    pub const Stream = @import("../http2/runtime.zig").ServerDuplexStream;
    pub const Event = @import("../http2/runtime.zig").DuplexRequestEvent;
    /// Result of `Connection.serveRequestBatchConcurrent`: per-input handler
    /// errors after responses were serialized in completion order.
    pub const ConcurrentResult = @import("../http2/runtime.zig").ConcurrentHandlerServeResult;
    pub const Connection = @import("../http2/runtime.zig").Connection;
};

pub const http3 = struct {
    /// Multiplexed server request event from `Server.receiveRequestEvent*`.
    /// Events carry the peer and stream identity so one polling loop can route
    /// DATA, trailers, FIN and reset to independent per-stream state.
    pub const RequestEvent = @import("../http3/runtime.zig").StreamingRequestEvent;
    pub const ResponseEvent = @import("../http3/runtime.zig").StreamingResponseEvent;
    /// Result of `Server.serveConcurrent`; requests/errors stay alive until the
    /// batch is deinitialized.
    pub const ConcurrentResult = @import("../http3/runtime.zig").ConcurrentServeResult;
    pub const Server = @import("../http3/runtime.zig").Server;
};

test "streaming aliases resolve to public runtime types" {
    _ = http1.Request;
    _ = http1.RequestHead;
    _ = http1.BodyReader;
    _ = http1.BodyHead;
    _ = http2.Request;
    _ = http2.RequestHead;
    _ = http2.Stream;
    _ = http2.Event;
    _ = http2.ConcurrentResult;
    _ = http3.RequestEvent;
    _ = http3.ResponseEvent;
    _ = http3.ConcurrentResult;
}
