//! HTTP persistence ends at EOF-delimited entities and protocol switches.
//! Both owned and streaming responses use the originating request method.
const framing = @import("../../response_framing.zig");

pub const switchesProtocol = framing.switchesProtocol;
pub const reusable = framing.reusable;
