//! Publication hook errors shared with listener orchestration.
pub const PublishError = @import("../../channel/shared.zig").Error || @import("../ads.zig").Error || error{XdsLimitExceeded};
