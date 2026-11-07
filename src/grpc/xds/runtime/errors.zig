//! Publication hook errors shared with listener orchestration.
pub const PublishError = @import("../../channel/shared.zig").Error || @import("../ads.zig").Error || @import("../ads/delta.zig").Error || @import("../tls_material.zig").Error || @import("lrs_bindings.zig").Error || error{ XdsLimitExceeded, InvalidXdsResourceName };
