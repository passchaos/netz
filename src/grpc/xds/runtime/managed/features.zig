//! Incoming source features are scoped to one serialized resource application.
const Controller = @import("../controller.zig").Controller;
pub const Saved = struct {
    ignore_deletion: bool,
    fail_data: bool,
    trusted: bool,
    transient_timer: bool,

    pub fn capture(controller: *Controller) Saved {
        const options = controller.options;
        return .{ .ignore_deletion = options.ignore_resource_deletion, .fail_data = options.fail_on_data_errors, .trusted = options.trusted_xds_server, .transient_timer = options.resource_timer_is_transient_error };
    }
    pub fn restore(self: Saved, controller: *Controller) void {
        controller.options.ignore_resource_deletion = self.ignore_deletion;
        controller.options.fail_on_data_errors = self.fail_data;
        controller.options.trusted_xds_server = self.trusted;
        controller.options.resource_timer_is_transient_error = self.transient_timer;
        if (controller.listener) |*listener| {
            listener.options.ignore_resource_deletion = self.ignore_deletion;
            listener.options.fail_on_data_errors = self.fail_data;
            listener.options.trusted_xds_server = self.trusted;
        }
    }
};
