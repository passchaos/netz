//! Optional reference owner for strings and connector contexts in resolver targets.
//! Copying the descriptor does not retain it; ownership transfers explicitly.
pub const Lifetime = struct {
    context: *anyopaque,
    retain_fn: *const fn (*anyopaque) void,
    release_fn: *const fn (*anyopaque) void,
    pub fn retain(self: Lifetime) Lifetime {
        self.retain_fn(self.context);
        return self;
    }
    pub fn release(self: Lifetime) void {
        self.release_fn(self.context);
    }
};
