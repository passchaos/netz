pub const backend: ?[]const u8 = null;
pub const ResolveBeneathMode = enum { strict, best_effort };
pub const resolve_beneath_mode: ResolveBeneathMode = .strict;
pub const no_hacks = false;
pub const task_migration = true;
pub const scheduler_metrics = true;
