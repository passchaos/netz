//! Allocation-free server call observation hooks.
//!
//! Runtime types store this vtable so Channelz or another observer can count
//! calls without the transport importing the admin implementation.
const std = @import("std");

pub const ServerObserver = struct {
    context: *anyopaque,
    call_started_fn: *const fn (*anyopaque) void,
    call_succeeded_fn: *const fn (*anyopaque) void,
    call_failed_fn: *const fn (*anyopaque) void,

    pub fn callStarted(self: ServerObserver) void {
        self.call_started_fn(self.context);
    }

    pub fn callSucceeded(self: ServerObserver) void {
        self.call_succeeded_fn(self.context);
    }

    pub fn callFailed(self: ServerObserver) void {
        self.call_failed_fn(self.context);
    }
};
