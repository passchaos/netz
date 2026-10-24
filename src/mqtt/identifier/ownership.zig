//! Borrowed live sender reservations across Connection and Session owners.
pub const Ownership = struct {
    context: *const anyopaque,
    containsFn: *const fn (*const anyopaque, u16) bool,

    pub fn contains(self: Ownership, packet_id: u16) bool {
        return self.containsFn(self.context, packet_id);
    }
};
