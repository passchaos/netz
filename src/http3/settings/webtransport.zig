//! Supported WebTransport wire families. Keep every enable codepoint distinct
//! so a peer's legacy advertisement cannot stand in for draft-16 support.

pub const Version = enum {
    legacy,
    draft16,
};

pub const Versions = packed struct(u8) {
    legacy: bool = false,
    draft16: bool = false,
    reserved: u6 = 0,

    /// Source-compatible local advertisement used when no explicit set is
    /// provided. Received SETTINGS always record the actual enable flags.
    pub const compatible: Versions = .{ .legacy = true, .draft16 = true };

    pub fn any(self: Versions) bool {
        return self.legacy or self.draft16;
    }

    pub fn highestCommon(self: Versions, peer: Versions) ?Version {
        if (self.draft16 and peer.draft16) return .draft16;
        if (self.legacy and peer.legacy) return .legacy;
        return null;
    }

    pub fn containsAll(self: Versions, remembered: Versions) bool {
        return (!remembered.legacy or self.legacy) and
            (!remembered.draft16 or self.draft16);
    }
};
