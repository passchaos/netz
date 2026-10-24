//! Directional RFC 7692 history policy, named for the WebSocket endpoint roles.
pub const ContextTakeover = enum {
    none,
    client,
    server,
    both,
};

pub const Policy = struct {
    enable_permessage_deflate: bool = false,
    /// Legacy shorthand used when context_takeover is null.
    allow_context_takeover: bool = false,
    /// Explicit direction policy overrides the legacy shorthand. The client
    /// can locally disable takeover even without a response echo.
    context_takeover: ?ContextTakeover = null,
    /// Server selection for the peer compressor, emitted only when offered
    /// and capped by an explicit client value. Client offers ignore this.
    accept_client_max_window_bits: ?u8 = null,
    /// Server compressor bound, permitted without a client parameter; an
    /// offered maximum remains authoritative. Client offers ignore this.
    accept_server_max_window_bits: ?u8 = null,

    pub fn clientTakeover(self: Policy) bool {
        return switch (self.context_takeover orelse return self.allow_context_takeover) {
            .client, .both => true,
            .none, .server => false,
        };
    }

    pub fn serverTakeover(self: Policy) bool {
        return switch (self.context_takeover orelse return self.allow_context_takeover) {
            .server, .both => true,
            .none, .client => false,
        };
    }

    /// The client_no_context_takeover offer is a hint, not an acknowledgement
    /// requirement. Validate the server direction first; local send policy is
    /// applied after the response has been bound to an accepted offer.
    pub fn clientResponsePolicy(self: Policy) Policy {
        var policy = self;
        policy.context_takeover = if (self.serverTakeover()) .both else .client;
        return policy;
    }
};
