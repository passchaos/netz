// Server-side types are split by responsibility under runtime/server/.

const handshake_types = @import("server/handshake.zig");
const endpoint_types = @import("server/endpoint.zig");
const session_types = @import("server/session.zig");

pub const Server = handshake_types.Server;
pub const ProtectedServer = handshake_types.ProtectedServer;
pub const PendingSession = handshake_types.PendingSession;
pub const RejectedSession = handshake_types.RejectedSession;
pub const PendingProtectedSession = handshake_types.PendingProtectedSession;
pub const RejectedProtectedSession = handshake_types.RejectedProtectedSession;
pub const StatefulProtectedServer = handshake_types.StatefulProtectedServer;
pub const HandshakeServer = handshake_types.HandshakeServer;
pub const HandshakeAdmission = handshake_types.HandshakeAdmission;
pub const EndpointPendingSession = endpoint_types.EndpointPendingSession;
pub const EndpointAcceptedSession = endpoint_types.EndpointAcceptedSession;
pub const EndpointSessionEvent = endpoint_types.EndpointSessionEvent;
pub const EndpointSessionKey = endpoint_types.EndpointSessionKey;
pub const EndpointServerEvent = endpoint_types.EndpointServerEvent;
pub const ServeEvent = endpoint_types.ServeEvent;
pub const ServeOptions = endpoint_types.ServeOptions;
pub const EndpointServer = endpoint_types.EndpointServer;
pub const rejectAdditionalHandshakeRequestsOnce = endpoint_types.rejectAdditionalHandshakeRequestsOnce;
pub const AcceptedSession = session_types.AcceptedSession;
pub const OwnedConnectRequest = session_types.OwnedConnectRequest;
pub const AcceptedProtectedSession = session_types.AcceptedProtectedSession;
pub const OwnedProtectedConnectRequest = session_types.OwnedProtectedConnectRequest;
pub const OwnedHandshakeConnectRequest = session_types.OwnedHandshakeConnectRequest;
pub const PendingHandshakeSession = session_types.PendingHandshakeSession;
pub const RejectedHandshakeSession = session_types.RejectedHandshakeSession;
pub const AcceptedHandshakeSession = session_types.AcceptedHandshakeSession;
