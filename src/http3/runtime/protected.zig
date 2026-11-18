// Protected HTTP/3 server and client live in runtime/protected/.

pub const ProtectedServer = @import("protected/server.zig").ProtectedServer;
pub const ProtectedClient = @import("protected/client.zig").ProtectedClient;
