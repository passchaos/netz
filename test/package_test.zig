const std = @import("std");
const netz = @import("netz");

test "public modules are reachable" {
    try std.testing.expect(@hasDecl(netz, "runtime"));
    try std.testing.expect(@hasDecl(netz, "stream"));
    inline for (&.{ "connect", "io", "socket_options", "tls" }) |decl|
        try std.testing.expect(@hasDecl(netz.stream, decl));
    try std.testing.expect(@hasDecl(netz.runtime, "Backend"));
    try std.testing.expect(@hasDecl(netz.runtime.Backend, "initZio"));
    try std.testing.expect(!@hasDecl(netz.runtime, "zio"));
    try std.testing.expect(@hasDecl(netz, "grpc"));
    try std.testing.expect(@hasDecl(netz.grpc, "Status"));
    try std.testing.expect(@hasDecl(netz.grpc, "MessageIterator"));
    try std.testing.expect(@hasDecl(netz.grpc, "Timeout"));
    try std.testing.expect(@hasDecl(netz.grpc, "BinaryMetadata"));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "BinaryMetadataIterator",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "encodeBinaryMetadataAlloc",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "binaryMetadataFieldsDecodedUpperBound",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "CompressionAlgorithm",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "CompressionAlgorithmSet",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "parseCompressionAcceptEncoding",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "compressMessageAlloc",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "decompressMessageAlloc",
    ));
    try std.testing.expect(@hasDecl(netz.grpc, "unaryCall"));
    try std.testing.expect(@hasDecl(netz.grpc, "parseUnaryRequest"));
    try std.testing.expect(@hasDecl(netz.grpc, "writeUnaryResponse"));
    try std.testing.expect(@hasDecl(netz.grpc, "statusFromHttp2Error"));
    try std.testing.expect(@hasField(netz.grpc.UnaryResponse, "reset"));
    try std.testing.expect(@hasDecl(netz.grpc, "runtime"));
    try std.testing.expect(@hasDecl(netz.grpc, "health"));
    try std.testing.expect(@hasDecl(netz.grpc, "reflection"));
    try std.testing.expect(@hasDecl(netz.grpc.reflection, "Registry"));
    try std.testing.expect(@hasDecl(
        netz.grpc.reflection.Registry,
        "addFileDescriptorSet",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.reflection,
        "ClientSession",
    ));
    try std.testing.expect(@hasDecl(netz.grpc.health, "Registry"));
    try std.testing.expect(@hasDecl(netz.grpc.health, "WatchCursor"));
    try std.testing.expect(@hasDecl(netz.grpc.health, "CheckOptions"));
    try std.testing.expect(@hasDecl(netz.grpc.health, "check"));
    try std.testing.expect(@hasDecl(netz.grpc.health, "ClientWatch"));
    try std.testing.expect(@hasDecl(netz.grpc.health, "startWatch"));
    try std.testing.expect(@hasDecl(netz.grpc.runtime, "Client"));
    try std.testing.expect(@hasDecl(netz.grpc.runtime, "Server"));
    try std.testing.expect(@hasDecl(netz.grpc.runtime.Server, "accept"));
    try std.testing.expect(@hasDecl(netz.grpc.runtime.Client, "connectTlsHost"));
    try std.testing.expect(@hasDecl(netz.grpc.runtime.Client, "unary"));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "healthCheck",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "startHealthWatch",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "startReflection",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "startStreaming",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "startDuplex",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.Client,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(netz.grpc.runtime, "TlsServer"));
    try std.testing.expect(@hasDecl(netz.grpc.runtime.TlsServer, "accept"));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "readUnary",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "writeUnary",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "writeHealthCheck",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "serveHealthWatch",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "serveReflection",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "readStreaming",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "startStreamingResponse",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "acceptDuplex",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "acceptDuplexWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.runtime.ServerConnection,
        "acceptDuplexWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.ServerDuplex,
        "waitForPeerReset",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "MessageStreamDecoder",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "MessageStreamEncoder",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "startStreamingCall",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "readStreamingRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc,
        "startStreamingResponse",
    ));
    try std.testing.expect(@hasDecl(netz.grpc, "startDuplex"));
    try std.testing.expect(@hasDecl(netz.grpc, "acceptDuplex"));
    try std.testing.expect(@hasDecl(netz.grpc.ClientDuplex, "writeMessage"));
    try std.testing.expect(@hasDecl(
        netz.grpc.ClientDuplex,
        "writeFinalMessage",
    ));
    try std.testing.expect(@hasDecl(netz.grpc.ClientDuplex, "resumeMessage"));
    try std.testing.expect(@hasDecl(
        netz.grpc.ClientDuplex,
        "readResponseEvent",
    ));
    try std.testing.expect(@hasDecl(netz.grpc.ServerDuplex, "readRequestEvent"));
    try std.testing.expect(@hasDecl(netz.grpc.ServerDuplex, "writeMessage"));
    try std.testing.expect(@hasDecl(netz.grpc.ServerDuplex, "finishOk"));
    try std.testing.expect(@hasDecl(
        netz.grpc.StreamingClientWriter,
        "writeMessage",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.StreamingClientWriter,
        "finishAndRead",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.StreamingClientWriter,
        "writeMessageOrReadResponse",
    ));
    try std.testing.expect(@hasDecl(
        netz.grpc.StreamingServerWriter,
        "finishOk",
    ));
    try std.testing.expect(@hasField(netz.grpc.StreamingResponse, "reset"));
    try std.testing.expect(@hasDecl(netz, "tls"));
    try std.testing.expect(@hasDecl(netz.tls, "stream"));
    try std.testing.expect(@hasDecl(netz.tls, "trust"));
    try std.testing.expect(@hasDecl(netz.tls.trust, "BundleVerifier"));
    try std.testing.expect(@hasDecl(netz.tls.trust, "SystemStore"));
    try std.testing.expect(@hasDecl(
        netz.tls.stream,
        "ServerConnection",
    ));
    try std.testing.expect(@hasDecl(netz.tls.stream, "CipherSuite"));
    try std.testing.expect(@hasDecl(netz.tls.stream, "TranscriptHash"));
    try std.testing.expect(@hasDecl(netz.tls.stream, "KeyUpdateCounts"));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "sendCloseNotify",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "receivedCloseNotify",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "sendCloseNotify",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "receivedCloseNotify",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "initWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "initVerifiedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ServerConnection,
        "initWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.tls, "testing"));
    try std.testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", netz.websocket.handshake_guid);
    try std.testing.expectEqual(@as(usize, 64 * 1024), (netz.http1.runtime.Limits{}).max_head_bytes);
    try std.testing.expectEqual(@as(usize, 100), (netz.http1.runtime.Limits{}).max_request_headers);
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(u16) - 1),
        (netz.http1.runtime.Limits{}).max_request_target_bytes,
    );
    try std.testing.expect(@hasField(
        netz.http1.ParseOptions,
        "max_request_target_bytes",
    ));
    try std.testing.expect((netz.http1.runtime.Limits{}).keep_alive);
    try std.testing.expectEqual(
        netz.http1.runtime.WriteStrategy.auto,
        (netz.http1.runtime.Limits{}).write_strategy,
    );
    try std.testing.expect(@hasField(
        netz.http1.runtime.Limits,
        "keep_alive",
    ));
    try std.testing.expect(@hasField(
        netz.http1.runtime.Limits,
        "write_strategy",
    ));
    try std.testing.expect(@hasField(
        netz.http1.runtime.Limits,
        "connect_timeout",
    ));
    try std.testing.expect(@hasField(
        netz.http1.runtime.TlsClientOptions,
        "handshake_timeout",
    ));
    try std.testing.expect(@hasDecl(netz.http1.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http1, "client_pool"));
    try std.testing.expect(@hasDecl(netz.http1.client_pool, "Pool"));
    try std.testing.expect(@hasDecl(
        netz.http1.client_pool.Pool,
        "connectionCount",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.client_pool.Pool,
        "acquireUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.client_pool.Pool,
        "acquireUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.client_pool.Pool,
        "requestUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.client_pool.Pool,
        "requestUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.http1.runtime.Server, "serveUntil"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "UnixServer"));
    try std.testing.expect(@hasDecl(netz.http2, "client_pool"));
    try std.testing.expect(@hasDecl(netz.http2.client_pool, "Pool"));
    try std.testing.expect(@hasDecl(
        netz.http2.client_pool.Pool,
        "requestUri",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.client_pool.Pool,
        "pruneExpired",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.client_pool.Pool,
        "acquireUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.client_pool.Pool,
        "acquireUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.client_pool.Pool,
        "requestUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.client_pool.Pool,
        "requestUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "isReusable",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithInformationalAndHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithInformationalAndHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithInformationalAndHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResponseStreamingWithInformationalAndHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithInformationalAndHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithInformationalAndHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectTlsAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectUnixWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectTlsHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectTlsAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectUnixWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectTlsHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectTlsAddressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "requestUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "requestUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "requestUriTlsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "requestUriTlsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectUpgradeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectUpgradeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "requestUriUpgradeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "requestUriUpgradeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectStreamUpgradeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectStreamUpgradeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.UnixServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.UnixServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.UnixServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.UnixServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "serveOne",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "serveConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "acceptStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "acceptStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsServer,
        "acceptStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.TlsClientConnection,
        "initWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readRequestFromStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamForRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "ServeUntilOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectUnix",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectUnixWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectTlsHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectTlsAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectVailTlsHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectVailTlsAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectUnixWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectTlsHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectTlsAddressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectVailTlsHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectVailTlsAddressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readResponseFromStreamBuffered"));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readRequestFromStreamBufferedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readRequestFromStreamBufferedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "InformationalObserver",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "InformationalResponseHead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestWithInformational",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriTlsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriTlsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriVailTlsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriVailTlsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestStreamingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestStreamingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestStreamingWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestStreamingWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseStreamingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseStreamingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseStreamingWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseStreamingWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestStreamingWithInformational",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectVailTlsHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "connectVailTlsAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestUriVailTls",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "VailTlsClientOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "waitForContinueWithInformational",
    ));
    try std.testing.expect(@hasDecl(netz.http1, "ResponseContext"));
    try std.testing.expect(@hasDecl(netz.http1, "parseResponseForRequest"));
    try std.testing.expect(@hasDecl(netz.http1, "RequestHead"));
    try std.testing.expect(@hasDecl(netz.http1, "ResponseHead"));
    try std.testing.expect(@hasDecl(netz.http1, "parseRequestHead"));
    try std.testing.expect(@hasDecl(netz.http1, "parseResponseHead"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readResponseFromStreamBufferedForRequest"));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamBufferedForRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamBufferedForRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamForRequestObservedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamForRequestObservedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamBufferedForRequestObservedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "readResponseFromStreamBufferedForRequestObservedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readRequestFromStreamBuffered"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readResponseFromStreamForRequest"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "Tunnel"));
    try std.testing.expect(@hasDecl(netz.http1.runtime.Client, "openConnectTunnel"));
    try std.testing.expect(@hasDecl(netz.http1.runtime.Connection, "acceptConnectTunnel"));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "readRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "readRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Tunnel,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Tunnel,
        "writeParts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Tunnel,
        "writeSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Tunnel,
        "readWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Tunnel,
        "readWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Tunnel,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "readRequestBatchInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "readRequestStreamingWithOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Client,
        "requestStreamingWithParseOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.RequestWriter,
        "readResponseStreamingWithParseOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "writeResponses",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchWithInformationalIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchWithInformationalIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchStreamingIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchStreamingIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchStreamingWithInformationalIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBatchStreamingWithInformationalIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchWithInformationalIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchWithInformationalIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchStreamingInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchStreamingIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchStreamingIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchStreamingWithInformationalInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchStreamingWithInformationalIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestBodyBatchStreamingWithInformationalIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestBatchStreamingIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestBatchStreamingIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "writeResponseBatch",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "takeLastPeerReset",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "pingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "pingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "gracefulShutdown",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "gracefulShutdownWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "gracefulShutdownWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "gracefulShutdownComplete",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "startResponse",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "startRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "acceptDuplexRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "acceptDuplexRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "acceptDuplexRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "RequestWriter",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "RequestTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreaming",
    ));
    inline for (&.{
        "writeWithTimeout",
        "writeWithDeadline",
        "finishDataWithTimeout",
        "finishDataWithDeadline",
        "finishWithTimeout",
        "finishWithDeadline",
        "committedBytes",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.http2.runtime.RequestWriter,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "ResponseWriter",
    ));
    inline for (&.{
        "writeWithTimeout",
        "writeWithDeadline",
        "finishDataWithTimeout",
        "finishDataWithDeadline",
        "finishWithTimeout",
        "finishWithDeadline",
        "committedBytes",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.http2.runtime.ResponseWriter,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.ResponseWriter,
        "finishTrailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "ClientDuplexStream",
    ));
    inline for (&.{
        "writeWithTimeout",
        "writeWithDeadline",
        "writePartsWithTimeout",
        "writePartsWithDeadline",
        "writeRequestSlicesWithTimeout",
        "writeRequestSlicesWithDeadline",
        "finishRequestWithTimeout",
        "finishRequestWithDeadline",
        "finishRequestDataWithTimeout",
        "finishRequestDataWithDeadline",
        "finishRequestPartsWithTimeout",
        "finishRequestPartsWithDeadline",
        "requestCommittedBytes",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.http2.runtime.ClientDuplexStream,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "ServerDuplexStream",
    ));
    inline for (&.{
        "writeResponseWithTimeout",
        "writeResponseWithDeadline",
        "writeResponsePartsWithTimeout",
        "writeResponsePartsWithDeadline",
        "writeResponseSlicesWithTimeout",
        "writeResponseSlicesWithDeadline",
        "finishResponseWithTimeout",
        "finishResponseWithDeadline",
        "finishResponseDataWithTimeout",
        "finishResponseDataWithDeadline",
        "responseCommittedBytes",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.http2.runtime.ServerDuplexStream,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreaming",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreamingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreamingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreaming",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreamingWithHead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreamingWithHead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreamingWithHeadAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreamingWithHeadAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.RequestWriter,
        "readResponseStreamingWithHead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "StreamingRequestHead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "StreamingResponseHead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "StreamingRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "StreamingResponse",
    ));
    try std.testing.expect(@hasField(netz.http1.runtime.RequestOptions, "trailers"));
    try std.testing.expect(@hasField(netz.http1.runtime.ResponseOptions, "trailers"));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime,
        "HeaderNameCasing",
    ));
    try std.testing.expectEqual(
        netz.http1.runtime.HeaderNameCasing.preserve,
        (netz.http1.runtime.RequestOptions{}).header_name_casing,
    );
    try std.testing.expect(@hasField(
        netz.http1.runtime.RequestOptions,
        "header_name_casing",
    ));
    try std.testing.expect(@hasField(
        netz.http1.runtime.ResponseOptions,
        "header_name_casing",
    ));
    try std.testing.expect(@hasField(
        netz.http1.runtime.StreamingRequestOptions,
        "header_name_casing",
    ));
    try std.testing.expect(@hasField(
        netz.http1.runtime.StreamingResponseOptions,
        "header_name_casing",
    ));
    try std.testing.expect(@hasField(netz.http1.ParseOptions, "allow_obs_fold"));
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.websocket.runtime.Limits{}).max_frame_bytes);
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.websocket.runtime.Limits{}).max_message_bytes);
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Server, "serveUntil"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "PendingH2Upgrade",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Server,
        "receiveUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Server,
        "receiveUpgradeRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingH2Upgrade,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingH2Upgrade,
        "reject",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingH2Upgrade,
        "rejectWithBody",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "H2ConnectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2ConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2ConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Client,
        "openAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Client,
        "openAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "ExtendedConnectAttempt",
    ));
    try std.testing.expect(@hasField(
        netz.http2.runtime.ExtendedConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasField(
        netz.http2.runtime.ExtendedConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "openExtendedConnectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "openExtendedConnectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "TlsServer",
    ));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "h3"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.h3, "Client"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.h3, "Server"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectUri",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectUriAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectUriAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectUriAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "UriConnectOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "ConnectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectSessionWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectSessionAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectSessionAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectSessionAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Client,
        "connectSessionWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "acceptSessionWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "acceptSessionWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "receiveUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "receiveUpgradeRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.Server,
        "receiveSessionUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "PendingUpgrade",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.PendingUpgrade,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.PendingUpgrade,
        "reject",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.PendingUpgrade,
        "rejectWithBody",
    ));
    try std.testing.expect(@hasField(
        netz.websocket.runtime.h3.AcceptOptions,
        "require_subprotocol",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveFrame",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveMessage",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveMessageInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveMessageIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveMessageIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "sendBinaryParts",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "sendBinaryInPlace",
    ));
    inline for (&.{
        "sendTextWithTimeout",
        "sendTextWithDeadline",
        "sendBinaryWithTimeout",
        "sendBinaryWithDeadline",
        "sendPongWithTimeout",
        "sendPongWithDeadline",
        "sendPingWithTimeout",
        "sendPingWithDeadline",
        "sendCloseWithTimeout",
        "sendCloseWithDeadline",
        "sendCloseFrameWithTimeout",
        "sendCloseFrameWithDeadline",
        "sendFragmentedWithTimeout",
        "sendFragmentedWithDeadline",
        "sendBinaryInPlaceWithTimeout",
        "sendBinaryInPlaceWithDeadline",
        "sendBinarySlicesWithTimeout",
        "sendBinarySlicesWithDeadline",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.websocket.runtime.h3.ClientConnection,
            decl,
        ));
        try std.testing.expect(@hasDecl(
            netz.websocket.runtime.h3.ServerConnection,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "pingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "pingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "continuePingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "continuePingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "sendCloseFrame",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveCloseFrame",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveCloseFrameWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "receiveCloseFrameWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "continueCloseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3.ClientConnection,
        "continueCloseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "PingEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "CloseHandshakeEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "Message",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.h3,
        "MessageWriteProgress",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "MessageWriteProgress",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "UnixServer",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.UnixServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.UnixServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnix",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "ConnectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTlsAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTlsAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTlsAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectHostAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectHostAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectHostAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnixAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnixAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnixAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHostAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHostAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHostAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddressAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddressAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddressAttemptWithTimeout",
    ));
    try std.testing.expect(!@hasDecl(
        netz.http1.runtime,
        "LinuxIoUringStream",
    ));
    try std.testing.expect(!@hasDecl(
        netz.http1.runtime.Client,
        "requestUriLinuxIoUring",
    ));
    try std.testing.expect(!@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriLinuxIoUring",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnixWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnixWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTlsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTlsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "ServeUntilOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasField(netz.websocket.runtime.Connection, "send_mutex"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "OwnedMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "Message"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "PingEvent"));
    try std.testing.expect(@hasDecl(netz.websocket, "BorrowedFrame"));
    try std.testing.expect(@hasDecl(netz.websocket, "parseFrameInto"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "receiveMessage"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveFrameWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveCloseFrameWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveCloseFrameWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveFrameAutoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveFrameAutoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveMessageWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "receiveMessageInto"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveMessageIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "receiveMessageIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "pingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "pingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "continuePingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "continuePingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "continueCloseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "continueCloseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveMessageInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveFrameWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveCloseFrameWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveCloseFrameWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveFrameAutoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveFrameAutoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveMessageWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveMessageIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "receiveMessageIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "sendBinaryInPlace",
    ));
    inline for (&.{
        "sendTextWithTimeout",
        "sendTextWithDeadline",
        "sendBinaryWithTimeout",
        "sendBinaryWithDeadline",
        "sendPongWithTimeout",
        "sendPongWithDeadline",
        "sendPingWithTimeout",
        "sendPingWithDeadline",
        "sendCloseWithTimeout",
        "sendCloseWithDeadline",
        "sendCloseFrameWithTimeout",
        "sendCloseFrameWithDeadline",
        "sendFragmentedWithTimeout",
        "sendFragmentedWithDeadline",
        "sendBinaryInPlaceWithTimeout",
        "sendBinaryInPlaceWithDeadline",
        "sendBinarySlicesWithTimeout",
        "sendBinarySlicesWithDeadline",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.websocket.runtime.H2Connection,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.websocket,
        "decompressMessageInto",
    ));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "sendMessage"));
    inline for (&.{
        "sendTextWithTimeout",
        "sendTextWithDeadline",
        "sendBinaryWithTimeout",
        "sendBinaryWithDeadline",
        "sendPongWithTimeout",
        "sendPongWithDeadline",
        "sendPingWithTimeout",
        "sendPingWithDeadline",
        "sendCloseWithTimeout",
        "sendCloseWithDeadline",
        "sendCloseFrameWithTimeout",
        "sendCloseFrameWithDeadline",
        "sendFragmentedWithTimeout",
        "sendFragmentedWithDeadline",
        "sendBinaryInPlaceWithTimeout",
        "sendBinaryInPlaceWithDeadline",
        "sendBinarySlicesWithTimeout",
        "sendBinarySlicesWithDeadline",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.websocket.runtime.Connection,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "sendBinaryInPlace"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "sendFragmented"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAcceptedStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAcceptedStreamAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAcceptedTlsStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectAcceptedTlsStreamAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Server,
        "acceptStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "acceptHttpConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "acceptHttpConnectionWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "acceptHttpConnectionWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "receiveUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "receiveUpgradeRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "receiveUpgradeRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "receiveHttpUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Server,
        "receiveStreamUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.UnixServer,
        "receiveUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.UnixServer,
        "receiveHttpUpgradeRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "receiveUpgradeRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "receiveStreamUpgradeRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "PendingUpgrade",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingUpgrade,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingUpgrade,
        "reject",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingUpgrade,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.PendingUpgrade,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "acceptStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "acceptStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "acceptStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.UnixServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.UnixServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasField(netz.websocket.runtime.Connection, "close_sent"));
    try std.testing.expect(@hasField(netz.websocket.runtime.Connection, "close_received"));
    try std.testing.expect(@hasField(netz.websocket.runtime.Connection, "selected_protocol"));
    try std.testing.expect(@hasField(netz.websocket.runtime.Connection, "permessage_deflate"));
    try std.testing.expect(@hasField(netz.websocket.runtime.AcceptOptions, "protocols"));
    try std.testing.expect(@hasField(netz.websocket.runtime.AcceptOptions, "enable_permessage_deflate"));
    try std.testing.expect(@hasField(netz.websocket.runtime.Limits, "tcp_nodelay"));
    try std.testing.expect(@hasField(netz.websocket.runtime.ConnectOptions, "protocols"));
    try std.testing.expect(@hasField(netz.websocket.runtime.ConnectOptions, "enable_permessage_deflate"));
    try std.testing.expect(@hasField(netz.websocket.runtime.ConnectOptions, "tcp_nodelay"));
    try std.testing.expect(@hasField(netz.websocket.runtime.ConnectOptions, "extra_headers"));
    try std.testing.expect(@hasField(
        netz.websocket.runtime.ConnectOptions,
        "connect_timeout",
    ));
    try std.testing.expect(@hasField(
        netz.websocket.runtime.ConnectOptions,
        "tls_handshake_timeout",
    ));
    try std.testing.expect(@hasDecl(netz.websocket, "ExtensionNegotiation"));
    try std.testing.expect(@hasDecl(netz.websocket, "compressMessage"));
    try std.testing.expect(@hasDecl(netz.websocket, "decompressMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "H2Client"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "H2Server"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "H2Connection"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Client, "open"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Client,
        "openWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Client,
        "openWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Server, "accept"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Connection, "receiveMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Connection, "sendClose"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "pingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "continuePingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.H2Connection,
        "continueCloseWithTimeout",
    ));
    try std.testing.expectEqual(@as(u8, 0x40), netz.quic.varint.prefixForLength(2));
    try std.testing.expect(netz.http1.Method.GET.safe());
    try std.testing.expect(std.meta.stringToEnum(netz.http1.BodyFraming, "close_delimited") != null);
    try std.testing.expect(@hasDecl(netz.http1, "validateTrailers"));
    try std.testing.expect(@hasDecl(netz.http1, "validateHeader"));
    try std.testing.expect(@hasDecl(netz.http1, "validateRequestTarget"));
    try std.testing.expect(@hasDecl(netz.http1, "validateConnectTarget"));
    try std.testing.expect(@hasDecl(netz.http1, "validateReasonPhrase"));
    try std.testing.expect(@hasDecl(netz.http1, "validateStatusCode"));
    try std.testing.expect(@hasDecl(netz.http1, "statusCodeForbidsBody"));
    try std.testing.expect(@hasDecl(netz.http1, "validateResponseBodyForStatus"));
    try std.testing.expect(@hasDecl(netz.http1, "parseChunkSize"));
    try std.testing.expectEqual(@as(usize, 16 * 1024), netz.http1.max_chunk_extension_bytes);
    try std.testing.expectEqual(@as(u64, 9), netz.http2.FrameHeader.encoded_len);
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.http2.runtime.Limits{}).max_body_bytes);
    try std.testing.expectEqual(@as(usize, 16 * 1024), (netz.http2.runtime.Limits{}).max_header_list_size);
    try std.testing.expectEqual(@as(usize, 256), (netz.http2.runtime.Limits{}).max_peer_origins);
    try std.testing.expectEqual(@as(usize, 256), (netz.http2.runtime.Limits{}).max_alternative_services);
    try std.testing.expect(@hasField(
        netz.http2.runtime.Limits,
        "connect_timeout",
    ));
    try std.testing.expectEqual(
        @as(usize, 64),
        (netz.http2.runtime.Limits{}).max_reset_stream_history,
    );
    try std.testing.expectEqual(
        @as(i96, std.time.ns_per_s),
        (netz.http2.runtime.Limits{}).reset_stream_duration.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(?usize, 1024),
        (netz.http2.runtime.Limits{}).max_local_error_reset_streams,
    );
    try std.testing.expect(@hasDecl(netz.http2.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Server, "serveUntil"));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Server,
        "acceptUpgradeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Server,
        "acceptUpgradeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.http2.runtime, "UnixServer"));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.UnixServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.UnixServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Client,
        "connectUnix",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.TlsServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.TlsServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.TlsServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.TlsServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.TlsServer,
        "acceptStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.TlsServer,
        "acceptStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Server,
        "acceptStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Server,
        "acceptStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.UnixServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.UnixServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "ServeUntilOptions",
    ));
    try std.testing.expect(@hasField(netz.http2.runtime.Limits, "enable_connect_protocol"));
    try std.testing.expect(@hasField(netz.http2.runtime.Limits, "header_table_size"));
    try std.testing.expect(@hasField(netz.http2.runtime.Limits, "initial_window_size"));
    try std.testing.expect(@hasField(netz.http2.runtime.Limits, "max_concurrent_streams"));
    try std.testing.expect(@hasField(netz.http2.runtime.Limits, "max_frame_size"));
    try std.testing.expect(@hasField(netz.http2.runtime.RequestOptions, "protocol"));
    try std.testing.expect(@hasField(netz.http2.runtime.RequestOptions, "trailers"));
    try std.testing.expect(@hasField(netz.http2.runtime.ResponseOptions, "trailers"));
    try std.testing.expect(@hasField(netz.http2.runtime.OwnedRequest, "protocol"));
    try std.testing.expect(@hasField(netz.http2.runtime.OwnedRequest, "trailers"));
    try std.testing.expect(@hasField(netz.http2.runtime.OwnedResponse, "trailers"));
    try std.testing.expect(@hasDecl(netz.http2.runtime, "Tunnel"));
    try std.testing.expect(@hasDecl(netz.http2.runtime, "ExtendedConnectRequest"));
    try std.testing.expect(@hasDecl(netz.http2.runtime, "ExtendedConnectResponse"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "openExtendedConnect"));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "openExtendedConnectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "openExtendedConnectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "openConnectTunnel"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "readExtendedConnectRequest"));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readExtendedConnectRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readExtendedConnectRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "acceptExtendedConnect"));
    try std.testing.expect(@hasField(
        netz.http2.runtime.Limits,
        "max_local_error_reset_streams",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "rejectExtendedConnectWithBody",
    ));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "acceptConnectTunnel"));
    try std.testing.expect(@hasDecl(netz.http2, "PingPayload"));
    try std.testing.expect(@hasDecl(netz.http2, "GoAwayPayload"));
    try std.testing.expect(@hasDecl(netz.http2, "ResetStreamPayload"));
    try std.testing.expect(@hasDecl(netz.http2, "WindowUpdatePayload"));
    try std.testing.expect(@hasDecl(netz.http2, "PriorityPayload"));
    try std.testing.expect(@hasDecl(netz.http2, "PushPromisePayload"));
    try std.testing.expect(@hasDecl(netz.http2, "validateSetting"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "Decoder"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "Encoder"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "DynamicTable"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack.Decoder, "decodeBlockInto"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "encodeHuffman"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "decodeHuffman"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "freeDecodedFields"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "freeDecodedFieldStorages"));
    try std.testing.expect(@hasDecl(netz.http2.Hpack, "sensitiveHeaderName"));
    try std.testing.expect(@hasDecl(netz.http2.runtime, "FlowWindow"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.FlowWindow, "available"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "sendResetStream"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "readResetStream"));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readPriorityUpdateWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readPriorityUpdateWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResetStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readResetStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readPingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readPingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readGoAwayWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readGoAwayWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readWindowUpdateWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readWindowUpdateWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Tunnel,
        "readWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Tunnel,
        "readWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "TunnelWriteProgress",
    ));
    inline for (&.{
        "writeWithTimeout",
        "writeWithDeadline",
        "writePartsWithTimeout",
        "writePartsWithDeadline",
        "writeSlicesWithTimeout",
        "writeSlicesWithDeadline",
        "closeWriteWithTimeout",
        "closeWriteWithDeadline",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.http2.runtime.Tunnel,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "TunnelWriter",
    ));
    inline for (&.{
        "writeWithTimeout",
        "writeWithDeadline",
        "writePartsWithTimeout",
        "writePartsWithDeadline",
        "writeSlicesWithTimeout",
        "writeSlicesWithDeadline",
    }) |decl| {
        try std.testing.expect(@hasDecl(
            netz.http2.runtime.TunnelWriter,
            decl,
        ));
    }
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "releaseReceivedCapacity"));
    const stream_reset_error: netz.http2.runtime.Error = error.StreamReset;
    try std.testing.expect(stream_reset_error == error.StreamReset);
    const goaway_error: netz.http2.runtime.Error = error.ConnectionGoAway;
    try std.testing.expect(goaway_error == error.ConnectionGoAway);
    try std.testing.expect(@hasDecl(
        netz.http2.runtime,
        "GoAwayRetryDisposition",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "peerGoAwayLastStreamId",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "goAwayRetryDisposition",
    ));
    try std.testing.expectEqual(@as(u64, 0x01), netz.http3.FrameType.headers);
    try std.testing.expect(@hasField(netz.http3.Response, "request_method"));
    try std.testing.expect(@hasField(netz.http3.Response, "extended_connect"));
    try std.testing.expect(@hasField(
        netz.http3.ResponseDecodeOptions,
        "request_method",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3,
        "applyResponseHeadRequestSemantics",
    ));
    try std.testing.expect(@hasDecl(netz.http3, "firstHttp3AltSvc"));
    try std.testing.expect(@hasDecl(netz.http3, "firstHttp3AltSvcHeader"));
    try std.testing.expect(@hasDecl(netz.http3, "firstHttp3AltSvcTarget"));
    try std.testing.expect(@hasDecl(netz.http3, "altSvcTarget"));
    try std.testing.expect(@hasDecl(netz.http3, "isHttp3Alpn"));
    try std.testing.expect(@hasDecl(netz.http3, "Origin"));
    try std.testing.expect(@hasDecl(netz.http3, "OriginKey"));
    try std.testing.expect(@hasDecl(netz.http3, "requestOrigin"));
    try std.testing.expect(@hasDecl(netz.http3, "requestOriginKey"));
    try std.testing.expect(@hasDecl(netz.http3, "originKeyFromOrigin"));
    try std.testing.expect(@hasDecl(netz.http3, "sameOrigin"));
    try std.testing.expect(@hasDecl(netz.http3, "ReuseDecision"));
    try std.testing.expect(@hasDecl(netz.http3, "connectionReuseDecision"));
    try std.testing.expect(@hasDecl(netz.http3, "origin_pool"));
    try std.testing.expect(@hasDecl(netz.http3.origin_pool, "Pool"));
    try std.testing.expect(@hasDecl(netz.http3.origin_pool, "Config"));
    try std.testing.expect(@hasDecl(netz.http3.origin_pool, "Stats"));
    try std.testing.expect(@hasDecl(netz.http3.origin_pool.Pool(usize), "pruneExpired"));
    try std.testing.expect(@hasDecl(netz.http3.origin_pool.Pool(usize), "releaseKey"));
    try std.testing.expect(@hasDecl(netz.http3.origin_pool.Pool(usize), "hitRate"));
    try std.testing.expect(@hasDecl(netz.http3, "capsule"));
    try std.testing.expect(@hasDecl(netz.http3, "Datagram"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "OwnedConnectDatagram",
    ));
    try std.testing.expect(@hasDecl(netz.http3.capsule, "Iterator"));
    try std.testing.expect(@hasDecl(netz.http3.capsule, "writeInto"));
    try std.testing.expect(@hasDecl(netz.http3.capsule, "protocolEnabled"));
    try std.testing.expect(@hasDecl(netz.http3.Frame, "parseHeader"));
    try std.testing.expectEqual(@as(usize, 65_535), (netz.http3.runtime.Limits{}).quic.max_datagram_size);
    try std.testing.expect((netz.http3.runtime.Limits{}).auto_date_header);
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveBytesBatchTimeout"));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesBatchWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesBatchWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesIntoWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesWithTimeout",
    ));
    try std.testing.expectEqual(
        @as(usize, 128),
        (netz.http3.runtime.Limits{}).max_concurrent_request_streams,
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        (netz.http3.runtime.Limits{}).max_queued_runtime_datagrams,
    );
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestHeadWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveRequestEventForWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "finishRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "pollRequestEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "readRequestData",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "skipRequestData",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "startResponse",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "sendResponseBody",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "sendResponseBodyWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "sendResponseBodyWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "sendDevelopmentStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "sendDevelopmentStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Server,
        "cancelRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "requestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "requestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "requestWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "requestWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "startRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "sendRequestBody",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "sendRequestBodyWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "sendRequestBodyWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "sendDevelopmentStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "sendDevelopmentStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "receiveResponseEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "receiveResponseEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "receiveResponseEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "finishRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "pollResponseEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "readResponseData",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "skipResponseData",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.Client,
        "cancelRequest",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.Server, "receiveRequestsConcurrent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "ConcurrentServeResult"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ConcurrentServeResult,
        "successCount",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "ProtectedClient"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "HandshakeClient"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeClientPool",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeClientPoolOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeClientPoolDefaultConnector",
    ));
    try std.testing.expect(@hasField(
        netz.http3.runtime.HandshakeClientOptions,
        "connect_timeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "requestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "requestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendConnectDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "pollConnectDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveConnectDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "maxConnectDatagramPayloadSize",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "closeConnectDatagramAssociation",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "hasConnectDatagramAssociation",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "requestWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "requestWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "requestUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "requestUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClientPool,
        "requestUri",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClientPool,
        "requestUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClientPool,
        "requestUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "isReusable",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "abandonExtendedConnectOnce",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "trySendRequestBodyParts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "trySendRequestBodyBatch",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "BodyBatchProgress",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "BodyWriteProgress",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendRequestBodyPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendRequestBodyPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendRequestBodyPartsPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendRequestBodyPartsPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.SharedHandshakeClientPool.Lease,
        "trySendRequestBodyParts",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.SharedHandshakeClientPool.Lease,
        "trySendRequestBodyBatch",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "UriEndpoint"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "uriEndpoint"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendGoAway"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendGoAwayWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendGoAwayWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "pollControlWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "pollControlWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendMaxPushId"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendMaxPushIdWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendMaxPushIdWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "cancelPush"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "cancelPushWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "cancelPushWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "sendGoAway"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendGoAwayWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendGoAwayWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendOriginsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendOriginsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "pollControlWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "pollControlWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendPriorityUpdate"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendPriorityUpdateWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendPriorityUpdateWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendPushPriorityUpdate"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendPushPriorityUpdateWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendPushPriorityUpdateWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendRequest"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "requestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "requestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "requestWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "requestWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveResponse"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveNextResponse"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveNextResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveNextResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveNextResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveNextResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveResponseEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "pollResponseEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveResponseEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveResponseEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveNextResponseEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "pollNextResponseEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveNextResponseEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receiveNextResponseEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "readResponseData"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "skipResponseData",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receivePush"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePushWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePushWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePushWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePushWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receivePushEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "pollPushEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePushEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePushEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "readPushData"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "skipPushData",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "startRequest"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "startRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "startRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendRequestBody"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyPartsPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyPartsPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyPartsPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyBatchPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyBatchPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "sendRequestBodyBatchPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "finishRequestTrailers"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "finishRequestTrailersPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "finishRequestTrailersPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "OwnedProtectedResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "rejectRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "initiateShutdown"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "initiateShutdownWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "initiateShutdownWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "completeShutdown"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "completeShutdownWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "completeShutdownWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "drainComplete"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "receiveRequestEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "receiveRequestEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "receiveRequestEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "pollRequestEvent",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "readRequestData"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "skipRequestData",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "startResponse"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "startResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "startResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "sendResponseBody"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyPartsPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyPartsPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyPartsPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyBatchPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyBatchPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodyBatchPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodiesPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodiesPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseBodiesPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "finishResponseTrailers"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "finishResponseTrailersPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "finishResponseTrailersPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendGoAway"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendGoAwayWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendGoAwayWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "pollControlWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "pollControlWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "GoAwayRetryDisposition",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "peerGoAwayId",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "goAwayRetryDisposition",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "goAwayRetryDisposition",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePeerSettings",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePeerSettingsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedClient,
        "receivePeerSettingsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "serveConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptFromInitial",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "bindDispatcher",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "dispatcherBound",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseBodyPartsPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseBodyPartsPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "trySendResponseBodyParts",
    ));
    inline for (.{
        "sendConnectDatagrams",
        "trySendConnectDatagrams",
        "sendConnectDatagramsWithTimeout",
        "sendConnectDatagramsWithDeadline",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.http3.runtime.HandshakeServerSession,
            name,
        ));
        try std.testing.expect(@hasDecl(
            netz.http3.runtime.HandshakeClient,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendMaxPushId"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendMaxPushIdWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendMaxPushIdWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "trySendMaxPushId",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "cancelPush"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "cancelPushWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "cancelPushWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "tryCancelPush",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "trySendGoAway",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendGoAway"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendGoAwayWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendGoAwayWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "initiateShutdownWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "initiateShutdownWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "completeShutdownWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "completeShutdownWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "trySendOrigins",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendOriginsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendOriginsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "trySendGoAway",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendConnectDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "pollConnectDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveConnectDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "maxConnectDatagramPayloadSize",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "closeConnectDatagramAssociation",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "prepareConnectDatagramAssociation",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendPriorityUpdate"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendPriorityUpdateWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendPriorityUpdateWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "trySendPriorityUpdate",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendPushPriorityUpdate"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendPushPriorityUpdateWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "sendPushPriorityUpdateWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "trySendPushPriorityUpdate",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "connectUri"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "requestUri"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "requestUriAltSvc"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "requestUriAltSvcHeader"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveResponse"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "ReceiveTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveDetachedResponseProgressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveDetachedResponseProgressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "processDetachedResponsePacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "initEstablished",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectFrom",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "processResponsePacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePeerSettingsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "pollResponseEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "pollNextResponseEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "pollPushEvent",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveNextResponse"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveNextResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveNextResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveNextResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveNextResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveResponseEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveResponseEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveResponseEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveNextResponseEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveNextResponseEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receiveNextResponseEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "readResponseData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "skipResponseData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receivePush"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePushWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePushWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePushWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePushWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receivePushEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePushEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "receivePushEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "readPushData"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "skipPushData",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "startRequest"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "startRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "startRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequestBody"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequestBodyPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "BodyChunk"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequestBodyBatchPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "finishRequestTrailers"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "finishRequestTrailersPaced"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "finishRequestTrailersPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "finishRequestTrailersPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "OwnedHandshakeResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "rejectRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "finishRequest"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "finishRejectedRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "finishRequest",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "initiateShutdown"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "tryInitiateShutdown",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "completeShutdown"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "tryCompleteShutdown",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "drainComplete"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "receiveRequestEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveRequestEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveRequestEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "pollRequestEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "pollControlWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "pollControlWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "processRequestPacket",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "readRequestData"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "readRequestDataOnce",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "skipRequestData"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "skipRequestDataOnce",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "startResponse"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "startResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "startResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "tryStartResponse",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "serveOne"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "serve"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponsePaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponsePacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponsePacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receivePeerResponseCancellationWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receivePeerResponseCancellationWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseBody"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "trySendResponseLiteral",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "trySendResponseBody",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseBodyPaced"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseBodyPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseBodyPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseBodyBatchPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "finishResponseTrailers"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "tryFinishResponseTrailers",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "finishResponseTrailersPaced"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "finishResponseTrailersPacedWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "finishResponseTrailersPacedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "ShutdownState"));
    try std.testing.expect(@hasDecl(netz.http3, "SettingsState"));
    try std.testing.expectEqual(
        @as(u64, 0x10c),
        netz.http3.ApplicationErrorCode.request_cancelled,
    );
    try std.testing.expectEqual(
        @as(u64, 0x108),
        netz.http3.ApplicationErrorCode.id_error,
    );
    try std.testing.expectEqual(
        @as(usize, 256),
        netz.http3.default_max_priority_updates,
    );
    try std.testing.expect(@hasDecl(netz.http3, "ControlState"));
    try std.testing.expect(@hasDecl(netz.http3.ControlState, "init"));
    try std.testing.expect(@hasDecl(netz.http3.ControlState, "deinit"));
    try std.testing.expect(@hasDecl(netz.http3.ControlState, "clone"));
    try std.testing.expect(@hasDecl(netz.http3, "Priority"));
    try std.testing.expect(@hasDecl(netz.http3, "PriorityUpdatePayload"));
    try std.testing.expect(@hasDecl(netz.http3, "writePriorityUpdateFrame"));
    try std.testing.expect(@hasDecl(netz.http3, "writePushPriorityUpdateFrame"));
    try std.testing.expect(@hasDecl(netz.http3, "parsePriorityUpdatePayload"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "static_table"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "staticEntry"));
    try std.testing.expect(@hasDecl(netz.http3, "writeSettingsFrame"));
    try std.testing.expect(@hasDecl(netz.http3, "writeControlStreamPrefix"));
    try std.testing.expect(@hasDecl(netz.http3, "writeQpackEncoderStreamPrefix"));
    try std.testing.expect(@hasDecl(netz.http3, "writeQpackDecoderStreamPrefix"));
    try std.testing.expect(@hasDecl(netz.http3.ControlState, "registerControlStream"));
    try std.testing.expect(@hasDecl(netz.http3.ControlState, "registerQpackStream"));
    try std.testing.expect(@hasDecl(
        netz.http3.ControlState,
        "removeRequestPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.ControlState,
        "removePushPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.ControlState,
        "retireRequestPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.ControlState,
        "retirePushPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.ControlState,
        "discardRetiredPriorityUpdates",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.ControlState,
        "appendControlPayloadValidated",
    ));
    try std.testing.expect(@hasDecl(netz.http3, "writeMaxPushIdFrame"));
    try std.testing.expect(@hasDecl(netz.http3, "writeCancelPushFrame"));
    try std.testing.expect(@hasDecl(netz.http3, "writePushPromiseFrame"));
    try std.testing.expect(@hasDecl(netz.http3, "writePushPromiseDynamic"));
    try std.testing.expect(@hasDecl(netz.http3, "parsePushPromisePayload"));
    try std.testing.expect(@hasDecl(netz.http3, "decodePushPromiseWithDynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3, "DecodedPushPromise"));
    try std.testing.expect(@hasField(netz.http3.Request, "trailers"));
    try std.testing.expect(@hasField(netz.http3.Response, "trailers"));
    try std.testing.expect(@hasField(netz.http3.DecodedRequest, "trailers"));
    try std.testing.expect(@hasField(netz.http3.DecodedResponse, "body_storage"));
    try std.testing.expect(@hasField(netz.http3.Settings, "enable_webtransport"));
    try std.testing.expect(@hasField(netz.http3.Settings, "webtransport_initial_max_data"));
    try std.testing.expectEqual(
        @as(u64, 128),
        netz.http3.Settings.max_supported_qpack_blocked_streams,
    );
    try std.testing.expectEqual(@as(u64, 0x14e9cd29), @intFromEnum(netz.http3.SettingId.webtransport_max_sessions_v13));
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedConfig, "local_settings"));
    try std.testing.expect(@hasField(
        netz.http3.runtime.ProtectedConfig,
        "max_priority_updates",
    ));
    try std.testing.expect(@hasField(
        netz.http3.runtime.ProtectedConfig,
        "max_client_bidirectional_streams",
    ));
    try std.testing.expect(@hasField(
        netz.http3.runtime.ProtectedConfig,
        "response_scheduler_max_batch_packets",
    ));
    try std.testing.expect(
        @hasField(netz.http3.runtime.ProtectedConfig, "auto_date_header"),
    );
    try std.testing.expect((netz.http3.runtime.HandshakeSessionOptions{}).auto_date_header);
    try std.testing.expectEqual(
        @as(usize, 128),
        (netz.http3.runtime.HandshakeSessionOptions{}).max_concurrent_request_streams,
    );
    try std.testing.expectEqual(
        netz.http3.default_max_priority_updates,
        (netz.http3.runtime.HandshakeSessionOptions{}).max_priority_updates,
    );
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedClient, "control"));
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedClient, "qpack_encode"));
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedServer, "qpack_encode"));
    try std.testing.expect(@hasField(netz.http3.runtime.HandshakeClient, "control"));
    try std.testing.expect(@hasField(netz.http3.runtime.HandshakeClient, "qpack_encode"));
    try std.testing.expect(@hasField(netz.http3.runtime.HandshakeServerSession, "qpack_encode"));
    try std.testing.expect(@hasField(
        netz.http3.runtime.HandshakeServerOptions,
        "serve_connection_recovery_drain_timeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "waitForRecoveryIdleWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "waitForRecoveryIdleWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "waitForRecoveryIdleWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "waitForRecoveryIdleWithDeadline",
    ));
    try std.testing.expectEqual(@as(u8, 5), netz.mqtt.ProtocolVersion.v5.byte());
    try std.testing.expect(@hasDecl(netz.mqtt, "bridge"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge, "Bridge"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge, "Rule"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge, "Options"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge, "MultiOptions"));
    try std.testing.expect(@hasField(netz.mqtt.bridge.Bridge, "rule"));
    try std.testing.expect(@hasField(netz.mqtt.bridge.Bridge, "rules"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Bridge, "init"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Bridge, "initMany"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Bridge, "initHost"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.bridge.Bridge,
        "initHostMany",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.bridge.Bridge,
        "initConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.bridge.Bridge,
        "initConnectorMany",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Bridge, "connect"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Bridge, "step"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Bridge, "run"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Rule, "mapTopicAlloc"));
    try std.testing.expect(@hasDecl(netz.mqtt.bridge.Rule, "overlaps"));
    try std.testing.expect(@hasDecl(netz.mqtt, "reconnect"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "Client"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "ReconnectPolicy"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "Jitter"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "ClientEvent"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "PollOptions"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "CommandQueue"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "QueuedRun"));
    try std.testing.expect(@hasDecl(netz.mqtt.reconnect, "ClientOptions"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "InboundQoS2ReleasePolicy",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.reconnect.ClientOptions,
        "inbound_qos2_release_policy",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "hasSubscription",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "completeIncomingQoS2",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "peerMaximumPacketSize",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "PublishDelivery",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "PublishDeliveryHandler",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "PublishDeliveryQueue",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "OwnedPublishDelivery",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "PublishDeliveryQueueReceiveTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.PublishDeliveryQueue,
        "receiveTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.PublishDeliveryQueue,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.PublishDeliveryQueue,
        "ReceiveTimeoutError",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.reconnect.ClientOptions,
        "manual_acknowledgements",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.reconnect.ClientOptions,
        "publish_delivery",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "CommandCompletion",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "OwnedCommandCompletion",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "CompletionQueue",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "CompletionQueueReceiveTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CompletionQueue,
        "receiveTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CompletionQueue,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CompletionQueue,
        "ReceiveTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "ClientEventQueue",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "OwnedClientEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "ClientEventQueueReceiveTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.ClientEventQueue,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "QueuedEventRun",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "serveQueuedUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "runQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "runQueuedEvents",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "publishAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "publishAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "publishAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "CommandEnqueueTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "publishAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "publishAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "publishQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "publishQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "subscribeAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "subscribeAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "subscribeAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "unsubscribeAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "unsubscribeAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "unsubscribeAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "disconnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "disconnectAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "disconnectAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "disconnectAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "acknowledge",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "acknowledgeAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "acknowledgeAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "acknowledgeAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "flushPendingAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "flushPendingAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "flushPendingAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "beginReauthenticationAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "beginReauthenticationAsyncTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.CommandQueue,
        "beginReauthenticationAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "subscribeAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "subscribeAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "unsubscribeAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "unsubscribeAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "publishQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "subscribeQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "subscribeQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "subscribeQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "unsubscribeQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "unsubscribeQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "unsubscribeQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "disconnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "disconnectAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "disconnectAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "disconnectQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "disconnectQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "disconnectQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "acknowledge",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "acknowledgeAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "acknowledgeAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "acknowledgeQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "acknowledgeQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "acknowledgeQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "flushPendingAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "flushPendingAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "flushPendingQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "flushPendingQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "flushPendingQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "beginReauthenticationAsync",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "beginReauthenticationAsyncWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "beginReauthenticationQueued",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "beginReauthenticationQueuedTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.QueuedRun,
        "beginReauthenticationQueuedWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "disconnectWithProperties",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "acknowledge",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime,
        "AcknowledgeOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime,
        "ClientConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "HostReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "UriReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHostWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHostAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddressWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddressAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUriWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUriAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHostWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHostAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddressWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddressAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUriWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUriAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "ReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "HostReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "TlsHostReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "TlsAddressReconnectConnector",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "pollWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "initHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "initHostWithOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "initUri",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "initUriWithOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "pollWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect,
        "DeadlinePollOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "pollWithOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "beginReauthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "subscribe",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "unsubscribe",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "completeNextPublish",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "writeClientSessionTransmission",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "validTopicName"));
    try std.testing.expect(@hasDecl(netz.mqtt, "validTopicFilter"));
    try std.testing.expect(@hasDecl(netz.mqtt, "topicMatchesFilter"));
    try std.testing.expect(@hasDecl(netz.mqtt, "router"));
    try std.testing.expect(@hasDecl(netz.mqtt.router, "Router"));
    try std.testing.expect(@hasDecl(netz.mqtt.router.Router, "subscribe"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.router.Router,
        "subscribeWithStatus",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.router.Router,
        "subscribeWithIdentifierStatus",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.router.Router, "unsubscribe"));
    try std.testing.expect(@hasDecl(netz.mqtt.router.Router, "matchInto"));
    try std.testing.expect(@hasDecl(netz.mqtt.router.Router, "matchIntoForPublisher"));
    try std.testing.expect(@hasDecl(netz.mqtt.router.Router, "matchAlloc"));
    try std.testing.expect(@hasDecl(netz.mqtt.router.Router, "initWithOptions"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.router,
        "SharedSubscriptionStrategy",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "maximumQoS"));
    try std.testing.expect(@hasDecl(netz.mqtt, "retainAvailable"));
    try std.testing.expect(@hasDecl(netz.mqtt, "serverKeepAlive"));
    try std.testing.expect(@hasDecl(netz.mqtt, "receiveMaximum"));
    try std.testing.expect(@hasDecl(netz.mqtt, "maximumPacketSize"));
    try std.testing.expect(@hasDecl(
        netz.mqtt,
        "assignedClientIdentifier",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt,
        "messageExpiryInterval",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "retained"));
    try std.testing.expect(@hasDecl(netz.mqtt, "persistence"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.persistence,
        "saveAtomic",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "saveSnapshot",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "saveLiveSnapshot",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "restoreSnapshot",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ChangeAutosaveOptions",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.ChangeAutosaveOptions,
        "dir",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.ChangeAutosaveOptions,
        "sub_path",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.ChangeAutosaveOptions,
        "max_changes",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "stats",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "publishSystemStats",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "publishLocal",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "Stats"));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "LoadRates"));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "LoadSnapshot"));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "SystemMetric"));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "system_metrics"));
    try std.testing.expect(@hasField(netz.mqtt.broker.Stats, "uptime_seconds"));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Stats,
        "connections_received",
    ));
    try std.testing.expect(@hasField(netz.mqtt.broker.Stats, "load"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime, "TrafficStats"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime, "TrafficCounters"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "trafficStats",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "attachTrafficCounters",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.AcceptOptions,
        "traffic_counters",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Options,
        "system_stats_interval",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Options,
        "persistent_change_autosave",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "persistentChangeAutosaveError",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "drainIntoTrackingSnapshotChange",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Scheduler,
        "retryDue",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.router.Router,
        "sharedSubscriptionCount",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "aggregateStats",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.retained, "Store"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.retained.Store,
        "applyPublish",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.retained.Store,
        "applyParsedPublish",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.retained.Store,
        "deliveriesInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.retained.Store,
        "deliveriesAlloc",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "session"));
    try std.testing.expect(@hasDecl(netz.mqtt.session, "Store"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "openConnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "disconnectPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "enqueuePublish",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "drainInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "handleAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "recordIncomingQoS2",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "stats",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.session.Store,
        "find",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "will_scheduler"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler,
        "Scheduler",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Scheduler,
        "setConnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Scheduler,
        "acceptConnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Scheduler,
        "onReconnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Scheduler,
        "closeDisconnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Scheduler,
        "pollDue",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.will_scheduler.Due,
        "writePublish",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt,
        "willDelayInterval",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt,
        "sessionExpiryInterval",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "topicAlias"));
    try std.testing.expect(@hasDecl(netz.mqtt, "topicAliasMaximum"));
    try std.testing.expect(@hasDecl(netz.mqtt, "LastWill"));
    try std.testing.expect(@hasDecl(netz.mqtt, "ConnectPacketOptions"));
    try std.testing.expect(@hasDecl(netz.mqtt, "writeConnectPacket"));
    try std.testing.expect(@hasDecl(netz.mqtt, "writePingInto"));
    try std.testing.expectEqual(@as(usize, 2), netz.mqtt.ping_packet_len);
    try std.testing.expect(@hasField(netz.mqtt.Connect, "will"));
    try std.testing.expect(@hasField(netz.mqtt.runtime.ConnectOptions, "username"));
    try std.testing.expect(@hasField(netz.mqtt.runtime.ConnectOptions, "password"));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.ConnectOptions,
        "network_connect_timeout",
    ));
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.mqtt.runtime.Limits{}).max_packet_size);
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.Limits,
        "proxy_protocol",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.Limits,
        "proxy_v2_require_tls",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.Limits,
        "proxy_v2_require_client_certificate",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.Limits,
        "proxy_header_timeout",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Server, "serveUntil"));
    try std.testing.expect(@hasDecl(netz.mqtt, "broker"));
    try std.testing.expect(@hasDecl(netz.mqtt, "proxy_protocol"));
    try std.testing.expect(@hasDecl(netz.mqtt, "listener_namespace"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.listener_namespace,
        "Namespace",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.listener_namespace.Namespace,
        "mapTopicAlloc",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.listener_namespace.Namespace,
        "mapFilterAlloc",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.listener_namespace.Namespace,
        "visibleTopic",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.listener_namespace.Namespace,
        "mapConnectWill",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.proxy_protocol,
        "Metadata",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "Broker"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "BridgeQoS2Store",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "BridgeQoS2Key",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "stageBridgeQoS2",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "releaseBridgeQoS2",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "completeBridgeQoS2",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ConnectContext",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ConnectContextAuthorizationHandler",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "listen",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "serve",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.broker.Broker, "init"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "serveListeners",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "serveListenersUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "servePending",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "servePendingWithOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "enqueueSessionPublish",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Listener,
        "accept",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "Listener"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ListenerEndpoint",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ServeListenersUntilOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ListenerAuthorization",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.ListenerAuthorization,
        "use_username_as_client_id",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "ListenerAccessControlHandler",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "servePendingWithListenerOptions",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Listener,
        "authorization",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.ListenerEndpoint,
        "authorization",
    ));
    try std.testing.expectEqual(
        @as(usize, 1024),
        (netz.mqtt.broker.Limits{}).max_connections,
    );
    try std.testing.expectEqual(
        @as(usize, 4096),
        (netz.mqtt.broker.Limits{}).max_pending_incoming_qos2,
    );
    try std.testing.expectEqual(
        @as(usize, 65_536),
        (netz.mqtt.broker.Options{}).will.max_wills,
    );
    try std.testing.expectEqual(
        @as(usize, 16_384),
        (netz.mqtt.broker.Options{}).session.max_sessions,
    );
    try std.testing.expectEqualStrings(
        "netz-",
        (netz.mqtt.broker.Options{}).auto_client_id_prefix,
    );
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Options,
        "persistent_session_expiry_seconds",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.Options,
        "check_retain_source",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.broker.AccessControlHandler,
        "authorize_retained_source",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "RetainedSourceAuthorization",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.retained.Match,
        "source_client_id",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptPending",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime, "UnixServer"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "pendingSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime,
        "ServeUntilOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime,
        "serveSourceUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnix",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostWithConnAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUri",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriWithConnAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnixWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnixWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnixAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectHostAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUriAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnixWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnixWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Client,
        "connectUnixAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "establishClientWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.ClientConnector,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.reconnect.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "establishClientWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostWithConnAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostWithConnAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressWithConnAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnixWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnixWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnixAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUriWithConnAckWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUriAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectHostAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsHostAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectTlsAddressAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnixWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnixWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnixAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUriWithConnAckWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUriAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "pendingSource",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime, "PendingSource"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptPendingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptPendingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptStreamPendingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptStreamPendingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime,
        "PendingAcceptedClient",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.AcceptOptions,
        "assigned_client_identifier",
    ));
    try std.testing.expect(@hasField(netz.mqtt.runtime.Connection, "max_outgoing_inflight"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readPubAck"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "readConnectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "pingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "readClientPacketEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "readBrokerEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "readBrokerEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "readBrokerEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "localMaximumQoS",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "applyPubAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "applyPubRec",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "applyPubComp",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "shutdown",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "assignedClientId",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "writeEncodedSessionPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "readSessionPubRel",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.AckPacket, "accepted"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.ConnAck,
        "writeNoPropertiesInto",
    ));
    try std.testing.expectEqual(
        @as(usize, 5),
        netz.mqtt.ConnAck.no_properties_max_len,
    );
    try std.testing.expect(@hasDecl(
        netz.mqtt.AckPacket,
        "writeNoPropertiesInto",
    ));
    try std.testing.expectEqual(
        @as(usize, 5),
        netz.mqtt.AckPacket.no_properties_max_len,
    );
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubAckWithProperties"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubRecWithProperties"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubRec"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readPubRec"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubRel"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubRelWithProperties"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readPubRel"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubComp"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writePubCompWithProperties"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readPubComp"));
    try std.testing.expect(@hasDecl(netz.mqtt, "Unsubscribe"));
    try std.testing.expect(@hasDecl(netz.mqtt, "UnsubAck"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.SubAck,
        "writeNoPropertiesInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.SubAck,
        "noPropertiesWireLen",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.UnsubAck,
        "writeNoPropertiesInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.UnsubAck,
        "noPropertiesWireLen",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "unsubscribe"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readUnsubscribe"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writeUnsubAck"));
    try std.testing.expect(@hasDecl(netz.mqtt, "Auth"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.Disconnect,
        "writeNoPropertiesInto",
    ));
    try std.testing.expectEqual(
        @as(usize, 3),
        netz.mqtt.Disconnect.no_properties_max_len,
    );
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writeAuth"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readAuth"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.Auth,
        "writeNoPropertiesInto",
    ));
    try std.testing.expectEqual(
        @as(usize, 4),
        netz.mqtt.Auth.no_properties_max_len,
    );
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime,
        "ClientAuthHandler",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.PendingAcceptedClient,
        "challengeAuthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.PendingAcceptedClient,
        "receiveAuthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.PendingAcceptedClient,
        "authorizeAuthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.PendingAcceptedClient,
        "authorizeAuthenticationWithData",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "beginReauthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "receiveReauthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "acceptReauthentication",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "applyAuthenticationEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt,
        "authenticationMethod",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt,
        "authenticationData",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.runtime.BrokerEvent,
        "auth",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker,
        "AuthenticationHandler",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "initWebSocket",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "establishClient",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "initTls",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "tls_runtime"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "Client",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "Server",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "listen",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "accept",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "acceptPending",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "acceptPendingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "acceptPendingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "pendingSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Server,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ServerIdentity",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ServerSigner",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "CipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ClientAuthPolicy",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ClientCertificateVerifier",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ClientAuthRequirement",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime,
        "ClientIdentity",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.tls_runtime.Client,
        "connectUri",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ConnectOptions,
        "tcp_nodelay",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ConnectOptions,
        "client_identity",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ConnectOptions,
        "server_verifier",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ConnectOptions,
        "alpn_protocols",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ListenOptions,
        "identity",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ListenOptions,
        "client_auth",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ListenOptions,
        "alpn_protocols",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "updateTrafficKeys",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "keyUpdateCounts",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "acceptPendingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "acceptPendingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "acceptStreamPendingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.UnixServer,
        "acceptStreamPendingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "proxyMetadata",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "remoteAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "setTopicNamespace",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "topicNamespace",
    ));
    try std.testing.expect(@hasDecl(netz.mqtt, "websocket_runtime"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "Server",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "TlsServer",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "UnixServer",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.UnixServer,
        "pendingSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.UnixServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.UnixServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUnix",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.TlsServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.TlsServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.TlsServer,
        "acceptPending",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.TlsServer,
        "pendingSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "listen",
    ));
    inline for (.{
        "acceptWithDeadline",
        "acceptWithTimeout",
        "acceptPendingWithDeadline",
        "acceptPendingWithTimeout",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.mqtt.websocket_runtime.Server,
            name,
        ));
        try std.testing.expect(@hasDecl(
            netz.mqtt.websocket_runtime.UnixServer,
            name,
        ));
        try std.testing.expect(@hasDecl(
            netz.mqtt.websocket_runtime.TlsServer,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "accept",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "acceptPending",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "pendingSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime,
        "Client",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connect",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Client,
        "connectUri",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.websocket_runtime.ConnectOptions,
        "tls",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.websocket_runtime.ConnectOptions,
        "client_identity",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.websocket_runtime.ConnectOptions,
        "server_verifier",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.websocket_runtime.ConnectOptions,
        "use_vail_tls",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "TlsClientIdentityOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "ClientIdentity",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "ClientCertificateVerifier",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHost",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTls",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUnixWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsHostWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectTlsAddressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Client,
        "connectUriTlsWithDeadline",
    ));
    try std.testing.expect(@hasField(
        netz.websocket.runtime.ConnectOptions,
        "tls_identity",
    ));
    try std.testing.expect(@hasField(
        netz.websocket.runtime.ConnectOptions,
        "vail_tls",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "initVerified",
    ));
    try std.testing.expectEqual(@as(usize, 65_535), (netz.quic.runtime.Limits{}).max_datagram_size);
    try std.testing.expect(!(netz.quic.runtime.Limits{}).enable_gro_receive);
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveBytesBatch"));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Server,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Client,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.quic.runtime, "OwnedBytesBatch"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "receivePacketBatch"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "servicePacketBatch"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receivePacketBatchServicingTimersTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receivePacketBatchServicingTimersDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receivePacketServicingTimersTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receivePacketServicingTimersDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "visitPacketServicingTimersTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "visitPacketServicingTimersDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "servicePacketServicingTimersTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "servicePacketServicingTimersDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "ReceivedPacketBatch"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.ReceivedPacketBatch, "takeNext"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.ReceivedPacketBatch, "remaining"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "ConnectionBatchSendResult"));
    try std.testing.expectEqual(
        @as(u64, 1) << 23,
        netz.quic.protection.aes_128_gcm_confidentiality_limit,
    );
    try std.testing.expectEqual(
        @as(u64, 1) << 52,
        netz.quic.protection.aes_128_gcm_integrity_limit,
    );
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "encryptedPacketsWithCurrentKeys"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "authenticationFailureCount"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "getSendStreamStats"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "getRecvStreamStats"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "PeerStreamLifecycle"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "StreamLifecycle"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "peerStreamLifecycle",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "requestCompletedPeerStreamRelease",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "pendingDeliveryRecovery",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receivedStreamIdsAfterInto",
    ));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "sent_packet_stats"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "received_packet_stats"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "recovery_queue_stats"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "active_send_streams"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "active_receive_streams"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "closed_peer_stream_ranges"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "closed_local_stream_ranges"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "requestCompletedLocalStreamRelease",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "localStreamClosed",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "streamLifecycle",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "takeQlogError"));
    try std.testing.expectEqual(@as(usize, 16), netz.quic.protection.aes_128_key_len);
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "DynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "EncoderInstruction"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "findStaticName"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "applyEncoderInstructions"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "decodeRequiredInsertCount"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "encodeDynamicBlock"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "decodeDynamicBlock"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "decodeFieldSectionPrefix"));
    try std.testing.expect(@hasDecl(netz.http3.Qpack, "DecoderInstruction"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "QpackDecodeState"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "QpackEncodeState"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.QpackEncodeState, "configurePeerCapacity"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.QpackEncodeState, "abandonStream"));
    try std.testing.expect(@hasDecl(netz.http3.Request, "writeDynamic"));
    try std.testing.expect(@hasDecl(netz.http3.Request, "writeStreamingHeadDynamic"));
    try std.testing.expect(@hasDecl(netz.http3.Response, "writeDynamic"));
    try std.testing.expect(@hasDecl(netz.http3.Response, "writeStreamingHeadDynamic"));
    try std.testing.expect(@hasDecl(netz.http3, "writeTrailersDynamic"));
    try std.testing.expect(@hasDecl(netz.http3, "decodeRequestWithDynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3, "decodeResponseWithDynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3, "DecodedRequestHead"));
    try std.testing.expect(@hasDecl(netz.http3, "DecodedResponseHead"));
    try std.testing.expect(@hasDecl(netz.http3, "DecodedTrailers"));
    try std.testing.expect(@hasDecl(netz.http3, "decodeRequestHeadWithDynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3, "decodeResponseHeadWithDynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3, "decodeTrailersWithDynamicTable"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "StreamingMessageReader"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "StreamingEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "StreamingRequestEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "StreamingResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "StreamingPushEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "PushedResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "ServerPush"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "receiveRequest"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "receiveRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "receiveRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "sendResponseWithPush"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithPushPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithPushPacedAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithPushPacedAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithPushAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithPushAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.ProtectedServer,
        "sendResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "receiveRequest"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveDetachedRequestProgressWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "receiveDetachedRequestProgressWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseWithPush"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithPushPaced",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithPushPacedAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithPushPacedAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithPushAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithPushAndDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithInformationalAndTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "sendResponseWithInformationalAndDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.quic.crypto_stream, "Reassembler"));
    try std.testing.expectEqual(@as(usize, 1200), netz.quic.initial_exchange.min_initial_udp_datagram_size);
    try std.testing.expect(@hasDecl(netz.quic, "appendPadding"));
    try std.testing.expect(@hasDecl(netz.quic.initial_exchange, "sendInitialCrypto"));
    try std.testing.expect(@hasDecl(netz.quic.initial_exchange, "sendCoalescedInitialHandshakeCrypto"));
    try std.testing.expect(@hasDecl(netz.quic.initial_exchange, "receiveCoalescedInitialHandshakeCrypto"));
    try std.testing.expect(@hasDecl(netz.quic.initial_exchange, "openCoalescedInitialHandshakeCrypto"));
    try std.testing.expect(@hasDecl(netz.quic.initial_exchange, "openInitialCrypto"));
    try std.testing.expect(@hasDecl(netz.quic.initial_exchange, "openHandshakeCrypto"));
    try std.testing.expect(@hasDecl(netz.quic.tls_client_hello, "writeClientHello"));
    try std.testing.expect(@hasDecl(netz.quic.tls_client_hello, "deriveHandshakeSecrets"));
    try std.testing.expect(@hasDecl(netz.quic.tls_client_hello, "deriveHandshakeSecretsForVersion"));
    try std.testing.expect(@hasDecl(netz.quic.tls_client_hello, "deriveApplicationSecrets"));
    try std.testing.expect(@hasDecl(netz.quic.tls_client_hello, "deriveApplicationSecretsForVersion"));
    try std.testing.expect(@hasDecl(netz.quic, "tls"));
    try std.testing.expect(@hasDecl(netz.quic.tls, "auth"));
    try std.testing.expect(@hasDecl(netz.quic.tls, "trust"));
    try std.testing.expect(@hasDecl(netz.quic.tls, "client_auth"));
    try std.testing.expect(@hasDecl(netz.quic.tls.auth, "ServerIdentity"));
    try std.testing.expect(@hasDecl(netz.quic.handshake, "connect"));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.quic.handshake, "accept"));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.quic, "TransportParameters"));
    try std.testing.expect(@hasDecl(netz.quic, "VersionInformation"));
    try std.testing.expect(@hasDecl(netz.quic, "parseTransportParametersTyped"));
    try std.testing.expect(@hasDecl(netz.quic, "encodeTransportParameters"));
    try std.testing.expect(@hasDecl(netz.quic, "encodeVersionInformationFromVersions"));
    try std.testing.expect(@hasDecl(netz.quic, "validateTransportParameters"));
    try std.testing.expect(@hasDecl(netz.quic, "practical_transport_parameters"));
    try std.testing.expect(@hasDecl(netz.quic, "FramePacketType"));
    try std.testing.expect(@hasDecl(netz.quic.Frame, "wireLen"));
    try std.testing.expect(@hasDecl(netz.quic, "frameAllowedInPacketType"));
    try std.testing.expect(@hasDecl(netz.quic, "validateFrameForPacketType"));
    try std.testing.expect(@hasDecl(netz.quic, "VersionNegotiationPacket"));
    try std.testing.expectEqual(@as(u64, 1) << 32, netz.quic.max_idle_timeout_ms_cap);
    try std.testing.expect(@hasDecl(netz.quic, "writeVersionNegotiationPacket"));
    try std.testing.expect(@hasDecl(netz.quic, "parseVersionNegotiationPacket"));
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "versionNegotiationResponse"));
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "sendVersionNegotiationIfUnsupported"));
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveBytesHandlingVersionNegotiation"));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesHandlingVersionNegotiationWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveBytesHandlingVersionNegotiationWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveRoutedBytesHandlingVersionNegotiationWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveRoutedBytesHandlingVersionNegotiationWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Server,
        "receiveBytesHandlingVersionNegotiationWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Server,
        "receiveRoutedBytesHandlingVersionNegotiationWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "sendManyBytes"));
    try std.testing.expect(@hasDecl(netz.quic, "RetryPacket"));
    try std.testing.expect(@hasDecl(netz.quic, "writeRetryPacket"));
    try std.testing.expect(@hasDecl(netz.quic, "retryPacketLen"));
    try std.testing.expect(@hasDecl(netz.quic, "writeRetryPacketInto"));
    try std.testing.expect(@hasDecl(netz.quic, "verifyRetryIntegrityTag"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "issueInto"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "local_transport_parameters"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "address_validation_token"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "retry_source_connection_id"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "version"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "available_versions"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "local_transport_parameters"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "address_validation_secrets"));
    try std.testing.expect(@hasField(
        netz.quic.handshake.ServerOptions,
        "address_validation_replay_filter",
    ));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "retry_original_destination_connection_id"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "retry_source_connection_id"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "version"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "congestion_algorithm"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "enable_hystart"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "enable_pacing"));
    try std.testing.expect(@hasField(
        netz.quic.handshake.OneRttConfig,
        "enable_spin_bit",
    ));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "max_receive_window"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "max_stream_receive_window"));
    try std.testing.expect(@hasField(
        netz.quic.handshake.OneRttConfig,
        "enable_reset_partial_delivery",
    ));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_endpoint"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "initial_send_max_stream_data_bidi_local"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "initial_send_max_streams_bidi"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "initial_receive_max_streams_uni"));
    try std.testing.expectEqual(
        netz.quic.practical_transport_parameters.initial_max_streams_bidi,
        (netz.quic.one_rtt.ConnectionConfig{
            .peer = undefined,
            .receive_keys = undefined,
            .send_keys = undefined,
            .local_connection_id = &.{},
            .peer_connection_id = &.{},
        }).initial_receive_max_streams_bidi,
    );
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "max_receive_window"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "max_stream_receive_window"));
    try std.testing.expect(@hasField(
        netz.quic.one_rtt.ConnectionConfig,
        "enable_reset_partial_delivery",
    ));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_spin_bit"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "active_connection_id_limit"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_max_idle_timeout_ms"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_max_idle_timeout_ms"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_ack_delay_exponent"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_ack_delay_exponent"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_max_ack_delay_ms"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_pmtud"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "pmtud_max_probe_size"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_disable_active_migration"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_disable_active_migration"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_preferred_address"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_max_datagram_frame_size"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_max_datagram_frame_size"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "max_datagram_queue_items"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_ack_frequency"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "congestion_algorithm"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_hystart"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_pacing"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "pacing_max_burst_packets"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_min_ack_delay"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_min_ack_delay"));
    try std.testing.expect(@hasField(netz.quic.TransportParameters, "min_ack_delay"));
    try std.testing.expect(@hasDecl(netz.quic, "AckFrequencyFrame"));
    try std.testing.expect(@hasDecl(netz.quic.connection_id, "PeerPool"));
    try std.testing.expect(@hasDecl(netz.quic.connection_id.PeerPool, "addWithLimit"));
    try std.testing.expect(@hasDecl(netz.quic.connection_id.LocalPool, "issueQuicLb"));
    try std.testing.expect(@hasDecl(netz.quic.stateless_reset, "matches"));
    try std.testing.expect(@hasDecl(netz.quic.stateless_reset, "encodeInto"));
    try std.testing.expect(@hasDecl(netz.quic.stateless_reset, "encodeForConnectionIdInto"));
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "sendStatelessResetForConnectionId"));
    try std.testing.expectEqual(netz.quic.varint.max_value, netz.quic.protection.max_packet_number);
    try std.testing.expect(@hasDecl(netz.quic.protection, "packetNumberLen"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "packetNumberLenForPayload"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "shortPacketLen"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "sealShortPacketInto"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "initial_salt_v2"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "deriveInitialSecretsForVersion"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "deriveAes128KeysForVersion"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "peekProtectedLongPacketInfo"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "ProtectedLongPacketInfo"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "ZeroRttPacketOptions"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "sealZeroRttPacket"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "openZeroRttPacket"));
    try std.testing.expect(@hasField(netz.quic.protection.ShortPacketOptions, "spin_bit"));
    try std.testing.expect(@hasField(netz.quic.protection.OpenedShortPacket, "spin_bit"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "nextAes128PacketProtectionKeys"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "nextAes128PacketProtectionKeysForVersion"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "Aes128KeyPhaseState"));
    try std.testing.expect(@hasDecl(netz.quic.protection, "openShortPacketWithKeyUpdate"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "sendFrames"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "BatchSendOptions"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "BatchSendResult"));
    try std.testing.expect(@hasField(
        netz.quic.one_rtt.BatchSendResult,
        "protected_count",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "batchStorageSizes"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "sendFramesBatchInto"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "sendFramesBatchIntoProgress"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "sendFramesBatch"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "sendZeroRttFrames"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "receiveZeroRtt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "openZeroRttBytes"));
    try std.testing.expect(@hasDecl(netz.quic, "zero_rtt"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt, "sendFrames"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt, "EarlyDataSender"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "receiveWithKeyUpdate"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "openReceivedBytesWithKeyUpdate"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "Connection"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "receivePacketAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "receivePacketBatchServicingTimers"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "receiveRoutedDatagramAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "receiveRoutedDatagramWithEcnAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "closeTransport"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "isPeerInitiatedStreamIdWithinLimit",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "isPeerInitiatedBidirectionalStreamIdWithinLimit",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendMany"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendManyProgress"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendManyProgressAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "packetLenForFramesAtOffset"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendWithEcn"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "releaseReceivedCapacity"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "openStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "openStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "openUnidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "openUnidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendAckForPacketsIfNeeded"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ackDelayDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "serviceAckDelayTimerAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "retransmitPacketThresholdLoss"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "retransmitTimeThresholdLoss"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "timeThresholdLossDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ptoBackoffCount"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ptoPeriod"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ptoDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "retransmitPtoProbesAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "lossDetectionTimerDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "serviceLossDetectionTimer"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "localOneRttKeyPhase"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "peerOneRttKeyPhase"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "initiateKeyUpdate"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pendingOneRttKeyUpdateAckThreshold"));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake.EstablishedConnection,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake.EstablishedConnection,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake.EstablishedConnection,
        "initiateKeyUpdate",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "resetStream"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendStopSending"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "sendStopSendingWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "sendStopSendingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "streamResetReceived"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "StreamRead"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "pollStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "pollStreamId",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receiveStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receiveStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receiveStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receiveStreamId",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receiveStreamIdWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receiveStreamIdWithDeadline",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "streamStopped"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendHandshakeDone"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendNewToken"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendNewConnectionIdQuicLb"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendAddressValidationToken"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "latestNewToken"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "handshakeConfirmed"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "nextSpinBit"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "resetSpinBit"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "effectiveIdleTimeoutMillis"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "peerAddressValidated"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "setPeerAddressValidated"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "beginPeerMigration"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "beginPeerPreferredAddressMigration"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "peerPreferredAddress"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "peerActiveMigrationDisabled"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "localActiveMigrationDisabled"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendPendingPathChallengeAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pathValidationDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "checkPathValidationTimeouts"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "failedPathValidationCount"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "recordPeerAddressBytesReceived"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "recordPeerAddressDatagramReceived"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "antiAmplificationLimitRemaining"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendPmtuProbeAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pmtudCurrentSize"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pmtudShouldProbe"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "currentSendDatagramSize"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "idleTimeoutDeadlineMillis"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "checkIdleTimeout"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "keepAliveIntervalMillis"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "keepAliveDeadlineMillis"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "serviceKeepAliveAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendKeepAliveAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "nextTimerDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "serviceNextTimerAt"));
    try std.testing.expect(@hasDecl(netz.quic, "endpoint_timers"));
    try std.testing.expect(@hasDecl(netz.quic.endpoint_timers, "EndpointTimers"));
    try std.testing.expect(@hasDecl(netz.quic.endpoint_timers.EndpointTimers, "armFromConnection"));
    try std.testing.expect(@hasDecl(netz.quic.endpoint_timers.EndpointTimers, "earliestDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.endpoint_timers.EndpointTimers, "serviceConnection"));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveManyVisitingTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "closing"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "draining"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "checkCloseExpired"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendDatagram"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendDatagrams"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "trySendDatagrams"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendDatagramsWithTimeout"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendDatagramsWithDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "popDatagram"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "maxDatagramPayloadSize"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "datagramReceiveQueueLen"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendAckFrequency"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendImmediateAck"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ackFrequencyThreshold"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "immediateAckRequested"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "congestionAlgorithm"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "congestionWindow"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "congestionAvailable"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "bytesInFlight"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "hystartEnabled"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "hystartPhase"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pacingEnabled"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pacingBudgetAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "pacingDeadlineAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "nextPacketPacingDeadlineAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "decodedPeerAckDelayNanos"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "processStatelessResetDatagram"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ackRttSample"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "updateRttFromAck"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "persistentCongestionPeriod"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "CloseState"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "LossDetectionTimerDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "LossDetectionTimerKind"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "StreamResetInfo"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "StopSendingInfo"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space, "ReceivedPacketTracker"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space, "ReceivedPacketStats"));
    try std.testing.expect(@hasField(netz.quic.packet_space.ReceivedPacketStats, "retained_packets"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "wouldRecordFresh"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "recordFresh"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "recordWithEcn"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "latestEcnCounts"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "largestReceived"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "stats"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.ReceivedPacketTracker, "getStats"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space, "EcnCodepoint"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space, "default_packet_threshold"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "largestAcknowledged"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "sentWithEcn"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "validateAckEcnCounters"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "validateAckEcnFrame"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "ecnDisabled"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "validateAckCoversSentPackets"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "ackRttSample"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "detectPacketThresholdLoss"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "detectTimeThresholdLoss"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "persistentCongestionPeriod"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "timeThresholdLossDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "latestAckElicitingInFlightSentTime"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "sentAt"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space, "SentPacketStats"));
    try std.testing.expect(@hasField(netz.quic.packet_space.SentPacketStats, "ack_eliciting_in_flight_packets"));
    try std.testing.expect(@hasField(netz.quic.packet_space.SentPacketStats, "latest_ack_eliciting_in_flight_sent_time_ns"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "stats"));
    try std.testing.expect(@hasDecl(netz.quic.packet_space.SentPacketTracker, "getStats"));
    try std.testing.expect(@hasDecl(netz.quic.stream_state, "RecvState"));
    const stream_conflict_error: netz.quic.stream_state.Error = error.ConflictingStreamData;
    try std.testing.expect(stream_conflict_error == error.ConflictingStreamData);
    const crypto_conflict_error: netz.quic.crypto_stream.Error = error.ConflictingCryptoData;
    try std.testing.expect(crypto_conflict_error == error.ConflictingCryptoData);
    try std.testing.expect(@hasDecl(netz.quic.flow_control, "SendFlow"));
    try std.testing.expect(@hasDecl(netz.quic.recovery, "Queue"));
    try std.testing.expect(@hasDecl(netz.quic.recovery, "QueueStats"));
    try std.testing.expect(@hasDecl(netz.quic.recovery.Queue, "packetThresholdCandidate"));
    try std.testing.expect(@hasDecl(netz.quic.recovery.Queue, "packetNumberCandidate"));
    try std.testing.expect(@hasDecl(netz.quic.recovery.Queue, "ptoCandidateAt"));
    try std.testing.expect(@hasDecl(netz.quic.recovery.Queue, "stats"));
    try std.testing.expect(@hasDecl(netz.quic.recovery.Queue, "getStats"));
    try std.testing.expect(@hasDecl(netz.quic.congestion, "Controller"));
    try std.testing.expect(@hasDecl(netz.quic.congestion, "Algorithm"));
    try std.testing.expect(@hasDecl(netz.quic.congestion, "CubicState"));
    try std.testing.expect(@hasDecl(netz.quic.congestion.Controller, "initWithAlgorithm"));
    try std.testing.expect(@hasDecl(netz.quic.congestion.Controller, "onAckedWithContext"));
    try std.testing.expect(@hasDecl(netz.quic.congestion.Controller, "onExplicitCongestion"));
    try std.testing.expect(@hasDecl(netz.quic.congestion.Controller, "onPersistentCongestion"));
    try std.testing.expect(@hasDecl(netz.quic.congestion.Controller, "onRttSample"));
    try std.testing.expect(@hasDecl(netz.quic.congestion.Controller, "endAck"));
    try std.testing.expect(@hasDecl(netz.quic, "hystart"));
    try std.testing.expect(@hasDecl(netz.quic.hystart, "State"));
    try std.testing.expect(@hasDecl(netz.quic, "pacing"));
    try std.testing.expect(@hasDecl(netz.quic.pacing, "Pacer"));
    try std.testing.expect(@hasDecl(netz.quic.path_validation, "State"));
    try std.testing.expect(@hasDecl(netz.quic.path_validation.State, "pendingChallengeCount"));
    try std.testing.expect(@hasDecl(netz.quic.path_validation.State, "receiveResponseValidated"));
    try std.testing.expect(@hasDecl(netz.quic.path_validation.State, "earliestChallengeDeadline"));
    try std.testing.expect(@hasDecl(netz.quic.path_validation.State, "checkTimeouts"));
    try std.testing.expect(@hasDecl(netz.quic.rtt, "Stats"));
    try std.testing.expect(@hasDecl(netz.quic.rtt, "decodeAckDelayNanos"));
    try std.testing.expect(@hasDecl(netz.quic.rtt.Stats, "updateAt"));
    try std.testing.expect(@hasDecl(netz.quic.rtt.Stats, "onPersistentCongestion"));
    try std.testing.expect(@hasDecl(netz.quic, "pmtu"));
    try std.testing.expect(@hasDecl(netz.quic, "address_validation_token"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "encode"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "encodeInto"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "validate"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "encodeRetry"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "encodeRetryInto"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "validateRetry"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "validateRetryAnySecret"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "ReplayFilter"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "ReplayFilterSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token.ReplayFilter, "exportSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token.ReplayFilter, "initWithSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token.ReplayFilter, "entryCount"));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token,
        "SharedReplayFilter",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "init",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "initWithSnapshot",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "deinit",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "entryCount",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "contains",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "rememberValidated",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token.SharedReplayFilter,
        "exportSnapshot",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.address_validation_token,
        "validateAnySecretAndRememberShared",
    ));
    try std.testing.expect(@hasDecl(netz.quic, "retry_flow"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "issue"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "validate"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "validateAnySecret"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "processClient"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "ClientState"));
    try std.testing.expect(@hasDecl(netz.quic.retry_flow, "ProcessedRetry"));
    try std.testing.expect(@hasDecl(netz.quic, "version_negotiation"));
    try std.testing.expect(@hasDecl(netz.quic, "qlog"));
    try std.testing.expect(@hasDecl(netz.quic.qlog, "Trace"));
    try std.testing.expect(@hasDecl(netz.quic.qlog, "frame_adapter"));
    try std.testing.expect(@hasDecl(netz.quic.qlog, "Observer"));
    try std.testing.expect(@hasDecl(netz.quic, "keylog"));
    try std.testing.expect(@hasDecl(netz.quic.keylog, "Log"));
    try std.testing.expect(@hasDecl(netz.quic, "quic_lb"));
    try std.testing.expect(@hasDecl(netz.quic.quic_lb, "encode"));
    try std.testing.expect(@hasDecl(netz.quic.quic_lb, "decodeServerId"));
    try std.testing.expect(@hasDecl(netz.quic, "resumption"));
    try std.testing.expect(@hasDecl(netz.quic.resumption, "Cache"));
    try std.testing.expect(@hasDecl(netz.quic.resumption, "CacheStats"));
    try std.testing.expect(@hasDecl(netz.quic.resumption.Cache, "stats"));
    try std.testing.expect(@hasDecl(netz.quic.resumption.Cache, "getStats"));
    try std.testing.expect(@hasDecl(netz.quic.resumption, "tls_psk"));
    try std.testing.expect(@hasDecl(netz.quic.resumption, "ticket"));
    try std.testing.expect(@hasDecl(
        netz.quic.resumption.ticket,
        "ServerStore",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.resumption.ticket,
        "Keyring",
    ));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt, "handshake"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt, "ReplayFilter"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt, "replay_filter"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt.replay_filter, "Snapshot"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt.ReplayFilter, "exportSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt.ReplayFilter, "initWithSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt.ReplayFilter, "pruneExpired"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt.ReplayFilter, "entryCount"));
    try std.testing.expect(@hasDecl(netz.quic.zero_rtt.ReplayFilter, "nextExpiryMillis"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt, "EarlyDataSender"));
    try std.testing.expect(@hasDecl(netz.quic.version_negotiation, "processClient"));
    try std.testing.expect(@hasDecl(netz.quic.version_negotiation, "ClientState"));
    try std.testing.expect(@hasDecl(netz.quic.version_negotiation, "Processed"));
    try std.testing.expect(@hasDecl(netz.quic.version_negotiation, "selectMutualVersion"));
    try std.testing.expect(@hasDecl(netz.quic.pmtu, "State"));
    try std.testing.expectEqual(@as(usize, 1200), netz.quic.pmtu.min_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 100_000_000), netz.quic.rtt.default_initial_rtt_ns);
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveManyConcurrent"));
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveRoutedBytes"));
    try std.testing.expect(@hasDecl(netz.quic.connection_router, "Router"));
    try std.testing.expect(@hasField(netz.quic.connection_router.Route, "peer_address"));
    try std.testing.expect(@hasField(netz.quic.connection_router.Route, "active_migration_disabled"));
    try std.testing.expect(@hasDecl(netz.quic.connection_router.Router, "routeDatagramFrom"));
    try std.testing.expect(@hasDecl(netz.quic, "endpoint_dispatcher"));
    try std.testing.expect(@hasDecl(netz.quic, "endpoint_server"));
    try std.testing.expect(@hasDecl(netz.quic.endpoint_server, "Server"));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "receiveVisiting",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "receiveVisitingOnce",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "receiveVisitingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "receiveManyVisitingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "pollStreamId",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "trySend",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_server.Server,
        "acknowledgePacketIfNeeded",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher,
        "Dispatcher",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receive",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "serviceDueTimersAt",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "syncConnectionIds",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "localConnectionIdsInto",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher,
        "InitialDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher,
        "UnroutedKind",
    ));
    try std.testing.expect(@hasDecl(netz.quic.handshake, "acceptFromInitial"));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptFromInitialWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptFromInitialWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.quic.handshake, "connectFrom"));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "connectFromWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "connectFromWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptFromInitialSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptFromInitialSourceWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake,
        "acceptFromInitialSourceWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.quic, "handshake_inbox"));
    try std.testing.expect(@hasDecl(netz.quic.handshake_inbox, "Inbox"));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake_inbox.Inbox,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.handshake_inbox.Inbox,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.DatagramSource,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.DatagramSource,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "registerPendingHandshake",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "admitPendingHandshake",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "promotePendingHandshake",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "pollConnectionPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "replaceConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "pollPendingPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveVisiting",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveVisitingTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveVisitingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "receiveManyVisitingWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Dispatcher,
        "syncConnectionIdsIfChanged",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "visitRoutedDatagramAt",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "localConnectionIdRevision",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime,
        "RoutedBytesView",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveManyBytesIntoTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.runtime.Endpoint,
        "receiveManyBytesIntoWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "receivePendingPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptFromInitialSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptFromInitialWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptFromInitialWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptFromInitialSourceWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "acceptFromInitialSourceWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectFromWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectFromWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "beginHandshakeAdmission",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServer,
        "promoteAdmission",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeAdmissionOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeWorkerError",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeFailure",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "HandshakeFailure",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeAdmission,
        "deadline",
    ));
    try std.testing.expect(@hasField(
        netz.http3.runtime.HandshakeAdmissionOptions,
        "max_connections",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "HandshakeSupervisor",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "PromotedHandshakeSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeSupervisor,
        "receive",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeSupervisor,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeSupervisor,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeSupervisor,
        "connectionCount",
    ));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "EndpointServer"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "EndpointServerEvent"));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "receiveTransportOnce",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "receiveTransportWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "receiveTransportWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "serveTransportUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointTransportEvent,
        "deinit",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.EndpointServer,
        "takeSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "beginSessionAdmissionFromInitialSource",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "beginSessionAdmissionFromInitialSourceWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "beginSessionAdmissionFromInitialSourceWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "acceptSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "acceptSessionWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "acceptSessionWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestFromSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestFromSessionWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestFromSessionWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestFromInitialWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestFromInitialWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "HandshakeAdmission",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.endpoint_dispatcher.Event,
        "takeNewInitial",
    ));
    try std.testing.expect(netz.webtransport.SessionId.init(0).isClientInitiatedBidirectional());
    try std.testing.expect(@hasDecl(netz.webtransport, "SessionState"));
    try std.testing.expect(@hasDecl(netz.webtransport, "StreamRegistry"));
    try std.testing.expect(@hasDecl(
        netz.webtransport,
        "BidirectionalStreamHeader",
    ));
    try std.testing.expect(@hasDecl(netz.webtransport, "defaultSettings"));
    try std.testing.expect(@hasDecl(netz.webtransport, "ensureDatagramsNegotiated"));
    try std.testing.expectEqual(@as(?usize, 1199), netz.webtransport.maxDatagramPayloadSize(1200, .init(0)));
    try std.testing.expectEqual(@as(usize, 65_535), (netz.webtransport.runtime.Limits{}).http3.quic.max_datagram_size);
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveDatagramWithDeadline",
    ));
    inline for (.{
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.Server,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveSessionRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveSessionRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "sendSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "sendSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "drain",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "receiveSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "receiveSessionEventWithDeadline",
    ));
    inline for (.{
        "sendDatagram",
        "sendDatagramWithTimeout",
        "sendDatagramWithDeadline",
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.AcceptedSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "sessionId",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "remoteAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "sendStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "sendStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingSession,
        "sessionId",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.RejectedSession,
        "sessionId",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "SessionDataRead",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime,
        "DevelopmentBodyWriteProgress",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveDatagramWithDeadline",
    ));
    inline for (.{
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.ClientSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "drain",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveSessionEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendStreamWithDeadline",
    ));
    try std.testing.expect(@hasField(
        netz.webtransport.runtime.HandshakeUriConnectOptions,
        "h3",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectUriWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectUriWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectUriAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectPreconfiguredWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectPreconfiguredWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectPreconfiguredAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectPreconfiguredAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime, "ProtectedClientSession"));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "ProtectedSessionRead",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendSessionDataSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendSessionDataSlicesWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendSessionDataSlicesWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "sendDatagramWithDeadline",
    ));
    inline for (.{
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.ProtectedClientSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "receiveSessionEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "drain",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "sendDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "sendDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendSessionDataSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendSessionDataSlicesWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendSessionDataSlicesWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveSessionRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveSessionRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "sendDatagramWithDeadline",
    ));
    inline for (.{
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.ProtectedServer,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "drain",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "receiveSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedProtectedSession,
        "receiveSessionEventWithDeadline",
    ));
    inline for (.{
        "sendDatagram",
        "sendDatagramWithTimeout",
        "sendDatagramWithDeadline",
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.AcceptedProtectedSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(netz.webtransport.runtime, "HandshakeClientSession"));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "EstablishedConnectOptions",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "PendingHandshakeConnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "beginEstablishedConnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "beginConnectFrom",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "beginConnectFromWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "beginConnectFromWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeConnect,
        "processPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeConnect,
        "pollConnect",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeConnect,
        "pollConnectForDispatcher",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "StatefulProtectedServer",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "StatefulProtectedClientSession",
    ));
    inline for (.{
        "sendSessionData",
        "sendSessionDataWithTimeout",
        "sendSessionDataWithDeadline",
        "sendSessionDataSlices",
        "sendSessionDataSlicesWithTimeout",
        "sendSessionDataSlicesWithDeadline",
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "maxDatagramPayloadSize",
        "maxDatagramSize",
        "openBidirectionalStream",
        "openBidirectionalStreamWithTimeout",
        "openBidirectionalStreamWithDeadline",
        "openUnidirectionalStream",
        "openUnidirectionalStreamWithTimeout",
        "openUnidirectionalStreamWithDeadline",
        "sendStream",
        "sendStreamWithTimeout",
        "sendStreamWithDeadline",
        "sendStreamSlices",
        "sendStreamSlicesWithTimeout",
        "sendStreamSlicesWithDeadline",
        "writeStream",
        "writeStreamWithTimeout",
        "writeStreamWithDeadline",
        "writeStreamSlices",
        "writeStreamSlicesWithTimeout",
        "writeStreamSlicesWithDeadline",
        "setStreamPriority",
        "streamPriority",
        "writeStreams",
        "writeStreamsWithTimeout",
        "writeStreamsWithDeadline",
        "finishStream",
        "finishStreamWithTimeout",
        "finishStreamWithDeadline",
        "releaseCompletedPeerStream",
        "receiveStream",
        "receiveStreamWithTimeout",
        "receiveStreamWithDeadline",
        "pollCompleteStream",
        "pollStream",
        "readStream",
        "readStreamWithTimeout",
        "readStreamWithDeadline",
        "readStreamId",
        "readStreamIdWithTimeout",
        "readStreamIdWithDeadline",
        "flushPendingAck",
        "serviceTransport",
        "resetStream",
        "resetStreamWithTimeout",
        "resetStreamWithDeadline",
        "stopStream",
        "stopStreamWithTimeout",
        "stopStreamWithDeadline",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.StatefulProtectedClientSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "PendingHandshakeSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "sendSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "sendSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "sendSessionDataSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "sendSessionDataSlicesWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "sendSessionDataSlicesWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendSessionDataWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendSessionDataWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendSessionDataSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendSessionDataSlicesWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendSessionDataSlicesWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "RejectedHandshakeSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "EndpointServer",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "EndpointServerEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointServer,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointServer,
        "removeConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointServer,
        "serveUntil",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointServer,
        "receiveWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointServer,
        "receiveWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "sendDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "sendDatagrams",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "sendSessionData",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "sendSessionDataSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "sendStreamSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "writeStreamSlices",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "ReceiveTimeoutError",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "openBidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "openBidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "openUnidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "openUnidirectionalStreamWithDeadline",
    ));
    inline for (.{
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "sendStreamSlices",
        "sendStreamSlicesWithTimeout",
        "sendStreamSlicesWithDeadline",
        "writeStreamSlices",
        "writeStreamSlicesWithTimeout",
        "writeStreamSlicesWithDeadline",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.AcceptedHandshakeSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "releaseCompletedPeerStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveManyDatagramsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveManyDatagramsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "readStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "pollCompleteStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "readStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveSessionEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receivePeerConnectionCloseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receivePeerConnectionCloseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "pollPeerConnectionClose",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "openBidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "openBidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "openUnidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "openUnidirectionalStreamWithDeadline",
    ));
    inline for (.{
        "sendDatagrams",
        "sendDatagramsWithTimeout",
        "sendDatagramsWithDeadline",
        "sendStreamSlices",
        "sendStreamSlicesWithTimeout",
        "sendStreamSlicesWithDeadline",
        "writeStreamSlices",
        "writeStreamSlicesWithTimeout",
        "writeStreamSlicesWithDeadline",
    }) |name| {
        try std.testing.expect(@hasDecl(
            netz.webtransport.runtime.HandshakeClientSession,
            name,
        ));
    }
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "releaseCompletedPeerStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveManyDatagramsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveManyDatagramsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "readStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "pollCompleteStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "processPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "pollStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "pollDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "pollSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "readStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "stopStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "stopStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "stopStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "stopStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveSessionEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receivePeerConnectionCloseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receivePeerConnectionCloseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "pollPeerConnectionClose",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveDatagramWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "openBidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "openBidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "openUnidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "openUnidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "releaseCompletedPeerStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveDatagramWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveManyDatagramsWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveManyDatagramsWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "readStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "pollCompleteStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "processPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "pollStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "pollDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "pollSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "readStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "readStreamId",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "readStreamIdWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "readStreamIdWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "flushPendingAck",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "stopStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "stopStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveSessionEventWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receiveSessionEventWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "sendStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "releaseCompletedPeerStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "openClientBidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "openClientBidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeClient,
        "openClientBidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "openServerUnidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "openServerUnidirectionalStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.http3.runtime.HandshakeServerSession,
        "openServerUnidirectionalStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.EndpointAcceptedSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeServer,
        "receiveSessionRequestFromInitial",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.Server,
        "receiveSessionRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedServer,
        "receiveSessionRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingSession,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingSession,
        "reject",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingSession,
        "rejectWithBody",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingProtectedSession,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingProtectedSession,
        "reject",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingProtectedSession,
        "rejectWithBody",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "responseHeader",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "connectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "openBidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "openUnidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "sendStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ClientSession,
        "receiveStreamWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "openBidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "openUnidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "sendStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedSession,
        "receiveStreamWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ConnectAttempt,
        "requireAccepted",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "responseHeader",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedClientSession,
        "connectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedConnectAttempt,
        "requireAccepted",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.ProtectedConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasField(
        netz.webtransport.runtime.ConnectOptions,
        "headers",
    ));
    try std.testing.expect(@hasField(
        netz.webtransport.runtime.Limits,
        "max_rejection_body_bytes",
    ));
    try std.testing.expect(@hasField(
        netz.webtransport.runtime.ProtectedConnectOptions,
        "headers",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectUri",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectSession",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectSessionWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectSessionWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectSessionAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectSessionAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectSessionAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectUriAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "connectPreconfiguredAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeConnectAttempt,
        "requireAccepted",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sessionId",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "remoteAddress",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "remoteAddressValidated",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "rttNanos",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "closeConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "exportKeyingMaterial",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "initiateKeyUpdate",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "closeConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "closeConnection",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "processPacket",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "pollStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "pollDatagram",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "pollSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "peerCertificates",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "negotiatedAlpn",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "negotiatedCipherSuite",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "negotiatedTranscriptHash",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "initiateKeyUpdate",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "receiveSessionRequest",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "receiveSessionRequestWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "receiveSessionRequestWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "acceptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "acceptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "receiveSessionRequestFromWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "receiveSessionRequestFromWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "acceptFromWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedServer,
        "acceptFromWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeSession,
        "acceptWithHeaders",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeSession,
        "reject",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeSession,
        "rejectWithBody",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeSession,
        "forbidden",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeSession,
        "notFound",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.PendingHandshakeSession,
        "tooManyRequests",
    ));
    try std.testing.expect(@hasField(
        netz.webtransport.runtime.HandshakeConnectOptions,
        "headers",
    ));
    try std.testing.expect(@hasField(
        netz.webtransport.runtime.HandshakeClientSession,
        "response",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "writeStreams",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "connectAttempt",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "connectWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "connectWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "connectAttemptWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "connectAttemptWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedConnectAttempt,
        "requireAccepted",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedConnectAttempt,
        "body",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedConnectAttempt,
        "trailers",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receivePeerConnectionClose",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receivePeerConnectionCloseWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "receivePeerConnectionCloseWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "pollPeerConnectionClose",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.StatefulProtectedClientSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasField(netz.webtransport.runtime.OwnedHandshakeDatagram, "bytes"));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime.HandshakeClientSession, "receiveManyDatagrams"));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime.HandshakeClientSession, "maxDatagramPayloadSize"));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime.HandshakeClientSession, "datagramsNegotiated"));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime.HandshakeClientSession, "getStats"));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "openBidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "openUnidirectionalStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "setStreamPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "streamPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "sendStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "writeStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "finishStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "readStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "resetStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "stopStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "drain",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "receiveSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "readStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "writeStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "setStreamPriority",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "finishStream",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "drain",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "close",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "closeWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "closeWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "drainWithTimeout",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.HandshakeClientSession,
        "drainWithDeadline",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime.AcceptedHandshakeSession,
        "receiveSessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "StreamRead",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport.runtime,
        "SessionEvent",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport,
        "applicationErrorCodeToHttp3",
    ));
    try std.testing.expect(@hasDecl(
        netz.webtransport,
        "http3ToApplicationErrorCode",
    ));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt,
        "SendCredit",
    ));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime.AcceptedHandshakeSession, "getStats"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "pto_jitter_percentage"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "pto_jitter_percentage"));
    try std.testing.expect(@hasDecl(netz.quic, "ecn"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "automatic_ecn_policy"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "automatic_ecn_policy"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "jitteredPtoPeriod"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ptoJitterEnabled"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "ptoJitterEpoch"));
    try std.testing.expect(@hasDecl(
        netz.quic.one_rtt.Connection,
        "resetPartialDeliveryEnabled",
    ));
}
