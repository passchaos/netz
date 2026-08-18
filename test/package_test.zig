const std = @import("std");
const netz = @import("netz");

test "public modules are reachable" {
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
    try std.testing.expect(@hasDecl(netz, "tls"));
    try std.testing.expect(@hasDecl(netz.tls, "stream"));
    try std.testing.expect(@hasDecl(
        netz.tls.stream,
        "ServerConnection",
    ));
    try std.testing.expect(@hasDecl(netz.tls, "testing"));
    try std.testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", netz.websocket.handshake_guid);
    try std.testing.expectEqual(@as(usize, 64 * 1024), (netz.http1.runtime.Limits{}).max_head_bytes);
    try std.testing.expect(@hasDecl(netz.http1.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readResponseFromStreamBuffered"));
    try std.testing.expect(@hasDecl(netz.http1, "ResponseContext"));
    try std.testing.expect(@hasDecl(netz.http1, "parseResponseForRequest"));
    try std.testing.expect(@hasDecl(netz.http1, "RequestHead"));
    try std.testing.expect(@hasDecl(netz.http1, "ResponseHead"));
    try std.testing.expect(@hasDecl(netz.http1, "parseRequestHead"));
    try std.testing.expect(@hasDecl(netz.http1, "parseResponseHead"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readResponseFromStreamBufferedForRequest"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readRequestFromStreamBuffered"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "readResponseFromStreamForRequest"));
    try std.testing.expect(@hasDecl(netz.http1.runtime, "Tunnel"));
    try std.testing.expect(@hasDecl(netz.http1.runtime.Client, "openConnectTunnel"));
    try std.testing.expect(@hasDecl(netz.http1.runtime.Connection, "acceptConnectTunnel"));
    try std.testing.expect(@hasDecl(
        netz.http1.runtime.Connection,
        "readRequestBatchInto",
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
        "writeResponseBatch",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "readRequestStreaming",
    ));
    try std.testing.expect(@hasDecl(
        netz.http2.runtime.Connection,
        "requestStreaming",
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
    try std.testing.expect(@hasField(netz.http1.ParseOptions, "allow_obs_fold"));
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.websocket.runtime.Limits{}).max_frame_bytes);
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.websocket.runtime.Limits{}).max_message_bytes);
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime,
        "TlsServer",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.TlsServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.websocket.runtime.Connection,
        "peerCertificates",
    ));
    try std.testing.expect(@hasField(netz.websocket.runtime.Connection, "send_mutex"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "OwnedMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "Message"));
    try std.testing.expect(@hasDecl(netz.websocket, "BorrowedFrame"));
    try std.testing.expect(@hasDecl(netz.websocket, "parseFrameInto"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "receiveMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "receiveMessageInto"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "sendMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "sendBinaryInPlace"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.Connection, "sendFragmented"));
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
    try std.testing.expect(@hasDecl(netz.websocket, "ExtensionNegotiation"));
    try std.testing.expect(@hasDecl(netz.websocket, "compressMessage"));
    try std.testing.expect(@hasDecl(netz.websocket, "decompressMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "H2Client"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "H2Server"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime, "H2Connection"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Client, "open"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Server, "accept"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Connection, "receiveMessage"));
    try std.testing.expect(@hasDecl(netz.websocket.runtime.H2Connection, "sendClose"));
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
    try std.testing.expect(@hasDecl(netz.http2.runtime.Server, "serveConcurrent"));
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
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "openConnectTunnel"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "readExtendedConnectRequest"));
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "acceptExtendedConnect"));
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
    try std.testing.expect(@hasDecl(netz.http2.runtime.Connection, "releaseReceivedCapacity"));
    const stream_reset_error: netz.http2.runtime.Error = error.StreamReset;
    try std.testing.expect(stream_reset_error == error.StreamReset);
    const goaway_error: netz.http2.runtime.Error = error.ConnectionGoAway;
    try std.testing.expect(goaway_error == error.ConnectionGoAway);
    try std.testing.expectEqual(@as(u64, 0x01), netz.http3.FrameType.headers);
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
    try std.testing.expect(@hasDecl(netz.http3.capsule, "Iterator"));
    try std.testing.expect(@hasDecl(netz.http3.capsule, "writeInto"));
    try std.testing.expect(@hasDecl(netz.http3.capsule, "protocolEnabled"));
    try std.testing.expect(@hasDecl(netz.http3.Frame, "parseHeader"));
    try std.testing.expectEqual(@as(usize, 65_535), (netz.http3.runtime.Limits{}).quic.max_datagram_size);
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveBytesBatchTimeout"));
    try std.testing.expectEqual(
        @as(usize, 128),
        (netz.http3.runtime.Limits{}).max_concurrent_request_streams,
    );
    try std.testing.expect(@hasDecl(netz.http3.runtime.Server, "receiveRequestsConcurrent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "ProtectedClient"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "HandshakeClient"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "UriEndpoint"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "uriEndpoint"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendGoAway"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendMaxPushId"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "cancelPush"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "sendGoAway"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendPriorityUpdate"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendPushPriorityUpdate"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveNextResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receiveNextResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "readResponseData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receivePush"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "receivePushEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "readPushData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "startRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "sendRequestBody"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedClient, "finishRequestTrailers"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "OwnedProtectedResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "rejectRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "initiateShutdown"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "completeShutdown"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "drainComplete"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "receiveRequestEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "readRequestData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "startResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "sendResponseBody"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "finishResponseTrailers"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendGoAway"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendMaxPushId"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "cancelPush"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendGoAway"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendPriorityUpdate"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendPushPriorityUpdate"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "connectUri"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "requestUri"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "requestUriAltSvc"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "requestUriAltSvcHeader"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveNextResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receiveNextResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "readResponseData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "skipResponseData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receivePush"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "receivePushEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "readPushData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "startRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequestBody"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequestBodyPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "BodyChunk"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "sendRequestBodyBatchPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "finishRequestTrailers"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeClient, "finishRequestTrailersPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "OwnedHandshakeResponseEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "cancelRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "rejectRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "initiateShutdown"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "completeShutdown"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "drainComplete"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "receiveRequestEvent"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "readRequestData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "skipRequestData"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "startResponse"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseBody"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseBodyPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseBodyBatchPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "finishResponseTrailers"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "finishResponseTrailersPaced"));
    try std.testing.expect(@hasDecl(netz.http3.runtime, "ShutdownState"));
    try std.testing.expect(@hasDecl(netz.http3, "SettingsState"));
    try std.testing.expectEqual(
        @as(u64, 0x10c),
        netz.http3.ApplicationErrorCode.request_cancelled,
    );
    try std.testing.expect(@hasDecl(netz.http3, "ControlState"));
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
    try std.testing.expectEqual(
        @as(usize, 128),
        (netz.http3.runtime.HandshakeSessionOptions{}).max_concurrent_request_streams,
    );
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedClient, "control"));
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedClient, "qpack_encode"));
    try std.testing.expect(@hasField(netz.http3.runtime.ProtectedServer, "qpack_encode"));
    try std.testing.expect(@hasField(netz.http3.runtime.HandshakeClient, "control"));
    try std.testing.expect(@hasField(netz.http3.runtime.HandshakeClient, "qpack_encode"));
    try std.testing.expect(@hasField(netz.http3.runtime.HandshakeServerSession, "qpack_encode"));
    try std.testing.expectEqual(@as(u8, 5), netz.mqtt.ProtocolVersion.v5.byte());
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
    try std.testing.expect(@hasField(netz.mqtt.Connect, "will"));
    try std.testing.expect(@hasField(netz.mqtt.runtime.ConnectOptions, "username"));
    try std.testing.expect(@hasField(netz.mqtt.runtime.ConnectOptions, "password"));
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), (netz.mqtt.runtime.Limits{}).max_packet_size);
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Server, "serveConcurrent"));
    try std.testing.expect(@hasDecl(netz.mqtt, "broker"));
    try std.testing.expect(@hasDecl(netz.mqtt.broker, "Broker"));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "listen",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.broker.Broker,
        "serve",
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
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Server,
        "acceptPending",
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
        "readBrokerEvent",
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
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "unsubscribe"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readUnsubscribe"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writeUnsubAck"));
    try std.testing.expect(@hasDecl(netz.mqtt, "Auth"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "writeAuth"));
    try std.testing.expect(@hasDecl(netz.mqtt.runtime.Connection, "readAuth"));
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
        "serveConcurrent",
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
        netz.mqtt.tls_runtime.ListenOptions,
        "identity",
    ));
    try std.testing.expect(@hasField(
        netz.mqtt.tls_runtime.ListenOptions,
        "client_auth",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.runtime.Connection,
        "peerCertificates",
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
        netz.mqtt.websocket_runtime.TlsServer,
        "serveConcurrent",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "listen",
    ));
    try std.testing.expect(@hasDecl(
        netz.mqtt.websocket_runtime.Server,
        "accept",
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
        "connectUriTls",
    ));
    try std.testing.expect(@hasField(
        netz.websocket.runtime.ConnectOptions,
        "tls_identity",
    ));
    try std.testing.expect(@hasDecl(
        netz.tls.stream.ClientConnection,
        "initVerified",
    ));
    try std.testing.expectEqual(@as(usize, 65_535), (netz.quic.runtime.Limits{}).max_datagram_size);
    try std.testing.expect(!(netz.quic.runtime.Limits{}).enable_gro_receive);
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "receiveBytesBatch"));
    try std.testing.expect(@hasDecl(netz.quic.runtime, "OwnedBytesBatch"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "receivePacketBatch"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "servicePacketBatch"));
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
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "sent_packet_stats"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "received_packet_stats"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionStats, "recovery_queue_stats"));
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
    try std.testing.expect(@hasDecl(netz.http3.runtime.ProtectedServer, "sendResponseWithPush"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "receiveRequest"));
    try std.testing.expect(@hasDecl(netz.http3.runtime.HandshakeServerSession, "sendResponseWithPush"));
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
    try std.testing.expect(@hasDecl(netz.quic.handshake, "accept"));
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
    try std.testing.expect(@hasDecl(netz.quic.runtime.Endpoint, "sendManyBytes"));
    try std.testing.expect(@hasDecl(netz.quic, "RetryPacket"));
    try std.testing.expect(@hasDecl(netz.quic, "writeRetryPacket"));
    try std.testing.expect(@hasDecl(netz.quic, "verifyRetryIntegrityTag"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "local_transport_parameters"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "address_validation_token"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "retry_source_connection_id"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "version"));
    try std.testing.expect(@hasField(netz.quic.handshake.ClientOptions, "available_versions"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "local_transport_parameters"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "address_validation_secrets"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "retry_original_destination_connection_id"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "retry_source_connection_id"));
    try std.testing.expect(@hasField(netz.quic.handshake.ServerOptions, "version"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "congestion_algorithm"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "enable_hystart"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "enable_pacing"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "max_receive_window"));
    try std.testing.expect(@hasField(netz.quic.handshake.OneRttConfig, "max_stream_receive_window"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_endpoint"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "initial_send_max_stream_data_bidi_local"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "initial_send_max_streams_bidi"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "initial_receive_max_streams_uni"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "max_receive_window"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "max_stream_receive_window"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_spin_bit"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "active_connection_id_limit"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_max_idle_timeout_ms"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_max_idle_timeout_ms"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "local_ack_delay_exponent"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_ack_delay_exponent"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "peer_max_ack_delay_ms"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "enable_pmtud"));
    try std.testing.expect(@hasField(netz.quic.one_rtt.ConnectionConfig, "pmtud_max_probe_size"));
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
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendMany"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendManyProgress"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendManyProgressAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "packetLenForFramesAtOffset"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendWithEcn"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendAt"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "releaseReceivedCapacity"));
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
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "resetStream"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendStopSending"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "streamResetReceived"));
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
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "closing"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "draining"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "checkCloseExpired"));
    try std.testing.expect(@hasDecl(netz.quic.one_rtt.Connection, "sendDatagram"));
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
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "validate"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "encodeRetry"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "validateRetry"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "validateRetryAnySecret"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "ReplayFilter"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token, "ReplayFilterSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token.ReplayFilter, "exportSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token.ReplayFilter, "initWithSnapshot"));
    try std.testing.expect(@hasDecl(netz.quic.address_validation_token.ReplayFilter, "entryCount"));
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
    try std.testing.expect(@hasDecl(netz.webtransport.runtime, "ProtectedClientSession"));
    try std.testing.expect(@hasDecl(netz.webtransport.runtime, "HandshakeClientSession"));
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
    try std.testing.expectEqual(@as(u32, 0x2112A442), netz.webrtc.stun.magic_cookie);
    try std.testing.expect(@hasDecl(netz.webrtc.stun, "writeIceBindingRequest"));
    try std.testing.expect(@hasDecl(netz.webrtc.stun, "validateMessageIntegrity"));
    try std.testing.expect(@hasDecl(netz.webrtc.stun, "validateFingerprint"));
    try std.testing.expect(@hasDecl(netz.webrtc.stun, "BindingRequestOptions"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtp, "HeaderExtensionElement"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtp, "parseHeaderExtensionElements"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtp, "writeOneByteHeaderExtensions"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtp, "writeTwoByteHeaderExtensions"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtp, "transportWideSequenceNumber"));
    try std.testing.expectEqual(@as(u16, 0xbede), netz.webrtc.rtp.one_byte_header_extension_profile);
    try std.testing.expect(@hasDecl(netz.webrtc, "rtcp"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "SenderStats"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "ntpTimestamp"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "ReceiverReport"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "SourceDescription"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "writeCompound"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "parseCompound"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "ReceiverStats"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "PictureLossIndication"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "FullIntraRequest"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "FirEntry"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "TransportLayerNack"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "TransportWideCc"));
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "TwccPacketResult"));
    try std.testing.expectEqual(@as(u5, 15), netz.webrtc.rtcp.transport_feedback_twcc);
    try std.testing.expect(@hasDecl(netz.webrtc.rtcp, "NackTracker"));
    try std.testing.expect(@hasDecl(netz.webrtc, "srtp"));
    try std.testing.expect(@hasDecl(netz.webrtc.srtp, "Context"));
    try std.testing.expect(@hasDecl(netz.webrtc.srtp.Context, "protectRtpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.srtp.Context, "unprotectRtp"));
    try std.testing.expect(@hasDecl(netz.webrtc.srtp.Context, "protectRtcpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.srtp.Context, "unprotectRtcp"));
    try std.testing.expectEqual(@as(usize, 10), netz.webrtc.srtp.auth_tag_len_80);
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "extractFingerprint"));
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "extractIceCredentials"));
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "Fingerprint"));
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "IceCredentials"));
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "ExtMap"));
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "parseExtMapAttribute"));
    try std.testing.expect(@hasDecl(netz.webrtc.sdp, "findExtMapInSession"));
    try std.testing.expectEqualStrings("urn:ietf:params:rtp-hdrext:sdes:mid", netz.webrtc.sdp.sdes_mid_uri);
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "DataChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "Reassembler"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "ReassembledMessage"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "ReceiveState"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "SackChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeSackPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "InitChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeInitPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeCookieEchoPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeCookieAckPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "ReconfigChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeReconfigPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "ForwardTsnChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeForwardTsnPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "HeartbeatChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeHeartbeatPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "ShutdownChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeShutdownPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "AbortChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "ErrorChunk"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeAbortPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeErrorPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "writeDataPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.sctp, "parseDcepMessage"));
    try std.testing.expectEqual(@as(usize, 2048), (netz.webrtc.runtime.Limits{}).max_datagram_size);
    try std.testing.expect(@hasDecl(netz.webrtc.runtime, "RtpClient"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime, "Peer"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime, "DtlsDatagram"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime, "RtcpDatagram"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime, "SrtpDatagram"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime, "SrtcpDatagram"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "sendSrtpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "receiveSrtpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "sendSrtcpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "receiveSrtcpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "sendRtcpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "receiveRtcpPacket"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "iceBindingRequest"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.StunClient, "iceBindingRequest"));
    try std.testing.expect(@hasDecl(netz.webrtc.runtime.Peer, "receiveManyConcurrent"));
}
