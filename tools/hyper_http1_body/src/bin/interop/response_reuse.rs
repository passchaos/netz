//! Unknown-length HTTP/1.0 bodies require EOF even with a keep-alive request.
use bytes::Bytes;
use http_body_util::StreamBody;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, Version};

pub(super) async fn handle(
    request: Request<Incoming>,
) -> Result<Response<super::Body>, std::io::Error> {
    if request.method() != Method::GET
        || request.version() != Version::HTTP_10
        || request.uri().path() != "/eof"
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected EOF response request",
        ));
    }
    Ok(Response::new(StreamBody::new(super::ThreeFrameBody {
        first: Some(Bytes::from_static(b"hyper-eof")),
        second: None,
        trailers: None,
    })))
}
