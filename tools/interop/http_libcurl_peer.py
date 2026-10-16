#!/usr/bin/env python3
"""Drive HTTP/1.1 chunked-trailer interop through libcurl's C ABI."""

from __future__ import annotations

import ctypes
import ctypes.util
from dataclasses import dataclass, field
from pathlib import Path


# Stable libcurl 8.5.0 ABI values from include/curl/curl.h. Pointer options use
# the 10000 range, function callbacks the 20000 range, and CURLINFO_LONG the
# 0x200000 range. Keeping this narrow list here avoids requiring development
# headers merely to exercise the installed production shared library.
CURLOPT_WRITEDATA = 10001
CURLOPT_URL = 10002
CURLOPT_READDATA = 10009
CURLOPT_WRITEFUNCTION = 20011
CURLOPT_READFUNCTION = 20012
CURLOPT_HTTPHEADER = 10023
CURLOPT_HEADERDATA = 10029
CURLOPT_POST = 47
CURLOPT_POSTFIELDSIZE = 60
CURLOPT_CAINFO = 10065
CURLOPT_HEADERFUNCTION = 20079
CURLOPT_HTTPGET = 80
CURLOPT_HTTP_VERSION = 84
CURLOPT_NOSIGNAL = 99
CURLOPT_TIMEOUT_MS = 155
CURLOPT_CONNECTTIMEOUT_MS = 156
CURLOPT_NOPROXY = 10177
CURLOPT_RESOLVE = 10203
CURLOPT_TRAILERFUNCTION = 20283
CURLOPT_TRAILERDATA = 10284

CURLINFO_RESPONSE_CODE = 0x200002
CURLINFO_NUM_CONNECTS = 0x20001A
CURLINFO_HTTP_VERSION = 0x20002E

CURL_HTTP_VERSION_1_1 = 2
CURL_GLOBAL_ALL = 3
CURL_TRAILERFUNC_OK = 0
CURLH_TRAILER = 1 << 1
CURLHE_OK = 0

REQUEST_BODY = b"libcurl-request-body"
REQUEST_TRAILER_NAME = b"x-libcurl-request-complete"
RESPONSE_TRAILER_NAME = b"x-netz-libcurl-response-complete"

WRITE_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.c_void_p,
)
READ_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.c_void_p,
)
TRAILER_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_void_p,
)


class LibcurlError(RuntimeError):
    pass


class CurlHeader(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("value", ctypes.c_char_p),
        ("amount", ctypes.c_size_t),
        ("index", ctypes.c_size_t),
        ("origin", ctypes.c_uint),
        ("anchor", ctypes.c_void_p),
    ]


@dataclass
class Capture:
    body: bytearray = field(default_factory=bytearray)
    headers: list[bytes] = field(default_factory=list)


@dataclass
class Upload:
    data: bytes
    offset: int = 0


def _capture_from_userdata(userdata: int) -> Capture:
    pointer = ctypes.cast(
        userdata,
        ctypes.POINTER(ctypes.py_object),
    )
    return pointer.contents.value


def _object_from_userdata(userdata: int) -> object:
    pointer = ctypes.cast(
        userdata,
        ctypes.POINTER(ctypes.py_object),
    )
    return pointer.contents.value


@READ_CALLBACK
def _read_body(
    destination: int,
    size: int,
    count: int,
    userdata: int,
) -> int:
    upload = _object_from_userdata(userdata)
    assert isinstance(upload, Upload)
    capacity = size * count
    remaining = upload.data[upload.offset :]
    part = remaining[:capacity]
    if not part:
        return 0
    ctypes.memmove(destination, part, len(part))
    upload.offset += len(part)
    return len(part)


@WRITE_CALLBACK
def _write_body(
    data: int,
    size: int,
    count: int,
    userdata: int,
) -> int:
    length = size * count
    _capture_from_userdata(userdata).body.extend(
        ctypes.string_at(data, length)
    )
    return length


@WRITE_CALLBACK
def _write_header(
    data: int,
    size: int,
    count: int,
    userdata: int,
) -> int:
    length = size * count
    _capture_from_userdata(userdata).headers.append(
        ctypes.string_at(data, length)
    )
    return length


class LibcurlPeer:
    def __init__(self) -> None:
        library_name = ctypes.util.find_library("curl")
        if library_name is None:
            raise LibcurlError("installed libcurl shared library not found")
        self.library = ctypes.CDLL(library_name)
        self.library.curl_global_init.argtypes = [ctypes.c_long]
        self.library.curl_global_init.restype = ctypes.c_int
        self.library.curl_global_cleanup.argtypes = []
        self.library.curl_easy_init.argtypes = []
        self.library.curl_easy_init.restype = ctypes.c_void_p
        self.library.curl_easy_cleanup.argtypes = [ctypes.c_void_p]
        self.library.curl_easy_setopt.restype = ctypes.c_int
        self.library.curl_easy_perform.argtypes = [ctypes.c_void_p]
        self.library.curl_easy_perform.restype = ctypes.c_int
        self.library.curl_easy_getinfo.restype = ctypes.c_int
        self.library.curl_easy_header.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(CurlHeader)),
        ]
        self.library.curl_easy_header.restype = ctypes.c_int
        self.library.curl_easy_strerror.argtypes = [ctypes.c_int]
        self.library.curl_easy_strerror.restype = ctypes.c_char_p
        self.library.curl_slist_append.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
        ]
        self.library.curl_slist_append.restype = ctypes.c_void_p
        self.library.curl_slist_free_all.argtypes = [ctypes.c_void_p]
        self.library.curl_version.argtypes = []
        self.library.curl_version.restype = ctypes.c_char_p
        self._check(self.library.curl_global_init(CURL_GLOBAL_ALL))
        version = self.library.curl_version()
        if version is None or not version.startswith(b"libcurl/8.5.0 "):
            self.close()
            raise LibcurlError(f"expected libcurl 8.5.0, found {version!r}")
        self.version = version.decode().split()[0]
        self.closed = False

    def close(self) -> None:
        if getattr(self, "closed", False):
            return
        self.library.curl_global_cleanup()
        self.closed = True

    def _check(self, code: int) -> None:
        if code == 0:
            return
        message = self.library.curl_easy_strerror(code)
        raise LibcurlError(
            message.decode(errors="replace") if message else f"CURLcode {code}"
        )

    def _set_long(self, easy: int, option: int, value: int) -> None:
        self._check(self.library.curl_easy_setopt(
            ctypes.c_void_p(easy),
            ctypes.c_int(option),
            ctypes.c_long(value),
        ))

    def _set_pointer(self, easy: int, option: int, value: object) -> None:
        self._check(self.library.curl_easy_setopt(
            ctypes.c_void_p(easy),
            ctypes.c_int(option),
            value,
        ))

    def _get_long(self, easy: int, info: int) -> int:
        value = ctypes.c_long()
        self._check(self.library.curl_easy_getinfo(
            ctypes.c_void_p(easy),
            ctypes.c_int(info),
            ctypes.byref(value),
        ))
        return value.value

    def _trailer_value(self, easy: int, name: bytes) -> bytes:
        header = ctypes.POINTER(CurlHeader)()
        code = self.library.curl_easy_header(
            ctypes.c_void_p(easy),
            name,
            ctypes.c_size_t(0),
            ctypes.c_uint(CURLH_TRAILER),
            ctypes.c_int(-1),
            ctypes.byref(header),
        )
        if code != CURLHE_OK or not header:
            raise LibcurlError(
                f"libcurl trailer lookup failed: name={name!r} code={code}"
            )
        value = header.contents
        if value.amount != 1 or value.index != 0 or (
            value.origin & CURLH_TRAILER == 0
        ) or value.value is None:
            raise LibcurlError(
                f"libcurl trailer metadata mismatch: name={name!r} "
                f"amount={value.amount} index={value.index} "
                f"origin={value.origin}"
            )
        return bytes(value.value)

    def _headers(self, lines: tuple[bytes, ...]) -> int:
        headers = ctypes.c_void_p()
        try:
            for line in lines:
                appended = self.library.curl_slist_append(headers, line)
                if not appended:
                    raise MemoryError("curl_slist_append")
                headers = ctypes.c_void_p(appended)
            return headers.value or 0
        except BaseException:
            if headers.value:
                self.library.curl_slist_free_all(headers)
            raise

    def _capture(self, easy: int) -> tuple[Capture, ctypes.py_object]:
        capture = Capture()
        reference = ctypes.py_object(capture)
        userdata = ctypes.cast(
            ctypes.pointer(reference),
            ctypes.c_void_p,
        )
        self._set_pointer(easy, CURLOPT_WRITEDATA, userdata)
        self._set_pointer(
            easy,
            CURLOPT_WRITEFUNCTION,
            ctypes.cast(_write_body, ctypes.c_void_p),
        )
        self._set_pointer(easy, CURLOPT_HEADERDATA, userdata)
        self._set_pointer(
            easy,
            CURLOPT_HEADERFUNCTION,
            ctypes.cast(_write_header, ctypes.c_void_p),
        )
        return capture, reference

    def run_case(
        self,
        port: int,
        protocol: str,
        tls: bool,
        certificate: Path,
    ) -> str:
        if protocol != "http1":
            raise ValueError(
                "libcurl 8.5 trailer interop is available only for HTTP/1.1"
            )
        easy = self.library.curl_easy_init()
        if not easy:
            raise MemoryError("curl_easy_init")
        header_list = 0
        resolve_list = 0
        trailer_callback: TRAILER_CALLBACK | None = None
        try:
            self._set_long(easy, CURLOPT_NOSIGNAL, 1)
            self._set_long(easy, CURLOPT_CONNECTTIMEOUT_MS, 5000)
            self._set_long(easy, CURLOPT_TIMEOUT_MS, 10000)
            self._set_pointer(easy, CURLOPT_NOPROXY, ctypes.c_char_p(b"*"))
            expected_http_version = CURL_HTTP_VERSION_1_1
            self._set_long(easy, CURLOPT_HTTP_VERSION, expected_http_version)

            scheme = "https" if tls else "http"
            host = "localhost" if tls else "127.0.0.1"
            if tls:
                self._set_pointer(
                    easy,
                    CURLOPT_CAINFO,
                    ctypes.c_char_p(str(certificate).encode()),
                )
                resolve_list = self._headers((
                    f"localhost:{port}:127.0.0.1".encode(),
                ))
                self._set_pointer(
                    easy,
                    CURLOPT_RESOLVE,
                    ctypes.c_void_p(resolve_list),
                )

            upload_url = (
                f"{scheme}://{host}:{port}/upload?client=libcurl".encode()
            )
            self._set_pointer(easy, CURLOPT_URL, ctypes.c_char_p(upload_url))
            upload_headers = [
                b"x-interop-client: libcurl",
                b"TE: trailers",
                b"Trailer: x-libcurl-request-complete",
                b"Connection: TE",
                b"Transfer-Encoding: chunked",
            ]
            header_list = self._headers(tuple(upload_headers))
            self._set_pointer(
                easy,
                CURLOPT_HTTPHEADER,
                ctypes.c_void_p(header_list),
            )
            self._set_long(easy, CURLOPT_POST, 1)
            upload_source = Upload(REQUEST_BODY)
            upload_reference = ctypes.py_object(upload_source)
            upload_userdata = ctypes.cast(
                ctypes.pointer(upload_reference),
                ctypes.c_void_p,
            )
            self._set_pointer(
                easy,
                CURLOPT_READDATA,
                upload_userdata,
            )
            self._set_pointer(
                easy,
                CURLOPT_READFUNCTION,
                ctypes.cast(_read_body, ctypes.c_void_p),
            )
            self._set_long(easy, CURLOPT_POSTFIELDSIZE, len(REQUEST_BODY))

            @TRAILER_CALLBACK
            def send_trailer(
                trailers: ctypes.POINTER(ctypes.c_void_p),
                _: int,
            ) -> int:
                value = self.library.curl_slist_append(
                    ctypes.c_void_p(),
                    REQUEST_TRAILER_NAME + b": yes",
                )
                if not value:
                    return 1
                trailers[0] = ctypes.c_void_p(value)
                return CURL_TRAILERFUNC_OK

            trailer_callback = send_trailer
            self._set_pointer(
                easy,
                CURLOPT_TRAILERFUNCTION,
                ctypes.cast(trailer_callback, ctypes.c_void_p),
            )
            self._set_pointer(easy, CURLOPT_TRAILERDATA, ctypes.c_void_p())
            upload, capture_reference = self._capture(easy)
            self._check(self.library.curl_easy_perform(ctypes.c_void_p(easy)))
            _ = upload_reference, capture_reference
            if self._get_long(easy, CURLINFO_RESPONSE_CODE) != 200 or (
                bytes(upload.body) != b"netz-libcurl-upload"
            ):
                raise LibcurlError("libcurl upload response mismatch")
            upload_trailer = self._trailer_value(
                easy,
                RESPONSE_TRAILER_NAME,
            )
            if upload_trailer != b"first":
                raise LibcurlError(
                    "libcurl upload response trailer mismatch: "
                    f"value={upload_trailer!r} headers={upload.headers!r}"
                )
            if self._get_long(easy, CURLINFO_HTTP_VERSION) != expected_http_version:
                raise LibcurlError("libcurl upload HTTP version mismatch")
            if self._get_long(easy, CURLINFO_NUM_CONNECTS) != 1:
                raise LibcurlError("libcurl upload did not open exactly one connection")

            self.library.curl_slist_free_all(ctypes.c_void_p(header_list))
            header_list = 0
            reuse_headers = [
                b"x-interop-client: libcurl",
                b"TE: trailers",
                b"Connection: TE",
            ]
            header_list = self._headers(tuple(reuse_headers))
            self._set_pointer(
                easy,
                CURLOPT_HTTPHEADER,
                ctypes.c_void_p(header_list),
            )
            self._set_pointer(
                easy,
                CURLOPT_TRAILERFUNCTION,
                ctypes.c_void_p(),
            )
            self._set_pointer(easy, CURLOPT_TRAILERDATA, ctypes.c_void_p())
            self._set_long(easy, CURLOPT_HTTPGET, 1)
            reuse_url = (
                f"{scheme}://{host}:{port}/reuse?client=libcurl".encode()
            )
            self._set_pointer(easy, CURLOPT_URL, ctypes.c_char_p(reuse_url))
            reused, reused_reference = self._capture(easy)
            self._check(self.library.curl_easy_perform(ctypes.c_void_p(easy)))
            _ = reused_reference
            if self._get_long(easy, CURLINFO_RESPONSE_CODE) != 200 or (
                bytes(reused.body) != b"netz-libcurl-reuse"
            ):
                raise LibcurlError("libcurl reused response mismatch")
            reused_trailer = self._trailer_value(
                easy,
                RESPONSE_TRAILER_NAME,
            )
            if reused_trailer != b"second":
                raise LibcurlError(
                    "libcurl reused response trailer mismatch: "
                    f"value={reused_trailer!r} headers={reused.headers!r}"
                )
            if self._get_long(easy, CURLINFO_HTTP_VERSION) != expected_http_version:
                raise LibcurlError("libcurl reused HTTP version mismatch")
            if self._get_long(easy, CURLINFO_NUM_CONNECTS) != 0:
                raise LibcurlError("libcurl did not reuse its existing connection")
            return (
                f"libcurl trailer interop passed: protocol={protocol} "
                f"transport={'tls' if tls else 'cleartext'} requests=2 "
                "connections=1 request_trailers=1 "
                "response_trailers=2"
            )
        finally:
            if header_list:
                self.library.curl_slist_free_all(ctypes.c_void_p(header_list))
            if resolve_list:
                self.library.curl_slist_free_all(ctypes.c_void_p(resolve_list))
            self.library.curl_easy_cleanup(ctypes.c_void_p(easy))

