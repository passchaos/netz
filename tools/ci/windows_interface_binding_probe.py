"""Bounded Winsock option diagnostics for the native transport CI job."""
import ctypes
import json
import socket
import struct
import sys


def main():
    if sys.platform != "win32":
        raise SystemExit("This probe requires native Windows")
    api = ctypes.WinDLL("iphlpapi.dll")
    alias = api.ConvertInterfaceAliasToLuid
    alias.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64)]
    alias.restype = ctypes.c_uint32
    to_index = api.ConvertInterfaceLuidToIndex
    to_index.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint32)]
    to_index.restype = ctypes.c_uint32
    luid, index = ctypes.c_uint64(), ctypes.c_uint32()
    assert alias("Loopback Pseudo-Interface 1", ctypes.byref(luid)) == 0
    assert to_index(ctypes.byref(luid), ctypes.byref(index)) == 0
    for family, level, address in [
        (socket.AF_INET, socket.IPPROTO_IP, "127.0.0.1"),
        (socket.AF_INET6, socket.IPPROTO_IPV6, "::1"),
    ]:
        for enable_first in [True, False]:
            for byte_order in ["=I", "!I"]:
                for bind_first in [False, True]:
                    row = dict(family=family, index=index.value, enable_first=enable_first, byte_order=byte_order, bind_first=bind_first)
                    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                        step = "bind"
                        try:
                            if family == socket.AF_INET6:
                                sock.setsockopt(level, 27, 1)
                                row["v6_only_bytes"] = sock.getsockopt(level, 27, 4).hex()
                            if bind_first:
                                sock.bind((address, 0))
                            step = "UNICAST_IF"
                            sock.setsockopt(level, 31, struct.pack("!I" if family == socket.AF_INET else "=I", index.value))
                            if enable_first:
                                step = "IFLIST enable"
                                sock.setsockopt(level, 28, 1)
                            step = "ADD_IFLIST"
                            sock.setsockopt(level, 29, struct.pack(byte_order, index.value))
                            if not enable_first:
                                step = "IFLIST enable"
                                sock.setsockopt(level, 28, 1)
                            if not bind_first:
                                step = "bind after interface configuration"
                                sock.bind((address, 0))
                            step = "GET_IFLIST"
                            data = sock.getsockopt(level, 33, 64)
                            row.update(state=sock.getsockopt(level, 28), iflist_bytes=sock.getsockopt(level, 28, 4).hex(), indices=list(struct.unpack("=" + "I" * (len(data) // 4), data)), result="success")
                        except OSError as err:
                            row.update(step=step, winerror=getattr(err, "winerror", None), errno=err.errno, result=str(err))
                    print("::notice title=Winsock interface probe::" + json.dumps(row))


if __name__ == "__main__":
    main()
