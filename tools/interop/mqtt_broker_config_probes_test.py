import socket
import os
import time
import unittest
from mqtt_broker_config_probes import tls_peer_state


class Peer:
    def __init__(self, socket): self.socket = socket
    def fileno(self): return self.socket.fileno()
    def pending(self): return 0


@unittest.skipUnless(os.name == "posix" and hasattr(socket, "MSG_DONTWAIT"), "CA reload peer observation requires POSIX nonblocking peek")
class PeerObservationTest(unittest.TestCase):
    def setUp(self):
        self.client, self.server = socket.socketpair()
        self.client.settimeout(0.5)
        self.peer = Peer(self.client)
        self.started = time.monotonic()

    def tearDown(self):
        self.client.close()
        self.server.close()

    def test_idle_observation_keeps_socket_mode_and_handle(self):
        state = tls_peer_state(self.peer, "idle", self.started)
        self.assertEqual("idle", state["tcp"])
        self.assertEqual(0.5, self.client.gettimeout())
        self.server.sendall(b"x")
        self.assertEqual(b"x", self.client.recv(1))

    def test_pending_observation_does_not_consume_payload(self):
        self.server.sendall(b"abc")
        state = tls_peer_state(self.peer, "data", self.started)
        self.assertEqual("pending", state["tcp"])
        self.assertEqual(b"abc", self.client.recv(3))
        self.assertEqual(0.5, self.client.gettimeout())

    def test_eof_observation_does_not_close_owned_socket(self):
        self.server.close()
        state = tls_peer_state(self.peer, "eof", self.started)
        self.assertEqual("eof", state["tcp"])
        self.assertGreaterEqual(self.client.fileno(), 0)
        self.assertEqual(b"", self.client.recv(1))


if __name__ == "__main__": unittest.main()
