#!/usr/bin/env python3

import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("udp_fault_proxy.py")
SPEC = importlib.util.spec_from_file_location("udp_fault_proxy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PROXY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROXY)


class FakeSocket:
    def __init__(self) -> None:
        self.sent = []

    def sendto(self, payload, target) -> None:
        self.sent.append((payload, target))


class FaultStateTests(unittest.TestCase):
    def test_xorshift_matches_u64_reference_sequence(self) -> None:
        state = PROXY.FaultState("loss", 5, 5)
        self.assertEqual(
            [state.xorshift() for _ in range(4)],
            [
                0xBCDC4D74B807630D,
                0x4A99465CA1D80E8B,
                0x8D10A95197E57C56,
                0x443E2AA4A443632E,
            ],
        )

    def test_pair_reorder_sends_successor_before_held_packet(self) -> None:
        state = PROXY.FaultState("reorder", 5, 2)
        state.armed = True
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"one", target)
        state.forward(sock, b"two", target)
        state.forward(sock, b"three", target)
        self.assertEqual(sock.sent, [(b"one", target), (b"three", target), (b"two", target)])
        self.assertEqual(state.held, 1)
        self.assertEqual(state.reordered, 1)

    def test_disarmed_path_does_not_count_or_drop(self) -> None:
        state = PROXY.FaultState("loss", 100, 5)
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"handshake", target)
        self.assertEqual(sock.sent, [(b"handshake", target)])
        self.assertEqual(state.considered, 0)
        self.assertEqual(state.dropped, 0)

    def test_forced_first_loss_is_deterministic(self) -> None:
        state = PROXY.FaultState("loss", 5, 5)
        state.arm(force_next=True)
        sock = FakeSocket()
        state.forward(sock, b"first", ("127.0.0.1", 4433))
        self.assertEqual(sock.sent, [])
        self.assertEqual(state.dropped, 1)

    def test_forced_first_reorder_is_released_by_successor(self) -> None:
        state = PROXY.FaultState("reorder", 5, 99)
        state.arm(force_next=True)
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"first", target)
        state.forward(sock, b"second", target)
        self.assertEqual(sock.sent, [(b"second", target), (b"first", target)])
        self.assertEqual(state.reordered, 1)

    def test_flush_releases_unpaired_tail(self) -> None:
        state = PROXY.FaultState("reorder", 5, 2)
        state.armed = True
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"one", target)
        state.forward(sock, b"two", target)
        self.assertEqual(sock.sent, [(b"one", target)])
        state.flush(sock)
        self.assertEqual(sock.sent, [(b"one", target), (b"two", target)])
        self.assertEqual(state.reordered, 0)

    def test_disarm_clears_forced_selection(self) -> None:
        state = PROXY.FaultState("loss", 5, 5)
        state.arm(force_next=True)
        state.armed = False
        state.force_next = False
        state.arm()
        sock = FakeSocket()
        state.forward(sock, b"ordinary", ("127.0.0.1", 4433))
        self.assertEqual(sock.sent, [(b"ordinary", ("127.0.0.1", 4433))])

    def test_single_shot_loss_disarms_after_one_drop(self) -> None:
        state = PROXY.FaultState("loss", 100, 5)
        state.arm(force_next=True, single_shot=True)
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"lost", target)
        state.forward(sock, b"sent", target)
        self.assertEqual(sock.sent, [(b"sent", target)])
        self.assertEqual(state.dropped, 1)
        self.assertFalse(state.armed)

    def test_single_shot_reorder_disarms_after_pair(self) -> None:
        state = PROXY.FaultState("reorder", 5, 99)
        state.arm(force_next=True, single_shot=True)
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"first", target)
        state.forward(sock, b"second", target)
        state.forward(sock, b"third", target)
        self.assertEqual(
            sock.sent,
            [(b"second", target), (b"first", target), (b"third", target)],
        )
        self.assertEqual(state.held, 1)
        self.assertEqual(state.reordered, 1)
        self.assertFalse(state.armed)

    def test_single_shot_corruption_flips_one_ciphertext_bit(self) -> None:
        state = PROXY.FaultState("corrupt", 5, 99)
        state.arm(force_next=True, single_shot=True)
        sock = FakeSocket()
        target = ("127.0.0.1", 4433)
        state.forward(sock, b"ciphertext", target)
        state.forward(sock, b"next", target)
        self.assertEqual(
            sock.sent,
            [(b"ciphertexu", target), (b"next", target)],
        )
        self.assertEqual(state.considered, 1)
        self.assertEqual(state.corrupted, 1)
        self.assertEqual(
            state.summary(),
            "considered=1 dropped=0 held=0 reordered=0 corrupted=1",
        )
        self.assertFalse(state.armed)

    def test_server_direction_uses_the_same_fault_state(self) -> None:
        state = PROXY.FaultState("loss", 100, 5)
        state.arm()
        sock = FakeSocket()
        client = ("127.0.0.1", 31337)
        state.forward(sock, b"server packet", client)
        self.assertEqual(sock.sent, [])
        self.assertEqual(state.considered, 1)
        self.assertEqual(state.dropped, 1)


if __name__ == "__main__":
    unittest.main()
