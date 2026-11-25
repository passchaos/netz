#!/usr/bin/env python3
"""Action annotations retain useful failures from both Zig runner modes."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from test_failure_annotations import annotate


class AnnotationsTest(unittest.TestCase):
    def render(self, text, name="native-trust.log"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_text(text)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                annotate(path)
            return output.getvalue()

    def test_terminal_failure_precedes_later_build_error(self):
        text = "1/2 tls.test.peer identity...\nFAIL (CertificateUntrusted)\ntrace at verify.zig:12\n"
        text += "2/2 tls.test.other case...OK\nerror: build command failed\n"
        output = self.render(text)
        first = output.splitlines()[0]
        self.assertIn("tls.test.peer identity", first)
        self.assertIn("FAIL (CertificateUntrusted)", first)
        self.assertIn("::error title=Native regression: native trust::", first)
        self.assertNotIn("hostname", first)

    def test_panic_retains_name_and_escapes_action_payload(self):
        output = self.render("4/5 quic.test.cancel...\nthread 1 panic: invalid 50% state\nframe one\n")
        self.assertIn("quic.test.cancel", output)
        self.assertIn("panic: invalid 50%25 state", output)
        self.assertIn("%0Aframe one", output)
        self.assertEqual(1, len(output.splitlines()))

    def test_terminal_failure_keeps_name_after_test_diagnostics(self):
        text = "9/10 http3.test.handshake budget...\n"
        text += "\n".join("test diagnostic %d" % index for index in range(12))
        text += "\nFAIL (HandshakeTimeout)\ntrace\n"
        output = self.render(text)
        self.assertIn("http3.test.handshake budget", output)
        self.assertIn("FAIL (HandshakeTimeout)", output)

    def test_server_mode_failures_keep_bounded_annotation_count(self):
        text = "\n".join("error: 'case %d' failed" % index for index in range(20))
        self.assertEqual(12, len(self.render(text).splitlines()))

    def test_python_helper_failure_keeps_its_test_and_assertion(self):
        text = "FAIL: test_windows_text_output (ProgressTest)\nTraceback (most recent call last):\n  File 'test.py', line 12\nAssertionError: CRLF differs from LF\n"
        output = self.render(text, "ci-helper-tests.log")
        self.assertIn("test_windows_text_output", output.splitlines()[0])
        self.assertIn("AssertionError: CRLF differs from LF", output)
        self.assertIn("Native regression: ci helper tests", output)

    def test_unclassified_exit_retains_bounded_tail(self):
        text = "\n".join("line %d" % index for index in range(100))
        output = self.render(text, "native-resolver.log")
        self.assertIn("Native regression: native resolver", output)
        self.assertIn("line 60", output)
        self.assertNotIn("line 0%0A", output)


if __name__ == "__main__":
    unittest.main()
