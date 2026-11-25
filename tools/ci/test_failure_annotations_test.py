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

    def test_allocator_leak_keeps_case_and_stack_before_later_build_error(self):
        text = "1/2 quic.test.borrowed completion...OK\n"
        text += "[gpa] (err): memory address 0x1234 leaked:\nallocation at owner.zig:42\n"
        text += "2/2 quic.test.other case...OK\n1 tests leaked memory.\n"
        text += "error: process exited with error code 1\n"
        first = self.render(text, "native-protocol-ci.log").splitlines()[0]
        self.assertIn("quic.test.borrowed completion", first)
        self.assertIn("memory address 0x1234 leaked", first)
        self.assertIn("allocation at owner.zig:42", first)


    def test_scoped_error_keeps_case_even_when_all_test_results_are_ok(self):
        for diagnostic in ["[tls] (err): peer cleanup failed", "error(tls): peer cleanup failed"]:
            with self.subTest(diagnostic=diagnostic):
                text = "1/2 webtransport.test.cleanup...OK\n" + diagnostic + "\n"
                text += "allocation or cleanup context\n2/2 tls.test.other...OK\n"
                text += "error: process exited with error code 1\n"
                first = self.render(text, "native-protocol-ci.log").splitlines()[0]
                self.assertIn("webtransport.test.cleanup", first)
                self.assertIn(diagnostic, first)
                self.assertIn("cleanup context", first)

    def test_logged_error_excludes_warnings_and_debug_diagnostics(self):
        text = "1/2 quic.test.other...OK\n[tls] (warn): slow peer\nerror budget is 10\n"
        text += "2/2 quic.test.cleanup...OK\n[default] (err): unexpected cleanup\n"
        first = self.render(text).splitlines()[0]
        self.assertIn("quic.test.cleanup", first)
        self.assertIn("[default] (err): unexpected cleanup", first)
        self.assertNotIn("quic.test.other", first)


if __name__ == "__main__":
    unittest.main()
