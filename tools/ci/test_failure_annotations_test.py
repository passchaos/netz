#!/usr/bin/env python3
"""Action annotations retain useful failures from both Zig runner modes."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
import os
import signal
import subprocess
import sys

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

    def test_segfault_keeps_first_case_before_long_stack_and_fuzz_output(self):
        text = "72/233 quic.test.receive credit...Segmentation fault at address 0x0\n"
        text += "allocator at Allocator.zig:142\n" + "\n".join("stack frame %d" % n for n in range(50))
        text += "\nerror: process terminated with signal ABRT\n"
        text += "failed command: ./test\n1/3 fuzz.test.other...OK\n"
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertIn("quic.test.receive credit", first)
        self.assertIn("Segmentation fault at address 0x0", first)
        self.assertIn("allocator at Allocator.zig:142", first)
        self.assertNotIn("fuzz.test.other", first)

    def test_signal_exit_keeps_case_without_panic_preface(self):
        text = "68/230 quic.test.batch prefix...\n+- run test failure\n"
        text += "error: process terminated with signal ILL\nfailed command: ./test\n"
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertIn("quic.test.batch prefix", first)
        self.assertIn("process terminated with signal ILL", first)

    def test_native_crash_prefaces_keep_case_before_long_stack_and_build_output(self):
        for diagnostic in [
            "General protection exception (no address available)",
            "Illegal instruction at address 0x1234",
            "Stack overflow at address 0x1234",
        ]:
            with self.subTest(diagnostic=diagnostic):
                text = "2287/7451 webtransport.test.visible prefix..." + diagnostic + "\n"
                text += "backend at Threaded.zig:42\n"
                text += "\n".join("stack frame %d" % n for n in range(60))
                text += "\n1/3 fuzz.test.other...OK\nerror: process terminated with signal ABRT\n"
                first = self.render(text, "complete-tests.log").splitlines()[0]
                self.assertIn("webtransport.test.visible prefix", first)
                self.assertIn(diagnostic, first)
                self.assertIn("backend at Threaded.zig:42", first)
                self.assertNotIn("fuzz.test.other", first)

    def test_crash_words_in_test_names_and_diagnostics_are_not_native_crashes(self):
        text = "1/2 test.General protection exception fixture...OK\n"
        text += "[test] (warn): Illegal instruction is an expected fixture diagnostic\n"
        text += "2/2 test.real failure...\nFAIL (TestUnexpectedResult)\n"
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertIn("test.real failure", first)
        self.assertIn("FAIL (TestUnexpectedResult)", first)
        self.assertNotIn("test.General protection", first)

    def test_delayed_signal_uses_failed_artifact_instead_of_later_fuzz(self):
        root = "/tmp/.zig-cache/o/" + "a" * 32 + "/test"
        fuzz = "/tmp/.zig-cache/o/" + "b" * 32 + "/fuzz-replay-mqtt_outbound"
        text = root + " --cache-dir=.zig-cache\n7470/7483 http2.test.retained read...\n"
        text += "\n".join("root diagnostic %d" % n for n in range(50))
        text += "\n" + fuzz + " --cache-dir=.zig-cache\n1/12 fuzz.test.other...OK\n"
        text += "+- run test test: src/root.zig failure\nerror: process terminated with signal ABRT\n"
        text += "failed command: " + root + " --cache-dir=.zig-cache\n"
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertIn("Last visible test for failed artifact", first)
        self.assertIn("http2.test.retained read", first)
        self.assertNotIn("fuzz.test.other", first)

    def test_allocator_abort_preface_keeps_case_before_later_artifacts(self):
        for diagnostic in ["free(): invalid pointer", "malloc(): corrupted top size", "double free or corruption (!prev)", "Fatal glibc error: malloc assertion failure"]:
            with self.subTest(diagnostic=diagnostic):
                text = "7470/7483 http2.test.owner cleanup...\n" + diagnostic + "\n"
                text += "\n".join("stack frame %d" % n for n in range(60))
                text += "\n1/12 fuzz.test.other...OK\nerror: process terminated with signal ABRT\n"
                first = self.render(text, "complete-tests.log").splitlines()[0]
                self.assertIn("http2.test.owner cleanup", first)
                self.assertIn(diagnostic, first)
                self.assertNotIn("fuzz.test.other", first)

    def test_crash_is_not_hidden_by_twelve_earlier_build_errors(self):
        text = "\n".join("error: earlier build diagnostic %d" % n for n in range(40))
        text += "\n7470/7483 http2.test.frame owner...\nthread 1 panic: invalid 50% owner\n"
        text += "\n".join("stack frame %d" % n for n in range(60))
        text += "\nerror: process terminated with signal ABRT\n"
        lines = self.render(text, "complete-tests.log").splitlines()
        self.assertEqual(12, len(lines))
        self.assertIn("http2.test.frame owner", lines[0])
        self.assertIn("invalid 50%25 owner", lines[0])

    def test_unknown_failed_artifact_does_not_guess_a_different_test(self):
        root = "/tmp/.zig-cache/o/" + "a" * 32 + "/test"
        fuzz = "/tmp/.zig-cache/o/" + "b" * 32 + "/fuzz-replay-other"
        text = fuzz + " --cache-dir=.zig-cache\n1/3 fuzz.test.other...OK\n"
        text += "+- run test test: src/root.zig failure\nerror: process terminated with signal ABRT\n"
        text += "failed command: " + root + " --cache-dir=.zig-cache\n"
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertNotIn("fuzz.test.other", first)

    def test_repeated_artifact_without_new_test_does_not_reuse_previous_run(self):
        root = "/tmp/.zig-cache/o/" + "a" * 32 + "/test"
        text = root + " --cache-dir=.zig-cache\n1/2 http.test.previous...OK\n"
        text += root + " --cache-dir=.zig-cache\nerror: process terminated with signal ABRT\n"
        text += "failed command: " + root + " --cache-dir=.zig-cache\n"
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertNotIn("http.test.previous", first)

    def test_empty_failed_log_reports_missing_output(self):
        lines = self.render("", "complete-tests.log").splitlines()
        self.assertEqual(1, len(lines))
        self.assertIn("No command output captured", lines[0])

    def test_failed_expectation_after_long_error_trace_keeps_active_test(self):
        root = "/tmp/.zig-cache/o/" + "a" * 32 + "/test"
        text = root + " --cache-dir=cache\n88/143 http3.test.send deadline...\n"
        text += "\n".join("native transport trace %d" % n for n in range(80))
        text += "\nexpected error.Timeout, found error.Unexpected\nFAIL (TestUnexpectedError)\n"
        first = self.render(text, "native-http3-send-deadlines.log").splitlines()[0]
        self.assertIn("Last visible test for active artifact", first)
        self.assertIn("http3.test.send deadline", first)
        self.assertIn("expected error.Timeout, found error.Unexpected", first)

    def test_nonverbose_immediate_failure_retains_test_before_long_trace(self):
        text = "88/143 http3.test.response deadline...\n"
        text += "\n".join("native transport trace %d" % n for n in range(80))
        text += "\nexpected error.Timeout, found error.Unexpected\nFAIL (TestUnexpectedError)\n"
        first = self.render(text, "native-protocol-test-contexts.log").splitlines()[0]
        self.assertIn("Last visible test in command output", first)
        self.assertIn("http3.test.response deadline", first)
        self.assertIn("expected error.Timeout, found error.Unexpected", first)

    def test_new_known_artifact_immediate_failure_does_not_reuse_old_test(self):
        old = "/tmp/.zig-cache/o/" + "a" * 32 + "/test"
        current = "/tmp/.zig-cache/o/" + "b" * 32 + "/test"
        text = old + " --cache-dir=cache\n1/1 http.test.old...OK\n"
        text += current + " --cache-dir=cache\nexpected error.Timeout, found error.Unexpected\nFAIL (TestUnexpectedError)\n"
        first = self.render(text, "native-context.log").splitlines()[0]
        self.assertNotIn("http.test.old", first)

    def test_delayed_windows_signal_matches_quoted_artifact_with_spaces(self):
        root = r"D:\a Project\netz\.zig-cache\o" + "\\" + "a" * 32 + r"\test.exe"
        fuzz = r"D:\a Project\netz\.zig-cache\o" + "\\" + "b" * 32 + r"\fuzz-replay-other.exe"
        text = '"' + root + '" "--cache-dir=D:\\a Project\\netz\\.zig-cache"\n'
        text += "7470/7483 http2.test.windows owner...\n"
        text += '"' + fuzz + '" --cache-dir=cache\n1/3 fuzz.test.other...OK\n'
        text += "error: process terminated with signal ABRT\nfailed command: \"" + root + '" --cache-dir=cache\n'
        first = self.render(text, "complete-tests.log").splitlines()[0]
        self.assertIn("http2.test.windows owner", first)
        self.assertNotIn("fuzz.test.other", first)

    @unittest.skipUnless(os.name == "posix", "POSIX child abort status")
    def test_real_child_abort_retains_its_artifact_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ".zig-cache" / "o" / ("a" * 32) / "test"
            root.parent.mkdir(parents=True)
            root.write_text("#!" + sys.executable + "\nimport os,resource\nresource.setrlimit(resource.RLIMIT_CORE,(0,0))\nprint('7470/7483 http2.test.native abort...',flush=True)\nos.abort()\n")
            root.chmod(0o755)
            result = subprocess.run([str(root), "--cache-dir=cache"], capture_output=True, timeout=5)
            self.assertEqual(-signal.SIGABRT, result.returncode)
            fuzz = str(root.parent.parent / ("b" * 32) / "fuzz-replay-other")
            text = str(root) + " --cache-dir=cache\n" + result.stdout.decode()
            text += fuzz + " --cache-dir=cache\n1/3 fuzz.test.other...OK\n"
            text += "error: process terminated with signal ABRT\nfailed command: " + str(root) + " --cache-dir=cache\n"
            first = self.render(text, "complete-tests.log").splitlines()[0]
            self.assertIn("Last visible test for failed artifact", first)
            self.assertIn("http2.test.native abort", first)
            self.assertNotIn("fuzz.test.other", first)


if __name__ == "__main__":
    unittest.main()
