#!/usr/bin/env python3
"""Exercise real child processes, partial progress and command exit status."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ProgressTest(unittest.TestCase):
    def launch(self, source, title="Test progress"):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "progress.log"
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("run_test_progress.py")),
                 "--log", str(log), "--title", title, "--interval", "0.03",
                 "--", sys.executable, "-c", source],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            return result, log.read_bytes()

    def test_partial_name_is_reported_before_command_finishes(self):
        result, log = self.launch("import os,time; os.write(1,b'1/1 http.test.wait...'); time.sleep(0.15); os.write(1,b'OK'+bytes([10]))")
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"1/1 http.test.wait...OK\n", log)
        output = result.stdout.decode()
        self.assertIn("::notice title=Test progress::1/1 http.test.wait...", output)
        self.assertIn("\n::notice title=Test progress::", output)
        self.assertLess(output.index("::notice"), output.rindex("OK"))

    def test_failing_child_keeps_exit_code_and_log(self):
        result, log = self.launch("import sys; print('2/2 tls.test.peer...FAIL (CertificateUntrusted)'); sys.exit(7)")
        self.assertEqual(7, result.returncode)
        self.assertIn(b"FAIL (CertificateUntrusted)", log)
        self.assertIn(b"::notice", result.stdout)

    def test_no_test_progress_identifies_build_phase_and_escapes_title(self):
        result, _ = self.launch("import time; print('compiling', flush=True); time.sleep(0.15)", "CI: compile, 50%")
        self.assertEqual(0, result.returncode)
        output = result.stdout.decode()
        self.assertIn("CI%3A compile%2C 50%25", output)
        self.assertIn("No test name emitted yet", output)

    def test_large_output_remains_exact_in_the_log(self):
        result, log = self.launch("import sys; sys.stdout.buffer.write(b'x' * (256 * 1024))")
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"x" * (256 * 1024), log)

    def test_text_output_crlf_is_retained_exactly(self):
        result, log = self.launch("import sys; sys.stdout.reconfigure(newline=chr(13)+chr(10)); print('1/1 http.test.crlf...OK')")
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"1/1 http.test.crlf...OK\r\n", log)

    def test_fragmented_utf8_test_name_is_not_corrupted(self):
        source = "import os,time; data='1/1 http.test.请求...'.encode(); pos=data.index(bytes([0xe8])); os.write(1,data[:pos+1]); time.sleep(0.03); os.write(1,data[pos+1:]); time.sleep(0.1); os.write(1,b'OK\\n')"
        result, log = self.launch(source)
        self.assertEqual(0, result.returncode)
        self.assertEqual("1/1 http.test.请求...OK\n".encode(), log)
        self.assertIn("http.test.请求...", result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
