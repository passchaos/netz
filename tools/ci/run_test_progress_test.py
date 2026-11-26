#!/usr/bin/env python3
"""Exercise real child processes, partial progress and command exit status."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest


class ProgressTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX repeated command interruption")
    def test_repeated_interrupts_cannot_unwind_owned_child_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            child_pid = root / "child.pid"
            terminating = root / "terminating"
            env = os.environ.copy()
            env["GITHUB_STEP_SUMMARY"] = str(summary)
            source = "import os,signal,time; from pathlib import Path; Path(" + repr(str(child_pid)) + ").write_text(str(os.getpid())); signal.signal(signal.SIGTERM,lambda *_: Path(" + repr(str(terminating)) + ").write_text('seen')); print('1/1 http.test.repeated_interrupt...',flush=True); time.sleep(30)"
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("run_test_progress.py")), "--log", str(root / "log"), "--interval", "0.01", "--", sys.executable, "-c", source], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            child_stopped = False
            try:
                until = time.monotonic() + 3
                while not summary.exists() or "http.test.repeated_interrupt" not in summary.read_text():
                    if time.monotonic() >= until:
                        self.fail("child progress was not published")
                    time.sleep(0.005)
                process.send_signal(signal.SIGINT)
                until = time.monotonic() + 2
                while not terminating.exists():
                    if time.monotonic() >= until:
                        self.fail("owned child cleanup did not start")
                    time.sleep(0.005)
                process.send_signal(signal.SIGINT)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
                try:
                    os.kill(int(child_pid.read_text()), 0)
                except ProcessLookupError:
                    child_stopped = True
                self.assertTrue(child_stopped, "owned child survived cleanup")
                self.assertEqual(130, process.returncode, stderr.decode())
                self.assertIn(b"::error title=Test progress::Interrupted command", stdout)
                self.assertIn("http.test.repeated_interrupt", summary.read_text())
            finally:
                if not child_stopped:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_summary_keeps_latest_test_beyond_notice_annotation_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            env = os.environ.copy()
            env["GITHUB_STEP_SUMMARY"] = str(summary)
            # Each child line waits for its own published summary before the
            # next one, ensuring notice count without assuming scheduler speed.
            source = "import html,os,time; from pathlib import Path;\nsummary=Path(os.environ['GITHUB_STEP_SUMMARY']); until=time.monotonic()+4\nfor n in range(1,15):\n marker=str(n)+'/14 http.test<&>...OK'; print(marker,flush=True)\n while not summary.exists() or marker not in html.unescape(summary.read_text()):\n  if time.monotonic()>=until: raise TimeoutError('summary did not publish '+marker)\n  time.sleep(0.001)\nprint('compiling <next & artifact>',flush=True)"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("run_test_progress.py")), "--log", str(root / "log"), "--interval", "0.01", "--", sys.executable, "-c", source], env=env, capture_output=True, timeout=8)
            self.assertEqual(0, result.returncode)
            self.assertGreater(result.stdout.count(b"::notice"), 10)
            text = summary.read_text()
            self.assertIn("14/14 http.test&lt;&amp;&gt;...OK", text)
            self.assertIn("compiling &lt;next &amp; artifact&gt;", text)

    @unittest.skipUnless(os.name == "posix", "POSIX process liveness check")
    def test_summary_write_failure_stops_child_with_buffered_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child_pid = root / "child.pid"
            env = os.environ.copy()
            env["GITHUB_STEP_SUMMARY"] = str(root)
            source = "import os,time; from pathlib import Path; Path(" + repr(str(child_pid)) + ").write_text(str(os.getpid())); os.write(1,b'x' * (256 * 1024)); time.sleep(10)"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("run_test_progress.py")), "--log", str(root / "log"), "--interval", "1", "--", sys.executable, "-c", source], env=env, capture_output=True, timeout=8)
            self.assertNotEqual(0, result.returncode)
            self.assertIn(b"IsADirectoryError", result.stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)

    @unittest.skipUnless(os.name == "posix", "POSIX command interruption")
    def test_interruption_reports_latest_progress_and_stops_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            child_pid = root / "child.pid"
            env = os.environ.copy()
            env["GITHUB_STEP_SUMMARY"] = str(summary)
            source = "import os,time; from pathlib import Path; Path(" + repr(str(child_pid)) + ").write_text(str(os.getpid())); print('1/1 http.test.interrupted...',flush=True); time.sleep(10)"
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("run_test_progress.py")), "--log", str(root / "log"), "--title", "CI: 50%, <HTTP & QUIC>", "--interval", "0.01", "--", sys.executable, "-c", source], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                until = time.monotonic() + 3
                while not summary.exists() or "http.test.interrupted" not in summary.read_text():
                    if time.monotonic() >= until:
                        self.fail("child test progress was not published")
                    time.sleep(0.005)
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(130, process.returncode, stderr.decode())
                self.assertIn(b"::error title=CI%3A 50%25%2C <HTTP & QUIC>::Interrupted command", stdout)
                self.assertIn("CI: 50%, &lt;HTTP &amp; QUIC&gt;", summary.read_text())
                self.assertIn("http.test.interrupted", summary.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(child_pid.read_text()), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

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
        self.assertIn("::notice title=Test progress::Test progress: 1/1 http.test.wait...", output)
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

    def test_short_command_identifies_invocation_before_first_periodic_notice(self):
        result, log = self.launch("print('completed')", "Native WT: deadline, 50%")
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"completed\n", log)
        output = result.stdout.decode()
        self.assertIn("::notice title=Native WT%3A deadline%2C 50%25::Native WT: deadline, 50%25: No test name emitted yet", output)
        self.assertLess(output.index("::notice"), output.index("completed"))

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
