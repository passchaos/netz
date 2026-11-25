# Windows trust fixture positional file preparation — 2026-11-25

The native Windows trust-startup gate at `5b83ec15` fails the real CA-file
authentication fixture with `INVALID_PARAMETER`. Linux and both macOS
compilation jobs pass. The fixture creates its PEM using `Dir.writeFile`,
which calls `File.writeStreamingAll`.

The pinned zio backend opens Windows files with OVERLAPPED handles. Its
streaming read/write tests explicitly document that such handles do not have
an implicit file cursor; positional I/O is supported. Preparing the fixture
with a scoped `createFile` and `writePositionalAll(..., 0)` honors that contract
and closes the writer before the trust loader opens the PEM.

The two actual authentication modes remain selected: POSIX `SSL_CERT_FILE`
loading and caller-owned roots from the same PEM. The second mode runs on
Windows and exercises the stable `BundleVerifier` callback owner. Each fixture
still uses one zio runtime and a joined server task.

The source change is limited to file preparation; no dependency or backend
implementation is changed. Scoped local and native verification is recorded
beside this document.

| Verification | Result | Evidence |
| --- | --- | --- |
| Native Windows fixture before positional preparation | Failed in the trust-startup gate | [native-windows-before.json](native-windows-before.json) |
| Both CA authentication fixture modes locally | 35/35 passed | [authentication.Debug.log](authentication.Debug.log) |
| Both modes for Windows | Compiled | [authentication.windows.compile.log](authentication.windows.compile.log) |
