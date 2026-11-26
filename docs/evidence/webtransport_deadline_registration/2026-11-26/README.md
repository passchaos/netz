# Focused WebTransport deadline test registration

The native Linux and Windows deadline CI steps on
`045cb2ad14a5f812d301ea852917d1faf1fcd70e` failed with
`NoMatchingProtocolTests`: the new STREAM socket cases were imported by the
lazy stream implementation. A broader local filter pulled that implementation
into test discovery, masking the narrower CI filter's missing named cases.

The cases now enter through the canonical WebTransport runtime test root. The
old implementation import was removed, retaining each original case and the
focused suite's nonempty-match guard. CI filters, dependency pins and timeout
values are unchanged.

[validation.json](validation.json) records the CI's exact filter set running
on macOS, with all three associated STREAM/prefix/FIN cases executed, plus
the same filter set compiling for x86_64 Windows. Native Linux and Windows
execution of the corrected registration still requires the next CI run.
The preceding complete gate also reported an earlier unlabelled ABRT, so this
focused registration fix does not establish full-gate completion.
