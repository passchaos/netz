# Deterministic summary-publication fixture

Run 45641634010 on 6b17e5f0 failed preflight's progress helper test because a
210-ms child schedule produced eight periodic notices rather than more than
ten. The final-summary content did not establish how many timer callbacks the
host scheduler could execute during that short duration.

The child now publishes one numbered marker and waits until the summary contains
that marker before continuing. Fourteen markers therefore require fourteen
summary publications and their corresponding notices. HTML escaping and the
final compiler-output update retain their existing assertions. A bounded child
wait and outer subprocess timeout still stop a broken publication contract.
The complete ten-test helper suite passes locally. The currently running
complete job is preserved until its terminal result before this correction is
pushed. [Validation](notice-publication-validation.json) records the source hash
and original CI failure boundary.
