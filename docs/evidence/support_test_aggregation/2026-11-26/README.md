# Share auxiliary test compilation without losing coverage

The full gate previously compiled 17 support test executables. They now share
one root and registration module. All 62 named baseline cases remain present;
the shared import root adds one entry, for 63 passing native cases. Existing
individual steps and a separate-executable diagnostic target remain available.
Library/package, soak, fuzz, Python and live interop membership is unchanged.

Main-tree verification passed 63 cases and scoped Windows compilation. The
member registry validates literal imports in one pass, keeping its branch
quota unchanged. Build registration is extracted from build.zig into cohesive
support modules, reducing the main script from 1071 to 776 lines.

An earlier same-source comparison measured the affected independent path at
107.551 seconds and grouped path at 34.918 seconds. These local measurements do
not prove complete CI now fits its existing 28-minute deadline. Native Windows
execution and the full gate still require CI. Dependency pins and CI budgets
remain unchanged.
