---
name: Bug report
about: Create a report to help us improve
labels: bug

---

**Describe the bug**
A clear and concise description of what the bug is.

**Reproduction**
The shortest script or command that shows the problem, followed by the output you
actually got from running it. A reproduction that was executed is worth much more
than one written from memory, so please paste real output rather than describing
it. If a capture file is needed to trigger it, attach one -- and **strip anything
sensitive from a capture first**, since a pcap taken from a real network usually
carries more than the bug.

**Expected behavior**
A clear and concise description of what you expected to happen. Where a value is
simply wrong, the most useful form is the observed value next to the expected one.

**System information**
A clear and concise description of your system information.
 - OS Version: [e.g. macOS 15.3, Ubuntu 24.04, Windows 11]
 - Python Version: [e.g. 3.14, 3.12, 3.10]
 - Python Implementation: [e.g. CPython, PyPy]
 - `pcapkit` Version: [`python -c "import pcapkit; print(pcapkit.__version__)"`]
 - If you are working from a checkout rather than an installed release, please give
   the commit too [`git rev-parse --short HEAD`]. The version string alone does not
   identify the tree, and an editable install can resolve to something well behind
   the branch you think you are on.

**Traceback stack**
If the bug raises, run the program again with `PCAPKIT_DEVMODE=true` set and paste
the traceback. Plenty of defects are silent rather than fatal -- if nothing is
raised, say so and leave this section out.

**Additional context**
Add any other context about the problem here. If you have already found the
offending code, an exact `file:line` is the single most useful thing you can
include; so is a note on why the existing tests do not catch it.
