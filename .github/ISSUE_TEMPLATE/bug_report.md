---
name: Bug report
about: Create a report to help us improve
labels: bug

---

**Describe the bug**
A clear and concise description of what the bug is.

**Reproduction**
The shortest script or command that shows the problem, and the output you got from
running it -- paste real output rather than describing it. If a capture file is
needed to trigger it, attach one, and **strip anything sensitive from it first**: a
pcap taken from a real network usually carries more than the bug.

**Expected behavior**
What you expected to happen. Where a value is wrong, give the observed value next to
the expected one.

**System information**
 - OS Version: [e.g. macOS 15.3, Ubuntu 24.04, Windows 11]
 - Python Version: [e.g. 3.15, 3.13, 3.11]
 - Python Implementation: [e.g. CPython, PyPy]
 - `pcapkit` Version: [`python -c "import pcapkit; print(pcapkit.__version__)"`]
 - From a checkout rather than an installed release, the commit too
   [`git rev-parse --short HEAD`]: the version string alone does not identify the
   tree.

**Traceback stack**
If the bug raises, run the program again with `PCAPKIT_DEVMODE=true` set and paste
the full traceback. If nothing is raised, say so and leave this section out.

**Additional context**
Any other context about the problem. If you have found the offending code, a
permalink to it is the most useful thing you can include; so is a note on why the
existing tests do not catch it.
