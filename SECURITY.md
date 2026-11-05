# Security Policy

## Supported Versions

Security fixes land on the current stable line, and on a development line while
one is in pre-release. Older lines are not patched; upgrade instead.

| Version         | Supported          | Notes                                   |
| --------------- | ------------------ | --------------------------------------- |
| 1.6.x           | :white_check_mark: | current stable                          |
| 1.5.x and older | :x:                | no longer patched                       |
| 0.x             | :x:                | no longer patched                       |

Supported interpreters are the test matrix's blocking tier: CPython 3.11
through 3.15. `pyproject.toml` declares `requires-python = ">=3.8"`, but 3.8 to 3.10 are
best-effort (tested, never blocking). A report that only reproduces outside the tested range is
still welcome; it may be fixed by raising the floor rather than by patching.

## Reporting a Vulnerability

**Please do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting instead:

- <https://github.com/JarryShaw/PyPCAPKit/security/advisories/new>

It opens an advisory visible only to the maintainer, so a patch can be prepared
before anything is public, and a CVE issued if one is warranted. If you cannot use
it, email the maintainer address in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) and
say the report is a security issue.

Please include whatever you have:

- the version of `pypcapkit` and the Python interpreter,
- what an attacker gains, and what they need in order to get it,
- a capture file or a short script that reproduces it -- **strip anything
  sensitive from a capture first**, since a pcap from a real network tends to carry
  more than the bug.

## What to Expect

This is a single-maintainer project, so response is best-effort:

- an acknowledgement that the report arrived, normally within a week,
- once reproduced, an assessment of whether it is accepted and a rough severity,
- a fix on the supported lines above, released as a patch version, with credit in
  the changelog unless you would rather not be named.

If a report is declined, you are told why -- most often that it describes expected
behaviour for a packet parser, which the threat model below covers.

## Threat Model

`pcapkit` parses attacker-controlled bytes by design: a capture file or a live
stream off the wire is untrusted input. Vulnerabilities in that parsing are in
scope, in particular:

- memory exhaustion, unbounded allocation, or a hang on a malformed packet,
- a parse error escaping the public API as anything but the
  `pcapkit.utilities.exceptions` type it is meant to be -- report it even though some
  cases are known,
- anything that executes code, writes outside the requested output path, or reads
  an unrelated file as a result of the *contents* of a capture.

Out of scope:

- the optional third-party extraction engines' own defects (`dpkt`, `scapy`,
  `pyshark`, `pypcap`, `pcap-ct`, `pypcapfile`) -- report those upstream, though
  do say so here if `pcapkit` passes them something it should not,
- a capture that parses to the wrong values without any security consequence;
  that is an ordinary bug and belongs in a public issue,
- needing elevated privileges to capture live traffic, which is the operating
  system's requirement rather than this project's.

## Handling Untrusted Captures

The parser cannot always tell a capture truncated in transit from one crafted to
look that way, from inside the field that declares the length. So for captures you
did not produce yourself:

- **Bound the memory.** A malformed or hostile capture can expand to far more than
  its size on disk. Parse in a subprocess under an address-space limit
  (`resource.RLIMIT_AS`) or a container memory limit, rather than relying on the
  parser to bound itself.
- **Bound the time**, by the same mechanism and for the same reason.
- **Expect failure, including failure the hierarchy does not cover.** Catch
  `pcapkit.utilities.exceptions.BaseError` for parse errors, and be ready for
  built-in types such as `MemoryError` as well.
- **Do not trust a field more than the capture it came from.** A truncated or
  malformed field may parse to a value rather than raise, so a value that carries
  a security decision deserves its own validation.
