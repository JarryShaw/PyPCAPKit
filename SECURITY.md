# Security Policy

## Supported Versions

Security fixes land on the current stable line and on the development line. Older
lines are not patched -- upgrading is the fix.

| Version         | Supported          | Notes                                   |
| --------------- | ------------------ | --------------------------------------- |
| 1.5.x           | :white_check_mark: | development line, currently pre-release |
| 1.4.x           | :white_check_mark: | current stable                          |
| 1.3.x and older | :x:                | no longer patched                       |
| 0.x             | :x:                | no longer patched                       |

Supported interpreters are those the test matrix actually covers, currently
CPython 3.10 through 3.14. `pyproject.toml` declares `requires-python = ">=3.6, <4"`
through the `bpc-*` source conversion, but 3.8 and 3.9 are best-effort and below
3.8 is intent rather than something that is exercised -- see the note above
`requires-python` in `pyproject.toml`. A report that only reproduces on an
interpreter outside the tested range is still welcome; it may be fixed by raising
the floor rather than by patching.

## Reporting a Vulnerability

**Please do not open a public issue for a security problem.** Public issues are
the right place for ordinary bugs, and the wrong place for anything exploitable.

Use GitHub's private vulnerability reporting, which is enabled on this repository:

- <https://github.com/JarryShaw/PyPCAPKit/security/advisories/new>

That opens a private advisory visible only to the maintainer, lets patches be
prepared before anything is public, and issues a CVE if one is warranted. If you
cannot use it, email the project contact listed in
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) instead and say that the report is a
security issue.

Please include whatever you have:

- the version of `pypcapkit` and the Python interpreter,
- what an attacker gains, and what they need in order to get it,
- a capture file or a short script that reproduces it -- **strip anything
  sensitive from a capture first**, since a pcap taken from a real network tends
  to carry more than the bug.

## What to expect

This is a single-maintainer project, so response is best-effort rather than
contractual:

- an acknowledgement that the report arrived, normally within a week,
- an assessment of whether it is accepted, and if so a rough severity, once it has
  been reproduced,
- a fix on the supported lines above, released as a patch version, with credit in
  the changelog unless you would rather not be named.

If a report is declined, you will be told why -- most often that it describes
expected behaviour for a packet parser. Note the threat model below before
deciding whether you have a finding.

## Threat model

`pcapkit` parses attacker-controlled bytes by design: a capture file, or a live
stream off the wire, is untrusted input. Vulnerabilities in that parsing are in
scope. In particular:

- memory exhaustion, unbounded allocation, or a hang on a malformed packet,
- an uncaught exception escaping the public API where a `pcapkit` exception was
  promised -- parse errors are meant to arrive as `pcapkit.utilities.exceptions`
  types rather than as an arbitrary traceback. That is the intent rather than
  something the parser manages everywhere today, so it is worth reporting even
  though some cases are already known,
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

## Handling untrusted captures

The scope above is about what to report. This is what a caller can do in the
meantime, because hardening a parser against hostile input is ongoing work rather
than a finished state, and some of it is limited by what a given layer can even
tell apart -- a capture legitimately truncated in transit and one crafted to look
that way are not always separable from inside the field that declares the length.

So if the captures you hand `pcapkit` are not ones you produced yourself:

- **Bound the memory.** A malformed or hostile capture can expand to a great deal
  more than its size on disk. Parse in a subprocess under an address-space limit
  (`resource.RLIMIT_AS`) or a container memory limit, rather than relying on the
  parser to bound itself.
- **Bound the time**, by the same mechanism and for the same reason.
- **Expect failure, including failure the hierarchy does not cover.** Catch
  `pcapkit.utilities.exceptions.BaseError` for parse errors, and be ready for
  built-in types such as `MemoryError` reaching you as well.
- **Do not trust a field more than the capture it came from.** A truncated or
  malformed field may parse to a value rather than raise, so a value that carries
  a security decision deserves its own validation.

None of this is peculiar to `pcapkit` -- it is the ordinary posture for giving
attacker-controlled bytes to any parser. It is written down because parsing them
is what `pcapkit` is for.
