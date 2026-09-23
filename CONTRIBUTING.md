# How to contribute

This document outlines the conventions on development workflow, commit message formatting and the
few repository-specific rules that are easy to trip over — the test tiers and the generated
changelog especially. The README is the authority on installing and building; this file covers what
happens after that.

## Getting started

- Fork the repository on GitHub.
- Read the README for installation and build instructions, and the *Testing* page it links from its
  *Documentation* table — `docs/source/testing.rst` — for the test commands.
- Set up a development environment. `make setup` runs `pipenv install --skip-lock --dev`, and the
  `Makefile` exports `PIPENV_VENV_IN_PROJECT=1`, so the environment lands in `.venv/` inside the
  checkout. **Only that environment has the dependencies** — the `make` targets below all run
  through `pipenv run`, and invoking `pytest` or `sphinx` from a system interpreter will fail on
  missing imports rather than on anything you changed.
- Looking for something to pick up? `docs/source/pep.rst` — rendered as the *Help Wanted* page — is
  the maintained list of open proposals, kept in step with the code.
- Play with the project, submit bugs, submit patches!

## Contribution flow

This is a rough outline of what a contributor's workflow looks like:

- Create a topic branch from where you want to base your work. This is usually `main`.
- Make commits of logical units, and add a test case if the change fixes a bug or adds new
  functionality.
- Run the tests and make sure they pass (see below).
- Add a changelog entry if the change is user-visible (see below).
- Make sure your commit messages are in the proper format (see below).
- Push your changes to a topic branch in your fork of the repository.
- Submit a pull request to the repo.

Thanks for your contributions!

## Running the tests

The suite runs in two tiers, and the tier is a property of a module's *path* rather than of the
command that collects it. `tests/_tiers.py` is the rule, and it documents itself at length.

```shell
make test        # the unit tier -- the selection CI runs
make test-all    # everything, regenerating the sample captures first
```

`make test` is the selection in `.github/workflows/unit-tests.yml`: everything under `tests/` except
`tests/integration/` and the `*_runtime.py` / `*_regression.py` modules. It has to pass on a fresh
clone with nothing but the package and its test extra installed.

The fixture-dependent tier reads sample captures under `examples/captures/`, most of which are
**not** tracked (see `.gitignore`); only a handful are committed. `make samples` rebuilds the rest,
and `make test-all` does that for you. This is the trap worth knowing
about: a unit-tier module that reads a *generated* capture passes on your machine, because you have
run `make samples`, and then fails on a fresh CI checkout with a missing-file error that blames the
fixture rather than the tier rule. `tests/conftest.py` and `tests/test_tier_guard.py` catch most
shapes of it at collection time and tell you what to do; read `tests/_tiers.py` if the message is
not enough.

## Changelog entries

Entries live in `docs/source/changelog/<version>.rst`, one file per version, listed newest-first in
the toctree of `docs/source/changelog.rst`. That tree is the single source of the project's history.

**`CHANGELOG.md` is generated — never edit it by hand.** It is a derivative of the newest entry
alone, produced by `util/changelog_md.py`, because its two consumers (the `Create Release`
workflow's release body and the source distribution) read Markdown rather than reStructuredText.
Add your bullet to the `.rst` entry, then regenerate:

```shell
python util/changelog_md.py            # rewrite CHANGELOG.md from the newest entry
python util/changelog_md.py --check    # exits 0 when they agree, prints a diff when they do not
```

The generator needs only the standard library, so it runs against a bare interpreter. The
`Changelog drift` job in `.github/workflows/unit-tests.yml` runs `--check` on every push to `main`
and every pull request targeting it, and again whenever another workflow calls that one as a gate —
the vendor and conda updates, the pages deploy and the release all do, and the job carries no
`gate-only` guard to opt out. A hand-edited `CHANGELOG.md` will fail it.

## Documentation

Documentation is reStructuredText under `docs/source/`, built with `make docs`. Docstrings in
`pcapkit/` are reStructuredText too, and they are what the API reference renders from.

The Markdown files at the repository root — this one, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
`CHANGELOG.md` and the README — are a deliberate exception to that rule, because their consumers are
GitHub's own rendering and the release body rather than Sphinx. The issue and pull-request templates
under `.github/` are Markdown for the same reason. The exception ends there: anything added under
`docs/source/` is `.rst`.

### What belongs in the API reference: document the contract, hide the recipe

The tenet is to **keep the usage and extensibility clear and straightforward, while hiding the
recipe**. A member earns an autodoc directive because a reader needs it, not because of its spelling —
so a leading underscore is not by itself a reason to leave something out, and being public is not by
itself a reason to put it in.

**Contract — document it.** Anything a *caller* needs in order to use a class, and anything an
*implementer* needs in order to subclass it:

- **Per-option and per-parameter `_read_*` / `_make_*` pairs.** These publish the data format: the
  keyword arguments a caller passes to construct that option, and the fields they get back when
  parsing it. There is nowhere else to look it up, so they stay documented even though the dispatch
  reaches them through `getattr` rather than by name.
- **Most class private attributes.** A private attribute that carries a subclass's state, or that a
  subclass sets or reads, is contract. Keep it unless there is a specific reason it is not.
- **Anything abstract, or implemented across subclasses.** An `@abstractmethod`, or an overridable
  hook a subclass is expected to provide — `_make_data` has a concrete base implementation on
  `ProtocolBase` and is overridden in 28 protocol modules, which is exactly the case this covers.
- **Members whose observable behaviour is documented**, such as a method whose docstring records the
  warning it emits or a guarantee it makes. A reader who hits that warning looks it up here.

**Recipe — leave it out.** The implementation detail that is on nobody's usage or extensibility
surface. In practice this is chiefly **module-level privates**: a private helper function, a lazily
imported backend flag, an internal lock, a private wrapper class nobody constructs or subclasses.
Removing one of these takes its members with it, which is correct — a member of a private class is
reachable only through that class.

The sweep runs **in both directions**. A must-implement member with no directive is the same defect as
a recipe body with one, only quieter: add the missing directive rather than aiming for a small diff.

Two mechanical points that decide real cases:

- **A private base class must stay documented when a documented subclass carries
  `:show-inheritance:`.** Sphinx renders that subclass's `Bases:` line as a link into the private
  class's page, so dropping the directive breaks a link a public page really does render. This is what
  keeps `pcapkit.protocols.schema.misc.pcapng._OPT_Option` and its five siblings, plus `_IPField`,
  `_IPInterfaceField` and `_TextField`.
- **Dunders keep their directives.** A `__dunder__` is reached through public syntax rather than by
  name — `__len__` is what `len()` calls, `__getitem__` is what `obj[key]` does — so overriding one
  changes behaviour a caller observes without ever writing the name. PyPCAPKit's own `__proto__`,
  `__option__`, `__schema__` and `__protocol_name__` family is the documented extension contract that
  subclass authors and the `register_*` functions write to: public API in everything but spelling.

One shape to know about because it is invisible: every const enum carries a `_missing_` fallback that
resolves an unregistered value and registers it, rather than raising as a plain `enum` would. That is
deliberate and it is the extensibility behaviour of the whole `pcapkit.const` package, so it is
documented once on the package's landing page rather than restated on each of the 121 enumerations
under `pcapkit/const/` that implement it. Note `docs/source/conf.py` already names `_missing_` in
`autodoc_default_options['exclude-members']`, so a per-class directive would be arguing with the
project's own configuration.

## Coding style

[PEP 8](https://peps.python.org/pep-0008/) is the baseline, but the repository's own linters are the
authority where they differ from it — notably on line length, which is 120 for `pylint` and 100 for
`isort`, not PEP 8's 79. Run them through the `Makefile`, which carries the flags they are meant to
be run with:

```shell
make isort     # import ordering
make pylint    # errors, warnings, refactoring and docstring style
make mypy      # type checking over pcapkit/
make bandit    # security lint
make vermin    # minimum-Python-version check
```

Four of them — `pylint`, `mypy`, `bandit` and `vermin` — also run in CI, as the `Lint` job in
`.github/workflows/lint.yml`: on every pull request against `main`, on a weekly Saturday schedule
and on demand through `workflow_dispatch`, on Python 3.14 alone rather than across the test matrix.
The job drives them through the `Makefile` rather than restating their flags — `pylint`, `mypy` and
`bandit` by the targets above, `vermin` by its `vermin-ci` variant — with `RUN=` emptying the
`pipenv run` prefix. Both paths read the same flag variables, so a check cannot come out clean
locally and red in CI because the two definitions drifted.

**Those steps are advisory, not a gate.** Each carries `continue-on-error: true`, so a finding lands
as a non-blocking annotation and a red linter will not fail your pull request. That is a consequence
of none of the four being clean today; the workflow's header records the current counts and what
each tool would need before its `continue-on-error` line could be deleted. Read the job's run
summary — each step writes its own verdict there — and try not to add to the numbers.

`isort` is the exception and is still local-only. It does appear in `cron-vendor.yml`, but as a
formatter that rewrites the regenerated constants rather than as a check, so nothing verifies import
ordering on a pull request.

One trap in the target list above: `make vermin` redirects its report into `temp/vermin.txt`
rather than to your terminal, and vermin exits 1 today because `vermin.ini` sets `targets = 3.6`
against a real floor of 3.11. Make gives up at that redirect, so the run fails with
`make: *** [vermin] Error 1`, the report left in the file, and the line that would have opened it
never reached. `make vermin-ci` runs the same flags straight to stdout, which is why CI uses it
and why it is the easier of the two to read at a desk. Running the lot before you push still saves
a review round.

### Format of the Commit Message

We follow a rough convention designed to answer two questions: what changed and why. The subject
line carries the what, and the body of the commit describes the why. A real one from the history,
with its body abridged:

```
fix(tcp): resolve the connection flags before building the options (#587) (#597)

Building any MP_JOIN option raised `AttributeError: 'TCP' object has no
attribute '_flags'`. `TCP.make` built the options at tcp.py:547 and assigned
`self._flags` only at tcp.py:567, but `_make_mptcp_join` (tcp.py:2780-2786)
branches on that attribute to choose between RFC 8684 s3.2's three MP_JOIN
layouts [...]
```

The format is:

```
type(scope): what changed (#issue)
BLANK LINE
why this change was made
BLANK LINE
footer (optional)
```

`type` is one of `feat`, `fix`, `docs`, `test`, `perf`, `refactor`, `ci` or `chore` — those are the
ones in use. `scope` names the part of the package affected — `tcp`, `corekit`, `schema`, `ipv4`,
`vendor` — and several are separated by commas inside the parentheses, as in `fix(link,internet):`
or `test(utilities,foundation):`. The scope may be omitted where nothing narrower than the whole
project applies, as in `docs:`.

Older history is mixed, and `git log` will show you a bare `protocols:` or `corekit:` subsystem
prefix from before this settled. Follow the form above for new work rather than the older one.

Reference issues and pull requests as `#nnn`, in the subject where they fit and in the body
otherwise. Keep the subject to one line and as short as clarity allows; there is no hard column
limit, and the history routinely runs past 70 characters and up to about 120, so do not truncate the
meaning to hit a number.

Say why in the body rather than falling back on a generic line. "Improve documentation." tells a
future reader nothing that the diff does not already show; the defect that was observed, or the
behaviour that was wrong, does.
