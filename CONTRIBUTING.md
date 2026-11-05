# How to contribute

This document covers the development workflow, the commit message format, and the repository rules
that are easy to trip over — the test tiers and the generated changelog especially. The README
covers installation.

## Getting started

- Fork the repository on GitHub.
- Read the README for installation, and the *Testing* page it links
  (`docs/source/contributing/testing.rst`) for the test commands.
- Set up a development environment with `make setup`, which runs `pipenv install --skip-lock --dev`.
  The `Makefile` exports `PIPENV_VENV_IN_PROJECT=1`, so the environment lands in `.venv/` inside the
  checkout. **Only that environment has the dependencies**: the `make` targets below run through
  `pipenv run`, and `pytest` or `sphinx` from a system interpreter fails on missing imports rather
  than on anything you changed.
- For something to pick up, `docs/source/contributing/pep.rst`, rendered as the *Help Wanted* page,
  lists the open proposals.

## Contribution flow

- Create a topic branch, usually from `main`.
- Make commits of logical units, and add a test case if the change fixes a bug or adds functionality.
- Run the tests and make sure they pass (see below).
- Describe a user-visible change in the pull request, and leave its changelog entry to the
  maintainer (see below).
- Format the commit messages as below.
- Push the branch to your fork and open a pull request.

## Running the tests

The suite has a unit tier and a fixture-dependent tier. The tier is a property of a module's *path*,
not of the command that collects it; `tests/_tiers.py` is the rule.

```shell
make test        # the unit tier -- the selection CI runs
make test-all    # everything, regenerating the sample captures first
```

`make test` runs what `.github/workflows/unit-tests.yml` runs: everything under `tests/` except
`tests/integration/` and the `*_runtime.py` / `*_regression.py` modules. It must pass on a fresh
clone with only the package and its test extra installed.

The fixture-dependent tier reads sample captures under `examples/captures/`, most of which are
**not** tracked (see `.gitignore`). `make samples` rebuilds them, and `make test-all` does that first.
The trap: a unit-tier module that reads a *generated* capture passes on your machine, where you have
run `make samples`, then fails on a fresh CI checkout with a missing-file error that blames the
fixture rather than the tier rule. `tests/conftest.py` and `tests/test_tier_guard.py` catch most
shapes of it at collection time and say what to do; `tests/_tiers.py` has the rest.

## Changelog entries

Entries live in `docs/source/changelog/<version>.rst`, one file per version, listed newest-first in
the toctree of `docs/source/changelog.rst`, which is the single source of the project's history.

**Pull requests for user-visible changes do not add their own bullet.** An unreleased version's
entry is written by the maintainer once a change is ready to merge or has merged, because pull
requests that each edit the same file conflict on every merge. Leave
`docs/source/changelog/<version>.rst` and `CHANGELOG.md` out of the diff.

**`CHANGELOG.md` is generated — never edit it by hand.** `util/changelog_md.py` derives it from the
newest entry alone, for consumers that read Markdown rather than reStructuredText: the
`Create Release` workflow's release body and the source distribution. The maintainer adds the
bullet to the `.rst` entry, then regenerates:

```shell
python util/changelog_md.py            # rewrite CHANGELOG.md from the newest entry
python util/changelog_md.py --check    # exits 0 when they agree, prints a diff when they do not
```

The generator needs only the standard library. The `Changelog drift` job in
`.github/workflows/unit-tests.yml` runs `--check` on every push to `main`, every pull request
targeting it, and whenever another workflow calls that one as a gate (the vendor and conda updates,
the pages deploy and the release), with no `gate-only` guard to opt out. A hand-edited
`CHANGELOG.md` fails it.

## Documentation

Documentation is reStructuredText under `docs/source/`, built with `make docs`. Docstrings in
`pcapkit/` are reStructuredText too, and the API reference renders from them.

The Markdown files at the repository root — this one, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
`CHANGELOG.md` and the README — are a deliberate exception, because GitHub and the release body
render them rather than Sphinx. The issue and pull-request templates under `.github/` are Markdown
for the same reason. Anything added under `docs/source/` is `.rst`.

### What belongs in the API reference: document the contract, hide the recipe

The tenet: **keep the usage and extensibility clear and straightforward, while hiding the recipe**.
A member earns an autodoc directive because a reader needs it: a leading underscore is not by itself
a reason to leave it out, and being public is not by itself a reason to put it in.

**Contract — document it.** Anything a *caller* needs in order to use a class, and anything an
*implementer* needs in order to subclass it:

- **Per-option and per-parameter `_read_*` / `_make_*` pairs.** These publish the data format: the
  keyword arguments a caller passes to construct that option, and the fields parsing it returns.
  Nothing else documents them, so they stay documented even though dispatch reaches them through
  `getattr` rather than by name.
- **Most class private attributes.** A private attribute that carries a subclass's state, or that a
  subclass sets or reads, is contract. Keep it unless there is a specific reason not to.
- **Anything abstract, or implemented across subclasses.** An `@abstractmethod`, or an overridable
  hook a subclass is expected to provide — `_make_data` has a concrete base implementation on
  `ProtocolBase` and is overridden across the protocol modules, which is exactly this case.
- **Members whose observable behaviour is documented**, such as a method whose docstring records the
  warning it emits or a guarantee it makes. A reader who hits that warning looks it up here.

**Recipe — leave it out.** Implementation detail on nobody's usage or extensibility surface, chiefly
**module-level privates**: a private helper function, a lazily imported backend flag, an internal
lock, a private wrapper class nobody constructs or subclasses. Removing one takes its members with
it, which is correct — they are reachable only through that class.

The rule cuts **both ways**: a must-implement member with no directive is the same defect as a
recipe body with one, only quieter. Add the missing directive rather than aiming for a small diff.

Mechanical points that decide real cases:

- **A private base class stays documented when a documented subclass carries
  `:show-inheritance:`.** Sphinx renders that subclass's `Bases:` line as a link into the private
  class's entry, so dropping the directive breaks a link on a public page. This keeps
  `pcapkit.protocols.misc.pcapng.schema._OPT_Option` and the other per-block option bases with
  documented subclasses, plus `_IPField`, `_IPInterfaceField` and `_TextField`.
- **Dunders keep their directives.** A `__dunder__` is reached through public syntax, not by name
  (`len()` calls `__len__`, `obj[key]` calls `__getitem__`), so overriding one changes behaviour a
  caller observes without writing the name. PyPCAPKit's own `__proto__`, `__option__`, `__schema__`
  and `__protocol_name__` family is the extension contract that subclass authors and the
  `register_*` functions write to: public API in everything but spelling.

One exception by design: the `pcapkit/const/` enums carry a `_missing_` fallback that resolves an
unregistered value rather than raising as a plain `enum` would. That is the extensibility behaviour
of the whole `pcapkit.const` package, so it is documented once on the package's landing page rather
than on each registry. `docs/source/conf.py` names `_missing_` in
`autodoc_default_options['exclude-members']`, so a per-class directive would contradict the
project's own configuration.

## Coding style

[PEP 8](https://peps.python.org/pep-0008/) is the baseline, and the repository's own linters win
where they differ from it — notably on line length, which is 120 for `pylint` and 100 for `isort`,
not PEP 8's 79. Run them through the `Makefile`, which carries their flags:

```shell
make isort     # import ordering
make pylint    # errors, warnings, refactoring and docstring style
make mypy      # type checking over pcapkit/
make bandit    # security lint
make vermin    # minimum-Python-version check
```

`pylint`, `mypy`, `bandit` and `vermin` also run as the `Lint` job in `.github/workflows/lint.yml`:
on every pull request against `main`, on a weekly Saturday schedule and through
`workflow_dispatch`, on the newest supported Python alone (`latest` in
`.github/python-versions.toml`). The job drives them through the `Makefile` (`vermin` by its
`vermin-ci` variant), with `RUN=` emptying the `pipenv run` prefix, so local and CI runs read the
same flags.

**Those steps are advisory, not a gate.** Each carries `continue-on-error: true`, so a finding lands
as a non-blocking annotation and a red linter will not fail your pull request. The workflow's
header records which of them are clean and what each of the others needs before its
`continue-on-error` line can go. Each step writes its verdict to the job's run summary; try not to
add to the numbers.

**One step does gate:** `actionlint`, which lints the workflow YAML rather than `pcapkit/`, has no
`continue-on-error` and no `Makefile` target, so a change under `.github/` can turn `Lint` red. The
header records that split, and asks for a promoted step to be moved below the advisory ones, since a
failed step skips every step after it.

No `Lint` step runs `isort`. It runs in `cron-vendor.yml` as a formatter over the regenerated
constants, and `tests/project/test_isort_clean.py`, which the `test` extra's `isort` lets run, fails
on a file whose imports `make isort` would reorder.

One trap: `make vermin` redirects its report into `temp/vermin.txt`, so when vermin finds code that
misses `vermin.ini`'s `targets = 3.8` and exits 1, Make stops at the redirect with
`make: *** [vermin] Error 1` and the report unread in the file. `make vermin-ci` runs the same flags
to stdout, which is why CI uses it. Running the lot before you push saves a review round.

### Format of the Commit Message

The subject line says what changed, and the body says why. A real one from the history, with its
body abridged and its line anchors replaced by names:

```
fix(tcp): resolve the connection flags before building the options (#587) (#597)

Building any MP_JOIN option raised `AttributeError: 'TCP' object has no
attribute '_flags'`. `TCP.make` built the options before it assigned
`self._flags`, but `_make_mptcp_join` branches on that attribute to choose
between RFC 8684 s3.2's three MP_JOIN layouts [...]
```

The format is:

```
type(scope): what changed (#issue)
BLANK LINE
why this change was made
BLANK LINE
footer (optional)
```

`type` is one of `feat`, `fix`, `docs`, `test`, `perf`, `refactor`, `ci`, `chore` or `release` —
the ones in use. `const` is not a type: it is a label for regenerated constant tables, applied
alongside the type label. `scope` names the part of the package affected — `tcp`, `corekit`,
`schema`, `ipv4`, `vendor` — with several separated by commas, as in `fix(link,internet):` or
`test(utilities,foundation):`. Omit the scope where nothing narrower than the whole project applies,
as in `docs:`. Older commits may carry a bare `protocols:` or `corekit:` prefix; follow the form
above.

Reference issues and pull requests as `#nnn`, in the subject where they fit and in the body
otherwise. Keep the subject to one line and as short as clarity allows. There is no hard column
limit — the history routinely runs past 70 characters — so do not truncate the meaning to hit one.

Say why in the body. "Improve documentation." tells a reader nothing the diff does not already
show; the defect observed, or the behaviour that was wrong, does.
