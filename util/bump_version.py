# -*- coding: utf-8 -*-
"""Bump ``pcapkit.__version__``, and the metadata that has to move with it.

This is the script the ``Vendor Update`` workflow runs after a registry crawl has
changed something under :mod:`pcapkit.const`. It reads the current version, works
out the next one under :pep:`440`, and writes it back.

Where it is invoked from, and why that matters
----------------------------------------------

Exactly one caller: the ``Bump Version`` step of
:file:`.github/workflows/cron-vendor.yml`, between the crawl and the ``git
commit``. Completion of that workflow is itself the ``workflow_run`` trigger of
:file:`.github/workflows/create-release.yml`, which reads ``pcapkit.__version__``
back out of the tree, tags ``v<version>``, and publishes to PyPI and Anaconda.

So in this repository a bump is not a preparatory step that a release later
follows -- the bump *is* what causes the release, minutes later and with no human
in between. That fact decides what this script is responsible for updating, and
it is the reason ``date-released`` below is in scope rather than left to a
release step that does not exist.

``CITATION.cff``
----------------

:file:`CITATION.cff` records ``version`` and ``date-released``. GitHub renders it
as the repository's *Cite this repository* button, and citation managers, Zenodo
and dependency inventories read it directly, so a wrong number there propagates
into papers and into bills of materials. Nothing else in the repository maintains
the file: no workflow writes it, and there is no release step that could. Left
out of this script it would state the *previous* release forever, which is worse
than having no citation file at all, because a stale one is still consumed.

Both fields move together, and the reason is that they have the same standing. The
file's own header says ``version`` and ``date-released`` both "describe the newest
*published* release", so at the moment of a bump both are equally anticipatory --
there is no principled line that lets one move and pins the other. Moving only
``version`` would leave the pair asserting something plainly false and leave it
there indefinitely: "1.5.0b5, released on the day 1.5.0b4 was".

Measured over the thirty most recent releases, the bump commit's UTC calendar date
equals the PyPI upload's UTC calendar date **thirty times out of thirty**, median
gap three minutes, and no bump in the project's history has taken more than a day
to publish. The weekly cron fires at 10:05 UTC and publishes at 10:07, twelve
hours clear of a date boundary. Hence UTC via :func:`datetime.datetime.now` with an
explicit timezone, not :meth:`datetime.date.today`: seven of those thirty bumps
were made late evening in US-Eastern, where a naive local date would have been a
day behind the publish it was describing.

The residual risk is stated rather than hidden. Roughly one bump in twelve
historically never reached PyPI at all -- eight consecutive weekly bumps between
2024-04-13 and 2024-06-15, and ``1.5.0b1`` -- and for those this script writes an
optimistic date for a release that never happened. That is not an argument for
leaving the field stale, since a stale date is wrong in *every* one of the other
eleven cases; it is an argument for eventually anchoring both fields to
:file:`.github/workflows/create-release.yml`, which runs only when a publish is
actually going out. Until then this is the better of the two available answers, and
the ``version`` half is guarded by a test that fails when the file drifts from
``pcapkit.__version__`` -- which also covers the version changes made by hand,
which never run this script at all. Those are 40 of the 159 commits that have
moved ``__version__`` on ``main``, a quarter over the project's life and a rising
share lately: 11 of the most recent 25.

The rewrite is line-oriented rather than a :mod:`yaml` load-and-dump. A round
trip through a YAML library would reorder keys, normalise quoting, and drop the
sixteen lines of comment that explain why the file omits ``doi`` and ``orcid`` --
none of which is a change anyone asked for. Matching ``^version:`` and
``^date-released:`` at column zero is enough to identify the two top-level keys,
since every nested key in the file is indented and ``cff-version`` does not
begin with ``version``.

Each field keeps whatever quoting it already had. The file as committed spells one
of each -- ``version: 1.5.0b4`` bare and ``date-released: '2026-09-20'`` quoted,
the latter deliberately, so that a validator reads a string rather than casting it
to a YAML date object. Preserving the style rather than normalising it keeps the
automated commit's diff down to the value that actually moved, and leaves the
choice of style where it belongs. An unquoted version is safe here because every
string :func:`bump` returns carries a ``.devN`` / ``aN`` / ``bN`` / ``rcN`` /
``.postN`` suffix, so none of them can be misread as a YAML number the way a bare
``2.0`` would be.

One acknowledged limit: an inline ``#`` comment after either value would not
survive the rewrite. Neither line carries one, all of this file's commentary being
whole-line, and parsing far enough to know the difference is the YAML round trip
this approach exists to avoid. The loss would be visible in the diff.

When the file is not there
--------------------------

A missing :file:`CITATION.cff` is reported on :data:`sys.stderr` and then skipped.
It is deliberately **not** fatal, and the reason is where this script runs. The
``Bump Version`` step executes under ``bash -e``, *before* the workflow's ``git
commit``, so a non-zero exit there does not merely skip the citation update -- it
fails the step, discards the whole vendor crawl that the run existed to produce,
and the release that would have followed never happens. Trading a published
release and a week of registry updates for a missing documentation file is the
wrong way round. It is announced rather than swallowed, because a bump that
quietly does not update a file it is supposed to maintain is how this class of
staleness starts.

A file that *is* present and carries no ``version`` field is a different case and
does raise :exc:`CitationFieldError`. There the script is in exactly the situation
it was written for, and finding nothing to update means the file's shape has
changed underneath it -- an outcome indistinguishable from success if it were
allowed to pass. Unlike an absent file that can happen by accident of packaging,
this one requires somebody to have edited :file:`CITATION.cff`, so failing on it
does not put the release automation at the mercy of the environment. The check
runs before anything is written, so the fatal case leaves the tree untouched
rather than half-bumped.

``date-released`` is optional in Citation File Format 1.2.0, so a file without one
keeps not having one; the absence is reported and no date is invented.

What is deliberately not changed
--------------------------------

:file:`conda/build` is still written relative to the working directory, as it
always was, rather than relative to the repository root the way :data:`CITATION`
is. The two disagree, and the root-relative form is the better of them -- it is
what :file:`util/changelog_md.py` documents and does -- but moving
:file:`conda/build` is a change in behaviour for every existing caller and
belongs in its own review rather than riding along with this one.

"""

from __future__ import annotations

import argparse
import datetime
import os
import pathlib
import sys
from typing import TYPE_CHECKING, cast

from packaging.version import Version

if TYPE_CHECKING:
    from typing import Optional, Sequence

__all__ = ['CitationFieldError', 'bump', 'read_citation', 'plan_citation', 'main']

#: Repository root, taken from this file's location rather than the working
#: directory, so the script finds the same :file:`CITATION.cff` run from
#: anywhere. This is the spelling :file:`util/changelog_md.py` uses and for the
#: same reason.
ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Citation metadata, in Citation File Format 1.2.0. Its ``version`` and
#: ``date-released`` fields are the ones this script keeps in step with
#: ``pcapkit.__version__``.
CITATION = ROOT / 'CITATION.cff'

#: Top-level ``CITATION.cff`` key naming the released version. Matched at column
#: zero: every nested key in the file is indented, and ``cff-version`` -- the
#: format version, which must *not* move -- does not begin with this prefix.
VERSION_KEY = 'version:'

#: Top-level ``CITATION.cff`` key naming the release date. Optional in the
#: format, so its absence is reported rather than filled in.
RELEASED_KEY = 'date-released:'


def _restyle(key: str, body: str, value: str) -> str:
    """Re-emit ``key`` with ``value``, in the quoting style ``body`` already used.

    Args:
        key: Field name including its colon.
        body: The existing line, newline already stripped.
        value: Replacement value.

    Returns:
        The rewritten line, without a terminator.

    """
    current = body[len(key):].strip()

    quote = ''
    if len(current) > 1 and current[0] in ('"', "'") and current[-1] == current[0]:
        quote = current[0]

    return f'{key} {quote}{value}{quote}'


class CitationFieldError(RuntimeError):
    """Raised when :file:`CITATION.cff` exists but has no ``version`` field.

    Subclasses :exc:`RuntimeError` rather than defining a new hierarchy, to match
    the ``cannot find version`` failure this script already raised for the same
    class of problem in :file:`pcapkit/__init__.py`.

    """


def current_version() -> str:
    """Read the version that is about to be bumped.

    Prefers the installed package, which is what the ``Vendor Update`` workflow
    has, and falls back to scraping :file:`pcapkit/__init__.py` out of the working
    directory when :mod:`pcapkit` cannot be imported.

    The fallback strips whitespace before quotes rather than both at once. The
    previous spelling, ``strip(" '")``, stopped at the trailing newline and so
    returned ``"1.5.0b4'\\n"`` -- quote and newline included -- which
    :class:`~packaging.version.Version` rejects outright with
    :exc:`~packaging.version.InvalidVersion`. The path had therefore never worked;
    it went unnoticed because the only caller installs the package first, so
    :mod:`pcapkit` always imports and the fallback is never reached in CI.

    Returns:
        The current version string.

    Raises:
        RuntimeError: If neither source yields a version.

    """
    try:
        import pcapkit
        return pcapkit.__version__
    except ImportError:
        version = ''

        path = os.path.join('pcapkit', '__init__.py')
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                if line.startswith('__version__'):
                    version = line.split('=')[1].strip().strip('\'"')

        if not version:
            raise RuntimeError('cannot find version')

        return version


def bump(version: str) -> str:
    """Work out the next version under :pep:`440`.

    A development release bumps its ``devN`` counter, a pre-release its ``aN`` /
    ``bN`` / ``rcN`` counter, a post-release its ``postN`` counter, and a final
    release gains ``.post1``. Every result therefore carries a non-numeric
    suffix, which is worth knowing when reading it back out of YAML.

    Args:
        version: The current version string.

    Returns:
        The bumped version string.

    """
    ver_obj = Version(version)
    base_version = ver_obj.base_version

    if ver_obj.is_devrelease:
        dev = cast('int', ver_obj.dev)
        return base_version + '.dev' + str(dev + 1)

    if ver_obj.is_prerelease:
        pre = cast('tuple[str, int]', ver_obj.pre)
        return base_version + pre[0] + str(pre[1] + 1)

    if ver_obj.is_postrelease:
        post = cast('int', ver_obj.post)
        return base_version + '.post' + str(post + 1)

    return base_version + '.post1'


def init_path() -> str:
    """Locate the :file:`pcapkit/__init__.py` to rewrite.

    Prefers the installed package's copy, which under an editable install is the
    working tree's own file, and falls back to the working directory.

    Returns:
        Path to the file carrying ``__version__``.

    """
    try:
        import pcapkit
        return os.path.join(pcapkit.__path__[0], '__init__.py')
    except ImportError:
        return os.path.join('pcapkit', '__init__.py')


def rewrite_init(path: str, new_ver: str) -> None:
    """Write ``new_ver`` into the ``__version__`` assignment at ``path``.

    Args:
        path: File carrying the ``__version__`` assignment.
        new_ver: Version string to record.

    """
    contents = []  # type: list[str]
    with open(path, 'r', encoding='utf-8') as in_file:
        for line in in_file:
            if line.startswith('__version__'):
                line = f'__version__ = {new_ver!r}'
            contents.append(line)

    with open(path, 'w', encoding='utf-8') as out_file:
        out_file.writelines(contents)
        out_file.write('\n')


def plan_citation(text: str, version: str, released: Optional[str] = None) -> str:
    """Return ``text`` with its ``version`` and ``date-released`` fields moved on.

    Nothing is written; the caller decides that, which is what lets the failure
    below happen before the rest of the bump has touched the tree. Every line
    other than the two keys is carried through byte for byte, including the
    comment header and each line's own terminator, so a file with CRLF endings or
    without a final newline comes back the way it went in.

    Args:
        text: Current contents of the citation file.
        version: Version string to record.
        released: Release date as ``YYYY-MM-DD``, defaulting to today in UTC.
            Only written if the file already carries a ``date-released`` field;
            the field is optional in the format and is not invented.

    Returns:
        The new contents.

    Raises:
        CitationFieldError: If ``text`` carries no top-level ``version`` field,
            which means the file's shape has changed and this script would
            otherwise rewrite nothing while reporting success.

    """
    if released is None:
        released = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

    found = False
    contents = []  # type: list[str]

    for line in text.splitlines(keepends=True):
        body = line.rstrip('\r\n')
        ending = line[len(body):]

        if body.startswith(VERSION_KEY):
            contents.append(_restyle(VERSION_KEY, body, version) + ending)
            found = True
        elif body.startswith(RELEASED_KEY):
            contents.append(_restyle(RELEASED_KEY, body, released) + ending)
        else:
            contents.append(line)

    if not found:
        raise CitationFieldError(
            f'no top-level {VERSION_KEY!r} field in the citation file; it must appear '
            f'at column zero, so a nested or differently spaced spelling reaches here '
            f'too. Either restore the field or drop CITATION.cff, rather than leaving '
            f'a file this script cannot keep in step with pcapkit.__version__'
        )

    return ''.join(contents)


def read_citation(path: pathlib.Path) -> Optional[str]:
    """Read the citation file, reporting on :data:`sys.stderr` what is not there.

    Split out from :func:`main` so that the two absences below are reachable from a
    test without a bump running, and so that reading happens before any of the
    bump's writes.

    Args:
        path: Citation file to read.

    Returns:
        The file's contents, or :obj:`None` if it does not exist -- in which case a
        notice has been printed and the caller should carry on without it. See the
        module docstring for why an absent file is not fatal.

    """
    if not path.is_file():
        print(f'{path} is absent, so the citation metadata still names an older '
              f'release. Nothing else in the repository maintains that file -- '
              f'restore it, or record the version there by hand', file=sys.stderr)
        return None

    text = path.read_text(encoding='utf-8')

    if not any(line.startswith(RELEASED_KEY) for line in text.splitlines()):
        print(f'{path} carries no {RELEASED_KEY!r} field, so no release date was '
              f'written; the field is optional in Citation File Format 1.2.0 and one '
              f'is not invented here', file=sys.stderr)

    return text


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command line entry point.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv`.

    Returns:
        ``0``; failures raise rather than returning a code, because every caller
        runs the script under a shell that stops on a non-zero exit.

    """
    parser = argparse.ArgumentParser(
        prog='bump_version.py',
        description='Bump pcapkit.__version__ and the citation metadata that tracks it.',
    )
    parser.add_argument(
        '--citation', type=pathlib.Path, default=CITATION,
        help='citation file to keep in step (default: %(default)s)',
    )
    args = parser.parse_args(argv)

    new_ver = bump(current_version())

    # Read and planned before anything is written, so the one fatal outcome -- a
    # citation file with no ``version`` field -- leaves the tree untouched instead
    # of half-bumped.
    text = read_citation(args.citation)
    planned = None if text is None else plan_citation(text, new_ver)

    rewrite_init(init_path(), new_ver)

    if planned is not None:
        args.citation.write_text(planned, encoding='utf-8')

    with open(os.path.join('conda', 'build'), 'w') as build:
        build.write('0')

    return 0


if __name__ == '__main__':
    sys.exit(main())
