# -*- coding: utf-8 -*-
"""Bump ``pcapkit.__version__``, and the metadata that has to move with it.

This is the script the ``Vendor Update`` workflow runs after a registry crawl has
changed something under :mod:`pcapkit.const`. It reads the current version, works
out the next one under :pep:`440`, and writes it back.

Reading and writing the version
-------------------------------

``__version__`` is read from :data:`INIT` through :mod:`ast`, never by importing
:mod:`pcapkit`: an import answers for whichever copy is installed, and not at all
once the file stops parsing (#2800). :data:`INIT` is taken from :data:`ROOT`, as
:data:`CITATION` is, so the file read is the file written. The rewrite is
line-oriented, and :func:`rewrite_init` reads its result back through :mod:`ast`
before writing it, refusing one that would not parse or not hold the new version.

``--github-output`` hands the new version to the workflow as the step output
``version``, which ``Commit changes`` puts in its subject; ``--print-version``
prints the current one and writes nothing, for ``Commit documentation changes``,
which commits without a bump. Importing :mod:`pcapkit` in those steps instead
fails on a tree that no longer parses, and ``git commit`` still runs, with no
version in the message (#2800).

Where it is invoked from, and why that matters
----------------------------------------------

Its caller is the ``Bump Version`` step of
:file:`.github/workflows/cron-vendor.yml`, between the crawl and the ``git
commit``. Completion of that workflow is itself the ``workflow_run`` trigger of
:file:`.github/workflows/create-release.yml`, which reads ``pcapkit.__version__``
back out of the tree, tags ``v<version>``, and publishes to PyPI and Anaconda.

So in this repository a bump is not a preparatory step that a release later
follows -- the bump *is* what causes the release, with nothing in between but the
``github-release`` environment's one approval (#887). That fact decides what this
script is responsible for updating, and it is the reason ``date-released`` below
is in scope rather than left to a release step that does not exist.

``CITATION.cff``
----------------

:file:`CITATION.cff` records ``version`` and ``date-released``. GitHub renders it
as the repository's *Cite this repository* button, and citation managers, Zenodo
and dependency inventories read it directly, so a wrong number there propagates
into papers and into bills of materials. Nothing else in the repository maintains
the file: no workflow writes it, and there is no release step that could. Left
out of this script it would state the *previous* release forever, which is worse
than having no citation file at all, because a stale one is still consumed.

``date-released`` is the date of the commit that bumps the version, not the date
the release is distributed (#2163). The release goes out only once the
``github-release`` environment is approved (#887), so the two can differ: a
release approved days after its bump keeps the bump's date, as ``1.5.0b9``'s
was (#1634), and a bump that never reaches PyPI (``1.5.0b1``'s did not) keeps
its date too. That is the intended meaning rather than a gap to close, which is
why this script writes the field and no release step does. Both fields move in
the same commit so that they describe the same bump; moving only ``version``
would leave the pair asserting something plainly false: "1.5.0b5, released on
the day 1.5.0b4 was".

The date is taken in UTC via :func:`datetime.datetime.now` with an explicit
timezone, not :meth:`datetime.date.today`, so a bump run by hand late in the
evening in US-Eastern records the commit's UTC calendar date rather than a local
one a day behind it.

The ``version`` half is guarded by a test that fails when the file drifts from
``pcapkit.__version__`` -- which also covers the version changes made by hand,
which never run this script at all. Measured at ``a41137716`` (#625), those were
about a quarter of the commits that had moved ``__version__`` on ``main``.

The rewrite is line-oriented rather than a :mod:`yaml` load-and-dump. A round
trip through a YAML library would reorder keys, normalise quoting, and drop the
comment header, which among other things explains why the file omits ``doi``
and ``orcid`` --
none of which is a change anyone asked for. Matching ``^version:`` and
``^date-released:`` at column zero is enough to identify the two top-level keys,
since every nested key in the file is indented and ``cff-version`` does not
begin with ``version``.

Each field keeps whatever quoting it already had. The file as committed spells one
of each -- ``version`` bare and ``date-released`` quoted, the latter deliberately, so that a validator reads a string rather than casting it
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

:file:`conda/build` is written relative to the working directory, rather than
relative to the repository root the way :data:`CITATION` is. The two disagree,
and the root-relative form is the better of them -- it is what
:file:`util/changelog_md.py` documents and does -- but moving :file:`conda/build`
is a change in behaviour for every existing caller, so it is left as it is.

"""

from __future__ import annotations

import argparse
import ast
import datetime
import os
import pathlib
import sys
from typing import TYPE_CHECKING, cast

from packaging.version import Version

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional, Sequence, Union

__all__ = ['CitationFieldError', 'bump', 'read_version', 'current_version', 'rewrite_init',
           'read_citation', 'plan_citation', 'main']

#: Repository root, taken from this file's location rather than the working
#: directory, so the script finds the same :file:`CITATION.cff` run from
#: anywhere. This is the spelling :file:`util/changelog_md.py` uses and for the
#: same reason.
ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The module carrying ``__version__``, read and rewritten as text.
INIT = ROOT / 'pcapkit' / '__init__.py'

#: Citation metadata, in Citation File Format 1.2.0. Its ``version`` and
#: ``date-released`` fields are the ones this script keeps in step with
#: ``pcapkit.__version__``.
CITATION = ROOT / 'CITATION.cff'

#: Top-level ``CITATION.cff`` key naming the released version. Matched at column
#: zero: every nested key in the file is indented, and ``cff-version`` -- the
#: format version, which must *not* move -- does not begin with this prefix.
VERSION_KEY = 'version:'

#: Top-level ``CITATION.cff`` key naming the release date, which is the date of
#: the version bump rather than of the publish. Optional in the format, so its
#: absence is reported rather than filled in.
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
    the ``cannot find version`` failure this script already raises for the same
    class of problem in :file:`pcapkit/__init__.py`.

    """


def read_version(text: str, filename: str = '<unknown>') -> str:
    """Read the module-level ``__version__`` assignment of ``text`` through :mod:`ast`.

    A trailing comment, or a value spanning lines, reads as Python reads it, and
    the last assignment counts, as on import.

    Args:
        text: Source of the module carrying ``__version__``.
        filename: Its name, for the messages.

    Returns:
        The version string.

    Raises:
        SyntaxError: If ``text`` does not parse.
        RuntimeError: If no module-level statement assigns ``__version__`` a string
            literal.

    """
    values = [node.value for node in ast.parse(text, filename).body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets)]
    if not values:
        raise RuntimeError(f'cannot find version: {filename} has no module-level __version__ assignment')

    try:
        version = ast.literal_eval(values[-1])
    except ValueError:
        version = None
    if not isinstance(version, str):
        raise RuntimeError(f'cannot find version: {filename} assigns __version__ '
                           f'{ast.get_source_segment(text, values[-1])}, not a string literal')
    return version


def current_version(path: Union[str, os.PathLike[str]] = INIT) -> str:
    """Read the version that is about to be bumped, from the file at ``path``.

    Args:
        path: File carrying the ``__version__`` assignment.

    Returns:
        The current version string.

    Raises:
        SyntaxError: If the file does not parse.
        RuntimeError: As :func:`read_version`.

    """
    with open(path, 'r', encoding='utf-8') as file:
        return read_version(file.read(), os.fspath(path))


def bump(version: str) -> str:
    """Work out the next version under :pep:`440`.

    A development release bumps its ``devN`` counter, a pre-release its ``aN`` /
    ``bN`` / ``rcN`` counter, a post-release its ``postN`` counter, and a final
    release gains ``.post1``. Every result therefore carries a non-numeric
    suffix, which is worth knowing when reading it back out of YAML.

    A dev release that also carries a pre-release and/or post-release segment --
    ``1.6.0rc1.dev2``, ``1.6.0.post1.dev0``, ``1.6.0rc1.post1.dev2`` -- which
    :attr:`~packaging.version.Version.is_devrelease` reports regardless of
    whether :attr:`~packaging.version.Version.pre` or
    :attr:`~packaging.version.Version.post` is set -- keeps both segments rather
    than dropping either. ``base_version`` discards ``pre`` *and* ``post``
    entirely, so the dev branch has to rebuild both from
    :attr:`~packaging.version.Version.pre` and
    :attr:`~packaging.version.Version.post` itself; omitting either would hand
    back a version that sorts *before* the one it was bumped from under
    :pep:`440` -- e.g. a bare ``1.6.0.dev1`` sorts before both ``1.6.0rc1.dev2``
    and ``1.6.0.post1.dev0``.

    Args:
        version: The current version string.

    Returns:
        The bumped version string.

    """
    ver_obj = Version(version)
    base_version = ver_obj.base_version

    if ver_obj.is_devrelease:
        dev = cast('int', ver_obj.dev)
        pre_str = ''
        if ver_obj.pre is not None:
            pre_tuple = cast('tuple[str, int]', ver_obj.pre)
            pre_str = pre_tuple[0] + str(pre_tuple[1])
        post_str = '' if ver_obj.post is None else '.post' + str(ver_obj.post)
        return base_version + pre_str + post_str + '.dev' + str(dev + 1)

    if ver_obj.is_prerelease:
        pre = cast('tuple[str, int]', ver_obj.pre)
        return base_version + pre[0] + str(pre[1] + 1)

    if ver_obj.is_postrelease:
        post = cast('int', ver_obj.post)
        return base_version + '.post' + str(post + 1)

    return base_version + '.post1'


def rewrite_init(path: Union[str, os.PathLike[str]], new_ver: str) -> None:
    """Write ``new_ver`` into the ``__version__`` assignment at ``path``.

    As in :func:`plan_citation`, the assignment keeps its own terminator and every
    other line is carried through byte for byte, so the next line is never joined
    onto it and the file ends as it began. ``newline=''`` stops the read and write
    translating CRLF.

    The rewritten text goes through :func:`read_version` before it is written, so
    a rewrite that would not parse or not hold ``new_ver`` leaves the file as it
    was (#2800).

    Args:
        path: File carrying the ``__version__`` assignment.
        new_ver: Version string to record.

    Raises:
        RuntimeError: If the rewritten file would not read back as ``new_ver``.

    """
    contents = []  # type: list[str]
    with open(path, 'r', encoding='utf-8', newline='') as in_file:
        for line in in_file:
            body = line.rstrip('\r\n')
            if body.startswith('__version__'):
                line = f'__version__ = {new_ver!r}' + line[len(body):]
            contents.append(line)
    planned = ''.join(contents)

    try:
        written = read_version(planned, os.fspath(path))
    except (SyntaxError, RuntimeError) as error:
        raise RuntimeError(f'refusing to bump {os.fspath(path)} to {new_ver}, as the rewritten '
                           f'file would not read back ({error}); it is left as it was') from error
    if written != new_ver:
        raise RuntimeError(f'refusing to bump {os.fspath(path)} to {new_ver}, as the rewritten '
                           f'file would assign {written!r}; it is left as it was')

    with open(path, 'w', encoding='utf-8', newline='') as out_file:
        out_file.write(planned)


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
        released: Release date as ``YYYY-MM-DD``, defaulting to today in UTC,
            which is the date of the bump this call is part of.
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
        '--init', type=pathlib.Path, default=INIT,
        help='module carrying __version__ (default: %(default)s)',
    )
    parser.add_argument(
        '--citation', type=pathlib.Path, default=CITATION,
        help='citation file to keep in step (default: %(default)s)',
    )
    parser.add_argument(
        '--github-output', action='store_true',
        help='append the new version to $GITHUB_OUTPUT as the step output "version"',
    )
    parser.add_argument(
        '--print-version', action='store_true',
        help='print the current version and exit, bumping nothing',
    )
    args = parser.parse_args(argv)
    if args.print_version:
        print(current_version(args.init))
        return 0
    if args.github_output and not os.environ.get('GITHUB_OUTPUT'):
        parser.error('--github-output only works inside a workflow step, where GITHUB_OUTPUT is set')

    new_ver = bump(current_version(args.init))

    # Read and planned before anything is written, so the fatal outcomes -- a
    # citation file with no ``version`` field, or a rewrite of ``__version__`` that
    # would not read back -- leave the tree untouched instead of half-bumped.
    text = read_citation(args.citation)
    planned = None if text is None else plan_citation(text, new_ver)

    rewrite_init(args.init, new_ver)

    if planned is not None:
        args.citation.write_text(planned, encoding='utf-8')

    with open(os.path.join('conda', 'build'), 'w') as build:
        build.write('0')

    if args.github_output:
        _actions.set_output('version', new_ver)

    return 0


if __name__ == '__main__':
    sys.exit(main())
