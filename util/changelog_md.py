# -*- coding: utf-8 -*-
"""Generate the root ``CHANGELOG.md`` from the newest per-version changelog entry.

``docs/source/changelog/<version>.rst`` is the single source of every changelog
entry, and Sphinx renders the lot as the project's history. ``CHANGELOG.md`` is a
*derivative* of exactly one of them -- the version being released -- because its
two consumers, the ``Create Release`` workflow's release body and the source
distribution, both read Markdown rather than reStructuredText.

Nothing edits ``CHANGELOG.md`` by hand. That is the point: there is no "promote
the latest entry into the history" step to forget, because the entry was written
in the history in the first place, and the two surfaces cannot drift while one is
generated from the other. It is the same arrangement as ``pcapkit/const/**``,
which is generated from ``pcapkit/vendor/**``.

Markdown at the repository root is a deliberate exception to the "documentation is
reStructuredText" rule, justified by those two consumers.

Which entry is "newest"
-----------------------

**The first entry of the toctree in** ``docs/source/changelog.rst``.

Not a sort of the version strings. ``1.5.0b3``, ``1.5.0`` and ``1.10.0`` order
correctly under :pep:`440` and incorrectly under every lexical comparison, and
reimplementing :pep:`440` here to answer a question the toctree already answers
would be a second source of truth rather than a convenience. Not the file
modification time either, which says when a file was touched rather than which
release is current.

The toctree has to exist for Sphinx, and it has to be newest-first for the
rendered history to read correctly, so it is *already* the ordering of record.
Reading it means a release is added in exactly one place -- a new entry file, and
its name at the top of the toctree -- and this script follows.

The conversion
--------------

The entries are written in a deliberately small reStructuredText subset, so the
conversion is six mechanical rules rather than a document converter:

  1. the setext version heading becomes an ATX ``##`` heading;
  2. ``:rfc:`NNNN``` becomes a Markdown link to the RFC on the IETF datatracker;
  3. ``double backtick`` literals become single-backtick code spans;
  4. ``*`` bullets become ``-`` bullets;
  5. ``[n]_`` / ``.. [n]`` footnotes become GitHub's ``[^n]`` / ``[^n]:``;
  6. each paragraph and each bullet is unwrapped onto one line.

Everything else -- ``**strong**``, ``*emphasis*``, and the ``#nnn`` issue
references that GitHub autolinks in a release body -- is already valid Markdown
and is copied verbatim.

Rule 6 is the only one about the *consumer* rather than the syntax. A GitHub
release body is rendered like a comment, where a single newline is a hard line
break rather than a space, so a paragraph wrapped at 79 columns renders as a
column of short ragged lines. A paragraph with no newline inside it renders the
same either way, which is why unwrapping is the safe direction.

Six regexes cannot recognise everything reStructuredText can express, and a rule
that does not fire copies its construct straight through as literal text. That is
how a release body ends up with ``.. note::`` printed in it -- published to GitHub
and PyPI, where it is expensive and irreversible. So :func:`residual` re-reads the
converted entry and :func:`render` refuses to emit while anything is left.

What it guards, exactly -- the claim is kept level with the code, because a guard
believed to be broader than it is, is worse than no guard:

  * a ``double backtick`` literal rule 3 did not reach;
  * an interpreted-text role, ``:mod:`x```, rule 2 does not know;
  * a directive or comment, any line opening ``..`` -- which also catches the
    ``.. _name: url`` target that a bare ``name_`` reference needs, so that form is
    covered through its definition rather than through the reference;
  * a ``*`` bullet rule 4 missed;
  * a ``[n]_`` footnote reference rule 5 missed;
  * an inline or phrase hyperlink reference, ```text <url>`_``, which GFM renders
    as broken inline code plus a stray underscore, losing the link outright;
  * a substitution reference, ``|version|``, which has no Markdown equivalent;
  * a field list, ``:Author: ...``, which rule 6 would join onto one line;
  * a line block, ``| line``, which rule 6 joins into something GFM may read as a
    table row;
  * a grid or simple table, which rule 6 mangles onto one line;
  * a setext underline, whether left on its own line or joined into the prose
    above it by rule 6 -- the second is how a sub-heading would silently
    disappear into a paragraph.

Two things it deliberately does **not** catch. A bare ``name_`` reference on its
own, because a pattern loose enough to spot a trailing underscore in prose fires on
ordinary identifiers; its target line is caught instead, as above. And a construct
that rule 6 joins into the *middle* of a line rather than the start of one, since
every line-anchored pattern here then has nothing to anchor to -- a field list
buried inside a bullet, say. Both would need the guard to run before unwrapping,
which is a larger change than the insurance is worth.

Every pattern was measured against all 37 committed entries and matches none of
them, so the guard costs nothing until an entry actually leaves the subset.

Usage
-----

.. code-block:: shell

   python util/changelog_md.py            # regenerate CHANGELOG.md
   python util/changelog_md.py --check    # exit non-zero if it has drifted

``--check`` regenerates into memory, compares, and prints a unified diff of what
moved. It is what a CI gate calls, and it is the same shape as the byte-
reproduction gate over the generated ``pcapkit.const`` modules.

"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import re
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional, Sequence

#: Repository root, taken from this file's location rather than the working
#: directory, so the script gives the same answer run from anywhere.
ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The page carrying the changelog title, preamble and toctree. The toctree in it
#: is the ordering of record; see the module docstring.
INDEX = ROOT / 'docs' / 'source' / 'changelog.rst'

#: The generated artefact.
OUTPUT = ROOT / 'CHANGELOG.md'

#: Base of the RFC links rule 2 emits. This is the form Sphinx's own ``:rfc:``
#: role resolves to, so the Markdown and the rendered documentation point at the
#: same page; docutils on its own would resolve the role to a ``tools.ietf.org``
#: URL instead.
RFC_URL = 'https://datatracker.ietf.org/doc/html/rfc'

#: Where the full rendered history lives. Must match ``[project.urls].changelog``
#: in ``pyproject.toml`` -- ``MANIFEST.in`` prunes ``docs/``, so in a source
#: distribution this is the only route from the shipped entry to the rest of the
#: history. ``tests/project/test_changelog_md.py`` asserts the two agree.
DOCS_URL = 'https://jarryshaw.github.io/PyPCAPKit/changelog.html'

#: Closing note on the generated file, explaining why it holds one release.
TRAILER = (
    '---\n'
    '\n'
    'Only the version being released is kept here. Every entry, including this'
    ' one, lives in the repository as `docs/source/changelog/<version>.rst`,'
    f' and the whole history is rendered at <{DOCS_URL}>.\n'
)

#: A single-backtick code span. Replaced by :data:`_SPAN` before :func:`residual`
#: looks for unconverted markup, because an entry may legitimately *discuss*
#: markup: the 1.5.0 entry says ``a Sphinx-only ``:mod:`` role``, which converts
#: to the code span ```:mod:``` and must not be read as a role that escaped rule
#: 2. Deliberately cannot match across a newline, so masking leaves every line
#: break -- and therefore every reported line number -- where it was.
_CODE_SPAN = re.compile(r'`[^`\n]*`')

#: Stands in for a masked code span. A *marker* rather than nothing, because the
#: difference between a leftover role and prose about a role is precisely whether
#: a code span follows the ``:name:`` or encloses it: ``:mod:`pcapkit.const``` is
#: a role that escaped rule 2, and ```:mod:``` is a sentence mentioning one.
_SPAN = '\x00'

#: reStructuredText that should be gone by the time conversion finishes. Checked
#: against the masked text, and each one means a rule did not fire. Every pattern
#: matches none of the 37 committed entries; see the module docstring for what is
#: covered and what is deliberately not.
_RESIDUAL = (
    (re.compile(r':[a-zA-Z][a-zA-Z0-9_+:.-]*:' + _SPAN),
     'an unconverted interpreted-text role'),
    (re.compile(r'(?m)^[ \t]*\.\.[ \t]'), 'an unconverted directive or comment'),
    (re.compile(r'(?m)^[ \t]*\*[ \t]'), 'an unconverted bullet'),
    (re.compile(r'\[\d+\]_'), 'an unconverted footnote reference'),
    # ``\x00_`` is a masked code span followed by an underscore, which is what
    # ```text <url>`_`` and its anonymous ```text <url>`__ form both reduce to.
    (re.compile(_SPAN + '_'),
     'an unconverted hyperlink reference (the link target would be lost)'),
    (re.compile(r'\|\S[^|\n]*\|'), 'an unconverted substitution reference'),
    (re.compile(r'(?m)^[ \t]*:[^:\n]+:[ \t]'), 'an unconverted field list'),
    (re.compile(r'(?m)^[ \t]*\|[ \t]'), 'an unconverted line block'),
    (re.compile(r'(?m)^[ \t]*\+[-=]+\+'), 'an unconverted grid table'),
    (re.compile(r'(?m)^[ \t]*=+[ \t]+=+'), 'an unconverted simple table'),
    (re.compile(r'(?m)^=+$'), 'a leftover setext underline'),
    (re.compile(r'(?m)^~+$'), 'a leftover setext underline'),
    # A sub-heading's underline does not survive as its own line: rule 6 joins it
    # onto the end of the heading text, so it has to be caught mid-line too. The
    # leading ``\S[ \t]+`` is what makes this specific to the joined case, so it
    # cannot fire on a ``---`` that is alone on its line -- which is what the
    # generated file's own trailer is made of.
    # ``(?m)`` matters: the run is followed by a newline rather than end of input,
    # and a bare ``$`` only matches at the very end of the string.
    #
    # ``=`` belongs in the alternation even though rule 1 handles ``=`` underlines,
    # because rule 1 requires the underline to be exactly as long as the title
    # while reStructuredText merely requires it to be no shorter. An over-long
    # underline therefore falls straight past rule 1 and gets joined like any other.
    (re.compile(r'(?m)\S[ \t]+(?:={3,}|-{3,}|~{3,}|\^{3,}|"{3,})(?:[ \t]|$)'),
     'a setext underline joined into the prose above it'),
)


class ResidualMarkupError(RuntimeError):
    """Conversion finished with reStructuredText still in the output.

    Deliberately fatal. The six rules cover the subset the entries are written
    in; anything outside it would otherwise be copied through as literal text and
    render as itself in a release body, which is a silent defect in a published
    artefact. Failing here instead names the construct and the line.

    """


def read_toctree(index: pathlib.Path) -> list[str]:
    """Return the document names in *index*'s first ``toctree``, in order.

    Args:
        index: The page carrying the toctree.

    Returns:
        The toctree entries, newest first, each as written -- so relative to
        *index*'s own directory -- with any ``Title <docname>`` wrapper reduced
        to the document name.

    Raises:
        ValueError: If *index* carries no ``toctree``, or it lists no entries.

    """
    lines = index.read_text(encoding='utf-8').split('\n')

    for start, line in enumerate(lines):
        if line.strip() == '.. toctree::':
            indent = len(line) - len(line.lstrip())
            break
    else:
        raise ValueError(f'no toctree directive in {index}')

    entries = []  # type: list[str]
    for line in lines[start + 1:]:
        if not line.strip():
            continue  # blank lines are allowed inside a directive body
        if len(line) - len(line.lstrip()) <= indent:
            break  # a dedent ends the directive
        body = line.strip()
        if body.startswith(':'):
            continue  # a directive option, such as :maxdepth:
        explicit = re.search(r'<([^<>]+)>\Z', body)
        entries.append(explicit.group(1) if explicit else body)

    if not entries:
        raise ValueError(f'the toctree in {index} lists no entries')
    return entries


def newest(index: pathlib.Path = INDEX) -> tuple[str, pathlib.Path]:
    """Resolve the newest changelog entry from *index*'s toctree.

    Args:
        index: The page carrying the toctree.

    Returns:
        The newest entry's version string and the path to its file.

    Raises:
        FileNotFoundError: If the toctree's first entry names a document that
            does not exist, which is what half of a release addition looks like.

    """
    first = read_toctree(index)[0]
    # ``+ '.rst'`` rather than :meth:`~pathlib.Path.with_suffix`: a version string
    # ends in what looks like a file extension, so ``with_suffix`` on
    # ``changelog/1.5.0`` yields ``changelog/1.5.rst``.
    entry = index.parent / (first + '.rst')
    if not entry.is_file():
        raise FileNotFoundError(
            f'{index} lists {first!r} as the newest entry, but {entry} does not exist'
        )
    return entry.stem, entry


def convert(rst: str) -> str:
    """Apply the six rules to one per-version entry.

    Args:
        rst: The entry's reStructuredText.

    Returns:
        The entry as Markdown, ending in a single newline.

    """
    lines = rst.rstrip('\n').split('\n')
    out = []  # type: list[str]

    index = 0
    while index < len(lines):
        line = lines[index]

        # 1. setext heading -> ATX. Only ``=`` is used in these files, and only
        #    for the version heading, so the underline can be consumed outright.
        if (index + 1 < len(lines) and line and set(lines[index + 1]) == {'='}
                and len(lines[index + 1]) == len(line)):
            out.append(f'## {line}')
            index += 2
            continue

        # 2. the one role these entries use.
        line = re.sub(r':rfc:`(\d+)`', lambda match: f'[RFC {match[1]}]({RFC_URL}{match[1]})', line)
        # 3. literals.
        line = re.sub(r'``([^`]+)``', r'`\1`', line)
        # 4. bullets, at any indent.
        line = re.sub(r'^(\s*)\* ', r'\1- ', line)
        # 5. footnotes.
        line = re.sub(r'^\.\. \[(\d+)\] ', r'[^\1]: ', line)
        line = re.sub(r'\[(\d+)\]_', r'[^\1]', line)

        out.append(line)
        index += 1

    return unwrap(out).rstrip('\n') + '\n'


def unwrap(lines: Sequence[str]) -> str:
    """Rule 6: collapse each paragraph and each bullet onto a single line.

    A block ends at a blank line, at the next bullet, at a heading, or at a
    footnote definition. Nothing in these entries is indentation-sensitive --
    no literal blocks, no tables, no definition lists -- so joining a block's
    lines with a single space is lossless.

    Args:
        lines: The entry's lines, with rules 1 to 5 already applied.

    Returns:
        The lines with each block joined onto one line.

    """
    blocks = []  # type: list[str]
    current = []  # type: list[str]

    def flush() -> None:
        if current:
            blocks.append(' '.join(item.strip() for item in current))
            current.clear()

    for line in lines:
        if not line.strip():
            flush()
            blocks.append('')
            continue
        if re.match(r'^\s*- ', line) or line.startswith('## ') \
                or re.match(r'^\[\^\d+\]: ', line):
            flush()
            current.append(line)
            continue
        current.append(line)
    flush()

    # Collapse the runs of blank lines the flush cycle can leave behind.
    return re.sub(r'\n{3,}', '\n\n', '\n'.join(blocks))


def residual(markdown: str) -> list[str]:
    """Report reStructuredText left in *markdown* that the six rules did not convert.

    See the module docstring for the guarded set, and for the two constructs left
    deliberately unguarded.

    Args:
        markdown: One converted entry, as :func:`convert` returned it. The
            generated file's trailer is not part of this and does not need to be:
            :func:`render` checks the body before appending it.

    Returns:
        One human-readable complaint per leftover construct, empty when clean.

    """
    problems = []  # type: list[str]

    # Checked before code spans are masked: masking would eat ``````` as an empty
    # code span and hide exactly the case this looks for.
    for number, line in enumerate(markdown.split('\n'), 1):
        if '``' in line:
            problems.append(f'line {number}: an unconverted `` literal: {line.strip()[:70]!r}')

    masked = _CODE_SPAN.sub(_SPAN, markdown)
    for pattern, label in _RESIDUAL:
        for match in pattern.finditer(masked):
            number = masked.count('\n', 0, match.start()) + 1
            found = match.group(0).replace(_SPAN, '`...`')
            problems.append(f'line {number}: {label}: {found!r}')
    return problems


def render(index: pathlib.Path = INDEX) -> str:
    """Render the complete ``CHANGELOG.md``.

    Args:
        index: The page carrying the toctree that decides which entry is newest.

    Returns:
        The file's content, ready to be written.

    Raises:
        ResidualMarkupError: If the entry uses reStructuredText the rules do not
            cover, so the output would carry markup through as literal text.

    """
    _, entry = newest(index)
    body = convert(entry.read_text(encoding='utf-8'))

    problems = residual(body)
    if problems:
        raise ResidualMarkupError(
            f'{entry} uses reStructuredText the six conversion rules do not cover, '
            f'so CHANGELOG.md would carry it through as literal text:\n  '
            + '\n  '.join(problems)
            + '\nEither rewrite the entry in the supported subset, or teach '
              'util/changelog_md.py the construct.'
        )

    return body + '\n' + TRAILER


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command line entry point.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv`.

    Returns:
        ``0`` on success; ``1`` if ``--check`` found the output stale or missing.

    """
    parser = argparse.ArgumentParser(
        prog='changelog_md.py',
        description='Generate CHANGELOG.md from the newest per-version changelog entry.',
    )
    parser.add_argument(
        '--check', action='store_true',
        help='write nothing; exit non-zero if the committed file has drifted',
    )
    parser.add_argument(
        '--index', type=pathlib.Path, default=INDEX,
        help='page carrying the toctree that orders the entries (default: %(default)s)',
    )
    parser.add_argument(
        '--output', type=pathlib.Path, default=OUTPUT,
        help='file to generate (default: %(default)s)',
    )
    args = parser.parse_args(argv)

    version, entry = newest(args.index)
    want = render(args.index)

    if not args.check:
        args.output.write_text(want, encoding='utf-8')
        print(f'wrote {args.output} from {entry} ({len(want.splitlines())} lines)')
        return 0

    have = args.output.read_text(encoding='utf-8') if args.output.is_file() else ''
    if have == want:
        print(f'{args.output} is in step with {entry}')
        return 0

    print(f'{args.output} has drifted from {entry}', file=sys.stderr)
    sys.stderr.writelines(difflib.unified_diff(
        have.splitlines(keepends=True),
        want.splitlines(keepends=True),
        fromfile=f'{args.output.name} (committed)',
        tofile=f'{args.output.name} (regenerated from {version})',
    ))
    return 1


if __name__ == '__main__':
    sys.exit(main())
