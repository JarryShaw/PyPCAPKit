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
  2. ``:rfc:`NNNN``` -- and ``:rfc:`NNNN#section-3```, the anchored spelling
     Sphinx accepts too -- become Markdown links to the RFC on the IETF
     datatracker;
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

Where a complaint points
------------------------

A complaint cites a line of the **entry file**, because that is the only frame a
reader can act on, and the guard is the message on a gate that blocks merges.

It is not the frame the guard finds the construct in. Rule 6 joins a wrapped
bullet onto one line, so the converted body is a fraction of the file's length
and a number counted in it is not a location at all: measured on the 1.5.0
entry, the body is 55 lines against the file's 580, and four roles written on
source lines 467 and 468 all reported as ``line 46``. The bound alone settles it
-- a number that cannot exceed 55 cannot name a line in a 580-line file.

So :func:`convert_traced` returns a *source map* alongside the Markdown, saying
which line of the entry each stretch of output came from, and :func:`residual`
resolves every hit through it. That is also what separates the hits: several
constructs joined onto one output line become several complaints at their own
source lines, in file order, rather than several copies of one wrong number.
Masking a code span preserves its length for the same reason -- so that an offset
in the masked text is still an offset in the Markdown.

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

#: Sphinx's ``:rfc:`` role, in both spellings it accepts: a bare number, and a
#: number with a section anchor -- ``:rfc:`6554#section-3```, which is what
#: anyone writing about a specific section reaches for. Only the anchor shapes
#: :func:`rfc_link` can name are matched; a stranger one falls through to
#: :func:`residual` and is reported, rather than being carried into a link whose
#: text nobody checked.
_RFC_ROLE = re.compile(r':rfc:`(\d+)(?:#([\w.-]+))?`')

#: Anchor prefixes Sphinx renders as words rather than as part of the target,
#: from ``sphinx.roles._format_rfc_target`` (read from Sphinx 9.1.0, the version
#: this repository builds its documentation with): ``#section-3`` is titled
#: ``Section 3``, and an anchor of any other shape is left exactly as written.
#: Kept level with Sphinx so the Markdown link and the rendered documentation say
#: the same thing about the same page, which is the whole point of rule 2.
_RFC_ANCHORS = frozenset({'appendix', 'page', 'section'})

#: Where the full rendered history lives. Must match ``[project.urls].changelog``
#: in ``pyproject.toml`` -- ``MANIFEST.in`` prunes ``docs/``, so in a source
#: distribution this is the only route from the shipped entry to the rest of the
#: history. ``tests/project/test_changelog_md.py`` asserts the two agree.
DOCS_URL = 'https://jarryshaw.github.io/PyPCAPKit/changelog.html'

#: Closing note on the generated file, pointing at the rest of the history.
#:
#: Deliberately short. This file is read on a GitHub release page and on PyPI,
#: where a reader has no repository in front of them -- so an explanation of
#: which ``docs/source/changelog/<version>.rst`` the entry came from is noise to
#: them, while the link is the one thing that is useful everywhere.
TRAILER = (
    '---\n'
    '\n'
    f'Full changelog: <{DOCS_URL}>\n'
)

#: A single-backtick code span. Replaced by :data:`_SPAN` before :func:`residual`
#: looks for unconverted markup, because an entry may legitimately *discuss*
#: markup: the 1.5.0 entry says ``a Sphinx-only ``:mod:`` role``, which converts
#: to the code span ```:mod:``` and must not be read as a role that escaped rule
#: 2. Deliberately cannot match across a newline, so masking leaves every line
#: break where it was.
_CODE_SPAN = re.compile(r'`[^`\n]*`')

#: Stands in for one character of a masked code span. A *marker* rather than
#: nothing, because the difference between a leftover role and prose about a role
#: is precisely whether a code span follows the ``:name:`` or encloses it:
#: ``:mod:`pcapkit.const``` is a role that escaped rule 2, and ```:mod:``` is a
#: sentence mentioning one.
#:
#: A span is masked character for character rather than collapsed to one marker,
#: so that a match offset in the masked text is also an offset in the Markdown --
#: which is what lets :func:`residual` resolve a hit through the source map. No
#: pattern below counts markers, so the runs change nothing about what matches.
_SPAN = '\x00'

#: A run of markers, rendered back as one code span when a complaint quotes what
#: it matched.
_SPAN_RUN = re.compile(_SPAN + '+')

#: A ``double backtick`` literal rule 3 did not reach -- because it holds a
#: backtick, or is empty, or its closing pair was on the next source line. Whole
#: literal where one line holds both pairs, lone pair otherwise, so one leftover
#: literal is one complaint rather than two. Checked before masking: masking
#: would eat ``````` as an empty code span and hide exactly this case.
_LITERAL = re.compile(r'``[^\n]*?``|``')

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
    artefact. Failing here instead names the construct, and the line of the entry
    file it was written on -- see "Where a complaint points" in the module
    docstring for why that is not the line the guard found it on.

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


def rfc_link(number: str, anchor: str = '') -> str:
    """Render one ``:rfc:`` role as a Markdown link.

    The link text follows Sphinx's own ``:rfc:`` role rather than being invented
    here, so an entry reads the same in the generated Markdown as it does in the
    rendered documentation: ``:rfc:`6554#section-3``` is *RFC 6554 Section 3* in
    both, pointing at the same anchor on the same page.

    Args:
        number: The RFC number, as written in the role.
        anchor: The fragment after ``#``, if the role carried one.

    Returns:
        A Markdown inline link.

    """
    if not anchor:
        return f'[RFC {number}]({RFC_URL}{number})'

    # ``section-3`` -> ``Section 3``, as ``sphinx.roles._format_rfc_target`` does.
    # An anchor whose prefix Sphinx does not know is shown as written, there as
    # here, and a prefix with nothing after it -- ``#section`` -- keeps the word
    # alone rather than gaining a trailing space.
    kind, _, remaining = anchor.partition('-')
    if kind in _RFC_ANCHORS:
        title = f'RFC {number} {kind.title()}' + (f' {remaining}' if remaining else '')
    else:
        title = f'RFC {number}#{anchor}'
    return f'[{title}]({RFC_URL}{number}#{anchor})'


def convert(rst: str) -> str:
    """Apply the six rules to one per-version entry.

    Args:
        rst: The entry's reStructuredText.

    Returns:
        The entry as Markdown, ending in a single newline.

    """
    return convert_traced(rst)[0]


def convert_traced(rst: str) -> tuple[str, list[tuple[int, int]]]:
    """Apply the six rules, and record where each piece of the output came from.

    What :func:`convert` returns, plus the bookkeeping :func:`residual` needs to
    report a location in *rst* rather than in its own much shorter output. Rules 1
    to 5 rewrite a line in place, so every character of an output line came from
    one source line and the map has one entry per line; rule 6 then joins lines,
    which is what makes the map necessary at all.

    Args:
        rst: The entry's reStructuredText.

    Returns:
        The entry as Markdown, ending in a single newline, and its *source map*:
        ``(offset, line)`` pairs in ascending *offset* order, each saying that the
        Markdown from *offset* onwards was written on 1-based *line* of *rst*.

    """
    lines = rst.rstrip('\n').split('\n')
    out = []  # type: list[str]
    origin = []  # type: list[int]

    index = 0
    while index < len(lines):
        line = lines[index]

        # 1. setext heading -> ATX. Only ``=`` is used in these files, and only
        #    for the version heading, so the underline can be consumed outright.
        #    The heading is attributed to the title, not to the underline that
        #    followed it, because the title is what a reader would look for.
        if (index + 1 < len(lines) and line and set(lines[index + 1]) == {'='}
                and len(lines[index + 1]) == len(line)):
            out.append(f'## {line}')
            origin.append(index + 1)
            index += 2
            continue

        # 2. the one role these entries use, in both spellings Sphinx accepts.
        line = _RFC_ROLE.sub(lambda match: rfc_link(match[1], match[2] or ''), line)
        # 3. literals.
        line = re.sub(r'``([^`]+)``', r'`\1`', line)
        # 4. bullets, at any indent.
        line = re.sub(r'^(\s*)\* ', r'\1- ', line)
        # 5. footnotes.
        line = re.sub(r'^\.\. \[(\d+)\] ', r'[^\1]: ', line)
        line = re.sub(r'\[(\d+)\]_', r'[^\1]', line)

        out.append(line)
        origin.append(index + 1)
        index += 1

    markdown, sources = unwrap(out, origin)
    # ``rstrip`` only ever drops trailing newlines, which no map entry points
    # past: the last entry is the last non-blank line's own offset.
    return markdown.rstrip('\n') + '\n', sources


def unwrap(lines: Sequence[str], origin: Sequence[int]) -> tuple[str, list[tuple[int, int]]]:
    """Rule 6: collapse each paragraph and each bullet onto a single line.

    A block ends at a blank line, at the next bullet, at a heading, or at a
    footnote definition. Nothing in these entries is indentation-sensitive --
    no literal blocks, no tables, no definition lists -- so joining a block's
    lines with a single space is lossless.

    Joining is also what costs the output its line numbers, so each line's source
    is carried alongside it and comes back as the source map described in
    :func:`convert_traced`.

    Args:
        lines: The entry's lines, with rules 1 to 5 already applied.
        origin: The 1-based source line each of *lines* came from, in step with it.

    Returns:
        The lines with each block joined onto one line, and the source map.

    """
    rows = []  # type: list[list[tuple[str, int]]]
    current = []  # type: list[tuple[str, int]]

    def flush() -> None:
        if current:
            rows.append(current.copy())
            current.clear()

    for line, source in zip(lines, origin):
        if not line.strip():
            flush()
            # One blank row per run: the flush cycle can leave several behind, and
            # a run of blank lines is one paragraph break however long it is -- and
            # a run before the first block is no break at all, where the ``\n{3,}``
            # substitution this replaces left an empty first line behind.
            if rows and rows[-1]:
                rows.append([])
            continue
        if re.match(r'^\s*- ', line) or line.startswith('## ') \
                or re.match(r'^\[\^\d+\]: ', line):
            flush()
            current.append((line, source))
            continue
        current.append((line, source))
    flush()

    out = []  # type: list[str]
    sources = []  # type: list[tuple[int, int]]
    offset = 0

    for index, row in enumerate(rows):
        if index:
            out.append('\n')
            offset += 1
        for position, (line, source) in enumerate(row):
            text = (' ' if position else '') + line.strip()
            # The joining space belongs to neither line, and is attributed to the
            # one after it. Nothing can match starting there in any case -- the
            # line-anchored patterns only ever match at the start of a row, where
            # there is no joining space -- but it is the kind of off-by-one that is
            # invisible until it is written down.
            sources.append((offset, source))
            out.append(text)
            offset += len(text)

    return ''.join(out), sources


def residual(markdown: str,
             sources: Optional[Sequence[tuple[int, int]]] = None) -> list[str]:
    """Report reStructuredText left in *markdown* that the six rules did not convert.

    See the module docstring for the guarded set, for the two constructs left
    deliberately unguarded, and for why a complaint's line number belongs to the
    entry file rather than to *markdown*.

    Args:
        markdown: One converted entry, as :func:`convert` returned it. The
            generated file's trailer is not part of this and does not need to be:
            :func:`render` checks the body before appending it.
        sources: The source map :func:`convert_traced` returned beside *markdown*.
            With one, each complaint cites the line of the entry the construct was
            written on -- the line a reader can open. Without one there is nothing
            to map through, so the complaints count lines of *markdown* and say
            so, rather than passing an unusable number off as a location.

    Returns:
        One human-readable complaint per leftover construct, in source order,
        empty when clean.

    """
    offsets = [offset for offset, _ in sources] if sources is not None else []

    def locate(offset: int) -> int:
        """The 1-based line *offset* should be reported against."""
        if sources is None:
            return markdown.count('\n', 0, offset) + 1
        # A linear scan: the map holds one entry per line of one changelog entry,
        # and a clean entry has nothing to locate, so a search is not worth an
        # import. ``offsets`` ascends, so the last entry at or before *offset*
        # owns it. The first row is never blank, so entry zero sits at offset zero
        # and the loop always fires; the default is for a map that is empty.
        line = 1
        for index, start in enumerate(offsets):
            if start > offset:
                break
            line = sources[index][1]
        return line

    frame = 'line' if sources is not None else 'converted line'
    problems = []  # type: list[tuple[int, str]]

    def report(offset: int, label: str, found: str) -> None:
        line = locate(offset)
        problems.append((line, f'{frame} {line}: {label}: {found!r}'))

    # Checked before code spans are masked; see :data:`_LITERAL`.
    for match in _LITERAL.finditer(markdown):
        report(match.start(), 'an unconverted `` literal', match.group(0)[:70])

    masked = _CODE_SPAN.sub(lambda match: _SPAN * len(match.group(0)), markdown)
    for pattern, label in _RESIDUAL:
        for match in pattern.finditer(masked):
            report(match.start(), label, _SPAN_RUN.sub('`...`', match.group(0)))

    # In source order, so a reader walks the entry once rather than once per
    # pattern; :func:`sorted` is stable, so hits sharing a line keep the order the
    # patterns found them in.
    return [complaint for _, complaint in sorted(problems, key=lambda item: item[0])]


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
    body, sources = convert_traced(entry.read_text(encoding='utf-8'))

    # With the map, every complaint cites a line of *entry* -- the file named in
    # the message -- so the reader can open one at the number they were given.
    problems = residual(body, sources)
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
