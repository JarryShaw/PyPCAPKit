# -*- coding: utf-8 -*-
"""Every ``:rfc:`` role's ``#`` fragment must name a real RFC anchor shape.

#942: ``FEATCode``'s class docstring cited :rfc:`5797#secion-3` in both
:file:`pcapkit/vendor/ftp/command.py` (the ``LINE`` template) and its generated
copy :file:`pcapkit/const/ftp/command.py`. Sphinx's ``sphinx.roles.RFC``, like
docutils' ``rfc_reference_role``, appends the fragment to the RFC's URL unchecked
and returns a plain ``nodes.reference``, never a ``pending_xref``, so no build
warns on any configuration. The same sweep found ``:rfc:`5797#secion-2.2``` in
``Command``'s ``feat`` attribute docstring, in the same two files, fixed with it.

:class:`RFCAnchorFragmentTests` checks every fragment under :mod:`pcapkit`
against :data:`ACCEPTED_FRAGMENT`, the three prefixes
``sphinx.roles._format_rfc_target`` titles (``appendix``, ``page``, ``section``)
with their numbering, so the next misspelling fails rather than only this one.
``page-N`` is accepted though nothing under :mod:`pcapkit` cites one, matching
Sphinx and :file:`tests/project/test_changelog_md.py`'s ``793#page-5``, a real
anchor in RFC 793's HTML. Rejected:

* a bare ``N[.N...]``, as in ``:rfc:`8684#3.1```: RFC HTML uses
  ``id="section-3.1"``, never ``id="3.1"``. The generators behind
  :mod:`pcapkit.const.tcp.mp_tcp_option` and :mod:`pcapkit.const.reg.apptype.tcp`
  (``MPTCPOption.process``, ``AppType.records``) parse IANA's
  ``RFC8684, Section 3.1`` down to the number, so each emits ``#section-{sec}``;
* ``#introduction`` and a numberless ``#section``, which Sphinx does not error
  on. The first is one of an open-ended set of named anchors a shape check cannot
  tell from a typo; the second cannot be told from a citation that dropped its
  number. Neither appears under :mod:`pcapkit`.

A shape check cannot see whether the anchor exists. #944 found
``:rfc:`959#section-4.1```, and RFC 959's HTML renders only ``section-1`` through
``section-8``, so the maintainer ruled the enclosing ``#section-4``; #947 ruled
``#section-5`` for the ``959#section-5.3`` citations in :file:`tests/` and
:file:`docs/source/changelog/1.5.0.rst`. :data:`KNOWN_DEAD_ANCHORS` denylists
both, over :data:`DEAD_ANCHOR_SCAN`, which reaches :file:`docs/source` and
:file:`tests` as well. It is a denylist, not an existence oracle: it proves
nothing about an unlisted fragment, each entry means someone read that RFC's
HTML, and it makes no network call.

"""

from __future__ import annotations

import pathlib
import re
import unittest
from typing import NamedTuple

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Matches a Sphinx/docutils ``:rfc:`` role that carries a ``#`` fragment, e.g.
#: ``:rfc:`5797#secion-3```. Group 2 is everything between ``#`` and the
#: closing backtick.
RFC_FRAGMENT = re.compile(r':rfc:`(\d+)#([^`]+)`')

#: The three anchor prefixes ``sphinx.roles._format_rfc_target`` titles, each with
#: its numbering: ``section-N[.N...]``, ``appendix-X[.N...]``, ``page-N``. The
#: module docstring says why numberless and bare-number shapes are rejected.
ACCEPTED_FRAGMENT = re.compile(
    r'\A(?:section-\d+(?:\.\d+)*|appendix-[A-Z](?:\.\d+)*|page-\d+)\Z')

#: A **denylist** of RFC number -> anchor fragments that RFC's rendered HTML is
#: known not to have, confirmed by reading ``https://www.rfc-editor.org/rfc/rfc<N>.html``
#: (or the datatracker mirror). A fragment missing here is not thereby live. Both
#: ``959`` entries are from #944: RFC 959 renders anchors only for ``section-1``
#: through ``section-8``, so every sub-numbered ``959`` fragment is dead.
#: ``section-4.1`` is the one #944 reported; ``section-5.3`` turned up in the same
#: sweep.
KNOWN_DEAD_ANCHORS: 'dict[int, frozenset[str]]' = {
    959: frozenset({'section-4.1', 'section-5.3'}),
}

#: The exact ways this repository writes a ``:rfc:`` citation in order to *name* a
#: defect rather than commit one, as ``(prefix, suffix)`` around the role text. A hit
#: matching any of these is documentation, not a live link.
#:
#: The first entry is the inline-literal idiom -- ``` ``:rfc:`959#section-4.1``` ``` --
#: where the literal's content is itself a role, so the opening delimiter is two
#: backticks and the close is three: two for the literal plus the role's own trailing
#: one. That asymmetry is why the list holds prefix/suffix pairs rather than a single
#: delimiter.
#:
#: **A list rather than a general masker.** Deciding "is this text inside any inline
#: literal" over the whole tree was wrong under every approach tried -- a lookbehind
#: heuristic, a ``re.DOTALL`` span that crosses paragraph breaks and hides a live
#: ``:rfc:`4303#section-2.1``` role, a greedy close that swallows the next literal's
#: opener, a role's own backtick fusing with an adjacent literal -- because that is
#: RST's inline-markup grammar, which a regex cannot model. Classifying only where a
#: denylisted fragment appears is bounded, and adding a form is one reviewed entry.
QUOTED_FORMS: 'tuple[tuple[str, str], ...]' = (
    ('``', '``'),
)

#: Where :func:`_dead_anchor_citations` looks, as ``(directory, glob patterns)``.
#: Wider than :func:`_malformed_fragments`'s ``pcapkit``-only sweep on purpose:
#: a dead anchor in a ``.rst`` page renders for readers exactly as one in a
#: docstring does, and most of the sites this caught were in ``.rst``.
DEAD_ANCHOR_SCAN: 'tuple[tuple[str, tuple[str, ...]], ...]' = (
    ('pcapkit', ('*.py',)),
    ('docs/source', ('*.rst', '*.py')),
    ('tests', ('*.py',)),
)


class Finding(NamedTuple):
    """One malformed ``:rfc:`` fragment, keyed so it survives lines moving."""

    #: Path relative to the repository root.
    path: 'str'
    #: The fragment text itself (after ``#``, before the closing backtick).
    fragment: 'str'


class DeadAnchorFinding(NamedTuple):
    """One citation of a fragment listed in :data:`KNOWN_DEAD_ANCHORS`."""

    #: Path relative to the repository root.
    path: 'str'
    #: The RFC number cited.
    rfc: 'int'
    #: The fragment text itself (after ``#``, before the closing backtick).
    fragment: 'str'


def _malformed_fragments() -> 'list[Finding]':
    """Every ``:rfc:`` fragment under :mod:`pcapkit` shaped unlike a real anchor."""
    findings = []
    for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
        text = path.read_text(encoding='utf-8')
        for match in RFC_FRAGMENT.finditer(text):
            fragment = match.group(2)
            if not ACCEPTED_FRAGMENT.match(fragment):
                findings.append(Finding(str(path.relative_to(ROOT)), fragment))
    return findings


def _is_documentation(text: 'str', start: 'int', length: 'int') -> 'bool':
    """Whether the citation at ``start`` is one of :data:`QUOTED_FORMS`.

    Local and exact: it looks only at the characters immediately either side of this
    one citation, so it cannot be thrown off by markup elsewhere in the file. That is
    the whole advantage over a masker, which decides the same question by pairing every
    literal delimiter in the file and gets it wrong whenever the pairing slips.

    Args:
        text: The file's contents.
        start: Index where the citation begins.
        length: The citation's length.

    Returns:
        Whether it is being named rather than committed.

    """
    for prefix, suffix in QUOTED_FORMS:
        opener = start - len(prefix)
        if opener < 0 or text[opener:start] != prefix:
            continue
        if text[start + length:start + length + len(suffix)] != suffix:
            continue
        # The opener has to *begin* a token, and only whitespace or the start of the
        # file may precede it.
        #
        # ``([{"'`` are not allowed there, though an opening bracket or quote may sit
        # before a literal -- that is **the sixth mechanism**: those characters are
        # equally valid as the last character of a literal's *content*, in which case
        # the ``` `` ``` is a **closer** and the role after it is live. So ```
        # ``'base'``:rfc:`959#…`` ``` would read as documentation -- and
        # ``` ``'base'`` ``` is a real literal in :file:`pcapkit/const/ftp/command.py`.
        # Measured across the scanned roots, hundreds of literals end in one of those
        # characters, so allowing them leaves the exemption one adjacency away from
        # hiding a live dead link.
        #
        # Whitespace and start-of-file are safe by RST's own grammar: an inline
        # literal's *end*-string cannot be preceded by whitespace, so ``` `` ```
        # following whitespace is always an opener.
        #
        # A condition measured only against ``` ``foo`` ``` -- a literal ending in a
        # letter -- and never against the characters in its own allowed set fails
        # exactly there. A measurement that skips the interesting inputs is reasoning
        # wearing a measurement's clothes.
        if opener == 0 or text[opener - 1].isspace():
            return True
    return False


def _dead_anchor_citations() -> 'list[DeadAnchorFinding]':
    """Every live citation of a fragment listed in :data:`KNOWN_DEAD_ANCHORS`.

    Offline by construction -- it consults the fixed table above and never the
    network -- so it runs the same way in CI, which has none.

    Searches for each denylisted fragment as a **literal string** rather than matching
    every ``:rfc:`` role and comparing. Two consequences worth stating:

    * The work is proportional to the number of *denylisted* fragments present, not to
      the amount of markup in the tree. There is no classifier to get wrong on a file
      that has nothing to do with these anchors.
    * A citation this table has never heard of is not examined at all. The denylist
      makes no claim about one, so this function answers a narrower question than a
      scan of every role would appear to.

    Scans :data:`DEAD_ANCHOR_SCAN` rather than :mod:`pcapkit` alone: scanning one
    directory is what let dead-anchor sites sit unnoticed outside it, most of them
    in ``.rst`` where they rendered for readers exactly as a docstring's would.

    """
    findings = []
    for root, patterns in DEAD_ANCHOR_SCAN:
        base = ROOT / root
        for pattern in patterns:
            for path in sorted(base.rglob(pattern)):
                text = path.read_text(encoding='utf-8')
                for rfc, fragments in KNOWN_DEAD_ANCHORS.items():
                    for fragment in sorted(fragments):
                        needle = f':rfc:`{rfc}#{fragment}`'
                        start = text.find(needle)
                        while start != -1:
                            if not _is_documentation(text, start, len(needle)):
                                findings.append(DeadAnchorFinding(
                                    str(path.relative_to(ROOT)), rfc, fragment))
                            start = text.find(needle, start + 1)
    return findings


class RFCAnchorFragmentTests(unittest.TestCase):
    """No ``:rfc:`` role may cite a malformed fragment, or a known-dead anchor.

    :meth:`test_no_malformed_fragments` sweeps :mod:`pcapkit` only;
    :meth:`test_no_known_dead_anchor_citations` sweeps :data:`DEAD_ANCHOR_SCAN`, which
    also covers :file:`docs/source` and :file:`tests`, because scanning one directory
    let dead-anchor sites sit unnoticed outside :mod:`pcapkit`.

    """

    def test_no_malformed_fragments(self) -> 'None':
        """No ``:rfc:`` fragment under :mod:`pcapkit` is shaped like a typo.

        Catches the next typo of ``section-``/``appendix-``/``page-``, or a
        bare-number fragment like those #942's sweep fixed; there is no
        allowlist. Shape only, not anchor existence (#944).

        """
        found = _malformed_fragments()

        self.assertEqual(
            found, [],
            f'malformed :rfc: fragment(s) found under pcapkit/: {found}',
        )

    def test_the_documentation_exemption_holds_on_every_known_mechanism(self) -> 'None':
        """:func:`_is_documentation` on each input known to defeat a naive masker.

        The regression table for every mechanism review has found, since fixing the
        one a postmortem names repeatedly missed the next: a new mechanism is handled
        once it has a row, and a redesign must keep every row passing.

        The rows are the real inputs. Most are live roles a masker hides, the dangerous
        direction, since a hidden role is a dead link nobody sees. The documentation
        idiom must stay exempt, or the defect cannot be written about in this file.

        """
        # Built from parts: literal test data would itself be a live-looking citation
        # of a denylisted fragment and trip the guard under test.
        needle = ':rfc:`%d#%s`' % (959, 'section-4.1')
        cases = (
            ('a plain live role', 'cites %s here', True),
            ('the documentation idiom', 'names ``%s`` here', False),
            ('a live role after a closing inline literal',
             'See ``foo``%s` dead.', True),
            ('a live role after a title reference', '`RFC 959`%s dead.', True),
            ('a live role several paragraphs after a literal',
             'Prose ``x``.\n\np2\n\np3\n\ncites %s live\n', True),
            ('a live role after two adjacent literals', '``a````b`` %s ``c``', True),
            ('a live role flush against a following literal',
             'cite %s``next`` after', True),
            ('a live role flush against a spaced literal',
             'cite %s` ``next`` after', True),
            # ``([{"'`` before the opener may be a literal's last content character,
            # making the delimiter a closer and the role live; one row per character.
            ("a live role after a literal whose content ends in a quote",
             "See ``x'``%s`` dead.", True),
            ('a live role after a literal whose content ends in a paren',
             'See ``foo(``%s`` dead.', True),
            ('a live role after a literal whose content ends in a bracket',
             'See ``foo[``%s`` dead.', True),
            ('a live role after a literal whose content ends in a brace',
             'See ``foo{``%s`` dead.', True),
            ('a live role after a literal whose content ends in a double quote',
             'See ``f"``%s`` dead.', True),
            # ``'base'`` is a real inline literal in pcapkit/const/ftp/command.py, and
            # many scanned literals end in one of those characters.
            ("a live role after this repository's own quoted literal",
             "See ``'base'``%s`` dead.", True),
            # Pins the suffix half of QUOTED_FORMS' pairs; deleting the suffix
            # condition passed every row above.
            ('a citation opened like the idiom but not closed like it',
             'names ``%s and more', True),
            # Pins any whitespace, not just a space: narrowing ``isspace()`` to
            # ``== ' '`` passed every earlier row. Covers the idiom after a line wrap.
            ('the idiom preceded by a tab', 'names\t``%s`` here', False),
            ('the idiom preceded by a newline', 'names\n``%s`` here', False),
        )
        cases = tuple((label, template % needle, live)
                      for label, template, live in cases)

        for label, text, expected_live in cases:
            with self.subTest(case=label):
                live = [index for index in range(len(text))
                        if text.startswith(needle, index)
                        and not _is_documentation(text, index, len(needle))]
                self.assertEqual(
                    bool(live), expected_live,
                    f'{label}: expected the citation to be treated as '
                    f'{"live" if expected_live else "documentation"} and it was not -- '
                    'a live role read as documentation is a dead link nobody sees')

    def test_no_known_dead_anchor_citations(self) -> 'None':
        """No ``:rfc:`` role anywhere in :data:`DEAD_ANCHOR_SCAN` cites a known-dead anchor.

        A well-shaped fragment can still name an anchor its RFC does not render,
        #944's ``:rfc:`959#section-4.1```. This checks every role in the scanned
        roots against :data:`KNOWN_DEAD_ANCHORS`. Passing proves only that none
        cites a listed anchor; an unlisted dead one passes, since the alternative
        is a network fetch this offline test does not make.

        """
        found = _dead_anchor_citations()

        self.assertEqual(
            found, [],
            f'known-dead RFC anchor cited as a live role: {found}',
        )

    #: Matches the ``FEATCode`` class header whatever its bases, so a re-parenting
    #: (as #930/#932/#937 did to its siblings) does not fail this pin; only the
    #: docstring wording and citation stay exact.
    _FEATCODE_CITATION = re.compile(
        r'class FEATCode\([^)]*\):\n'
        r'    """Keyword returned in FEAT response line for this command/extension,\n'
        r'    c\.f\., :rfc:`5797#section-3`\.\n')

    def test_featcode_class_docstring_cites_section_3(self) -> 'None':
        """#942's own defect: the exact citation the issue is about.

        Pinned by exact site, not just shape, so this specific typo cannot come
        back unnoticed even if some future fragment still happened to satisfy
        :data:`ACCEPTED_FRAGMENT`.

        """
        for rel_path in ('pcapkit/vendor/ftp/command.py',
                         'pcapkit/const/ftp/command.py'):
            text = (ROOT / rel_path).read_text(encoding='utf-8')
            self.assertRegex(
                text, self._FEATCODE_CITATION,
                f'{rel_path}: FEATCode class docstring no longer opens with '
                'the RFC 5797 section-3 citation expected after #942 (§3 is '
                'Initial Contents of Registry, where the FEAT keywords live)',
            )

    def test_command_feat_attribute_docstring_cites_section_2_2(self) -> 'None':
        """The sweep's second finding: ``Command.feat``'s own citation.

        Pinned by exact site for the same reason as the ``FEATCode`` pin above
        -- RFC 5797 §2.2 (*Registry Format*) is where the ``FEAT Code`` column
        ``feat`` holds is actually defined, so only the spelling was
        wrong here; the section number is correct.

        """
        expected = (
            "        #: Feature code. Keyword returned in FEAT response line for this command/extension,\n"
            "        #: c.f., :rfc:`5797#section-2.2`.\n"
        )
        for rel_path in ('pcapkit/vendor/ftp/command.py',
                         'pcapkit/const/ftp/command.py'):
            text = (ROOT / rel_path).read_text(encoding='utf-8')
            self.assertIn(
                expected, text,
                f'{rel_path}: Command.feat attribute docstring no longer '
                'carries the RFC 5797 section-2.2 citation',
            )


if __name__ == '__main__':
    unittest.main()
