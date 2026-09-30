# -*- coding: utf-8 -*-
"""Every ``:rfc:`` role's ``#`` fragment must name a real RFC anchor shape.

GitHub issue #942: ``FEATCode``'s class docstring cited :rfc:`5797#secion-3` --
``secion``, missing the ``t`` -- in both :file:`pcapkit/vendor/ftp/command.py`
(inside the ``LINE`` f-string template, the source of truth) and its generated
copy :file:`pcapkit/const/ftp/command.py`. Under Sphinx the role is
``sphinx.roles.RFC`` (:file:`sphinx/roles.py`, ``build_uri``, around
:file:`~362-367`): it appends whatever follows ``#`` onto the RFC's base URL
with no validation at all, and returns a plain ``nodes.reference`` carrying
that URL as ``refuri`` -- never a ``pending_xref``. Docutils' own
``rfc_reference_role`` behaves identically for the same reason. So this
rendered a live link to a **non-existent** anchor, and no build warned: not
because nitpicky mode is scoped to ``py:`` targets -- this repository's
``docs/source/conf.py`` does not enable nitpicky at all -- but because there
is no cross-reference node here for nitpicky to ever have inspected in the
first place, on any Sphinx configuration.

Pinning the exact string that was wrong only catches *this* typo coming back.
:class:`RFCAnchorFragmentTests` instead walks every ``:rfc:`` role with a ``#``
fragment across :mod:`pcapkit` and asserts each fragment has one of the three
shapes Sphinx itself recognises (see :data:`ACCEPTED_FRAGMENT` below).
Anything else is a misspelling of ``section``/``appendix``/``page`` and would
silently link to a dead anchor exactly as ``secion-3`` did.

The sweep this test is built on also turned up a **second** instance of the
same defect: ``:rfc:`5797#secion-2.2``` in the ``feat`` attribute docstring of
the ``Command`` class (not ``FEATCode``), at
:file:`pcapkit/vendor/ftp/command.py:269` and its generated copy
:file:`pcapkit/const/ftp/command.py:257`. Same missing ``t``, same two files,
same one-character fix -- fixed alongside #942's rather than carried as a
documented exception.

A first version of this test accepted a *third* fragment shape, a bare
``N[.N...]`` with no ``section-`` word, to match ten fragments already in the
tree: nine in :file:`pcapkit/const/tcp/mp_tcp_option.py`
(``:rfc:`8684#3.1``` through ``#3.7```) and one in
:file:`pcapkit/const/reg/apptype/tcp.py` (``:rfc:`8765#6.1```). Those anchors
do not exist either -- RFC 8684's real HTML uses ``id="section-3.1"``, never
``id="3.1"`` -- so accepting that shape blessed exactly the defect class this
test exists to catch, the same mistake as the allowlist above one layer down.
The generators that produce them,
:file:`pcapkit/vendor/tcp/mp_tcp_option.py:59` and
:file:`pcapkit/vendor/reg/apptype/apptype.py:1146` (both parsing IANA's
``RFC8684, Section 3.1`` with the same ``re.fullmatch(r'RFC(?P<rfc>\\d+)(, Section
(?P<sec>.*?))?', ...)``, which discards the literal word ``Section`` and
keeps only the number), are fixed to emit ``#section-{sec}``, and the ten
already-generated lines are fixed to match -- exactly what a regeneration
would now produce, verified by reading the generators rather than by running
them. The third shape is dropped from :data:`ACCEPTED_FRAGMENT` entirely.

:data:`ACCEPTED_FRAGMENT`'s set is not a survey of shapes this tree happens to
use today -- it is Sphinx's own. ``sphinx.roles._format_rfc_target`` titles
exactly three anchor prefixes, ``{'appendix', 'page', 'section'}``, and
:file:`tests/project/test_changelog_md.py` already exercises ``#page-N`` as a
correctly-rendered citation (``793#page-5``); confirmed real against RFC
793's own HTML (``id="page-5"`` present). A shapes-in-use survey would have
missed it, since nothing under :mod:`pcapkit` cites a page anchor yet --
``page-\\d+`` is accepted here anyway, matching Sphinx and that sibling test.

That sibling test also exercises ``#introduction`` and a bare ``#section``
(no number) as citations Sphinx does not error on. Deliberately **not**
accepted here, on both counts. ``introduction`` is not one of Sphinx's three
known prefixes -- it renders untitled, one named anchor among an open-ended
set (``abstract``, ``overview``, ``references``, ...) that a fixed-prefix
shape check cannot tell from a typo without becoming a vocabulary list rather
than a shape check. A bare ``section`` with no number is indistinguishable
from a citation that dropped its number, the same incompleteness this test
exists to catch -- Sphinx happening not to error on it is not the same claim
as it being a well-formed citation. Neither shape appears under :mod:`pcapkit`
today, so this changes nothing here; rejecting is the more conservative
default should either turn up later.

One thing the shape check above does not catch: whether the anchor actually
exists on the RFC's own page, only whether it is *shaped* like one could --
that is exactly the class GitHub issue #944 found, ``:rfc:`959#section-4.1```
(RFC 959's own rendered HTML carries only ``section-1`` through ``section-8``;
verified by reading both ``https://www.rfc-editor.org/rfc/rfc959.html`` and
the datatracker mirror). The maintainer ruled on #944 for the enclosing
top-level section, so those citations became ``:rfc:`959#section-4``` --
which :data:`ACCEPTED_FRAGMENT` above already accepts as well-formed.

Eleven sites carried it, not the six #944 reported: that issue grepped
:mod:`pcapkit` only, and a cross-review of the fix found four more rendered
roles in :file:`docs/source/contributing/conventions/registry-protocol.rst`
and one in :file:`tests/const/test_const_enum_no_mint.py`. A further two
cited ``959#section-5.3``, equally dead, in
:file:`tests/protocols/application/test_ftp_unit.py` and
:file:`docs/source/changelog/1.5.0.rst`; #947 ruled ``#section-5`` for those.
**Every** sub-numbered ``959`` fragment is dead, since that RFC renders
anchors for its eight top-level sections and nothing finer -- which is the
general statement, and the reason the denylist below carries both fragments
rather than only the reported one.

:data:`KNOWN_DEAD_ANCHORS` and :meth:`RFCAnchorFragmentTests.
test_no_known_dead_anchor_citations` below add a second, narrower check for
that same defect class: a **denylist** of RFC-number -> anchor pairs already
confirmed, by reading that RFC's own rendered HTML, not to exist -- starting
with the two ``959`` fragments already confirmed dead, so neither can come
back unnoticed. This is deliberately a denylist, not an existence oracle: it
proves nothing about any fragment not already listed here, and adding a new
RFC/anchor pair always means someone read that RFC's actual HTML first --
never a guess extrapolated from this test alone. It stays offline (no network
call) so it keeps running under this repository's CI, which has none.

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

#: Sphinx's own three known anchor prefixes (``sphinx.roles._format_rfc_target``:
#: ``{'appendix', 'page', 'section'}``), each followed by its numbering --
#: ``section-N[.N...]``, ``appendix-X[.N...]``, ``page-N``. Deliberately
#: excludes the untitled/numberless shapes (``introduction``, bare ``section``)
#: that same function also does not error on -- see the module docstring
#: above for why those stay rejected. No bare ``N[.N...]`` alternative either
#: -- see the module docstring for why that shape was dropped rather than kept.
ACCEPTED_FRAGMENT = re.compile(
    r'\A(?:section-\d+(?:\.\d+)*|appendix-[A-Z](?:\.\d+)*|page-\d+)\Z')

#: A **denylist** of RFC number -> the set of anchor fragments that RFC's own
#: rendered HTML is *known* not to have, confirmed by reading
#: ``https://www.rfc-editor.org/rfc/rfc<N>.html`` (or the datatracker mirror)
#: rather than by any crawl or heuristic. This cannot catch an arbitrary dead
#: anchor -- only ones already found and added here -- so its absence from
#: this table is not evidence a fragment is live; see the module docstring's
#: closing paragraphs for why that limitation is deliberate. Both ``959`` entries
#: come from GitHub issue #944: RFC 959's HTML carries anchors only for its eight
#: top-level sections, ``section-1`` through ``section-8``, so *every* sub-numbered
#: ``959`` fragment is dead. ``section-4.1`` is the one #944 reported;
#: ``section-5.3`` turned up in the same sweep, cited for the case-insensitivity
#: rule it does correctly name in prose.
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
#: **This list replaced a general masker, and the reason is the point.** Deciding
#: "is this text inside any inline literal" over the whole tree was tried five times
#: and was wrong five times -- a lookbehind heuristic, then a ``re.DOTALL`` span that
#: crossed paragraph breaks and hid a live ``:rfc:`4303#section-2.1``` role, then a
#: greedy close that swallowed the next literal's opener, then a role's own backtick
#: fusing with an adjacent literal. Each fix addressed the mechanism the previous
#: postmortem had found and missed the next. The general problem is RST's
#: inline-markup grammar, which a regex was never going to model.
#:
#: The bounded question is a different size. Rather than classifying every literal in
#: the tree -- **23,869** spans across **926** files, every one of which had to be got
#: right -- it asks only where a *denylisted fragment* appears, which is **2**
#: occurrences today, and classifies each against this list. Adding a form means one
#: reviewed entry, the same scrutiny :data:`KNOWN_DEAD_ANCHORS` entries already get.
QUOTED_FORMS: 'tuple[tuple[str, str], ...]' = (
    ('``', '``'),
)

#: Where :func:`_dead_anchor_citations` looks, as ``(directory, glob patterns)``.
#: Wider than :func:`_malformed_fragments`'s ``pcapkit``-only sweep on purpose:
#: a dead anchor in a ``.rst`` page renders for readers exactly as one in a
#: docstring does, and four of the five sites this caught were in ``.rst``.
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
    the whole advantage over the masker it replaced, which decided the same question by
    pairing every literal delimiter in the file and got it wrong whenever the pairing
    slipped.

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
        # An earlier version also allowed ``([{"'`` there, on the reasoning that an
        # opening bracket or quote may sit before a literal. That was **the sixth
        # mechanism**, and it was mine: those characters are equally valid as the last
        # character of a literal's *content*, in which case the ``` `` ``` is a
        # **closer** and the role after it is live. So ``` ``'base'``:rfc:`959#…`` ```
        # read as documentation -- and ``` ``'base'`` ``` is a real literal in
        # :file:`pcapkit/const/ftp/command.py`. Measured across the scanned roots,
        # **764** literals in **188** files end in one of those five characters, so the
        # exemption was one adjacency away from hiding a live dead link.
        #
        # Whitespace and start-of-file are safe by RST's own grammar: an inline
        # literal's *end*-string cannot be preceded by whitespace, so ``` `` ```
        # following whitespace is always an opener.
        #
        # The comment this replaced claimed the condition was "measured, not reasoned
        # about". It had been measured only against ``` ``foo`` ``` -- a literal ending
        # in a letter -- and never against the characters in its own allowed set, which
        # is exactly where it failed. A measurement that skips the interesting inputs
        # is reasoning wearing a measurement's clothes.
        if opener == 0 or text[opener - 1].isspace():
            return True
    return False


def _dead_anchor_citations() -> 'list[DeadAnchorFinding]':
    """Every live citation of a fragment listed in :data:`KNOWN_DEAD_ANCHORS`.

    Offline by construction -- it consults the fixed table above and never the
    network -- so it runs the same way in CI, which has none.

    Searches for each denylisted fragment as a **literal string** rather than matching
    every ``:rfc:`` role and comparing. Two consequences worth stating, because the
    previous design had neither:

    * The work is proportional to the number of *denylisted* fragments present, not to
      the amount of markup in the tree. There is no classifier to get wrong on a file
      that has nothing to do with these anchors.
    * A citation this table has never heard of is not examined at all. That is not a
      regression -- the denylist never made a claim about one -- but it means this
      function answers a narrower question than its predecessor pretended to.

    Scans :data:`DEAD_ANCHOR_SCAN` rather than :mod:`pcapkit` alone: scanning one
    directory is what let five dead-anchor sites sit unnoticed outside it, four of them
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

    The two checks have **different scopes**, deliberately.
    :meth:`test_no_malformed_fragments` sweeps :mod:`pcapkit` only;
    :meth:`test_no_known_dead_anchor_citations` sweeps :data:`DEAD_ANCHOR_SCAN`, which
    also covers :file:`docs/source` and :file:`tests`, because scanning one directory
    is what let five dead-anchor sites sit unnoticed outside :mod:`pcapkit`.

    """

    def test_no_malformed_fragments(self) -> 'None':
        """No ``:rfc:`` fragment under :mod:`pcapkit` is shaped like a typo.

        Catches the *next* ``secion``, not just #942's: any freshly introduced
        typo of ``section-``/``appendix-``/``page-``, or any bare-number
        fragment like the ten this same sweep found and fixed, shows up as a
        finding and fails this test -- there is no allowlist left for one to
        hide behind. Shape only, not anchor existence -- see #944.

        """
        found = _malformed_fragments()

        self.assertEqual(
            found, [],
            f'malformed :rfc: fragment(s) found under pcapkit/: {found}',
        )

    def test_the_documentation_exemption_holds_on_every_known_mechanism(self) -> 'None':
        """:func:`_is_documentation` on each input that defeated the old masker.

        This is the regression suite for five rounds of review, and it exists because
        each of those rounds fixed the mechanism the previous postmortem had named and
        then missed the next one. Pinning the *table* rather than the latest fix is the
        difference: a sixth mechanism has to be added here to be considered handled, and
        a redesign has to keep every row passing.

        The rows are the real inputs, not paraphrases of them. Four are false negatives
        the masker produced -- a live role it hid -- which is the dangerous direction,
        since a hidden role is a dead link nobody sees. One is the documentation idiom
        that must stay exempt, or the defect becomes impossible to write about in the
        very file that guards against it.

        """
        # Built from parts so this file does not itself contain a live-looking
        # citation of a denylisted fragment -- writing the test data literally trips
        # the very guard under test, which is the same "documenting the defect is the
        # hazard" problem QUOTED_FORMS exists for, one layer up.
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
            # Mechanism 6: the five characters an earlier boundary check allowed before
            # the opener are equally valid as a literal's last *content* character, in
            # which case the delimiter is a closer and the role is live. One row each,
            # because they were allowed as a set and had to be refuted as a set.
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
            # The real one: ``'base'`` is an inline literal in
            # pcapkit/const/ftp/command.py, and 764 literals across 188 files end in
            # one of those five characters, so this shape is one adjacency away.
            ("a live role after this repository's own quoted literal",
             "See ``'base'``%s`` dead.", True),
            # Pins the suffix half of the (prefix, suffix) pair. Deleting the suffix
            # condition passed every row above, so without this the reason
            # QUOTED_FORMS holds pairs at all is unasserted.
            ('a citation opened like the idiom but not closed like it',
             'names ``%s and more', True),
            # Pins **any** whitespace rather than a literal space. Narrowing
            # ``isspace()`` to ``== ' '`` passed all fifteen earlier rows, because the
            # only row reaching that branch used a plain space -- so the boundary
            # condition the comment above relies on was asserted for one whitespace
            # character out of the set it names. A reader writing the idiom after a
            # line wrap, or first on an indented line, hits exactly these.
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

        A well-formed fragment (one :meth:`test_no_malformed_fragments` above
        already accepts) can still name an anchor its RFC does not render --
        that is #944's defect, ``:rfc:`959#section-4.1```, which the shape
        check cannot see because ``section-4.1`` is a perfectly well-shaped
        fragment. This test catches that *narrower* class by checking every
        role in the scanned roots against :data:`KNOWN_DEAD_ANCHORS`, a
        denylist of RFC number -> anchors already confirmed dead by reading
        that RFC's own rendered HTML.

        This is a denylist, not an oracle: passing this test is not proof
        that every ``:rfc:`` citation in the tree resolves, only that none of
        them cite one of the specific, already-known-dead anchors listed in
        :data:`KNOWN_DEAD_ANCHORS`. An anchor dead in some RFC this table has
        never heard of would sail through unnoticed -- deliberately, since
        the alternative is a live network fetch this offline test (and this
        repository's CI, which has none) cannot make.

        """
        found = _dead_anchor_citations()

        self.assertEqual(
            found, [],
            f'known-dead RFC anchor cited as a live role: {found}',
        )

    #: Matches the ``FEATCode`` class header regardless of its base classes,
    #: so a future re-parenting (like #930/#932/#937 did to five siblings)
    #: does not fail this pin for a reason unrelated to the RFC citation --
    #: only the docstring wording and the citation itself stay exact.
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
        ``feat`` holds is actually defined, so only the spelling was ever
        wrong here; the section number is correct and unchanged.

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
