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

One thing this test does not check: whether the anchor actually exists on the
RFC's own page, only whether it is *shaped* like one could -- filed
separately as GitHub issue #944 for the live instance this sweep does not
catch, ``:rfc:`959#section-4.1``` (RFC 959 has only ``section-1`` through
``section-8``; 4 of its 6 sites are in the two ``ftp/command.py`` files this
change touches), left for that issue's own editorial call rather than guessed
at here.

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


class Finding(NamedTuple):
    """One malformed ``:rfc:`` fragment, keyed so it survives lines moving."""

    #: Path relative to the repository root.
    path: 'str'
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


class RFCAnchorFragmentTests(unittest.TestCase):
    """No ``:rfc:`` role under :mod:`pcapkit` may cite a malformed fragment."""

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
