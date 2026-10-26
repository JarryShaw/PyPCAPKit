# -*- coding: utf-8 -*-
"""No docstring, comment or page claims a third-party engine agrees with another.

The owner's ruling on GitHub issue #1687, applied by issue #1708: third-party
engines are best effort, their adapters need not match the default engine one
to one, and protocol rules belong in the default engine only. So prose that
says an adapter does something "as the default engine does", "as every other
engine's adapters do", or "stops at the same depth" states a contract nobody
keeps.

This scans every module of :mod:`pcapkit` and every page and module under
:file:`docs/source` but the changelog for the shapes in :data:`PATTERNS`. The
text is matched whitespace-normalised, comment markers included, since a claim
wrapped across two lines is a claim all the same, and with its reST markup
stripped, since a reader sees "the default engine" in "the ``default``
engine" too. Each pattern is anchored on the engine or adapter being compared
to, so the ``pypcap-parity`` job, the pypcap against pcap-ct measurements,
"falls back to the default engine" and the reassembly conflict tables are not
matched.

This module is unit-tier: it reads source text and never imports the package.

"""
from __future__ import annotations

import bisect
import re
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Iterator

#: ``(name, pattern)`` of each agreement-shaped claim, matched case-insensitively.
PATTERNS = {
    # "as the default engine dates it", "as for the default engine",
    # "reads as the default engine's", "at the default engine's precision"
    'as the default engine': (
        r"\bas (?:for |by |with )?the default engine(?:['’]s)?(?: \w+)?"
        r"|\bat the default engine['’]s \w+"),
    # "which is what the default engine reports", "the same float the
    # default engine reports", "every packet block the default engine reads"
    'what the default engine does': (
        r'\b(?:what|(?:the same|every) \S+(?: \S+)?) the default engine '
        r'(?:reports|reads|returns|yields|hands|gives|does|dates|numbers|counts|traces)\b'),
    # "as by every other engine", "as every engine's adapters do"
    'every other engine': r"\bevery other engine\b|\bevery engine['’]s adapters?\b",
    # "which is the payload every adapter hands over"
    'every adapter does': (
        r'\bevery (?:other )?adapter '
        r'(?:hands|reports|reads|returns|does|yields|gives)\b'),
    # "the frame numbering still matches the other engines"
    'matches the other engines': (
        r'(?<!not )\bmatch(?:es|ing)? the (?:default|other|built-?in) engines?\b'),
    'agrees with the default engine': (
        r'(?<!not )(?<!never )\bagree(?:s|ing)? with (?:what )?(?:the )?'
        r'(?:default|other|every|each|all|built-?in|third[- ]party) (?:\S+ )?(?:engines?|adapters?)\b'),
    # a positive "match ... one to one" or "1:1"; the contract's own "need
    # not match the builtin adapters one to one" is the negation
    'one to one': (
        r'(?<!not )\bmatch(?:es|ing)?\b[^.]{0,80}?(?:\bone[- ]to[- ]one\b|\b1:1\b)'
        r'|\b1:1\b[^.]{0,40}\b(?:engine|adapter)s?\b|\b(?:engine|adapter)s?\b[^.]{0,40}\b1:1\b'),
    'stops at the same depth': r'\bstops? at the same depth\b',
    'parity': (
        r'\b(?:engine|adapter|cross-engine) parity\b|\bin parity with\b'
        r'|\bparity (?:with|between) (?:the )?(?:default|other|every|each|all|built-?in|third[- ]party) '
        r'(?:\S+ )?(?:engines?|adapters?)\b'),
    'same as the default engine': (
        r'\bsame as (?:the |what the )?(?:default|other|every|each|built-?in) (?:\S+ )?engines?\b'),
    # "the ``default`` engine reads one without a warning too", a clause-final
    # "too" only: "the default engine is too slow" compares nothing
    'the default engine too': r'\bthe default engine\b[^.;]{0,80}?\btoo\b(?= ?[.,;:)]| ?$)',
    # "just as the other engines do", "as the other adapters do", "as for the
    # built-in engines", "the same header record as the built-in engines'"
    'as the other engines': (
        r"\bas (?:for |by |with |in )?(?:the |all )?(?:other|built-?in) (?:\S+ )?"
        r"(?:engines?|adapters?)\b(?:['’]s?)?"),
    # "like the default engine", "like the other adapters"
    'like the default engine': (
        r'\blike (?:the |all )?(?:default|other|built-?in) (?:\S+ )?(?:engines?|adapters?)\b'),
}

#: Compiled :data:`PATTERNS`.
REGEXES = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in PATTERNS.items()}

#: ``(path, phrase)`` of each match that is not an agreement claim, with the reason.
EXEMPT = {
    # The default engine's own schema, describing the default engine's walk.
    ('pcapkit/protocols/schema/internet/ipv6.py', 'as the default engine walks'),
}

#: Whitespace, with the ``#`` or ``#:`` that opens a continued comment line,
#: read as one space; and reST markup -- a role prefix such as ``:obj:``, a
#: backtick run with the ``~`` it may carry, a hyperlink's trailing ``_`` --
#: read as nothing, so "the ``default`` engine" reads "the default engine".
_NORMALISE = re.compile(
    r'(?P<space>\s*\n[ \t]*#:?(?![#!])[ \t]*|\s+)'
    r'|(?P<markup>(?::[\w.+-]+)+:(?=`)|`+~?|(?<=`)_{1,2}(?!\w))')


def normalise(text: str) -> 'tuple[str, list[int]]':
    """Collapse whitespace, comment markers and reST markup, keeping each character's line.

    Args:
        text: File text.

    Returns:
        The text read through :data:`_NORMALISE`, with no two spaces in a row,
        and the line number in ``text`` of each character of it.

    """
    chars, lines = [], []
    starts = [0] + [match.end() for match in re.finditer('\n', text)]

    def keep(start: int, stop: int) -> None:
        for offset in range(start, stop):
            chars.append(text[offset])
            lines.append(bisect.bisect_right(starts, offset))

    position = 0
    for match in _NORMALISE.finditer(text):
        keep(position, match.start())
        if match.group('space') is not None and not (chars and chars[-1] == ' '):
            chars.append(' ')
            lines.append(bisect.bisect_right(starts, match.start()))
        position = match.end()
    keep(position, len(text))
    return ''.join(chars), lines


def claims(text: str) -> 'Iterator[tuple[int, str, str]]':
    """Yield ``(lineno, name, phrase)`` for each agreement claim in ``text``.

    Args:
        text: File text.

    Yields:
        The line the claim starts on, the :data:`PATTERNS` name it matched,
        and the matched phrase, whitespace-normalised.

    """
    flat, lines = normalise(text)
    for name, regex in REGEXES.items():
        for match in regex.finditer(flat):
            yield lines[match.start()], name, match.group(0)


def scanned() -> 'Iterator[Path]':
    """Yield every module of the package, and every page and module of the docs but the changelog."""
    yield from sorted((ROOT / 'pcapkit').rglob('*.py'))
    for path in sorted({*ROOT.glob('docs/sourc?/**/*.rst'), *ROOT.glob('docs/sourc?/**/*.py')}):
        if not path.relative_to(ROOT).parts[2].startswith('changelog'):
            yield path


class EngineAgreementProseTests(unittest.TestCase):
    def test_no_prose_claims_an_engine_agrees_with_another(self) -> None:
        found = []
        for path in scanned():
            relative = path.relative_to(ROOT).as_posix()
            for lineno, name, phrase in claims(path.read_text(encoding='utf-8')):
                if (relative, phrase) not in EXEMPT:
                    found.append(f'{relative}:{lineno}: [{name}] {phrase!r}')
        self.assertEqual(
            found, [],
            'third-party engines are best effort (#1687): state what the adapter '
            'does, not that it does what another engine does (#1708)')

    def test_every_exemption_still_matches(self) -> None:
        """An exemption whose phrase has gone is a stale entry, not a pass."""
        for relative, phrase in sorted(EXEMPT):
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding='utf-8')
                self.assertIn(phrase, [found for (_, _, found) in claims(text)])

    def test_the_issue_1708_shapes_are_matched(self) -> None:
        """Each claim of a shape #1708 names is seen, wrapped or not, so a pass is not vacuous."""
        source = (
            '    """Reassembly and flow tracing are handed a plain float of it, as by\n'
            '    every other engine (#1501). The float nearest the exact timestamp, as\n'
            '    the default engine hands over. Handed on as a float, as every\n'
            "    engine's adapters do. The fraction is in the capture's own resolution,\n"
            "    as the default engine's is.\n"
            '    """\n'
            '    # interleaves their fragments; it would also disagree with\n'
            '    # ``bufid[2]`` in every other engine, which feeds DatagramID.id.\n'
            "    #: The toolkit adapters that walk a\n"
            "    #: chain themselves stop at the same depth.\n"
            "    # keeps as ``sniff_timestamp`` is then '0.000000000', which is what\n"
            '    # the default engine reports (measured on frame 4).\n'
            '    # the frame numbering still matches the other\n'
            '    # engines, which fall back to a raw payload.\n'
            '    # the datagram runs to the end of the frame -- which is the\n'
            '    # payload every adapter hands over (#1547).\n'
            '    """The timestamp, as the same float the default engine reports."""\n'
            '    """It reads every packet block the default engine reads."""\n'
            "    # at the default engine's precision, not the caller's\n"
            '    # A zero-length record holds nothing to decode, which is not a decoding\n'
            '    # failure: the ``default`` engine reads one without a warning too.\n'
            '    """Its header record, just as the other engines do."""\n'
            '    """Read as a :obj:`float`, as the other adapters do."""\n'
            '    """Dated at the UNIX epoch, as for the built-in engines."""\n'
            '    """It skips the block, like the default engine."""\n'
            '    setup, so their output opens with the same header record as the\n'
            "    built-in engines' and :attr:`format` is set.\n"
            '    """Each flag is read from the flags octet, as the :doc:`builtin` engines do."""\n'
        )
        self.assertEqual(
            [(lineno, name) for (lineno, name, _) in sorted(claims(source))],
            [(2, 'as the default engine'), (2, 'every other engine'),
             (3, 'every other engine'), (5, 'as the default engine'),
             (8, 'every other engine'), (10, 'stops at the same depth'),
             (11, 'what the default engine does'), (13, 'matches the other engines'),
             (16, 'every adapter does'), (17, 'what the default engine does'),
             (18, 'what the default engine does'), (19, 'as the default engine'),
             (21, 'the default engine too'), (22, 'as the other engines'),
             (23, 'as the other engines'), (24, 'as the other engines'),
             (25, 'like the default engine'), (26, 'as the other engines'),
             (28, 'as the other engines')])

    def test_legitimate_uses_are_not_matched(self) -> None:
        """The contract itself, the parity job, fallbacks and conflict prose pass."""
        source = (
            'The adapters below are best effort (#1687): they need not match the\n'
            ':doc:`builtin` adapters one to one, since protocol rules belong in the\n'
            'default engine only. Like every third-party engine, both need not match\n'
            'the default engine. The ``pypcap-parity`` job, ``PyPCAP/PyPCAPFile parity\n'
            'Python 3.11``. By parity with ``TransportProtocol``. The extraction falls\n'
            'back to the default engine with a warning. Find where this fragment\n'
            'disagrees with what the buffer already holds. pcap-ct reads in.pcap\n'
            'identically on both. Every engine reads it to decide whether to feed\n'
            'the reassembler; every engine registration lands in one table.\n'
            'Unlike the default engine, it keeps the payload raw. The fragment is\n'
            'kept as the other fragments are, and the ``default`` engine is too slow.\n'
        )
        self.assertEqual(list(claims(source)), [])


if __name__ == '__main__':
    unittest.main()
