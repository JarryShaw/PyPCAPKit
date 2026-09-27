# -*- coding: utf-8 -*-
"""Tests for :file:`util/pyshark_encap_map.py`, the pyshark table generator.

GitHub issue #851. ``ENCAP_TYPE_TO_LINKTYPE`` and ``FILTER_NAME_TO_LINKTYPE`` in
:mod:`pcapkit.toolkit.pyshark` were measured, not transcribed, by sweeping every
encapsulation :program:`editcap` accepts through :program:`editcap`/:program:`tshark`
4.6.9. This generator is that sweep, made runnable; these tests pin the two traps
that cost real time when the tables were first produced (a PDML ``showname``
holding a ``/``, and the bogus token in ``editcap -T``'s own help banner), the
formatting that has to be byte-stable for a re-run to change nothing, and the
two exclusion rules (an unmapped DLT, an ambiguous filter name) generically --
against the real :class:`~pcapkit.const.reg.linktype.LinkType` registry, whose
``_missing_`` mints a placeholder member for *any* unknown value rather than
raising, which is itself worth pinning (#575).

Most of this is unit-tier: it exercises the parsing and formatting helpers
against fabricated PDML/help-text fragments and a fabricated measurement list,
never shelling out to :program:`editcap`/:program:`tshark`. Two classes do
shell out, both gated on :data:`HAS_WIRESHARK` -- a real ``HAS_*`` flag,
deliberately, rather than a same-effect :func:`shutil.which` check under an
unprefixed name. The latter was this file's first cut, on the theory that a
name ``tests/_dependency_gates.py``'s AST scan does not recognise cannot need
an entry there -- true, but the wrong lesson: it also means the scan cannot
see the gate at all, so a real skip on every CI leg (Wireshark is not
installed on most of them) went unreported as anything. ``HAS_WIRESHARK`` is
declared in :data:`~tests._dependency_gates.NON_DISTRIBUTION_FLAGS`, next to
the existing ``HAS_PROC_FD`` precedent for "a flag that asks about something
pip cannot install at all" -- see that module for the declaration, and
:func:`tests.test_tier_guard.DependencyGateCoverageTests
.test_every_gated_flag_is_classified` for the check that would fail if it were
missing.

* :class:`RealSweepTests` asserts the exact 4.6.9 sweep arithmetic (226
  accepted, 157 writable, 69 refused) and byte-identical reproduction of the
  committed tables. It additionally requires :data:`MEASURED_WIRESHARK_VERSION`
  itself, because those counts are properties of *that* Wireshark release, not
  of the sweep method -- Ubuntu noble's packaged 4.2.2, what CI's runners
  install, accepts 224 encapsulations, not 226, and asserting 226 there is a
  test bug, not a generator bug (found the hard way: PR #853's first CI run).
* :class:`VersionIndependentInvariantTests` runs the same real sweep on
  *whatever* Wireshark is on ``PATH`` and checks properties that hold
  regardless of how many encapsulations that copy accepts: no
  ``frame.encap_type`` key resolves to two different DLTs, no DLT resolves to
  two different keys, and every key or filter name the local sweep *did*
  measure agrees with the committed table rather than merely being present or
  absent from it. This is what still exercises the real binaries on the CI
  legs :class:`RealSweepTests` skips.

"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load_generator():
    """Load :file:`util/pyshark_encap_map.py` as a module.

    ``util/`` is a directory of scripts rather than a package, so there is no
    import path to it -- the same reason :file:`test_changelog_md.py` loads
    :file:`util/changelog_md.py` this way.

    """
    path = ROOT / 'util' / 'pyshark_encap_map.py'
    spec = importlib.util.spec_from_file_location('pyshark_encap_map', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


encap_map = _load_generator()

#: The real :program:`editcap`/:program:`tshark` binaries, resolved once and
#: kept as the resolved paths -- what :func:`~pyshark_encap_map.list_encap_types`
#: and :func:`~pyshark_encap_map.measure_encap` actually need to invoke them.
_EDITCAP = shutil.which('editcap')
_TSHARK = shutil.which('tshark')

#: Whether Wireshark is on ``PATH`` at all. Named with the ``HAS_`` prefix
#: deliberately: ``tests/_dependency_gates.py``'s AST scan keys on exactly that
#: prefix inside a ``skipUnless(...)`` call, and it needs to *see* this gate
#: darkening two classes on every CI leg -- see the module docstring for why
#: an unprefixed same-effect name was the wrong fix. Declared in
#: :data:`~tests._dependency_gates.NON_DISTRIBUTION_FLAGS` rather than
#: :data:`~tests._dependency_gates.MODULE_PROVIDERS`, since a Wireshark binary
#: is not something any ``pyproject.toml`` extra could ever install.
HAS_WIRESHARK = _EDITCAP is not None and _TSHARK is not None

#: The one Wireshark release ``ENCAP_TYPE_TO_LINKTYPE`` and
#: ``FILTER_NAME_TO_LINKTYPE`` were measured against, and the only one
#: :class:`RealSweepTests` trusts to reproduce their exact counts. Named here,
#: singly, so a future reader greps one constant rather than three magic
#: numbers scattered across assertions.
MEASURED_WIRESHARK_VERSION = '4.6.9'

#: ``tshark --version``'s first line reads
#: ``"TShark (Wireshark) 4.6.9 (Git commit ...)."`` -- Ubuntu noble's packaged
#: build reads ``"TShark (Wireshark) 4.2.2 (Git commit ...)."`` in exactly the
#: same shape, just a different number -- so an ``X.Y.Z`` anywhere in the
#: output is enough.
_VERSION_PATTERN = re.compile(r'(\d+\.\d+\.\d+)')


def detect_tshark_version(tshark: 'str | None') -> 'str | None':
    """The ``X.Y.Z`` :program:`tshark` reports itself as, or :obj:`None`.

    Args:
        tshark: Path or bare name of the :program:`tshark` binary, or
            :obj:`None` if it was not found at all.

    Returns:
        The version string, or :obj:`None` if *tshark* is :obj:`None` or its
        ``--version`` output does not contain a recognisable ``X.Y.Z``.

    """
    if tshark is None:
        return None
    completed = subprocess.run([tshark, '--version'], capture_output=True,
                                text=True, check=False)
    match = _VERSION_PATTERN.search(completed.stdout or completed.stderr)
    return match.group(1) if match else None


#: Resolved once, the same way :data:`_EDITCAP`/:data:`_TSHARK` are. Not itself
#: a ``HAS_*`` flag: it is a version *string*, not a boolean gate, so it drives
#: an equality check inside a :func:`unittest.skipUnless` rather than being the
#: condition directly -- :data:`HAS_WIRESHARK` is what the dependency-gate scan
#: needs to see, and it already is one.
_TSHARK_VERSION = detect_tshark_version(_TSHARK)


class ParseParenthesisedNumberTests(unittest.TestCase):
    """:func:`~pyshark_encap_map.parse_parenthesised_number`'s own robustness.

    **What this does not pin, stated plainly because it was previously
    overclaimed here:** #851/#850's real defect -- 10 of 157 rows lost,
    including ``null`` -- was in how the original ad hoc script extracted the
    *name* portion of a PDML ``showname`` such as ``"Encapsulation type:
    NULL/Loopback (15)"``. This generator never does that extraction at all;
    a key comes from ``frame.encap_type``'s number directly, and a filter
    name comes from the PDML ``<proto name=...>`` attribute, never parsed out
    of prose. Reverting :data:`~pyshark_encap_map._PAREN_NUMBER` to #850's
    original naive shape, ``r'(\\w+) \\((\\d+)\\)'`` used with
    :func:`re.search`, leaves every test below still passing: ``.search`` is
    unanchored, so ``\\w+`` matches ``Loopback`` and steps straight over the
    ``/`` -- confirmed by trying it.

    **What this does pin:** the number-extraction is anchored to the *end* of
    the string rather than to a run of name-shaped characters immediately
    before it, which is a genuinely different -- and stricter -- property.
    :meth:`test_a_name_with_no_word_boundary_before_the_number_still_matches`
    is the case that tells the two approaches apart: a naive
    ``\\w+ \\(\\d+\\)`` search requires *some* word character to sit directly
    against the space before the parenthesis, and a name ending in anything
    else -- a trailing ``/`` with nothing after it, say -- leaves the naive
    pattern with nothing in the whole string to match at all, so
    ``re.search`` returns :obj:`None` and the naive code (whatever it did
    with a failed match) drops the row. This function does not have that
    hole, because it never looks at the name.

    """

    def test_a_slash_in_the_name_does_not_stop_the_match(self) -> None:
        # The real showname tshark 4.6.9 renders for ``editcap -T null``.
        # Included for realism, not as proof of the fix -- see the class
        # docstring: the naive regex also passes this particular case.
        self.assertEqual(
            encap_map.parse_parenthesised_number('Encapsulation type: NULL/Loopback (15)'),
            15,
        )

    def test_a_name_with_no_word_boundary_before_the_number_still_matches(self) -> None:
        # The case that actually distinguishes this function from #850's
        # ``r'(\w+) \((\d+)\)'``: nothing but ``/`` sits between the name and
        # the number, so a search anchored on a word run immediately before
        # the space finds nothing anywhere in the string and returns None,
        # while the end-anchored pattern here does not care what precedes it.
        naive = re.compile(r'(\w+) \((\d+)\)')
        showname = 'Encapsulation type: NULL/ (15)'
        self.assertIsNone(naive.search(showname), 'test premise: the naive regex must fail here')

        self.assertEqual(encap_map.parse_parenthesised_number(showname), 15)

    def test_a_plain_name_still_matches(self) -> None:
        self.assertEqual(
            encap_map.parse_parenthesised_number('Encapsulation type: Ethernet (1)'),
            1,
        )

    def test_several_slashes_still_match(self) -> None:
        self.assertEqual(
            encap_map.parse_parenthesised_number('Encapsulation type: A/B/C (99)'),
            99,
        )

    def test_no_trailing_number_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            encap_map.parse_parenthesised_number('Encapsulation type: Ethernet')


class ListEncapTypesTests(unittest.TestCase):
    """The second trap: ``editcap -T ''``'s own banner contributes a bogus token."""

    #: Shaped like the real ``editcap -T ''`` output: an error line with no
    #: leading whitespace (the trap), a blank line, a banner line that itself
    #: reads ``editcap: ...`` with no leading whitespace either, then the
    #: indented ``<token> - <description>`` listing the real parser wants.
    LISTING = (
        'editcap: "" isn\'t a valid encapsulation type\n'
        '\n'
        'editcap: The available encapsulation types for the "-T" flag are:\n'
        '    alp - ATSC Link-Layer Protocol (A/330) packets\n'
        '    ap1394 - Apple IP-over-IEEE 1394\n'
        '    fddi-swapped - FDDI with bit-swapped MAC addresses\n'
    )

    def test_banner_lines_are_not_mistaken_for_tokens(self) -> None:
        # A split on the first run of whitespace reads the banner's own
        # ``editcap:`` as a token; only the indented shape excludes it.
        names = encap_map._ENCAP_LINE
        matches = [names.match(line) for line in self.LISTING.splitlines()]
        found = [match.group(1) for match in matches if match]

        self.assertNotIn('editcap:', found)
        self.assertEqual(found, ['alp', 'ap1394', 'fddi-swapped'])

    def test_list_encap_types_reads_a_fabricated_binary(self) -> None:
        # A fake "editcap" -- a tiny script that prints the fixture listing to
        # stderr and exits non-zero, exactly as the real ``-T ''`` invocation
        # does -- so the subprocess plumbing is exercised without needing the
        # real binary at all.
        fake = make_tmp_dir(self) / 'fake-editcap'
        fake.write_text(
            '#!/bin/sh\n'
            f'printf %s {shell_quote(self.LISTING)} >&2\n'
            'exit 1\n',
            encoding='utf-8',
        )
        fake.chmod(0o755)

        names = encap_map.list_encap_types(str(fake))

        self.assertEqual(names, ['alp', 'ap1394', 'fddi-swapped'])

    def test_a_listing_with_no_tokens_is_an_error(self) -> None:
        fake = make_tmp_dir(self) / 'fake-editcap'
        fake.write_text('#!/bin/sh\nprintf %s "nothing indented here" >&2\nexit 1\n',
                         encoding='utf-8')
        fake.chmod(0o755)

        with self.assertRaises(encap_map.EncapSweepError):
            encap_map.list_encap_types(str(fake))


def shell_quote(text: str) -> str:
    """A single-quoted, shell-safe literal for *text* -- no embedded quotes here."""
    return "'" + text.replace("'", "'\\''") + "'"


def make_tmp_dir(case: unittest.TestCase) -> pathlib.Path:
    """A scratch directory that cleans itself up when *case* finishes.

    :meth:`unittest.TestCase.enterContext` would do this in one line, but it
    is Python 3.11+ and this repository supports back to
    ``requires-python = ">=3.6, <4"`` (:file:`pyproject.toml`) -- CI's own
    oldest tested leg is ``Python 3.10``, where ``enterContext`` does not
    exist at all (``AttributeError``). ``TemporaryDirectory.cleanup`` plus
    :meth:`~unittest.TestCase.addCleanup` is the same "clean up after the
    test regardless of outcome" guarantee, built from APIs both present since
    3.6.

    """
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    return pathlib.Path(tmp.name)


class RenderDictTests(unittest.TestCase):
    """The formatting has to be byte-stable, or a re-run is not idempotent."""

    def test_comment_column_is_two_past_the_longest_entry(self) -> None:
        entries = {
            1: (Enum_LinkType.ETHERNET, ['ether']),
            2: (Enum_LinkType.IEEE802_5, ['tr']),
        }
        block = encap_map.render_dict('ENCAP_TYPE_TO_LINKTYPE', entries, 'int')
        # Entry lines only -- the closing "}  # type: ..." line carries a "#"
        # of its own, at a column that has nothing to do with entry alignment.
        entry_lines = [line for line in block.split('\n') if line.startswith('    ')]

        codes = [line[:line.index('#')].rstrip() for line in entry_lines]
        columns = {line.index('#') for line in entry_lines}

        self.assertEqual(len(columns), 1, f'comments are not aligned: {entry_lines}')
        self.assertEqual(next(iter(columns)), max(len(code) for code in codes) + 2)

    def test_multiple_sources_are_comma_joined_in_order(self) -> None:
        entries = {6: (Enum_LinkType.FDDI, ['fddi', 'fddi-nettl', 'fddi-swapped'])}
        block = encap_map.render_dict('ENCAP_TYPE_TO_LINKTYPE', entries, 'int')

        self.assertIn('# fddi,fddi-nettl,fddi-swapped', block)

    def test_string_keys_are_quoted_like_the_committed_table(self) -> None:
        entries = {'eth': (Enum_LinkType.ETHERNET, ['ether'])}
        block = encap_map.render_dict('FILTER_NAME_TO_LINKTYPE', entries, 'str')

        self.assertIn("    'eth': Enum_LinkType.ETHERNET,", block)
        self.assertTrue(block.rstrip('\n').endswith('}  # type: dict[str, Enum_LinkType]'))

    def test_empty_table_still_closes_correctly(self) -> None:
        block = encap_map.render_dict('EMPTY', {}, 'int')

        self.assertEqual(block, 'EMPTY = {\n}  # type: dict[int, Enum_LinkType]\n')


class ReplaceBlockTests(unittest.TestCase):
    """Only the two dict bodies move; everything else in the file is untouched."""

    TEXT = (
        'BEFORE = 1\n'
        '\n'
        'ENCAP_TYPE_TO_LINKTYPE = {\n'
        '    1: Enum_LinkType.ETHERNET,  # ether\n'
        '}  # type: dict[int, Enum_LinkType]\n'
        '\n'
        'FILTER_NAME_TO_LINKTYPE = {\n'
        "    'eth': Enum_LinkType.ETHERNET,  # ether\n"
        '}  # type: dict[str, Enum_LinkType]\n'
        '\n'
        'AFTER = 2\n'
    )

    def test_surrounding_text_survives_the_swap(self) -> None:
        replacement = 'ENCAP_TYPE_TO_LINKTYPE = {\n    2: Enum_LinkType.SLIP,  # slip\n}  # type: dict[int, Enum_LinkType]\n'

        updated = encap_map._replace_block(self.TEXT, 'ENCAP_TYPE_TO_LINKTYPE', replacement)

        self.assertIn('BEFORE = 1', updated)
        self.assertIn('AFTER = 2', updated)
        self.assertIn('Enum_LinkType.SLIP', updated)
        # ETHERNET is gone from the ENCAP_TYPE_TO_LINKTYPE block specifically --
        # it legitimately survives in FILTER_NAME_TO_LINKTYPE, untouched by this
        # replacement, which is the point of the assertion just above.
        encap_block = updated[updated.index('ENCAP_TYPE_TO_LINKTYPE'):
                               updated.index('FILTER_NAME_TO_LINKTYPE')]
        self.assertNotIn('Enum_LinkType.ETHERNET', encap_block)

    def test_a_missing_block_is_an_error(self) -> None:
        with self.assertRaises(encap_map.EncapSweepError):
            encap_map._replace_block('NOTHING_HERE = 1\n', 'ENCAP_TYPE_TO_LINKTYPE', 'x')

    def test_rewrite_is_idempotent(self) -> None:
        entries = {1: (Enum_LinkType.ETHERNET, ['ether'])}
        once = encap_map.rewrite(self.TEXT, entries, {})
        twice = encap_map.rewrite(once, entries, {})

        self.assertEqual(once, twice)


class BuildTablesExclusionTests(unittest.TestCase):
    """The two exclusion rules, against the real, mutable ``LinkType`` registry.

    ``LinkType``'s own ``_missing_`` mints a placeholder ``Unassigned_N`` member
    for *any* value in range rather than raising (#575) -- so a naive
    ``try: linktype(dlt) except ValueError`` never fires, and would silently
    invent a table entry for a DLT the registry never actually named. These
    exercise :func:`~pyshark_encap_map.build_tables` against a DLT (121) picked
    to be absent from the registry *right now*, which is what makes the
    assertion meaningful rather than assumed.

    """

    def setUp(self) -> None:
        self.assertNotIn(
            121, [member.value for member in Enum_LinkType],
            'DLT 121 has gained a LinkType member; this test needs a value the '
            'registry does not define yet to prove build_tables does not mint one',
        )

    def test_an_unmapped_dlt_is_left_out_and_noted(self) -> None:
        # frame.encap_type 32, editcap -T hhdlc, DLT 121 -- the one entry #850
        # deliberately left out of ENCAP_TYPE_TO_LINKTYPE.
        measurements = [encap_map.Measurement(name='hhdlc', dlt=121, encap_type=32,
                                               root_name='fake-field-wrapper')]

        encap_entries, filter_entries, notes = encap_map.build_tables(
            measurements, Enum_LinkType)

        self.assertEqual(encap_entries, {})
        self.assertEqual(filter_entries, {})
        self.assertTrue(any('32' in note and '121' in note for note in notes), notes)

        # And the lookup must not have minted Unassigned_121 as a side effect.
        self.assertNotIn(121, [member.value for member in Enum_LinkType])

    def test_an_ambiguous_filter_name_is_left_out_and_noted(self) -> None:
        measurements = [
            encap_map.Measurement(name='null', dlt=0, encap_type=15, root_name='null'),
            encap_map.Measurement(name='loop', dlt=108, encap_type=15, root_name='null'),
        ]

        encap_entries, filter_entries, notes = encap_map.build_tables(
            measurements, Enum_LinkType)

        self.assertNotIn('null', filter_entries)
        self.assertTrue(any('null' in note and 'ambiguous' in note for note in notes), notes)

    def test_pseudo_protocol_roots_are_never_candidates(self) -> None:
        measurements = [
            encap_map.Measurement(name='hhdlc', dlt=1, encap_type=99,
                                   root_name='fake-field-wrapper'),
        ]

        _, filter_entries, _ = encap_map.build_tables(measurements, Enum_LinkType)

        self.assertEqual(filter_entries, {})

    def test_an_unambiguous_name_is_kept_with_its_sources_in_order(self) -> None:
        # DLT 10 is FDDI's; frame.encap_type 6 is what tshark 4.6.9 reports for
        # it -- the two numbers are unrelated registries and the table's own
        # comment (#850) is explicit that a WTAP_ENCAP_* number is not a DLT.
        measurements = [
            encap_map.Measurement(name='fddi', dlt=10, encap_type=6, root_name='fddi'),
            encap_map.Measurement(name='fddi-nettl', dlt=10, encap_type=6, root_name='fddi'),
        ]

        encap_entries, filter_entries, _ = encap_map.build_tables(measurements, Enum_LinkType)

        self.assertEqual(encap_entries[6], (Enum_LinkType.FDDI, ['fddi', 'fddi-nettl']))
        self.assertEqual(filter_entries['fddi'], (Enum_LinkType.FDDI, ['fddi', 'fddi-nettl']))


class DetectTsharkVersionTests(unittest.TestCase):
    """The version parsing that decides whether :class:`RealSweepTests` runs.

    Unit-tier and binary-free: each case fabricates the *text* a real
    ``tshark --version`` would print, rather than requiring a second Wireshark
    install to prove the parser handles more than one release. The 4.2.2 case
    is exactly what CI's runners install (Ubuntu noble's
    ``libwireshark-data 4.2.2-1.1build3``) -- this is "the simulated older
    version" that PR #853's own CI run could not be, locally.

    """

    def test_the_local_4_6_9_style_banner_parses(self) -> None:
        fake = make_tmp_dir(self) / 'fake-tshark'
        fake.write_text(
            '#!/bin/sh\n'
            'printf %s '
            + shell_quote('TShark (Wireshark) 4.6.9 (Git commit 2d548b197c75).\n')
            + '\n',
            encoding='utf-8',
        )
        fake.chmod(0o755)

        self.assertEqual(detect_tshark_version(str(fake)), '4.6.9')

    def test_ubuntu_noble_4_2_2_style_banner_parses_and_mismatches(self) -> None:
        # The exact banner shape apt's packaged tshark prints, per the CI log
        # PR #853's cross-review quoted: libwireshark-data 4.2.2-1.1build3.
        fake = make_tmp_dir(self) / 'fake-tshark'
        fake.write_text(
            '#!/bin/sh\n'
            'printf %s '
            + shell_quote('TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).\n')
            + '\n',
            encoding='utf-8',
        )
        fake.chmod(0o755)

        version = detect_tshark_version(str(fake))

        self.assertEqual(version, '4.2.2')
        self.assertNotEqual(version, MEASURED_WIRESHARK_VERSION)

    def test_no_binary_is_none(self) -> None:
        self.assertIsNone(detect_tshark_version(None))

    def test_unparseable_output_is_none(self) -> None:
        fake = make_tmp_dir(self) / 'fake-tshark'
        fake.write_text('#!/bin/sh\nprintf %s "no version number here"\n', encoding='utf-8')
        fake.chmod(0o755)

        self.assertIsNone(detect_tshark_version(str(fake)))


@unittest.skipUnless(HAS_WIRESHARK, 'editcap/tshark not found on PATH')
@unittest.skipUnless(
    _TSHARK_VERSION == MEASURED_WIRESHARK_VERSION,
    f'tshark reports {_TSHARK_VERSION!r}, this class only trusts its exact '
    f'sweep arithmetic against {MEASURED_WIRESHARK_VERSION!r} -- the version '
    f'ENCAP_TYPE_TO_LINKTYPE and FILTER_NAME_TO_LINKTYPE were measured against '
    f'-- see VersionIndependentInvariantTests for what still runs here',
)
class RealSweepTests(unittest.TestCase):
    """The full sweep, for real, against the committed source capture.

    Skipped -- via :data:`HAS_WIRESHARK` and a version check stacked on top of
    it -- on any host without Wireshark installed, or whose Wireshark is not
    :data:`MEASURED_WIRESHARK_VERSION`. Where it does run, it is the
    executable form of #851's acceptance criteria: the sweep arithmetic
    and byte-identical reproduction of the committed tables. CI's runners
    install Ubuntu noble's packaged 4.2.2 (224 accepted, not 226), so this
    class is expected to skip there and run only locally, on a pinned
    Homebrew/self-built 4.6.9 -- see the module docstring and
    :file:`util/pyshark_encap_map.py`'s own docstring for why that is the
    right trade rather than a gap.

    """

    def test_sweep_arithmetic_matches_the_committed_comment(self) -> None:
        accepted = encap_map.list_encap_types(_EDITCAP)
        self.assertEqual(len(accepted), encap_map.EXPECTED_ACCEPTED)

    def test_check_mode_reports_the_committed_file_as_current(self) -> None:
        # examples/captures/in.pcap is git-tracked (not gitignored), so this is
        # a unit-tier-legal read per tests/_tiers.py -- it is one of the
        # captures committed rather than one only make_samples.py produces.
        source = ROOT / 'examples' / 'captures' / 'in.pcap'
        if not source.is_file():
            self.skipTest(f'{source} is absent')

        completed = subprocess.run(
            [sys.executable, str(ROOT / 'util' / 'pyshark_encap_map.py'), '--check'],
            capture_output=True, text=True, check=False, cwd=str(ROOT),
        )

        self.assertEqual(
            completed.returncode, 0,
            f'pcapkit/toolkit/pyshark.py has drifted from the sweep:\n'
            f'{completed.stdout}\n{completed.stderr}',
        )
        self.assertIn(
            f'sweep: {encap_map.EXPECTED_ACCEPTED} accepted, '
            f'{encap_map.EXPECTED_WRITABLE} writable, {encap_map.EXPECTED_REFUSED} refused',
            completed.stdout,
        )


@unittest.skipUnless(HAS_WIRESHARK, 'editcap/tshark not found on PATH')
class VersionIndependentInvariantTests(unittest.TestCase):
    """Properties of a real sweep that hold on any Wireshark, not only 4.6.9.

    Where :class:`RealSweepTests` skips -- any Wireshark that is not
    :data:`MEASURED_WIRESHARK_VERSION`, which is every CI leg today -- this
    still runs the real sweep against whatever :program:`editcap`/
    :program:`tshark` *is* on ``PATH`` (224 accepted on CI's Ubuntu noble
    4.2.2, not the 226 :class:`RealSweepTests` requires) and checks structure
    instead of counts: no ``frame.encap_type`` key or DLT is ambiguous within
    this sweep, and every key or filter name this sweep *did* measure agrees
    with what is committed. It does not require the committed table to be
    complete for this Wireshark -- only that it is not wrong about what this
    Wireshark actually reports, which is a property completeness on 4.6.9
    does not by itself establish.

    """

    @classmethod
    def setUpClass(cls) -> None:
        source = ROOT / 'examples' / 'captures' / 'in.pcap'
        if not source.is_file():
            raise unittest.SkipTest(f'{source} is absent')

        # The same value-must-already-be-registered guard build_tables() uses
        # (#575): Enum_LinkType(dlt) mints a placeholder member for any value
        # in range rather than raising, so "is this DLT really in the table"
        # has to be answered by membership, never by calling the constructor
        # first and asking forgiveness.
        cls.known_dlts = frozenset(member.value for member in Enum_LinkType)

        accepted = encap_map.list_encap_types(_EDITCAP)
        measurements = []  # type: list[encap_map.Measurement]
        with tempfile.TemporaryDirectory(prefix='pyshark_encap_map_invariants_') as tmp:
            tmp_dir = pathlib.Path(tmp)
            for name in accepted:
                result = encap_map.measure_encap(_EDITCAP, _TSHARK, source, name, tmp_dir)
                if isinstance(result, encap_map.Measurement):
                    measurements.append(result)
        cls.measurements = measurements

    def test_no_encap_type_key_resolves_to_two_dlts(self) -> None:
        by_key = {}  # type: dict[int, set[int]]
        for item in self.measurements:
            by_key.setdefault(item.encap_type, set()).add(item.dlt)

        ambiguous = {key: dlts for key, dlts in by_key.items() if len(dlts) > 1}
        self.assertEqual(ambiguous, {}, f'this Wireshark disagrees with itself: {ambiguous}')

    def test_no_dlt_resolves_to_two_encap_type_keys(self) -> None:
        by_dlt = {}  # type: dict[int, set[int]]
        for item in self.measurements:
            by_dlt.setdefault(item.dlt, set()).add(item.encap_type)

        ambiguous = {dlt: keys for dlt, keys in by_dlt.items() if len(keys) > 1}
        self.assertEqual(ambiguous, {}, f'this Wireshark disagrees with itself: {ambiguous}')

    def test_measured_encap_type_keys_agree_with_the_committed_table(self) -> None:
        from pcapkit.toolkit.pyshark import ENCAP_TYPE_TO_LINKTYPE

        mismatches = []
        for item in self.measurements:
            if item.encap_type not in ENCAP_TYPE_TO_LINKTYPE or item.dlt not in self.known_dlts:
                continue  # committed table may simply not cover this key -- not this test's job
            measured = Enum_LinkType(item.dlt)
            committed = ENCAP_TYPE_TO_LINKTYPE[item.encap_type]
            if measured != committed:
                mismatches.append((item.name, item.encap_type, item.dlt, committed))

        self.assertEqual(mismatches, [],
                          f'committed ENCAP_TYPE_TO_LINKTYPE disagrees with a live '
                          f'measurement: {mismatches}')

    def test_measured_filter_names_agree_with_the_committed_table(self) -> None:
        from pcapkit.toolkit.pyshark import FILTER_NAME_TO_LINKTYPE

        by_root = {}  # type: dict[str, set[int]]
        for item in self.measurements:
            if item.root_name is not None:
                by_root.setdefault(item.root_name, set()).add(item.dlt)

        mismatches = []
        for name, dlts in by_root.items():
            # Ambiguous within this sweep, or the committed table simply does
            # not cover this name -- either way, not what this test checks.
            if name not in FILTER_NAME_TO_LINKTYPE or len(dlts) != 1:
                continue
            dlt, = dlts
            if dlt not in self.known_dlts:
                continue
            measured = Enum_LinkType(dlt)
            committed = FILTER_NAME_TO_LINKTYPE[name]
            if measured != committed:
                mismatches.append((name, dlt, committed))

        self.assertEqual(mismatches, [],
                          f'committed FILTER_NAME_TO_LINKTYPE disagrees with a live '
                          f'measurement: {mismatches}')


if __name__ == '__main__':
    unittest.main()
