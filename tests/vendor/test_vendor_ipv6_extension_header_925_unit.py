# -*- coding: utf-8 -*-
"""Regression tests for GitHub issue #925.

:mod:`pcapkit.vendor.ipv6.extension_header` used to crawl the *Protocol
Numbers* registry (``protocol-numbers/protocol-numbers-1.csv``), filtered on
its ``IPv6 Extension Header`` column -- a derived signal, not the registry
:rfc:`8200#section-4` names as authoritative for this enumeration. That
registry disagrees with the authoritative one on header 147 (``BIT-EMU``):
the Protocol Numbers registry flags it as an IPv6 extension header (citing
:rfc:`9801`), while IANA's *IPv6 Extension Header Types* registry
(``ipv6-parameters/extension-header.csv``) omits 147 entirely. The fix moves
:attr:`~pcapkit.vendor.ipv6.extension_header.ExtensionHeader.LINK` to the
authoritative registry and rewrites the parser for its 3-column shape
(``Protocol Number,Description,Reference`` -- no ``IPv6 Extension Header``
flag to filter on).

That registry's ``Description`` column is verbose (``Routing Header for
IPv6``), unlike the old registry's short ``Keyword`` column (``IPv6-Route``)
that :meth:`~pcapkit.vendor.ipv6.extension_header.ExtensionHeader.process`
used to derive most of the current member names from. Naively deriving names
from the new column would silently rename eight of the eleven surviving
members -- a breaking change far worse than the defect being fixed -- so the
crawler now carries an explicit
:attr:`~pcapkit.vendor.ipv6.extension_header.ExtensionHeader.NAMES` override
for exactly those eight, and :data:`EXPECTED_MEMBERS` below pins that no name
moves.

This suite feeds the fixture CSV text directly to the crawler's own
:meth:`~pcapkit.vendor.default.Vendor.request`, :meth:`count`, :meth:`process`
and :meth:`context` -- the same pipeline :meth:`~pcapkit.vendor.default.
Vendor.__init__` would drive from a live fetch -- so the fix is exercised
without ever calling :mod:`requests`. Per the standing rule on this package,
no test here (or anywhere) invokes the crawler against the network.

**The const half of the fix is now applied too.** Removing ``BIT_EMU`` looked
blocked at first: :meth:`pcapkit.protocols.internet.ipv6.IPv6
._decode_next_layer`'s walk resolves ``Enum_ExtensionHeader(proto)`` at the
top of its loop and used to rely on that succeeding for 147. But that test's
own docstring says 147 was only ever the *example* -- ``"253``/``254`` are
the same code path (also unregistered, also resolve to ``Raw``)"`` -- and 253
*is* in the authoritative registry where 147 never was, so
``tests.protocols.internet.test_ipv6_ext_unit
.IPv6ExtUnitTests.test_unimplemented_terminal_code_stops_the_walk_not_the_packet``
now exercises the identical code path on 253 instead, which frees
:mod:`pcapkit.const.ipv6.extension_header` to drop ``BIT_EMU`` for real.
:mod:`tests.const.test_const_ipv6_extension_header_925_unit` pins that side;
:func:`test_context_matches_the_committed_const_file_byte_for_byte` below is
the seam between the two -- it proves the *committed* const file is exactly
what this fixture, run through the fixed crawler, produces.

A real crawl against the live registry was still never run here -- the
standing rule on this repository disallows it. What this suite proves is
narrower and machine-checkable without one: feeding it the fixture text this
issue's own investigation fetched reproduces the committed const file
byte-for-byte. The owner should still run the crawler for real once, to
confirm the *live* registry matches the fixture -- IANA could have edited
the registry between the fetch and this PR landing.

"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why all three are checked
#: rather than only :mod:`requests`.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all; see
#: :mod:`tests.vendor.test_ipx_packet_unit` for the full rationale.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: The fixture the issue's own investigation fetched from
#: ``https://www.iana.org/assignments/ipv6-parameters/extension-header.csv``
#: on 2026-09-29, with the header's line ending kept ``\\r\\n`` to match the
#: shape :meth:`~pcapkit.vendor.default.Vendor.request` splits a real HTTP
#: response on.
FIXTURE_CSV = (
    'Protocol Number,Description,Reference\r\n'
    '0,IPv6 Hop-by-Hop Option,[RFC8200]\r\n'
    '43,Routing Header for IPv6,[RFC8200][RFC5095]\r\n'
    '44,Fragment Header for IPv6,[RFC8200]\r\n'
    '50,Encapsulating Security Payload,[RFC4303]\r\n'
    '51,Authentication Header,[RFC4302]\r\n'
    '60,Destination Options for IPv6,[RFC8200]\r\n'
    '135,Mobility Header,[RFC6275]\r\n'
    '139,Host Identity Protocol,[RFC7401]\r\n'
    '140,Shim6 Protocol,[RFC5533]\r\n'
    '253,Use for experimentation and testing,[RFC3692][RFC4727]\r\n'
    '254,Use for experimentation and testing,[RFC3692][RFC4727]'
)

#: Every member the fixed crawler is expected to produce from
#: :data:`FIXTURE_CSV`, as ``(name, value)`` in registry order -- exactly the
#: 11 non-``BIT_EMU`` members the committed
#: :class:`pcapkit.const.ipv6.extension_header.ExtensionHeader` now carries,
#: spelled out so a future change to :meth:`process` that renames one
#: silently fails here instead of shipping.
EXPECTED_MEMBERS = (
    ('HOPOPT', 0),
    ('IPv6_Route', 43),
    ('IPv6_Frag', 44),
    ('ESP', 50),
    ('AH', 51),
    ('IPv6_Opts', 60),
    ('Mobility_Header', 135),
    ('HIP', 139),
    ('Shim6', 140),
    ('Use_for_experimentation_and_testing_253', 253),
    ('Use_for_experimentation_and_testing_254', 254),
)

#: Comments :data:`EXPECTED_MEMBERS` carried in
#: :mod:`pcapkit.const.ipv6.extension_header` *before* this fix (i.e. sourced
#: from the Protocol Numbers registry), for the six members whose text this
#: registry change does not disturb -- the other five (``IPv6_Route``,
#: ``IPv6_Frag``, ``ESP``, and both ``Use_for_experimentation_and_testing``
#: members) draw genuinely different reference text from the new registry
#: (real RFC citations where the old one cited an author's name, or an extra
#: RFC 4727 citation), which is a known, reported divergence rather than a
#: parsing defect -- see the module docstring and this suite's
#: ``test_five_comments_genuinely_diverge_from_the_historical_registry``. The
#: committed const file now carries the *new* text for all 11, which is what
#: ``test_context_matches_the_committed_const_file_byte_for_byte`` pins.
UNCHANGED_COMMENTS = {
    'HOPOPT': 'HOPOPT, IPv6 Hop-by-Hop Option [:rfc:`8200`]',
    'AH': 'AH, Authentication Header [:rfc:`4302`]',
    'IPv6_Opts': 'IPv6-Opts, Destination Options for IPv6 [:rfc:`8200`]',
    'Mobility_Header': 'Mobility Header [:rfc:`6275`]',
    'HIP': 'HIP, Host Identity Protocol [:rfc:`7401`]',
    'Shim6': 'Shim6, Shim6 Protocol [:rfc:`5533`]',
}


def _members_from_enum(enum: 'list[str]') -> 'tuple[tuple[str, int], ...]':
    """Extract ``(name, value)`` pairs from :meth:`Vendor.process`'s ``enum`` list."""
    out = []  # type: list[tuple[str, int]]
    for entry in enum:
        match = re.search(r'(\w+) = (\d+)', entry)
        assert match is not None, f'could not parse enum entry: {entry!r}'
        out.append((match.group(1), int(match.group(2))))
    return tuple(out)


def _comment_from_enum(enum: 'list[str]', name: 'str') -> 'str':
    """Extract the ``#:`` comment text preceding the member named ``name``."""
    for entry in enum:
        if re.search(rf'\b{re.escape(name)} = \d+', entry):
            comment_line = entry.splitlines()[0]
            assert comment_line.startswith('#: ')
            return comment_line[len('#: '):]
    raise AssertionError(f'no enum entry named {name!r}')


def _normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation :meth:`Vendor.__init__` writes files
    through, so a byte comparison against the committed file does the same
    the generator itself would have -- see
    :mod:`tests.vendor.test_ipx_packet_unit` for the same helper.

    Args:
        context: Return value of :meth:`~pcapkit.vendor.default.Vendor.context`.

    Returns:
        The text as the generator would have written it to disk.

    """
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class ExtensionHeaderVendorTests(unittest.TestCase):
    """The crawler fix: correct registry, 3-column parser, names preserved."""

    if TYPE_CHECKING:
        vendor_module: 'Any'

    def setUp(self) -> None:
        reimport_once_per_class(self)

        import pcapkit.vendor.ipv6.extension_header as vendor_module

        resolved = pathlib.Path(vendor_module.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{vendor_module.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .` to '
                          f'run this suite against it')

        self.vendor_module = vendor_module

    def _vendor(self) -> 'Any':
        """A crawler instance with the attributes ``__init__`` would have set,
        but without ``__init__``'s network fetch and file write -- see
        :mod:`tests.vendor.test_ipx_packet_unit` for the same technique.

        """
        cls = self.vendor_module.ExtensionHeader
        vendor = cls.__new__(cls)
        vendor.NAME = cls.__name__
        vendor.DOCS = cls.__doc__
        lines = vendor.request(FIXTURE_CSV)
        vendor.record = vendor.count(lines)
        return vendor, lines

    def test_link_points_at_the_authoritative_registry(self) -> None:
        # The root-cause fix, stated as an assertion: no longer the Protocol
        # Numbers registry filtered on a derived flag.
        link = self.vendor_module.ExtensionHeader.LINK
        self.assertEqual(link, 'https://www.iana.org/assignments/ipv6-parameters/extension-header.csv')
        self.assertNotIn('protocol-numbers', link)

    def test_fixture_splits_into_twelve_lines(self) -> None:
        # Twelve lines: the header plus the eleven data rows -- confirms
        # request()'s ``\r\n`` split is doing something on this fixture at
        # all, before trusting count()/process() downstream of it.
        vendor, lines = self._vendor()
        self.assertEqual(len(lines), 12)

    def test_no_extension_header_type_is_lost_or_renamed(self) -> None:
        # The count, and every surviving name, in one assertion: losing 147
        # (BIT_EMU) is the fix; losing or renaming any of the other 11 is not.
        vendor, lines = self._vendor()
        enum, miss = vendor.process(lines)
        self.assertEqual(len(enum), 11)
        self.assertEqual(_members_from_enum(enum), EXPECTED_MEMBERS)
        self.assertEqual(miss, [])

    def test_bit_emu_is_absent_from_the_authoritative_registry_output(self) -> None:
        vendor, lines = self._vendor()
        enum, _ = vendor.process(lines)
        names, values = zip(*_members_from_enum(enum))
        self.assertNotIn('BIT_EMU', names)
        self.assertNotIn(147, values)

    def test_keyword_style_names_are_not_derived_from_the_verbose_description(self) -> None:
        # Sanity check on the *mechanism*, not just the outcome: feeding the
        # fixture's Description column through safe_name() directly (i.e.
        # without the NAMES override) would NOT reproduce these names --
        # proving the override is doing real work rather than being a no-op
        # that happens to agree with the default derivation.
        vendor, lines = self._vendor()
        naive = vendor.safe_name('Routing Header for IPv6')
        self.assertNotEqual(naive, 'IPv6_Route')
        self.assertEqual(naive, 'Routing_Header_for_IPv6')

    def test_six_comments_are_unchanged_from_the_historical_registry(self) -> None:
        vendor, lines = self._vendor()
        enum, _ = vendor.process(lines)
        for name, expected_comment in UNCHANGED_COMMENTS.items():
            with self.subTest(name=name):
                self.assertEqual(_comment_from_enum(enum, name), expected_comment)

    def test_five_comments_genuinely_diverge_from_the_historical_registry(self) -> None:
        # Documents the divergence rather than hiding it: these five members'
        # *comments* differ from the committed const file because the two
        # registries carry different Reference/Description text for the same
        # header -- not because the new parser mishandles them. Names and
        # values still match EXPECTED_MEMBERS exactly (see the sibling test).
        vendor, lines = self._vendor()
        enum, _ = vendor.process(lines)

        self.assertEqual(_comment_from_enum(enum, 'IPv6_Route'),
                         'IPv6-Route, Routing Header for IPv6 [:rfc:`8200`][:rfc:`5095`]')
        self.assertNotEqual(_comment_from_enum(enum, 'IPv6_Route'),
                            'IPv6-Route, Routing Header for IPv6 [Steve Deering]')

        self.assertEqual(_comment_from_enum(enum, 'IPv6_Frag'),
                         'IPv6-Frag, Fragment Header for IPv6 [:rfc:`8200`]')
        self.assertNotEqual(_comment_from_enum(enum, 'IPv6_Frag'),
                            'IPv6-Frag, Fragment Header for IPv6 [Steve Deering]')

        self.assertEqual(_comment_from_enum(enum, 'ESP'),
                         'ESP, Encapsulating Security Payload [:rfc:`4303`]')
        self.assertNotEqual(_comment_from_enum(enum, 'ESP'),
                            'ESP, Encap Security Payload [:rfc:`4303`]')

        for name in ('Use_for_experimentation_and_testing_253', 'Use_for_experimentation_and_testing_254'):
            with self.subTest(name=name):
                self.assertEqual(_comment_from_enum(enum, name),
                                 'Use for experimentation and testing [:rfc:`3692`][:rfc:`4727`]')
                self.assertNotEqual(_comment_from_enum(enum, name),
                                    'Use for experimentation and testing [:rfc:`3692`]')

    def test_context_round_trips_through_the_full_pipeline(self) -> None:
        # request() -> count() -> process() -> context(), the same sequence
        # Vendor.__init__ drives from a live fetch, exercised end to end
        # against the fixture with no network call anywhere in it.
        vendor, lines = self._vendor()
        generated = vendor.context(lines)
        self.assertIn('class ExtensionHeader(EnumRegistry, IntEnum):', generated)
        self.assertIn('HOPOPT = 0', generated)
        self.assertNotIn('BIT_EMU', generated)
        self.assertNotIn('147', generated)

    def test_context_matches_the_committed_const_file_byte_for_byte(self) -> None:
        # The seam this fix rests on: pcapkit/const/ipv6/extension_header.py
        # was hand-applied rather than produced by a live crawl (disallowed
        # in this environment), so this is what stands in for "regenerating
        # is a no-op" -- see tests.vendor.test_ipx_packet_unit for the same
        # technique against a crawler with no LINK at all. Passing here does
        # not prove the *live* registry still matches FIXTURE_CSV -- only
        # that the committed file is exactly what this fixture produces.
        vendor, lines = self._vendor()
        generated = _normalize(vendor.context(lines))
        committed = (ROOT / 'pcapkit' / 'const' / 'ipv6' / 'extension_header.py').read_text(encoding='utf-8')
        self.assertEqual(generated, committed,
                         'pcapkit/const/ipv6/extension_header.py no longer matches what '
                         'ExtensionHeader.context() produces from FIXTURE_CSV; either the '
                         'hand-applied const file or this fixture is stale')


if __name__ == '__main__':
    unittest.main()
