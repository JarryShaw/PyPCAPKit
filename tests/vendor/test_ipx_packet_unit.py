# -*- coding: utf-8 -*-
"""Regression tests for the retired :mod:`pcapkit.vendor.ipx.packet` scrape.

GitHub issue #518, and the same failure on the same article that #507 found for
the sibling socket crawler. The packet-type crawler used to scrape
``find_all('table', class_='wikitable')[1]`` out of the Wikipedia *Internetwork
Packet Exchange* article, and both halves of that stopped working. Wikipedia
answers |requests|_' default User-Agent with HTTP 403, so
:meth:`pcapkit.vendor.default.Vendor._request` could not fetch the page; and the
table was deleted from the article on 2026-08-25 in revision 1371327031, leaving
the live page with a single ``wikitable`` -- the IPX header format one -- so that
index raises :exc:`IndexError` even with the fetch fixed. The scrape is retired
in favour of the hand-maintained :data:`pcapkit.vendor.ipx.packet.DATA`.

.. |requests| replace:: ``requests``
.. _requests: https://requests.readthedocs.io

What that leaves worth pinning is the failure mode the issue is actually about: a
regeneration that quietly drops packet types. :data:`EXPECTED_MEMBERS` spells the
enumeration out in full, so losing one fails here rather than shipping.
``Broadcast_4`` is in it verbatim, footnote artefact and all -- ``[4]`` was
Wikipedia's own citation marker for :rfc:`1132` rather than part of the name, and
it leaked into the member. Keeping it is what makes byte identity achievable, and
renaming it would break a public member, so the name is pinned rather than
tidied.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and, by the
whole point of the change, makes no network call.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs. ``requests`` is the
#: obvious one -- ``pcapkit.vendor.default`` imports it at module scope -- but it
#: is not sufficient: importing *any* crawler imports the ``pcapkit.vendor``
#: package, whose :file:`__init__.py` pulls in all seventeen subpackages, seven of
#: which ``import bs4`` at module scope. So a guard on ``requests`` alone lets the
#: suite error instead of skipping on a machine that happens to have ``requests``
#: and not ``beautifulsoup4``.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all. They ship in the ``vendor`` extra
#: (:file:`pyproject.toml`), not ``test`` -- so these tests skip on the ``test``
#: and ``gate`` jobs of :file:`.github/workflows/unit-tests.yml`, which never
#: install ``vendor``, but run for real on ``engine-tests``, which does (#738).
#: Guarded the same way
#: :file:`tests/protocols/test_dispatch_registry_unit.py` guards its own optional
#: runtime dependencies, rather than making the whole unit tier depend on the
#: crawlers' requirements. See #518.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Every member the generated :class:`pcapkit.const.ipx.packet.Packet` is expected
#: to carry, as ``(name, value)`` in definition order. Spelled out rather than
#: derived so that a regeneration which loses a packet type -- the exact failure
#: #518 describes -- fails this test instead of passing a comparison against its
#: own output.
EXPECTED_MEMBERS = (
    ('Unknown', 0),
    ('RIP', 1),
    ('Echo_Packet', 2),
    ('Error_Packet', 3),
    ('PEP', 4),
    ('SPX', 5),
    ('NCP', 17),
    ('Broadcast_4', 20),
)


def _normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation the generator writes files through.

    :meth:`pcapkit.vendor.default.Vendor.__init__` does not write what
    :meth:`~pcapkit.vendor.default.Vendor.context` returns verbatim: it strips
    trailing whitespace from every non-blank line, drops whitespace-only lines
    outright, and ends the file with a newline courtesy of :func:`print`. Byte
    comparison against the committed file has to do the same, or it reports a
    difference that regeneration would not actually produce.

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
class IPXPacketVendorTests(unittest.TestCase):
    """The hand-maintained registry, and the crawler that no longer crawls."""

    if TYPE_CHECKING:
        vendor_module: 'Any'
        const_module: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import pcapkit.const.ipx.packet as const_module
        import pcapkit.vendor.ipx.packet as vendor_module

        # Both modules have to come from this checkout for any of the comparisons
        # below to mean anything: the generated text is compared against this
        # repository's constant file, so a vendor module imported from an
        # installed copy elsewhere would be comparing two trees. That is an
        # environment mismatch rather than a defect, hence a skip.
        for module in (vendor_module, const_module):
            resolved = pathlib.Path(module.__file__).resolve()
            if ROOT not in resolved.parents:
                self.skipTest(f'{module.__name__} was imported from {resolved}, which is outside '
                              f'{ROOT}; install this checkout with `pip install -e .` to run this '
                              f'suite against it')

        self.vendor_module = vendor_module
        self.const_module = const_module

    def _vendor(self) -> 'Any':
        """A crawler instance with the attributes ``__init__`` would have set.

        ``Vendor.__init__`` regenerates and *writes* the constant file as a side
        effect of construction, which a test has no business doing to the working
        tree, so the four attributes it sets are set here instead.

        """
        vendor = self.vendor_module.Packet.__new__(self.vendor_module.Packet)
        vendor.NAME = self.vendor_module.Packet.__name__
        vendor.DOCS = self.vendor_module.Packet.__doc__
        data = vendor.request()
        vendor.record = vendor.count(data)
        return vendor

    def test_link_is_none_so_nothing_is_fetched(self) -> None:
        # The retirement, stated as an assertion: with no LINK,
        # Vendor._request() short-circuits to Packet.request() and never reaches
        # requests.get() -- which is what used to take the 403.
        self.assertIsNone(self.vendor_module.Packet.LINK)

    def test_request_makes_no_network_call(self) -> None:
        import requests

        def explode(*args: 'Any', **kwargs: 'Any') -> 'Any':
            raise AssertionError(f'the crawler made a network call: {args!r}')

        original_get, original_request = requests.get, requests.Session.request
        requests.get = explode  # type: ignore[assignment]
        requests.Session.request = explode  # type: ignore[assignment,method-assign]
        try:
            vendor = self.vendor_module.Packet.__new__(self.vendor_module.Packet)
            vendor.NAME = self.vendor_module.Packet.__name__
            vendor.DOCS = self.vendor_module.Packet.__doc__
            self.assertIs(vendor._request(), self.vendor_module.DATA)  # pylint: disable=protected-access
        finally:
            requests.get = original_get  # type: ignore[assignment]
            requests.Session.request = original_request  # type: ignore[method-assign]

    def test_regeneration_reproduces_the_committed_constant_file(self) -> None:
        # The guard that makes the hand-maintained table trustworthy: running the
        # crawler must be a no-op against what is checked in, so an edit to DATA
        # that was never regenerated shows up here.
        vendor = self._vendor()
        generated = _normalize(vendor.context(vendor.request()))
        committed = (ROOT / 'pcapkit' / 'const' / 'ipx' / 'packet.py').read_text(encoding='utf-8')
        self.assertEqual(generated, committed,
                         'regenerating pcapkit/const/ipx/packet.py would change it; run '
                         '`python -m pcapkit.vendor.ipx.packet` and commit the result')

    def test_no_packet_type_is_lost(self) -> None:
        members = tuple((member.name, int(member.value)) for member in self.const_module.Packet)
        self.assertEqual(members, EXPECTED_MEMBERS)

    def test_registry_and_enumeration_agree(self) -> None:
        # Every hand-maintained row reaches the enumeration, and nothing in the
        # enumeration came from anywhere else.
        vendor = self._vendor()
        from_data = tuple(
            (vendor.rename(name, str(code)), code)
            for code, (name, _) in self.vendor_module.DATA.items()
        )
        self.assertEqual(from_data, EXPECTED_MEMBERS)

    def test_broadcast_footnote_artefact_is_preserved(self) -> None:
        # ``Broadcast_4`` is a public member whose name came from Wikipedia's
        # footnote marker for its RFC 1132 citation. Renaming it would be a
        # breaking change, and it is what makes byte identity reachable, so both
        # the member and the DATA row it comes from are pinned.
        self.assertEqual(self.const_module.Packet(20), self.const_module.Packet.Broadcast_4)
        self.assertEqual(self.vendor_module.DATA[20], ('Broadcast[4]', 'Broadcast[4]'))

    def test_unknown_packet_type_survives_the_retirement(self) -> None:
        # 0 is both the scraped table's "Unknown" row and IPX's own default for
        # the type field, so it must be present whatever the registry says.
        self.assertEqual(self.const_module.Packet(0), self.const_module.Packet.Unknown)
        self.assertEqual(self.const_module.Packet(0).value, 0)
        self.assertIn(0, self.vendor_module.DATA)

    def test_unlisted_packet_types_still_resolve(self) -> None:
        # ``_missing_`` has to cover the whole octet, so no legal wire value
        # raises. Sampled at the bounds and either side of every listed value.
        for value in (0, 1, 5, 6, 16, 17, 18, 19, 20, 21, 127, 128, 254, 255):
            with self.subTest(packet=value):
                self.assertEqual(int(self.const_module.Packet(value)), value)

    def test_out_of_range_packet_types_are_rejected(self) -> None:
        for value in (-1, 256):
            with self.subTest(packet=value):
                with self.assertRaises(ValueError):
                    self.const_module.Packet(value)


if __name__ == '__main__':
    unittest.main()
