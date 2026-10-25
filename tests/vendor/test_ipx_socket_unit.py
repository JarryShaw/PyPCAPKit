# -*- coding: utf-8 -*-
"""Regression tests for the hand-maintained :mod:`pcapkit.vendor.ipx.socket` registry.

GitHub issue #507: the crawler does not scrape the well-known-socket table out of
the Wikipedia *Internetwork Packet Exchange* article, because neither half of
that works. Wikipedia answers ``requests``' default User-Agent with HTTP 403, so
:meth:`pcapkit.vendor.default.Vendor._request` cannot fetch the page; and the
table was deleted from the article on 2026-08-25, so there is nothing at
``find_all('table', class_='wikitable')[3]`` to parse even with the fetch fixed.
The crawler reads the hand-maintained :data:`pcapkit.vendor.ipx.socket.DATA`
instead.

What that leaves worth pinning is the failure mode the issue is actually about:
a regeneration that quietly drops sockets. :data:`EXPECTED_MEMBERS` spells out
the enumeration in full, so losing one fails here rather than shipping. The
value ``0x0000`` in it is the member GitHub issue #492 called for -- IPX's own
default for the ``dst``/``src`` socket field -- which a scrape yielding nothing
would have to prepend unconditionally, and which a hand-maintained table has no
excuse to lose.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and, by
design, makes no network call.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders a constant module from recorded data and compares it
#: with the committed file, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Whether the crawler machinery is importable at all. ``pcapkit.vendor.default``
#: imports :mod:`requests` at module scope, and :mod:`pcapkit.vendor` imports its
#: crawlers, several of which import :mod:`bs4` at module scope, only when
#: :mod:`requests` and :mod:`bs4` are installed (#1850). This file's crawler
#: imports no :mod:`bs4`, so :mod:`bs4` is in the gate for the package to import
#: as it does in CI, not because the import would fail without it.
#:
#: Both ship in the ``test`` extra as well as ``vendor``
#: (:file:`pyproject.toml`), because CI installs ``.[test]`` and a skipped pin
#: guards nothing. The guard is kept as belt-and-braces for an environment that
#: lacks them anyway, so this file skips rather than erroring -- the same way
#: :file:`tests/protocols/test_dispatch_registry_unit.py` guards its own optional
#: dependencies. See #507.
HAS_CRAWLER_DEPS = all(importlib.util.find_spec(name) is not None
                       for name in ('requests', 'bs4'))

#: Every member the generated :class:`pcapkit.const.ipx.socket.Socket` is
#: expected to carry, as ``(name, value)`` in definition order. Spelled out
#: rather than derived so that a regeneration which loses a socket -- the exact
#: failure GitHub issue #507 describes -- fails this test instead of passing a
#: comparison against its own output.
EXPECTED_MEMBERS = (
    ('Unspecified', 0x0000),
    ('Routing_Information_Packet', 0x0001),
    ('Echo_Protocol_Packet', 0x0002),
    ('Error_Handling_Packet', 0x0003),
    ('NetWare_Core_Protocol', 0x0451),
    ('Service_Advertising_Protocol', 0x0452),
    ('Routing_Information_Protocol', 0x0453),
    ('NetBIOS', 0x0455),
    ('Diagnostic_Packet', 0x0456),
    ('Serialization_Packet', 0x0457),
    ('Used_by_Novell_NetWare_Client', 0x4003),
    ('LLC_4', 0x8060),
    ('TCP_over_IPXF', 0x9091),
    ('UDP_over_IPXF', 0x9092),
    ('IPXF', 0x9093),
)

#: The socket number ranges, in the order :meth:`Socket.process` emits them and
#: therefore the order the generated ``_missing_`` tests them in. Pinned because
#: that order decides which name an unlisted socket is given: a wide range
#: placed before a narrower one it fully contains masks that narrower one, so
#: reordering the list changes behaviour without changing any member.
#:
#: GitHub issue #841: each subset range is listed ahead of the wider range that
#: contains it -- ``(0x0020, 0x003F)`` before ``(0x0001, 0x0BB8)``, and both
#: ``(0x4000, 0x4FFF)`` and ``(0x8000, 0xFFFF)`` before ``(0x0BB9, 0xFFFF)`` --
#: so every branch of the generated ``_missing_`` fires for at least the values
#: only it covers. Listed after the wider range, a subset range's branch would
#: be unreachable.
EXPECTED_RANGES = (
    (0x0020, 0x003F, 'Experimental'),
    (0x0001, 0x0BB8, 'Registered by Xerox'),
    (0x4000, 0x4FFF, 'Dynamically Assigned Socket Numbers'),
    (0x8000, 0xFFFF, 'Statically Assigned Socket Numbers'),
    (0x0BB9, 0xFFFF, 'Dynamically Assigned'),
)

#: Sampled sockets and the member name each is expected to resolve to, at the
#: bounds of every range plus the gaps between. The *name* is pinned as well as
#: the value because the value alone cannot tell a live range branch from a
#: masked one: every branch of the generated ``_missing_`` returns ``value``,
#: so only the name says which branch ran -- for ``Registered by Xerox``,
#: that name carries the value as a numeric suffix even though it does not
#: mint (see below); asserting the value alone would pass just as happily
#: with the range branches deleted or reordered.
#:
#: Guards against the masking of GitHub issue #841: with the wide ranges
#: first, ``(0x0001, 0x0BB8)`` masks ``(0x0020, 0x003F)``, and ``(0x0BB9,
#: 0xFFFF)`` masks both ``(0x4000, 0x4FFF)`` and ``(0x8000, 0xFFFF)``, so
#: ``0x0020``, ``0x003F``, ``0x4000``, ``0x4FFF``, ``0x8000``, ``0x8061``,
#: ``0x9094`` and ``0xFFFF`` would all resolve under the wrong wide range's
#: name. See :data:`pcapkit.vendor.ipx.socket.RANGES` for the order.
#:
#: No range mints (GitHub issue #775). ``Experimental``, ``Dynamically
#: Assigned Socket Numbers``, ``Statically Assigned Socket Numbers`` and
#: ``Dynamically Assigned`` each name an allocation *policy* for the pool
#: rather than a specific assignment, so their bare name carries no numeric
#: suffix. ``Registered by Xerox`` keeps its hex-suffixed name: a proprietary
#: protocol may expose no name of its own, so the company name serves as its
#: name, and not registering is not renaming (PR #878). Every range resolves
#: through :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`.
EXPECTED_MISSING_NAMES = {
    0x0000: 'Unspecified',                    # a defined member
    0x0001: 'Routing_Information_Packet',     # a defined member
    0x0004: 'Registered by Xerox_0x0004',
    0x0020: 'Experimental',
    0x003F: 'Experimental',
    0x0BB8: 'Registered by Xerox_0x0BB8',
    0x0BB9: 'Dynamically Assigned',
    0x4000: 'Dynamically Assigned Socket Numbers',
    0x4FFF: 'Dynamically Assigned Socket Numbers',
    0x7FFF: 'Dynamically Assigned',
    0x8000: 'Statically Assigned Socket Numbers',
    0x8061: 'Statically Assigned Socket Numbers',
    0x9094: 'Statically Assigned Socket Numbers',
    0xFFFF: 'Statically Assigned Socket Numbers',
}


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


@unittest.skipUnless(HAS_CRAWLER_DEPS, 'requests and/or beautifulsoup4 not installed')
class IPXSocketVendorTests(unittest.TestCase):
    """The hand-maintained registry, and the crawler that does not crawl."""

    if TYPE_CHECKING:
        vendor_module: 'Any'
        const_module: 'Any'

    def setUp(self) -> None:
        reimport_once_per_class(self)

        import pcapkit.const.ipx.socket as const_module
        import pcapkit.vendor.ipx.socket as vendor_module

        # Both modules have to come from this checkout for any of the
        # comparisons below to mean anything: the generated text is compared
        # against this repository's constant file, so a vendor module imported
        # from an installed copy elsewhere would be comparing two trees. That is
        # an environment mismatch rather than a defect, hence a skip.
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
        effect of construction, which a test has no business doing to the
        working tree, so the attributes it sets -- ``NAME``, ``DOCS`` and
        ``record`` -- are set here instead.

        """
        vendor = self.vendor_module.Socket.__new__(self.vendor_module.Socket)
        vendor.NAME = self.vendor_module.Socket.__name__
        vendor.DOCS = self.vendor_module.Socket.__doc__
        data = vendor.request()
        vendor.record = vendor.count(data)
        return vendor

    def test_link_is_none_so_nothing_is_fetched(self) -> None:
        # No LINK, stated as an assertion: Vendor._request() short-circuits to
        # Socket.request() and never reaches requests.get(), which is what
        # takes the 403.
        self.assertIsNone(self.vendor_module.Socket.LINK)

    def test_request_makes_no_network_call(self) -> None:
        import requests

        def explode(*args: 'Any', **kwargs: 'Any') -> 'Any':
            raise AssertionError(f'the crawler made a network call: {args!r}')

        original_get, original_request = requests.get, requests.Session.request
        requests.get = explode  # type: ignore[assignment]
        requests.Session.request = explode  # type: ignore[assignment,method-assign]
        try:
            vendor = self.vendor_module.Socket.__new__(self.vendor_module.Socket)
            vendor.NAME = self.vendor_module.Socket.__name__
            vendor.DOCS = self.vendor_module.Socket.__doc__
            self.assertIs(vendor._request(), self.vendor_module.DATA)  # pylint: disable=protected-access
        finally:
            requests.get = original_get  # type: ignore[assignment]
            requests.Session.request = original_request  # type: ignore[method-assign]

    def test_regeneration_reproduces_the_committed_constant_file(self) -> None:
        # The guard that makes the hand-maintained table trustworthy: running
        # the crawler must be a no-op against what is checked in, so an edit to
        # DATA that was never regenerated shows up here.
        vendor = self._vendor()
        generated = _normalize(vendor.context(vendor.request()))
        committed = (ROOT / 'pcapkit' / 'const' / 'ipx' / 'socket.py').read_text(encoding='utf-8')
        self.assertEqual(generated, committed,
                         'regenerating pcapkit/const/ipx/socket.py would change it; run '
                         '`python -m pcapkit.vendor.ipx.socket` and commit the result')

    def test_no_socket_is_lost(self) -> None:
        members = tuple((member.name, int(member.value)) for member in self.const_module.Socket)
        self.assertEqual(members, EXPECTED_MEMBERS)

    def test_registry_and_enumeration_agree(self) -> None:
        # Every hand-maintained row reaches the enumeration, and nothing in the
        # enumeration came from anywhere else.
        vendor = self._vendor()
        from_data = tuple(
            (vendor.rename(name, f'0x{code:04X}'), code)
            for code, (name, _) in self.vendor_module.DATA.items()
        )
        self.assertEqual(from_data, EXPECTED_MEMBERS)

    def test_unspecified_socket_survives_the_retirement(self) -> None:
        # The member GitHub issue #492 called for: 0x0000 is IPX's own
        # default for the dst/src socket field, and was never in the scraped
        # table at all.
        self.assertEqual(self.const_module.Socket(0x0000), self.const_module.Socket.Unspecified)
        self.assertEqual(self.const_module.Socket(0x0000).value, 0)
        self.assertIn(0x0000, self.vendor_module.DATA)

    def test_range_order_is_preserved(self) -> None:
        self.assertEqual(tuple(self.vendor_module.RANGES), EXPECTED_RANGES)

    def test_previously_shadowed_ranges_are_reachable(self) -> None:
        # GitHub issue #841: with each wider range listed first, these values
        # would resolve as the range that masks their own -- 0x0030 as
        # 'Registered by Xerox_0x0030', 0x4080 and 0x8100 both as
        # 'Dynamically Assigned'. Pinned separately from
        # test_unlisted_sockets_still_resolve so the regression this issue
        # describes has a test that names it. The names are bare because
        # these ranges do not mint (GitHub issue #775).
        for value, name in (
            (0x0030, 'Experimental'),
            (0x4080, 'Dynamically Assigned Socket Numbers'),
            (0x8100, 'Statically Assigned Socket Numbers'),
        ):
            with self.subTest(socket=f'0x{value:04X}'):
                member = self.const_module.Socket(value)
                self.assertEqual(int(member), value)
                self.assertEqual(member.name, name)

    def test_unlisted_sockets_still_resolve(self) -> None:
        # _missing_ has to cover the whole 16-bit space, so no legal wire value
        # raises -- and it has to reach the branch it looks like it reaches.
        for value, name in EXPECTED_MISSING_NAMES.items():
            with self.subTest(socket=f'0x{value:04X}'):
                member = self.const_module.Socket(value)
                self.assertEqual(int(member), value)
                self.assertEqual(member.name, name)

    def test_out_of_range_sockets_are_rejected(self) -> None:
        for value in (-1, 0x10000):
            with self.subTest(socket=value):
                with self.assertRaises(ValueError):
                    self.const_module.Socket(value)


if __name__ == '__main__':
    unittest.main()
