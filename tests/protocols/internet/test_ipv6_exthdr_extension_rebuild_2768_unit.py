# -*- coding: utf-8 -*-
"""A whole IPv6 extension header rebuilds in the extension mode its parse used.

GitHub issue #2768: parsed with ``extension=True``, as
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` parses each header of its
chain, every extension header but ESP holds no next layer. ``from_data(info)``
rebuilt it without ``extension``, so its info gained ``__next_type__``,
``__next_name__`` and ``nopayload``, standalone and from the ``__exthdr__`` infos
of IPv6 alike.
:meth:`Internet.from_data <pcapkit.protocols.internet.internet.Internet.from_data>`
rebuilds a header whose data model holds no next layer with ``extension``.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round trips, one header per class.
__tier__ = 'ALL'

#: IPv6 Next Header code of each member of the family, as IANA's IPv6 Extension
#: Header Types registry assigns it. IPv6 reaches ``IPv6_Ext`` only as Shim6 (140),
#: whose code it hands over as ``alias``, which the rebuild does not replay
#: (#2768), so ``IPv6_Ext`` is rebuilt here only standalone.
CODES = {
    'HOPOPT': 0,
    'IPv6_Route': 43,
    'IPv6_Frag': 44,
    'ESP': 50,
    'AH': 51,
    'IPv6_Opts': 60,
    'MH': 135,
    'HIP': 139,
}


class TestExtensionModeRebuild(unittest.TestCase):
    """Pin ``from_data(info).info == info`` for a header parsed with ``extension``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _family() -> 'dict[str, Any]':
        """``IPv6_Ext`` and every class beneath it, every member module imported first."""
        from pcapkit.protocols import internet
        from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext

        # NOTE: the package imports each protocol on first use (#2730).
        for name in internet.__all__:
            getattr(internet, name)
        found = {'IPv6_Ext': IPv6_Ext}  # type: dict[str, Any]
        stack = list(IPv6_Ext.__subclasses__())
        while stack:
            klass = stack.pop()
            if klass.__name__ not in found:
                found[klass.__name__] = klass
                stack.extend(klass.__subclasses__())
        return found

    @staticmethod
    def _header(klass: 'Any') -> bytes:
        """A whole header of ``klass``, followed by No Next Header."""
        extra = {'data': bytes(6)} if klass.__name__ == 'IPv6_Ext' else {}
        return klass(next=59, **extra).data

    def _assert_rebuilds(self, klass: 'Any', info: 'Any', data: bytes) -> None:
        """``klass`` rebuilds ``info`` and ``data`` from ``info`` and its dict alike."""
        for source, value in (('info', info), ('to_dict', info.to_dict())):
            with self.subTest(source=source):
                rebuilt = klass.from_data(value)
                self.assertEqual(rebuilt.info, info)
                self.assertEqual(rebuilt.data, data)

    def test_every_member_has_a_code(self) -> None:
        self.assertEqual(set(self._family()) - {'IPv6_Ext'}, set(CODES))

    def test_standalone_header_rebuilds_its_info(self) -> None:
        for name, klass in sorted(self._family().items()):
            with self.subTest(header=name):
                header = self._header(klass)
                self._assert_rebuilds(klass, klass(header, extension=True).info, header)

    def test_chain_header_rebuilds_its_info(self) -> None:
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        family = self._family()
        for name, code in sorted(CODES.items()):
            with self.subTest(header=name):
                klass = family[name]
                header = self._header(klass)
                built = IPv6(next=code, src='2001:db8::1', dst='2001:db8::2', payload=header)
                ((proto, info),) = IPv6(built.data).info['__exthdr__']
                self.assertIs(proto, klass)
                self._assert_rebuilds(klass, info, header)

    def test_header_parsed_alone_keeps_its_next_layer(self) -> None:
        for name, klass in sorted(self._family().items()):
            with self.subTest(header=name):
                header = self._header(klass)
                parsed = klass(header)
                self.assertIn('__next_type__', parsed.info)
                self._assert_rebuilds(klass, parsed.info, header)

    def test_keywords_override_the_replayed_mode(self) -> None:
        for name, klass in sorted(self._family().items()):
            with self.subTest(header=name):
                parsed = klass(self._header(klass), extension=True)
                self.assertIn('__next_type__', klass.from_data(parsed.info, extension=False).info)


if __name__ == '__main__':
    unittest.main()
