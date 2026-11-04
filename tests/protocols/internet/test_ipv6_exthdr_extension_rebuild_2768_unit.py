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

Shim6, which :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext` parses,
also lost the ``protocol`` its ``read`` takes from the ``alias`` keyword. Its
``_make_data`` hands ``alias`` back, and its ``__keywords__`` lets the keyword
through the construction check, which every member then accepts and drops.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round trips, one header per class.
__tier__ = 'ALL'

#: IPv6 Next Header code of each member of the family, as IANA's IPv6 Extension
#: Header Types registry assigns it; ``IPv6_Ext`` parses Shim6. IPv6 hands each
#: header its code as ``alias``, and the standalone parses here do the same.
CODES = {
    'HOPOPT': 0,
    'IPv6_Route': 43,
    'IPv6_Frag': 44,
    'ESP': 50,
    'AH': 51,
    'IPv6_Opts': 60,
    'MH': 135,
    'HIP': 139,
    'IPv6_Ext': 140,
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
        """``klass`` rebuilds ``info`` and ``data`` from ``info`` and its dict alike.

        A keyword ``_make_data`` returns that no signature declares is warned of
        and fails the case too.

        """
        from pcapkit.utilities.warnings import UnknownFieldWarning

        for source, value in (('info', info), ('to_dict', info.to_dict())):
            with self.subTest(source=source):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    rebuilt = klass.from_data(value)
                self.assertEqual([str(item.message) for item in caught
                                  if issubclass(item.category, UnknownFieldWarning)], [])
                self.assertEqual(rebuilt.info, info)
                self.assertEqual(rebuilt.data, data)

    def test_every_member_has_a_code(self) -> None:
        self.assertEqual(set(self._family()), set(CODES))

    def test_standalone_header_rebuilds_its_info(self) -> None:
        for name, klass in sorted(self._family().items()):
            with self.subTest(header=name):
                header = self._header(klass)
                parsed = klass(header, extension=True, alias=CODES[name])
                self._assert_rebuilds(klass, parsed.info, header)

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
                parsed = klass(header, alias=CODES[name])
                self.assertIn('__next_type__', parsed.info)
                self._assert_rebuilds(klass, parsed.info, header)

    def test_keywords_override_the_replayed_mode(self) -> None:
        for name, klass in sorted(self._family().items()):
            with self.subTest(header=name):
                parsed = klass(self._header(klass), extension=True, alias=CODES[name])
                self.assertIn('__next_type__', klass.from_data(parsed.info, extension=False).info)

    def test_shim6_keeps_its_protocol(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext

        header = self._header(IPv6_Ext)
        parsed = IPv6_Ext(header, extension=True, alias=CODES['IPv6_Ext'])  # type: Any
        self.assertIs(parsed.info.protocol, ExtensionHeader.Shim6)
        for source, value in (('info', parsed.info), ('to_dict', parsed.info.to_dict())):
            with self.subTest(source=source):
                self.assertIs(IPv6_Ext.from_data(value).info.protocol, ExtensionHeader.Shim6)

    def test_a_member_accepts_and_drops_alias(self) -> None:
        from pcapkit.utilities.warnings import UnknownFieldWarning

        for name, klass in sorted(self._family().items()):
            if name == 'IPv6_Ext':
                continue
            with self.subTest(header=name):
                with warnings.catch_warnings():
                    warnings.simplefilter('error', UnknownFieldWarning)
                    built = klass(next=59, alias=CODES['IPv6_Ext'])
                self.assertEqual(built.data, self._header(klass))
                self.assertEqual(built.info, klass(next=59).info)


if __name__ == '__main__':
    unittest.main()
