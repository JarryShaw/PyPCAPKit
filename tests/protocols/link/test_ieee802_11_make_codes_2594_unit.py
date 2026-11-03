# -*- coding: utf-8 -*-
"""IEEE 802.11 ``make()`` takes a type and a subtype as a member or a code (GitHub issue #2594).

Owner's ruling (#2593, #2594), paraphrased: a ``make()`` field holding an enumeration
takes the member or an :class:`int`, resolved with the enumeration's ``get``, and no
maker takes a ``*_default``, ``*_namespace`` or ``*_reversed`` keyword. #2617: a code
the field cannot carry, or a :obj:`bool` for a field wider than
one bit, raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`.

:data:`ROWS` holds the Frame Control type, then the subtype once per type, since the
subtype resolves against the registry the type selects. Every case builds its own
frame in memory and reads no capture.

"""

import importlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: ``(label, keyword, enumeration, bits, member, the other keywords)``.
ROWS = (
    ('type', 'type', 'pcapkit.const.ieee802_11.type.Type', 2, 'Control',
     {'subtype': 13}),
    ('subtype/Management', 'subtype', 'pcapkit.const.ieee802_11.management_subtype.ManagementSubtype', 4,
     'Beacon', {'type': 0}),
    ('subtype/Control', 'subtype', 'pcapkit.const.ieee802_11.control_subtype.ControlSubtype', 4,
     'ACK', {'type': 1}),
    ('subtype/Data', 'subtype', 'pcapkit.const.ieee802_11.data_subtype.DataSubtype', 4,
     'QoS_Data', {'type': 2}),
    ('subtype/Extension', 'subtype', 'pcapkit.const.ieee802_11.extension_subtype.ExtensionSubtype', 4,
     'S1G_Beacon', {'type': 3}),
)  # type: tuple[tuple[str, str, str, int, str, dict[str, Any]], ...]


def _attr(path: 'str') -> 'Any':
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


class TestIEEE802_11MakeCodes(unittest.TestCase):
    """``type`` and ``subtype`` refuse what their field cannot carry."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _build(self, **kwargs: 'Any') -> 'bytes':
        return _attr('pcapkit.protocols.link.ieee802_11.IEEE802_11')(**kwargs).data

    def test_refusals(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        for label, keyword, enum_path, bits, member, extra in ROWS:
            for value in (1 << bits, True, member):
                with self.subTest(row=label, value=value):
                    with self.assertRaisesRegex(exc, rf'^802\.11: invalid {keyword}: '):
                        self._build(**extra, **{keyword: value})

    def test_member_and_code_build_the_same(self) -> None:
        for label, keyword, enum_path, _, member, extra in ROWS:
            with self.subTest(row=label):
                value = getattr(_attr(enum_path), member)
                built = self._build(**extra, **{keyword: value})
                self.assertEqual(self._build(**extra, **{keyword: int(value)}), built)
                self.assertNotEqual(self._build(**extra), built)

    def test_removed_keywords_are_refused(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.UnsupportedCall')
        for field in ('type', 'subtype'):
            for suffix, value in (('default', 0), ('namespace', {0: 'X'}), ('reversed', True)):
                with self.subTest(keyword=f'{field}_{suffix}'):
                    with self.assertRaises(exc):
                        self._build(**{f'{field}_{suffix}': value})


if __name__ == '__main__':
    unittest.main()
