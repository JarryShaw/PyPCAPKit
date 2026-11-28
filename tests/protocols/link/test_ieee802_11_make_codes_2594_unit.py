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

The checks the ``*_make_codes_2594`` modules share run from
:class:`~tests.protocols._make_codes.MakeCodeChecks` over this module's own table (#3148).

"""

import importlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.protocols._make_codes import Case, MakeCodeChecks

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


class TestIEEE802_11MakeCodes(MakeCodeChecks, unittest.TestCase):
    """``type`` and ``subtype`` refuse what their field cannot carry."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _build(self, **kwargs: 'Any') -> 'bytes':
        return _attr('pcapkit.protocols.link.ieee802_11.protocol.IEEE802_11').from_fields(**kwargs).data

    def cases(self) -> 'list[Case]':
        return [Case(label, bits, getattr(_attr(enum_path), member),
                     lambda value, keyword=keyword, extra=extra: self._build(**extra, **{keyword: value}),
                     f'802.11: invalid {keyword}: ', bare=lambda extra=extra: self._build(**extra))
                for label, keyword, enum_path, bits, member, extra in ROWS]

    def test_removed_keywords_are_refused(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.UnsupportedCall')
        for field in ('type', 'subtype'):
            for suffix, value in (('default', 0), ('namespace', {0: 'X'}), ('reversed', True)):
                with self.subTest(keyword=f'{field}_{suffix}'):
                    with self.assertRaises(exc):
                        self._build(**{f'{field}_{suffix}': value})


if __name__ == '__main__':
    unittest.main()
