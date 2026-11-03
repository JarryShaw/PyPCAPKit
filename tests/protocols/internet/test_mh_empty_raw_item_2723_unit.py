# -*- coding: utf-8 -*-
"""An MH option, sub-option, QoS attribute or CGA extension given as empty raw octets is refused.

GitHub issue #2723: the MH makers that take raw octets in a list --
``_make_mh_options``, ``_make_fid_suboptions``, ``_make_ani_suboptions``,
``_make_qos_attributes``, ``_make_lcmp_suboptions`` and ``_make_cga_extensions``
-- kept an empty item as it was. Packed, it adds no octets, so the header parsed
back held nothing in its place: alone, it reached ``read()`` as a schema and
raised a bare ``AttributeError``, or, for the access network identifier and
LMA-controlled MAG sub-options, failed as an option of length 0; beside a whole
item it was dropped. Empty octets raise ``ProtocolError``, as the
other malformed items in those branches do, wherever in the list they sit.

A whole raw item builds as given. Each case asserts it against
:rfc:`6275#section-6.2.1`: an option's Option Length counts the octets after
its own two, so a sub-option or attribute ends its option and lengthens it by
its own size. A raw CGA extension builds the octets its ``(type, kwargs)`` pair
does.

Every case builds its own octets in memory and reads no capture. :class:`MH`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: A PadN option carrying no padding octets.
PADN = b'\x01\x00'
#: A sub-option or attribute of the unassigned type 200, carrying ``ab``.
ITEM = b'\xc8\x02ab'
#: A CGA extension of the unassigned type 1, carrying ``ab``.
EXTENSION = b'\x00\x01\x00\x02ab'
#: The octets of the fixed MH header and of a Binding Refresh Request.
HEADER = 8


def _build(options: 'list[Any]') -> 'bytes':
    """The octets of a Binding Refresh Request carrying ``options``."""
    from pcapkit.const.mh.packet import Packet
    from pcapkit.protocols.internet.mh import MH

    return MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00',
              data={'options': options}).data


def _lists() -> 'list[tuple[str, Any, str, str]]':
    """Each sub-list as its label, its option type, its keyword and its item noun."""
    from pcapkit.const.mh.option import Option

    return [
        ('FID', Option.Flow_Identification_Mobility_Option, 'suboptions', 'sub-option'),
        ('ANI', Option.Access_Network_Identifier, 'suboptions', 'sub-option'),
        ('QoS', Option.Quality_of_Service, 'attributes', 'attribute'),
        ('LCMP', Option.LMA_Controlled_MAG_Parameters, 'suboptions', 'sub-option'),
    ]


def _cga_fields() -> 'dict[str, Any]':
    """The fields of one CGA parameter, but its extensions."""
    from pcapkit.const.mh.cga_type import CGAType

    return {
        'modifier': CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
        'prefix': 0x20010db800000000,
        'collision_count': 0,
        'public_key': b'\x30\x02\xaa\xbb',
    }


def _cga_schema(extensions: 'list[Any]') -> 'Any':
    """A CGA parameter schema carrying ``extensions``."""
    from pcapkit.protocols.schema.internet.mh import CGAParameter

    return CGAParameter(extensions=extensions, public_key_test={'len': 2}, **_cga_fields())


class TestMHEmptyRawItem(unittest.TestCase):
    """Empty raw octets raise ``ProtocolError``; a whole raw item builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_option_is_refused(self) -> None:
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        for options in ([b''], [PADN, b''], [b'', PADN]):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ProtocolError, r"invalid option: b'' holds no type octet"):
                    MH(data={'options': options})

    def test_empty_sub_item_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for label, option, keyword, noun in _lists():
            for items in ([b''], [ITEM, b''], [b'', ITEM]):
                with self.subTest(option=label, items=items):
                    with self.assertRaisesRegex(ProtocolError, rf"invalid {noun}: b'' holds no type octet"):
                        _build([(option, {keyword: items})])

    def test_empty_cga_extension_is_refused(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.data.internet.mh import CGAParameter
        from pcapkit.utilities.exceptions import ProtocolError

        parameters = {
            'schema': _cga_schema([b'']),
            'schema beside a whole one': _cga_schema([EXTENSION, b'']),
            'data model': CGAParameter(extensions=[b''], **_cga_fields()),
        }
        for label, parameter in parameters.items():
            with self.subTest(parameter=label):
                with self.assertRaisesRegex(ProtocolError, r"invalid CGA extension: b'' holds no type field"):
                    _build([(Option.CGA_Parameters, {'parameters': [parameter]})])

    def test_whole_option_builds_as_given(self) -> None:
        built = _build([PADN])
        self.assertEqual(built[HEADER:HEADER + len(PADN)], PADN)

    def test_whole_sub_item_builds_as_given(self) -> None:
        for label, option, keyword, _ in _lists():
            with self.subTest(option=label):
                # ANI and LCMP options need a sub-option, so one item is the base.
                one = _build([(option, {keyword: [ITEM]})])
                built = _build([(option, {keyword: [ITEM, ITEM]})])
                self.assertEqual(built[HEADER], option)
                self.assertEqual(built[HEADER + 1], one[HEADER + 1] + len(ITEM))
                end = HEADER + 2 + built[HEADER + 1]
                self.assertEqual(built[end - 2 * len(ITEM):end], ITEM * 2)

    def test_whole_cga_extension_builds_as_its_pair(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.data.internet.mh import CGAParameter

        raw = _build([(Option.CGA_Parameters, {'parameters': [_cga_schema([EXTENSION])]})])
        pair = _build([(Option.CGA_Parameters, {'parameters': [
            CGAParameter(extensions=[(1, {'data': b'ab'})], **_cga_fields())]})])
        self.assertEqual(raw, pair)
        self.assertIn(EXTENSION, raw)


if __name__ == '__main__':
    unittest.main()
