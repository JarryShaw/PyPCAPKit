# -*- coding: utf-8 -*-
"""The MH CGA Parameters option maker neither takes nor advertises a mapping.

GitHub issue #2708: the annotation of ``parameters`` on
:meth:`MH._make_opt_cga_param <pcapkit.protocols.internet.mh.protocol.MH._make_opt_cga_param>`
names the forms the maker builds, octets, a schema and a data model, and no
mapping, which raises ``ProtocolError``. A mapping given to a maker stands for
some maker's keyword arguments, and no maker takes a CGA parameter's fields. A
parse gives each parameter as a data model, which
:meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` leaves intact
inside the option's tuple, so whatever parses still builds.

Every case builds its own octets in memory and reads no capture. :class:`MH`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import inspect
import unittest

from tests._support import reimport_once_per_class


def _fields() -> 'dict[str, object]':
    """Return the fields of one CGA parameter, as its data model takes them."""
    from pcapkit.const.mh.cga_type import CGAType

    return {
        'modifier': CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
        'prefix': 0x20010db800000000,
        'collision_count': 0,
        'public_key': b'\x30\x02\xaa\xbb',
        'extensions': [],
    }


class TestMHCGAParamDict(unittest.TestCase):
    """A CGA parameter is octets, a schema or a data model, and never a mapping."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_annotation_names_no_mapping(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH

        annotation = inspect.signature(MH._make_opt_cga_param).parameters['parameters'].annotation
        self.assertIsInstance(annotation, str)
        self.assertNotIn('dict', annotation)
        for name in ('Schema_CGAParameter', 'Data_CGAParameter', 'bytes'):
            with self.subTest(name=name):
                self.assertIn(name, annotation)

    def test_mapping_is_refused(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'unknown CGA parameter format'):
            MH()._make_opt_cga_param(Option.CGA_Parameters, parameters=[_fields()])

    def test_data_model_of_the_same_fields_round_trips(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh.data import CGAParameter
        from pcapkit.protocols.internet.mh.protocol import MH

        built = MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00', data={
            'options': [(Option.CGA_Parameters, {'parameters': [CGAParameter(**_fields())]})],
        })
        parsed = MH(built.data)
        (option,) = parsed.info.options.getlist(Option.CGA_Parameters)
        # 25 octets of modifier, prefix and collision count, then the key.
        self.assertEqual(option.length, 2 + 25 + 4)
        self.assertIsInstance(option.to_dict()['parameters'][0], CGAParameter)
        self.assertEqual(MH.from_data(parsed.info).data, built.data)


if __name__ == '__main__':
    unittest.main()
