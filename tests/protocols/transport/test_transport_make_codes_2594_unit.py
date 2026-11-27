# -*- coding: utf-8 -*-
"""The TCP and DCCP makers take an enumeration field as a member or a code (#2594).

Ruled in review of #2593 (#2489), and carried across the makers by #2594: a
maker's enumeration field takes the member or an :class:`int` code, resolved
with the enumeration's ``get``, and refuses a name rather than resolving it
against an enumeration inferred from the caller's frame. A caller holding a
name resolves it first, with :meth:`Protocol.resolve_index
<pcapkit.protocols.protocol.Protocol.resolve_index>`. Under #2617 a code the
field cannot carry, and a :obj:`bool` for a field wider than one bit, raise
:exc:`~pcapkit.utilities.exceptions.ProtocolError` too.

Each row of :data:`FIELDS` is one such field, reached the way a caller reaches
it: an option maker through ``options=``, a header field as a keyword of
``make()``, and the kind or type of each option in ``options=`` as the code of
its ``(code, args)`` tuple. The width is the field's own, from the schema and
the RFC. A parsed option list given back to ``make()`` has its keys checked as
those codes are.

Every case builds its own octets, so this belongs to the unit tier.

The checks the ``*_make_codes_2594`` modules share run from
:class:`~tests.protocols._make_codes.MakeCodeChecks` over this module's own table (#3148).

"""
from __future__ import annotations

import functools
import importlib
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import reimport_once_per_class
from tests.protocols._make_codes import Case, MakeCodeChecks

if TYPE_CHECKING:
    from typing import Any


class Field(NamedTuple):
    """An enumeration field of a maker."""

    #: The maker, as ``Class.method``; the class is the alias of its refusals.
    maker: 'str'
    #: The keyword the field is given by, in ``make()`` or the option's arguments.
    keyword: 'str'
    #: The enumeration, as ``module:Class`` under :mod:`pcapkit.const`.
    enum: 'str'
    #: A member of :attr:`enum` that the field carries.
    member: 'str'
    #: The width of the field, in bits.
    bits: 'int'
    #: The name of the field in the maker's refusal.
    name: 'str'


#: The fields, one row per maker and field. The widths: the TCP Alternate
#: Checksum Request ``Chksum`` octet (RFC 1146) and the 4-bit Multipath TCP
#: subtype (RFC 8684 section 3); the 4-bit DCCP Type and the one-octet Reset
#: Code (RFC 4340 sections 5.1 and 5.6), the one-octet Feature Number of
#: Change and Confirm (section 6), the 2-bit Ack Vector state (section 11.4)
#: and the 3-bit Data Dropped drop code (section 11.7); the one-octet TCP
#: option kind (RFC 9293 section 3.1) and DCCP option type (RFC 4340 section 5.8).
FIELDS = (
    Field('TCP._make_mode_chkreq', 'algorithm', 'tcp.checksum:Checksum',
          'Checksum_8_bit_Fletcher_s_algorithm', 8, '[OptNo 14] algorithm'),
    Field('TCP._make_mode_mp', 'subtype', 'tcp.mp_tcp_option:MPTCPOption', 'MP_PRIO', 4, '[OptNo 30] subtype'),
    Field('DCCP.make', 'type', 'dccp.packet_type:PacketType', 'DCCP_Ack', 4, 'type'),
    Field('DCCP.make', 'reset_code', 'dccp.reset_code:ResetCode', 'Option_Error', 8, 'reset code'),
    Field('DCCP._make_opt_change', 'feature', 'dccp.feature:Feature', 'Send_Ack_Vector', 8, '[Opt 32] feature'),
    Field('DCCP._make_opt_confirm', 'feature', 'dccp.feature:Feature', 'Send_Ack_Vector', 8, '[Opt 35] feature'),
    Field('DCCP._make_opt_ack_vector', 'state', 'dccp.ack_vector_state:AckVectorState',
          'Not_Yet_Received', 2, '[Opt 38] Ack Vector state'),
    Field('DCCP._make_opt_data_dropped', 'code', 'dccp.drop_code:DropCode', 'Corrupt', 3, '[Opt 40] drop code'),
    Field('TCP._make_tcp_options', 'kind', 'tcp.option:Option', 'No_Operation', 8, 'option kind'),
    Field('DCCP._make_dccp_options', 'type', 'dccp.option:Option', 'Slow_Receiver', 8, 'option type'),
)

#: The makers of :data:`FIELDS` that take an option list, as a parsed one is
#: given back to ``make()``.
OPTION_LISTS = ('TCP._make_tcp_options', 'DCCP._make_dccp_options')


class EnumerationFieldTests(MakeCodeChecks, unittest.TestCase):
    """Each field in :data:`FIELDS` takes a member or a code, and refuses the rest."""

    NEGATIVE = True

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    @staticmethod
    def enumeration(field: 'Field') -> 'Any':
        """The enumeration ``field`` holds."""
        module, name = field.enum.split(':')
        return getattr(importlib.import_module(f'pcapkit.const.{module}'), name)

    def cases(self) -> 'list[Case]':
        return [Case(f'{field.maker} {field.keyword}', field.bits, self.enumeration(field)[field.member],
                     functools.partial(self.build, field), f"{field.maker.split('.')[0]}: invalid {field.name}: ",
                     row=field) for field in FIELDS]

    @staticmethod
    def build(field: 'Field', value: 'Any') -> 'bytes':
        """The octets of a packet carrying ``value`` in ``field``."""
        from pcapkit.const.dccp.option import Option as DCCP_Option
        from pcapkit.const.dccp.packet_type import PacketType
        from pcapkit.const.tcp.option import Option as TCP_Option
        from pcapkit.protocols.transport.dccp.protocol import DCCP
        from pcapkit.protocols.transport.tcp.protocol import TCP

        def dccp_option(code: 'Any', args: 'dict[str, Any]') -> 'bytes':
            return DCCP.from_fields(type=PacketType.DCCP_Ack, ack=1, checksum=b'\x00\x00', options=[(code, args)]).data

        builders = {
            'TCP._make_mode_chkreq': lambda: TCP.from_fields(
                options=[(TCP_Option.TCP_Alternate_Checksum_Request, {'algorithm': value})]).data,
            # MP_PRIO takes an Address ID, and RFC 8684 section 3.3.8 an ACK.
            'TCP._make_mode_mp': lambda: TCP.from_fields(
                ack=True, options=[(TCP_Option.Multipath_TCP, {'subtype': value, 'addr_id': 1})]).data,
            'DCCP.make': lambda: DCCP.from_fields(**{'type': PacketType.DCCP_Reset, 'ack': 1, 'checksum': b'\x00\x00',
                                                     field.keyword: value}).data,
            'DCCP._make_opt_change': lambda: dccp_option(DCCP_Option.Change_L, {'feature': value, 'value': b'\x01'}),
            'DCCP._make_opt_confirm': lambda: dccp_option(DCCP_Option.Confirm_R, {'feature': value, 'value': b'\x01'}),
            'DCCP._make_opt_ack_vector': lambda: dccp_option(DCCP_Option.Ack_Vector_Nonce_0, {'vector': [(value, 3)]}),
            'DCCP._make_opt_data_dropped': lambda: dccp_option(DCCP_Option.Data_Dropped, {'vector': [(value, 2)]}),
            'TCP._make_tcp_options': lambda: TCP.from_fields(options=[(value, {})]).data,
            'DCCP._make_dccp_options': lambda: dccp_option(value, {}),
        }
        return builders[field.maker]()

    @staticmethod
    def build_list(field: 'Field', options: 'Any') -> 'bytes':
        """The octets of a packet carrying the option list ``options``."""
        from pcapkit.const.dccp.packet_type import PacketType
        from pcapkit.protocols.transport.dccp.protocol import DCCP
        from pcapkit.protocols.transport.tcp.protocol import TCP

        if field.maker == 'TCP._make_tcp_options':
            return TCP.from_fields(options=options).data
        return DCCP.from_fields(type=PacketType.DCCP_Ack, ack=1, checksum=b'\x00\x00', options=options).data

    def test_every_code_the_field_carries_is_taken(self) -> 'None':
        """The width is not too narrow: the widest code builds, as does zero.

        Where no member holds the code, as for TCP option kind 255, the code is
        written as given.

        """
        for field in FIELDS:
            for code in (0, (1 << field.bits) - 1):
                try:
                    resolved = self.enumeration(field).get(code)
                except ValueError:
                    resolved = code
                with self.subTest(maker=field.maker, field=field.keyword, code=code):
                    self.assertEqual(self.build(field, code), self.build(field, resolved))

    def test_a_parsed_option_list_has_its_keys_checked(self) -> 'None':
        """A parsed option list rebuilds as it was, and one keyed by a refused code is refused."""
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.transport.dccp.protocol import DCCP
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for case in self.cases():
            field = case.row
            if field.maker not in OPTION_LISTS:
                continue
            octets = case.build(case.member)
            parsed = (TCP if field.maker.startswith('TCP') else DCCP)(octets, len(octets)).info.options
            option = next(iter(parsed.items(multi=True)))[1]
            with self.subTest(maker=field.maker):
                self.assertEqual(self.build_list(field, parsed), octets)
                for value in self.refusals(case):
                    self.assertRefused(lambda value, field=field, option=option: self.build_list(
                        field, OrderedMultiDict([(value, option)])), value, case.message)


if __name__ == '__main__':
    unittest.main()
