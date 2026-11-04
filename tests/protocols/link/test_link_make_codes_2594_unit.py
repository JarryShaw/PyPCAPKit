# -*- coding: utf-8 -*-
"""GitHub issue #2594: the link makers take an enumeration field as a member or a code.

Each enumeration field of the ARP, Ethernet, GRE, L2TPv2, VLAN tag and Linux
cooked-capture makers goes through
:meth:`~pcapkit.protocols.protocol.Protocol._make_index`, which resolves a member
or an :class:`int` with the enumeration's ``get``. A name is refused rather than
resolved against an enumeration inferred from the caller's frame, and so are a
:obj:`bool` for a field wider than one bit and a code that does not fit the field
(#2617), where a maker wrote ``1`` for :data:`True` and a 16-bit field wrapped a
code too wide for it. Every refusal is a
:exc:`~pcapkit.utilities.exceptions.ProtocolError`.

``ROWS`` holds one row per class and field, the VLAN maker under both of its tags;
``test_every_enumeration_argument_has_a_row`` finds the enumeration arguments from
the maker signatures, so an argument added to a maker needs a row. A caller holding a name resolves it first, with
:meth:`~pcapkit.protocols.protocol.Protocol.resolve_index`.

Every case builds its own octets in memory and reads no capture. The classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import inspect
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


class Row(NamedTuple):
    """One enumeration field of one maker."""

    #: ``(module, class)`` of the protocol whose ``make()`` is called.
    cls: 'tuple[str, str]'
    #: The argument of ``make()``; ``tci.pcp`` is the ``pcp`` of the ``tci`` argument.
    field: 'str'
    #: ``(module, class)`` of the enumeration the field holds.
    enum: 'tuple[str, str]'
    #: Width of the field on the wire, in bits.
    bits: 'int'
    #: The member built with; not the argument's default.
    member: 'str'
    #: Dotted path of the field in the parsed ``info``.
    info: 'str'
    #: Other arguments the member needs to build.
    extra: 'dict[str, Any]' = {}


ARP = ('pcapkit.protocols.link.arp.protocol', 'ARP')
ETHERNET = ('pcapkit.protocols.link.ethernet.protocol', 'Ethernet')
GRE = ('pcapkit.protocols.link.gre.protocol', 'GRE')
L2TPV2 = ('pcapkit.protocols.link.l2tpv2.protocol', 'L2TPv2')
C_TAG = ('pcapkit.protocols.link.c_tag.protocol', 'C_Tag')
S_TAG = ('pcapkit.protocols.link.s_tag.protocol', 'S_Tag')
LINUX_SLL1 = ('pcapkit.protocols.link.linux_sll1.protocol', 'LinuxSLL1')
LINUX_SLL2 = ('pcapkit.protocols.link.linux_sll2.protocol', 'LinuxSLL2')

HARDWARE = ('pcapkit.const.arp.hardware', 'Hardware')
OPERATION = ('pcapkit.const.arp.operation', 'Operation')
ETHERTYPE = ('pcapkit.const.reg.ethertype', 'EtherType')
L2TP_TYPE = ('pcapkit.const.l2tp.type', 'Type')
PRIORITY = ('pcapkit.const.vlan.priority_level', 'PriorityLevel')

#: LLDP, an EtherType no layer is registered for, so the payload parses as nothing.
LLDP = 'IEEE_Std_802_1AB_Link_Layer_Discovery_Protocol'

#: Widths from each schema, as RFC 826, IEEE 802.3, RFC 2784, RFC 2661 section
#: 3.1, IEEE 802.1Q and the tcpdump ``LINKTYPE_LINUX_SLL``/``SLL2`` pages give them.
ROWS = (
    Row(ARP, 'htype', HARDWARE, 16, 'Frame_Relay', 'htype'),
    Row(ARP, 'ptype', ETHERTYPE, 16, 'Internet_Protocol_version_6', 'ptype',
        {'spa': '2001:db8::1', 'tpa': '2001:db8::2'}),
    Row(ARP, 'oper', OPERATION, 16, 'REPLY', 'oper'),
    Row(ETHERNET, 'type', ETHERTYPE, 16, LLDP, 'type'),
    Row(GRE, 'protocol_type', ETHERTYPE, 16, LLDP, 'protocol_type'),
    Row(L2TPV2, 'type', L2TP_TYPE, 1, 'Control', 'flags.type'),
    Row(C_TAG, 'pcp', PRIORITY, 3, 'VO', 'tci.pcp'),
    Row(C_TAG, 'tci.pcp', PRIORITY, 3, 'VO', 'tci.pcp'),
    Row(C_TAG, 'type', ETHERTYPE, 16, LLDP, 'type'),
    Row(S_TAG, 'pcp', PRIORITY, 3, 'VO', 'tci.pcp'),
    Row(S_TAG, 'tci.pcp', PRIORITY, 3, 'VO', 'tci.pcp'),
    Row(S_TAG, 'type', ETHERTYPE, 16, LLDP, 'type'),
    Row(LINUX_SLL1, 'arphrd_type', HARDWARE, 16, 'Frame_Relay', 'arphrd_type'),
    Row(LINUX_SLL1, 'protocol_type', ETHERTYPE, 16, LLDP, 'protocol_type'),
    Row(LINUX_SLL2, 'arphrd_type', HARDWARE, 16, 'Frame_Relay', 'arphrd_type'),
    Row(LINUX_SLL2, 'protocol_type', ETHERTYPE, 16, LLDP, 'protocol_type'),
)


def load(path: 'tuple[str, str]') -> 'Any':
    """The attribute ``path`` names, imported afresh."""
    return getattr(importlib.import_module(path[0]), path[1])


def arguments(row: 'Row', value: 'Any') -> 'dict[str, Any]':
    """The arguments of ``make()`` that give ``row``'s field ``value``."""
    if row.field == 'tci.pcp':
        return {'tci': {'pcp': value, 'dei': False, 'vid': 0}, **row.extra}
    return {row.field: value, **row.extra}


class TestLinkMakeCodes(unittest.TestCase):
    """Pin how each link maker takes its enumeration fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def build(self, row: 'Row', value: 'Any') -> 'bytes':
        """The octets ``row``'s maker builds with ``value`` for its field."""
        return load(row.cls)(**arguments(row, value)).data

    def test_a_code_wider_than_the_field_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for row in ROWS:
            with self.subTest(cls=row.cls[1], field=row.field, code=1 << row.bits):
                with self.assertRaises(ProtocolError):
                    self.build(row, 1 << row.bits)

    def test_a_bool_is_refused_for_a_wider_field(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        rows = [row for row in ROWS if row.bits > 1]
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(cls=row.cls[1], field=row.field):
                with self.assertRaises(ProtocolError):
                    self.build(row, True)

    def test_a_name_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for row in ROWS:
            with self.subTest(cls=row.cls[1], field=row.field, name=row.member):
                with self.assertRaises(ProtocolError):
                    self.build(row, row.member)

    def test_the_member_and_its_code_build_the_same_octets(self) -> None:
        for row in ROWS:
            member = getattr(load(row.enum), row.member)
            with self.subTest(cls=row.cls[1], field=row.field, member=member):
                made = self.build(row, member)
                self.assertEqual(made, self.build(row, int(member)))

                # the octets carry the member's code, read back from the field
                parsed = load(row.cls)(made, len(made))
                value = parsed.info
                for part in row.info.split('.'):
                    value = getattr(value, part)
                self.assertEqual(int(value), int(member))

    def test_every_enumeration_argument_has_a_row(self) -> None:
        """Found from the signatures, with no ``_default``, ``_namespace`` or ``_reversed`` left."""
        for path in sorted({row.cls for row in ROWS}):
            params = inspect.signature(load(path).make).parameters
            with self.subTest(cls=path[1]):
                found = {name for name, param in params.items()
                         if str(param.annotation).startswith('Enum_')}
                rows = {row.field for row in ROWS if row.cls == path and row.field != 'tci.pcp'}
                self.assertEqual(found, rows)
                self.assertEqual([name for name in params
                                  if name.endswith(('_default', '_namespace', '_reversed'))], [])


if __name__ == '__main__':
    unittest.main()
