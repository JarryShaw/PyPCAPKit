# -*- coding: utf-8 -*-
"""MH's makers take an enumeration field as a member or an ``int`` code.

GitHub issue #2594: each enumeration field of ``MH.make`` and of its message,
option and sub-option makers is resolved by ``Protocol._make_index`` with the
enumeration's ``get``. A name, a :obj:`bool` for a field wider than one bit,
and a code the field cannot carry raise ``ProtocolError`` naming the field
(#2617), and a member builds the same octets as its ``int`` code. A caller
holding a name resolves it with ``Protocol.resolve_index`` first. The widest
code each field carries builds, parses back and rebuilds as captured, as does
the parsed value given back to ``make``, also where no member holds it and the
enumeration's own range is narrower than the field.

The type of each option, sub-option, QoS attribute and CGA extension is such a
field too, given in a list of ``(type, kwargs)`` pairs or as the key of parsed
data: :data:`LIST_ROWS` holds one row per list maker, and a negative code joins
the refused values there.

Each row reaches its field the way a caller does: through ``MH.make``, with the
message as ``data`` and an option, sub-option or request in its list. Every case
builds its own octets in memory and reads no capture; the protocol classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel

import importlib
import inspect
import io
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: ``(label, kind, target, field, enumeration, member, bits, name, base)``, one
#: row per enumeration field. ``kind`` says how ``target`` is reached: the
#: header of ``make``, a message by its ``Packet`` name, an option by its
#: ``Option`` name, a Context Request entry, or a sub-option given as ``(option,
#: list argument, sub-option enumeration, sub-option)``. ``enumeration`` is
#: ``module:class``, ``bits`` the field's width in the schema, ``name`` the
#: field's name in the error message, and ``base`` the other arguments of the
#: message, option or sub-option.
ROWS = (
    ('make.next', 'header', None, 'next',
     'pcapkit.const.reg.transtype:TransType', 'UDP', 8, 'next header', {}),
    ('make.type', 'header', None, 'type',
     'pcapkit.const.mh.packet:Packet', 'Fast_Neighbor_Advertisement', 8, 'MH type', {}),
    # RFC 6275 section 6.1.8 and 6.1.9.
    ('_make_msg_ba.status', 'message', 'Binding_Acknowledgement', 'status',
     'pcapkit.const.mh.status_code:StatusCode', 'Accepted_but_prefix_discovery_necessary',
     8, 'status', {}),
    ('_make_msg_be.status', 'message', 'Binding_Error', 'status',
     'pcapkit.const.mh.binding_error:BindingError', 'Unrecognized_MH_Type_value',
     8, 'status', {}),
    # RFC 5568 section 6.2.3, 6.2.1.1 and 6.2.1.2.
    ('_make_msg_fback.status', 'message', 'Fast_Binding_Acknowledgment', 'status',
     'pcapkit.protocols.internet.mh:FastBindingAcknowledgmentStatus', 'Reason_unspecified',
     8, 'status', {}),
    ('_make_msg_hi.code', 'message', 'Handover_Initiate_Message', 'code',
     'pcapkit.const.mh.handover_initiate_status:HandoverInitiateStatus',
     'FBU_whose_source_IP_address_is_not_PCoA', 8, 'code', {}),
    ('_make_msg_hack.code', 'message', 'Handover_Acknowledge_Message', 'code',
     'pcapkit.const.mh.handover_ack_status:HandoverACKStatus',
     'Handover_Accepted_NCoA_not_valid', 8, 'code', {}),
    # RFC 5846 section 5.1 and 5.2: the octet after the B.R. Type draws from the
    # registry that type names.
    ('_make_msg_brm.br_type', 'message', 'Binding_Revocation_Message', 'br_type',
     'pcapkit.const.mh.binding_revocation:BindingRevocation',
     'Binding_Revocation_Acknowledgement', 8, 'binding revocation type', {}),
    ('_make_msg_brm.code (indication)', 'message', 'Binding_Revocation_Message', 'code',
     'pcapkit.const.mh.revocation_trigger:RevocationTrigger', 'Administrative_Reason',
     8, 'revocation trigger', {}),
    ('_make_msg_brm.code (acknowledgement)', 'message', 'Binding_Revocation_Message', 'code',
     'pcapkit.const.mh.revocation_status_code:RevocationStatusCode', 'partial_success',
     8, 'status', {'br_type': 2}),
    # RFC 6705 section 10.2.
    ('_make_msg_lra.status', 'message', 'Localized_Routing_Acknowledgment', 'status',
     'pcapkit.protocols.internet.mh:LocalizedRoutingStatus', 'MN_Not_Attached',
     8, 'status', {}),
    # RFC 7077 section 4.1 and 4.2; the notification reason is 16 bits.
    ('_make_msg_upn.reason', 'message', 'Update_Notification', 'reason',
     'pcapkit.const.mh.upn_reason:UpdateNotificationReason', 'UPDATE_SESSION_PARAMETERS',
     16, 'notification reason', {}),
    ('_make_msg_upa.status', 'message', 'Update_Notification_Acknowledgement', 'status',
     'pcapkit.const.mh.upa_status:UpdateNotificationACKStatus', 'Reason_unspecified',
     8, 'status', {}),
    # RFC 7109 section 6.1.1 and 6.1.2; the flow binding type is 16 bits.
    ('_make_msg_fbm.fb_type', 'message', 'Flow_Binding_Message', 'fb_type',
     'pcapkit.const.mh.fb_type:FlowBindingType', 'Acknowledgement',
     16, 'flow binding type', {}),
    ('_make_msg_fbm.code (indication)', 'message', 'Flow_Binding_Message', 'code',
     'pcapkit.const.mh.fb_indication_trigger:FlowBindingIndicationTrigger',
     'Administrative_Reason', 8, 'trigger', {}),
    ('_make_msg_fbm.code (acknowledgement)', 'message', 'Flow_Binding_Message', 'code',
     'pcapkit.const.mh.fb_ack_status:FlowBindingACKStatus', 'Binding',
     8, 'status', {'fb_type': 2}),
    # Options, each after the 8-octet Binding Refresh Request.
    ('_make_opt_mn_id.subtype', 'option', 'MN_ID_OPTION_TYPE', 'subtype',
     'pcapkit.const.mh.mn_id_subtype:MNIDSubtype', 'IPv6_Address', 8, 'MN-ID subtype', {}),
    ('_make_opt_auth.subtype', 'option', 'AUTH_OPTION_TYPE', 'subtype',
     'pcapkit.const.mh.auth_subtype:AuthSubtype', 'MN_AAA', 8, 'subtype',
     {'data': b'\xa5\xa5'}),
    ('_make_opt_ipv6_ap.code', 'option', 'Mobility_Header_IPv6_Address_Prefix', 'code',
     'pcapkit.protocols.internet.mh:IPv6AddressPrefixCode', 'NAR_Prefix', 8, 'code', {}),
    ('_make_opt_dns.status', 'option', 'DNS_UPDATE_TYPE', 'status',
     'pcapkit.const.mh.dns_status_code:DNSStatusCode', 'Reason_unspecified', 8, 'status', {}),
    ('_make_opt_hi.hi', 'option', 'Handoff_Indicator_Option', 'hi',
     'pcapkit.const.mh.handoff_type:HandoffType',
     'Handoff_between_two_different_interfaces_of_the_mobile_node', 8, 'handoff type', {}),
    ('_make_opt_att.att', 'option', 'Access_Technology_Type_Option', 'att',
     'pcapkit.const.mh.access_type:AccessType', 'IEEE_802_3', 8, 'access technology type', {}),
    ('_make_opt_ipv4_ack.status', 'option', 'IPv4_Address_Acknowledgement', 'status',
     'pcapkit.const.mh.dsmipv6_home_address:DSMIPv6HomeAddress', 'Failure_reason_unspecified',
     8, 'status', {}),
    ('_make_opt_bid.status', 'option', 'Binding_Identifier', 'status',
     'pcapkit.const.mh.status_code:StatusCode', 'Accepted_but_prefix_discovery_necessary',
     8, 'status', {}),
    ('_make_opt_ipv4_hoa_rep.status', 'option', 'IPv4_Home_Address_Reply', 'status',
     'pcapkit.const.mh.home_address_reply:HomeAddressReply', 'Failure_Reason_Unspecified',
     8, 'status', {}),
    # RFC 5844 section 3.4: the mode is the one-bit S flag.
    ('_make_opt_ipv4_dhcp.mode', 'option', 'IPv4_DHCP_Support_Mode', 'mode',
     'pcapkit.const.mh.dhcp_support_mode:DHCPSupportMode', 'S_flag', 1, 'DHCP support mode', {}),
    ('_make_opt_lmaa.code', 'option', 'Local_Mobility_Anchor_Address_Option', 'code',
     'pcapkit.protocols.internet.mh:LMAAddressCode', 'IPv4_LMAA', 8, 'code',
     {'address': '10.0.0.1'}),
    ('_make_opt_fid.status', 'option', 'Flow_Identification_Mobility_Option', 'status',
     'pcapkit.const.mh.flow_id_status:FlowIDStatus', 'Administratively_prohibited',
     8, 'status', {}),
    ('_make_opt_mn_group.subtype', 'option', 'Mobile_Node_Group_Identifier', 'subtype',
     'pcapkit.const.mh.mn_group_id:MNGroupID', 'Bulk_Binding_Update_Group',
     8, 'group identifier subtype', {}),
    ('_make_opt_mag_mp.att', 'option', 'MAG_Multipath_Binding', 'att',
     'pcapkit.const.mh.access_type:AccessType', 'IEEE_802_3', 8, 'access technology type', {}),
    ('_make_opt_mag_id.subtype', 'option', 'MAG_Identifier', 'subtype',
     'pcapkit.const.mh.mn_id_subtype:MNIDSubtype', 'IMSI', 8, 'MAG identifier subtype', {}),
    # RFC 5949 section 6.2.4: each Req-type is a mobility option type.
    ('_make_opt_cr.requests', 'request', 'Context_Request_Option', 'requests',
     'pcapkit.const.mh.option:Option', 'MN_ID_OPTION_TYPE', 8, 'request type', {}),
    # Sub-options, through the option that carries them.
    ('_make_fid_suboption.ts_format', 'suboption',
     ('Flow_Identification_Mobility_Option', 'suboptions',
      'pcapkit.const.mh.flow_id_suboption:FlowIDSuboption', 'Traffic_Selector'), 'ts_format',
     'pcapkit.const.mh.traffic_selector:TrafficSelector', 'IPv4_Binary_Traffic_Selector',
     8, 'TS format', {}),
    ('_make_fid_suboption.action', 'suboption',
     ('Flow_Identification_Mobility_Option', 'suboptions',
      'pcapkit.const.mh.flow_id_suboption:FlowIDSuboption', 'Flow_Binding_Action'), 'action',
     'pcapkit.const.mh.fb_action:FlowBindingAction', 'Delete', 8, 'action', {}),
    ('_make_ani_suboption.op_id_type', 'suboption',
     ('Access_Network_Identifier', 'suboptions',
      'pcapkit.const.mh.ani_suboption:ANISuboption', 'Operator_Identifier'), 'op_id_type',
     'pcapkit.const.mh.operator_id:OperatorID',
     'Operator_Identifier_as_a_variable_length_Private_Enterprise_Number', 8, 'Op-ID type', {}),
    ('_make_qos_attribute.ts_format', 'suboption',
     ('Quality_of_Service', 'attributes',
      'pcapkit.const.mh.qos_attribute:QoSAttribute', 'QoS_Traffic_Selector'), 'ts_format',
     'pcapkit.const.mh.traffic_selector:TrafficSelector', 'IPv4_Binary_Traffic_Selector',
     8, 'TS format', {}),
)

#: ``(maker, carrier, enumeration, member, bits, name)``, one row per list of
#: ``(type, kwargs)`` pairs. ``carrier`` is :data:`None` for the options of the
#: message, or the option and its list argument; ``CGA_Parameters`` carries
#: the extensions of its one CGA parameter. ``bits`` is the type's width in the
#: schema and ``name`` the field's name in the error message.
LIST_ROWS = (
    # RFC 6275 section 6.2.1: Option Type is 8 bits.
    ('_make_mh_options', None, 'pcapkit.const.mh.option:Option', 'Pad1', 8, 'option type'),
    # RFC 6089 section 4.2.1, RFC 6757 section 3.1, RFC 7222 section 4.2 and
    # RFC 8127 section 3.1: each sub-option or attribute type is 8 bits.
    ('_make_fid_suboptions', ('Flow_Identification_Mobility_Option', 'suboptions'),
     'pcapkit.const.mh.flow_id_suboption:FlowIDSuboption', 'BID_Reference', 8,
     'sub-option type'),
    ('_make_ani_suboptions', ('Access_Network_Identifier', 'suboptions'),
     'pcapkit.const.mh.ani_suboption:ANISuboption', 'Geo_Location', 8, 'sub-option type'),
    ('_make_qos_attributes', ('Quality_of_Service', 'attributes'),
     'pcapkit.const.mh.qos_attribute:QoSAttribute', 'Guaranteed_DL_Bit_Rate', 8,
     'attribute type'),
    ('_make_lcmp_suboptions', ('LMA_Controlled_MAG_Parameters', 'suboptions'),
     'pcapkit.const.mh.lma_mag_suboption:LMAControlledMAGSuboption', 'Heartbeat_Control', 8,
     'sub-option type'),
    # RFC 4581 section 2: the CGA Extension Type is 16 bits.
    ('_make_cga_extensions', ('CGA_Parameters', 'extensions'),
     'pcapkit.const.mh.cga_extension:CGAExtension', 'Multi_Prefix', 16, 'extension type'),
)

#: Rows the widest code cannot build and parse back through, and why.
WIDEST_EXEMPT = {
    # Closed enumerations: a parse refuses a code no member holds (#877, #2477).
    '_make_msg_fback.status', '_make_msg_lra.status', '_make_opt_ipv6_ap.code',
    # RFC 5949 section 6.2.2 ties each code to one address family (#2280).
    '_make_opt_lmaa.code',
}

#: Other arguments a row's widest code needs: an unassigned MN-ID subtype
#: carries its identifier as octets.
WIDEST_BASE = {
    '_make_opt_mn_id.subtype': {'identifier': b'\x01'},
}


def widest(row: 'tuple') -> 'tuple':
    """``row`` with the other arguments its widest code needs."""
    return (*row[:-1], {**row[-1], **WIDEST_BASE.get(row[0], {})})


def load(spec: 'str') -> 'type':
    """The class ``spec`` names as ``module:class``."""
    module, _, name = spec.partition(':')
    return getattr(importlib.import_module(module), name)


class MHMakeCodeTests(unittest.TestCase):
    """Each enumeration field of MH's makers, one row at a time."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _build(self, row: 'tuple', value: 'object') -> 'bytes':
        """The octets of an MH header whose ``row`` field is ``value``."""
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        _, kind, target, field, *_, base = row
        header = {'next': 59, 'type': Packet.Binding_Refresh_Request,
                  'chksum': b'\x00\x00', 'payload': b''}  # type: dict[str, object]
        if kind == 'header':
            header[field] = value
        elif kind == 'message':
            header.update(type=Packet[target], data={**base, field: value})
        elif kind == 'option':
            header['data'] = {'options': [(Option[target], {**base, field: value})]}
        elif kind == 'request':
            header['data'] = {'options': [(Option[target], {field: [(value, b'')]})]}
        else:
            option, key, sub_spec, sub = target
            header['data'] = {'options': [(Option[option], {
                key: [(load(sub_spec)[sub], {**base, field: value})]})]}
        return bytes(MH(**header))

    def _read(self, row: 'tuple', octets: 'bytes') -> 'object':
        """The ``row`` field as ``octets`` parse it back."""
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        _, kind, target, field, *_ = row
        info = MH(io.BytesIO(octets), len(octets), extension=True).info
        if kind in ('header', 'message'):
            return getattr(info, field)
        if kind != 'suboption':
            option = info.options[Option[target]]
            return option.requests[0].type if kind == 'request' else getattr(option, field)
        name, key, sub_spec, sub = target
        return getattr(getattr(info.options[Option[name]], key)[load(sub_spec)[sub]], field)

    def assertRefused(self, row: 'tuple', value: 'object') -> None:
        """The ``row`` field refuses ``value`` with a ProtocolError naming it."""
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            self._build(row, value)
        self.assertEqual(str(caught.exception), f'MH: invalid {row[7]}: {value!r}')

    def test_a_code_too_wide_for_its_field_is_refused(self) -> None:
        for row in ROWS:
            with self.subTest(row=row[0]):
                self.assertRefused(row, 1 << row[6])

    def test_a_bool_is_refused_for_a_field_wider_than_one_bit(self) -> None:
        for row in ROWS:
            with self.subTest(row=row[0]):
                if row[6] > 1:
                    self.assertRefused(row, True)
                else:
                    # A one-bit field takes a flag, as Protocol._make_uint lets it.
                    self.assertEqual(self._build(row, True), self._build(row, 1))

    def test_a_name_is_refused(self) -> None:
        for row in ROWS:
            with self.subTest(row=row[0]):
                self.assertRefused(row, row[5])

    def test_a_member_and_its_code_build_the_same_octets(self) -> None:
        for row in ROWS:
            member = load(row[4])[row[5]]
            with self.subTest(row=row[0]):
                octets = self._build(row, member)
                self.assertEqual(self._build(row, int(member)), octets)
                self.assertEqual(self._read(row, octets), member)

    def test_a_name_resolved_first_builds_the_members_octets(self) -> None:
        # The path the docstrings give a caller holding the name.
        from pcapkit.protocols.internet.mh import MH

        for row in ROWS:
            namespace = load(row[4])
            with self.subTest(row=row[0]):
                self.assertEqual(self._build(row, MH.resolve_index(row[5], namespace=namespace)),
                                 self._build(row, namespace[row[5]]))

    def test_the_widest_code_builds_parses_back_and_rebuilds(self) -> None:
        # #2594: the field width decides what is refused, so the widest code
        # builds, even where no member holds it.
        from pcapkit.protocols.internet.mh import MH

        for row in (widest(row) for row in ROWS if row[0] not in WIDEST_EXEMPT):
            code = (1 << row[6]) - 1
            with self.subTest(row=row[0], code=code):
                octets = self._build(row, code)
                self.assertEqual(int(self._read(row, octets)), code)  # type: ignore[call-overload]
                info = MH(io.BytesIO(octets), len(octets), extension=True).info
                rebuilt = bytes(MH(next=info.next, type=info.type, chksum=info.chksum,
                                   data=info, payload=b''))
                self.assertEqual(rebuilt.hex(), octets.hex())

    def test_a_parsed_code_builds_the_same_octets(self) -> None:
        # #2594: make() takes the value a parse hands back, also where no
        # member holds it, such as an UPN reason or FB type past 255.
        for row in (widest(row) for row in ROWS if row[0] not in WIDEST_EXEMPT):
            code = (1 << row[6]) - 1
            with self.subTest(row=row[0], code=code):
                octets = self._build(row, code)
                self.assertEqual(self._build(row, self._read(row, octets)).hex(), octets.hex())

    def test_the_binding_error_status_is_a_binding_error(self) -> None:
        # RFC 6275 section 6.1.9: the BE status draws from BindingError, the
        # registry its schema and data model hold, not from StatusCode.
        from pcapkit.const.mh.binding_error import BindingError
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        for value in (2, BindingError.Unrecognized_MH_Type_value):
            with self.subTest(value=value):
                schema = object.__new__(MH).make(next=59, type=Packet.Binding_Error,
                                                 chksum=b'\x00\x00', data={'status': value})
                status = schema['data']['status']
                self.assertIs(type(status), BindingError)
                self.assertEqual(status, BindingError.Unrecognized_MH_Type_value)

    def test_no_maker_takes_a_removed_keyword(self) -> None:
        """#2594: no maker's signature declares a ``*_default``, ``*_namespace`` or ``*_reversed`` keyword."""
        from pcapkit.protocols.internet.mh import MH

        for name in sorted(vars(MH)):
            if name != 'make' and not name.startswith('_make_'):
                continue
            func = getattr(MH, name)
            if not callable(func):
                continue
            for param in inspect.signature(func).parameters:
                with self.subTest(maker=name, argument=param):
                    self.assertFalse(param.endswith(('_default', '_namespace', '_reversed')))


class MHListTypeTests(unittest.TestCase):
    """The type of each item of an option, sub-option, attribute or extension list."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _octets(self, row: 'tuple', items: 'object') -> 'bytes':
        """The octets of an MH header carrying ``items`` in the ``row`` list."""
        from pcapkit.const.mh.cga_type import CGAType
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.data.internet.mh import CGAParameter
        from pcapkit.protocols.internet.mh import MH

        carrier = row[1]
        if carrier is None:
            options = items
        elif carrier[0] == 'CGA_Parameters':
            modifier = CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08  # type: Any
            param = CGAParameter(modifier=modifier, prefix=1, collision_count=1,
                                 public_key=b'\x30\x00', extensions=items)  # type: ignore[arg-type]
            options = [(Option.CGA_Parameters, {'parameters': [param]})]
        else:
            options = [(getattr(Option, carrier[0]), {carrier[1]: items})]
        return bytes(MH(next=59, type=Packet.Binding_Refresh_Request, chksum=b'\x00\x00',
                        payload=b'', data={'options': options}))

    def _parsed(self, row: 'tuple', octets: 'bytes') -> 'Any':
        """The ``row`` list as ``octets`` parse it back."""
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        info = MH(io.BytesIO(octets), len(octets), extension=True).info  # type: Any
        options = info.options
        carrier = row[1]
        if carrier is None:
            return options
        if carrier[0] == 'CGA_Parameters':
            return options[Option.CGA_Parameters].parameters[0].extensions
        return getattr(options[getattr(Option, carrier[0])], carrier[1])

    def _builders(self, row: 'tuple') -> 'dict[str, Any]':
        """A builder for each form the ``row`` list takes a type in."""
        from pcapkit.corekit.multidict import OrderedMultiDict

        octets = self._octets(row, [((1 << row[4]) - 1, {})])
        _, item = list(self._parsed(row, octets).items(multi=True))[0]
        return {
            'pair': lambda value: self._octets(row, [(value, {})]),
            'parsed': lambda value: self._octets(row, OrderedMultiDict([(value, item)])),
        }

    def assertRefused(self, row: 'tuple', build: 'Any', value: 'object') -> None:
        """``build(value)`` raises a ProtocolError naming the ``row`` field, and nothing else."""
        from pcapkit.utilities.exceptions import ProtocolError

        message = f'MH: invalid {row[5]}: {value!r}'
        try:
            octets = build(value)
        except ProtocolError as error:
            self.assertEqual(str(error), message)
        except Exception as error:  # pylint: disable=broad-except
            self.fail(f'{value!r} raised {type(error).__name__}: {error}; expected {message}')
        else:
            self.fail(f'{value!r} was accepted, building {octets.hex()}; expected {message}')

    def test_a_type_the_field_cannot_carry_is_refused(self) -> None:
        # #2594: a type checked as the field width checks it, before anything
        # reads it as a registry key or a padding code.
        for row in LIST_ROWS:
            for form, build in self._builders(row).items():
                for value in (1 << row[4], -1, True, row[3]):
                    with self.subTest(maker=row[0], form=form, value=value):
                        self.assertRefused(row, build, value)

    def test_the_widest_type_builds_parses_back_and_rebuilds(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        for row in LIST_ROWS:
            code = (1 << row[4]) - 1
            for form, build in self._builders(row).items():
                with self.subTest(maker=row[0], form=form):
                    octets = build(code)
                    # the options of the message end in the padding that aligns them
                    self.assertEqual(int(list(self._parsed(row, octets))[0]), code)
                    info = MH(io.BytesIO(octets), len(octets), extension=True).info
                    rebuilt = bytes(MH(next=info.next, type=info.type, chksum=info.chksum,
                                       data=info, payload=b''))
                    self.assertEqual(rebuilt.hex(), octets.hex())

    def test_a_member_and_its_code_build_the_same_octets(self) -> None:
        for row in LIST_ROWS:
            namespace = load(row[2])  # type: Any
            code = namespace.get((1 << row[4]) - 1)
            for form, build in self._builders(row).items():
                with self.subTest(maker=row[0], form=form):
                    self.assertEqual(build(code).hex(), build(int(code)).hex())


if __name__ == '__main__':
    unittest.main()
