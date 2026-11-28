# -*- coding: utf-8 -*-
"""The ``mh-message``, ``mh-option``, ``mh-extension``, ``mh-selector``,
``mh-qos-selector`` and ``mh-multicast`` families: Mobility Header messages,
options, extensions and the option payloads parsed through a registry of their
own (#2937).

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: Header fields shared by every constructed Mobility Header. ``next`` is
#: IPv6-NoNxt, so nothing downstream has to be constructed as well.
MH_BASE = {'next': 59, 'checksum': b'\x00\x00', 'payload': b''}


def _mh_message_registry() -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.__message__


def _mh_message_overrides() -> 'dict[Any, dict[str, Any]]':
    return {}


def _mh_message_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH

    # ``data`` has to be a mapping for ``make`` to dispatch on the message
    # type; a Data object takes the other branch, which is what rebuild uses.
    return MH.from_fields(type=code, data=dict(kwargs), **MH_BASE)


def _mh_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH(octets, len(octets), extension=True)


def _mh_message_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _mh_message_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.from_fields(type=message.type, data=message, **MH_BASE)


def _mh_option_registry() -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.__option__


def _mh_option_overrides() -> 'dict[Any, dict[str, Any]]':
    import ipaddress

    from pcapkit.const.mh.ani_suboption import ANISuboption as Enum_ANISuboption
    from pcapkit.const.mh.lma_mag_suboption import \
        LMAControlledMAGSuboption as Enum_LMAControlledMAGSuboption
    from pcapkit.const.mh.option import Option as Enum_Option
    return {
        # ``{}`` gives a valid zero-length PadN [RFC 6275 section 6.2.3]; a
        # non-zero length exercises the padding octets as well.
        Enum_Option.PadN: {'length': 4},
        # The authenticator has to be a multiple of 8 octets.
        Enum_Option.Authorization_Data: {'data': b'\xa5' * 8},
        Enum_Option.Mobility_Header_Link_Layer_Address_option: {
            'address': b'\x00\x11\x22\x33\x44\x55'},
        # ``(len + 6) % 4`` has to be 0.
        Enum_Option.AUTH_OPTION_TYPE: {'data': b'\xa5\xa5'},
        # Without this ``_make_opt_mesg_id`` reads the clock, and the capture
        # would differ on every regeneration.
        Enum_Option.MESG_ID_OPTION_TYPE: {'interval': generator.FIXED_TIME},
        Enum_Option.Signature: {'signature': b'\xaa' * 4},
        Enum_Option.Permanent_Home_Keygen_Token: {'token': b'\xbb' * 8},
        Enum_Option.Experimental_Mobility_Option: {'data': b'\xcc' * 4},
        Enum_Option.Binding_Authorization_Data_for_FMIPv6: {'data': b'\xb5'},
        # The entries below are not workarounds for defects: each option has a
        # minimum content its RFC requires, and the no-argument default is not a
        # well-formed instance of it. The constructors refuse it, correctly, so
        # the arguments here are what make the code reachable at all.
        #
        # ``Length`` of 0 "is not allowed" and the identifier is 1-255 octets
        # [RFC 5149 section 3]. ``'ims'`` is that RFC's own example.
        Enum_Option.Service_Selection_Mobility_Option: {'identifier': 'ims'},
        # "Both the 'K' and 'N' flags cannot be set or unset simultaneously"
        # [RFC 6463 section 4.2], so exactly one address is present and the
        # option is 18 octets long for IPv6 or 6 for IPv4. With neither given
        # the option's own length is undetermined.
        Enum_Option.Redirect_Mobility_Option: {
            'ipv6': ipaddress.IPv6Address('2001:db8::1')},
        # The option "MUST contain at least one ANI sub-option"
        # [RFC 6757 section 3]; it is a pure container and carries nothing else.
        Enum_Option.Access_Network_Identifier: {
            'suboptions': [(Enum_ANISuboption.Network_Identifier,
                            {'net_name': b'wifi',
                             'ap_name': b'\x00\x11\x22\x33\x44\x55'})]},
        # Likewise at least one LCMP sub-option [RFC 8127 section 3].
        Enum_Option.LMA_Controlled_MAG_Parameters: {
            'suboptions': [(Enum_LMAControlledMAGSuboption.Heartbeat_Control,
                            {'interval': 60, 'retransmission_delay': 3,
                             'max_retransmissions': 5})]},
    }


def _mh_carrier() -> 'Any':
    from pcapkit.const.mh.packet import Packet as Enum_Packet

    # Binding Refresh Request is the smallest message that carries an
    # arbitrary option list: two reserved octets and then the options.
    return Enum_Packet.Binding_Refresh_Request


def _mh_option_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.from_fields(type=_mh_carrier(), data={'options': [(code, dict(kwargs))]}, **MH_BASE)


def _mh_option_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _mh_option_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.from_fields(type=_mh_carrier(), data={'options': options}, **MH_BASE)


def _mh_extension_registry() -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.__extension__


def _mh_extension_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.mh.cga_extension import CGAExtension as Enum_CGAExtension
    return {Enum_CGAExtension.Multi_Prefix: {'prefixes': [0x20010db800000001]}}


def _mh_extension_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.mh.cga_type import CGAType as Enum_CGAType
    from pcapkit.const.mh.option import Option as Enum_Option
    from pcapkit.protocols.internet.mh.data import CGAParameter as Data_CGAParameter
    from pcapkit.protocols.internet.mh.protocol import MH

    # A CGA extension has exactly one carrier: the ``extensions`` list of a CGA
    # parameter, inside a CGA Parameters option. It has to be a *Data* model
    # rather than a schema, because ``_make_opt_cga_param`` keeps only the
    # length of the extensions it builds for a schema and throws the schemas
    # themselves away.
    # The data model annotates ``modifier`` as a CGAType and ``extensions`` as an
    # already-built OrderedMultiDict, but the constructor this feeds takes the
    # tuple form and resolves both -- so the arguments go through an untyped
    # mapping rather than being spelled as keywords a checker would reject.
    fields = {
        'modifier': Enum_CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
        'prefix': 0x20010db800000000,
        'collision_count': 0,
        'public_key': b'\x30\x02\xaa\xbb',
        'extensions': [(code, dict(kwargs))],
    }  # type: dict[str, Any]
    parameter = Data_CGAParameter(**fields)
    return MH.from_fields(type=_mh_carrier(),
                          data={'options': [(Enum_Option.CGA_Parameters,
                                             {'parameters': [parameter]})]},
                          **MH_BASE)


#: An RFC 6088 binary traffic selector selecting nothing: its flag word and
#: reserved half-word, both zero, which both formats share [RFC 6088 section 3].
TS_EMPTY = b'\x00\x00\x00\x00'

#: Multicast group addresses for the records below: 224.0.0.251 and ff02::fb.
GROUP_V4 = bytes.fromhex('e00000fb')
GROUP_V6 = bytes.fromhex('ff0200000000000000000000000000fb')

#: An IGMPv3 group record [RFC 3376 section 4.2] and an MLDv2 multicast address
#: record [RFC 3810 section 5.2]: MODE_IS_INCLUDE, no auxiliary data, no sources.
IGMPV3_RECORD = b'\x01\x00\x00\x00' + GROUP_V4
MLDV2_RECORD = b'\x01\x00\x00\x00' + GROUP_V6


def _mh_selector_registry() -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.__selector__


def _mh_selector_overrides() -> 'dict[Any, dict[str, Any]]':
    return {}


def _mh_selector_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption as Enum_FlowIDSuboption
    from pcapkit.const.mh.option import Option as Enum_Option
    from pcapkit.protocols.internet.mh.protocol import MH

    # The flow identification option's sub-option [RFC 6089 section 4.2.1.4].
    selector = {'ts_format': code, 'selector': TS_EMPTY, **kwargs}
    option = (Enum_Option.Flow_Identification_Mobility_Option,
              {'suboptions': [(Enum_FlowIDSuboption.Traffic_Selector, selector)]})
    return MH.from_fields(type=_mh_carrier(), data={'options': [option]}, **MH_BASE)


def _mh_qos_selector_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.mh.option import Option as Enum_Option
    from pcapkit.const.mh.qos_attribute import QoSAttribute as Enum_QoSAttribute
    from pcapkit.protocols.internet.mh.protocol import MH

    # The QoS option's attribute [RFC 7222 section 4.2.10], the selector's other carrier.
    selector = {'ts_format': code, 'selector': TS_EMPTY, **kwargs}
    option = (Enum_Option.Quality_of_Service,
              {'attributes': [(Enum_QoSAttribute.QoS_Traffic_Selector, selector)]})
    return MH.from_fields(type=_mh_carrier(), data={'options': [option]}, **MH_BASE)


def _mh_multicast_registry() -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.__multicast__


def _mh_multicast_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.mh.option import Option as Enum_Option

    selector = Enum_Option.Dynamic_IP_Multicast_Selector
    ipv4 = Enum_Option.Active_Multicast_Subscription_IPv4
    ipv6 = Enum_Option.Active_Multicast_Subscription_IPv6
    mobility = Enum_Option.Multicast_Mobility_Option
    # A report payload opens with a reserved half-word and the record count
    # [RFC 7411 section 5.3], one record here.
    igmpv3_report = b'\x00\x00\x00\x01' + IGMPV3_RECORD
    mldv2_report = b'\x00\x00\x00\x01' + MLDV2_RECORD
    return {
        # One record each, in the format RFC 7028 sections 5.1.2 and 8 name.
        (selector, 0x12): {'protocol': 0x12, 'records': 1, 'data': GROUP_V4},
        (selector, 0x16): {'protocol': 0x16, 'records': 1, 'data': GROUP_V4},
        (selector, 0x22): {'protocol': 0x22, 'records': 1, 'data': IGMPV3_RECORD},
        (selector, 131): {'protocol': 131, 'records': 1, 'data': GROUP_V6},
        (selector, 143): {'protocol': 143, 'records': 1, 'data': MLDV2_RECORD},
        # RFC 7161 sections 6.1, 4.1.2 and 4.1.3; MLDv1's context is a reserved
        # word and the address.
        (ipv4, 0x12): {'igmp_type': 0x12, 'context': GROUP_V4},
        (ipv4, 0x16): {'igmp_type': 0x16, 'context': GROUP_V4},
        (ipv4, 0x22): {'igmp_type': 0x22, 'context': IGMPV3_RECORD},
        (ipv6, 131): {'mld_type': 131, 'context': b'\x00' * 4 + GROUP_V6},
        (ipv6, 143): {'mld_type': 143, 'context': MLDV2_RECORD},
        (mobility, 1): {'code': 1, 'data': igmpv3_report},
        (mobility, 2): {'code': 2, 'data': mldv2_report},
        (mobility, 3): {'code': 3, 'data': igmpv3_report},
        (mobility, 4): {'code': 4, 'data': mldv2_report},
        # Status 1 carries the header line and no records [RFC 7411 section 5.4].
        (Enum_Option.Multicast_Acknowledgement_Option, 0): {
            'code': 0, 'status': 1, 'data': b'\x00\x00\x00\x00'},
    }


def _mh_multicast_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH

    option, _ = code
    return MH.from_fields(type=_mh_carrier(), data={'options': [(option, dict(kwargs))]}, **MH_BASE)


#: The families this module adds.
FAMILIES = (
    generator.Family('mh-message', _mh_message_registry, _mh_message_overrides,
                     _mh_message_build, _mh_parse, _mh_message_extract, _mh_message_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=135),
    generator.Family('mh-option', _mh_option_registry, _mh_option_overrides,
                     _mh_option_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=135),
    generator.Family('mh-extension', _mh_extension_registry, _mh_extension_overrides,
                     _mh_extension_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=135),
    generator.Family('mh-selector', _mh_selector_registry, _mh_selector_overrides,
                     _mh_selector_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=135),
    generator.Family('mh-qos-selector', _mh_selector_registry, _mh_selector_overrides,
                     _mh_qos_selector_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=135),
    generator.Family('mh-multicast', _mh_multicast_registry, _mh_multicast_overrides,
                     _mh_multicast_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=135),
)
