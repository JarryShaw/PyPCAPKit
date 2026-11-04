# -*- coding: utf-8 -*-
"""The ``mh-message``, ``mh-option`` and ``mh-extension`` families: Mobility Header
messages, options and extensions.

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
MH_BASE = {'next': 59, 'chksum': b'\x00\x00', 'payload': b''}


def _mh_message_registry() -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.__message__


def _mh_message_overrides() -> 'dict[Any, dict[str, Any]]':
    return {}


def _mh_message_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH

    # ``data`` has to be a mapping for ``make`` to dispatch on the message
    # type; a Data object takes the other branch, which is what rebuild uses.
    return MH(type=code, data=dict(kwargs), **MH_BASE)


def _mh_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH(octets, len(octets), extension=True)


def _mh_message_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _mh_message_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH(type=message.type, data=message, **MH_BASE)


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
    return MH(type=_mh_carrier(), data={'options': [(code, dict(kwargs))]}, **MH_BASE)


def _mh_option_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _mh_option_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH(type=_mh_carrier(), data={'options': options}, **MH_BASE)


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
    return MH(type=_mh_carrier(),
              data={'options': [(Enum_Option.CGA_Parameters,
                                 {'parameters': [parameter]})]},
              **MH_BASE)


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
)
