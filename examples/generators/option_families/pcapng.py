# -*- coding: utf-8 -*-
"""The ``pcapng-block``, ``pcapng-option``, ``pcapng-record`` and ``pcapng-secrets``
families: PCAP-NG blocks, block options, name records and decryption secrets.

These families are exercised by
:func:`~examples.generators.options.roundtrip` but deliberately write no
capture, and the reason is not that a PCAP-NG capture would be uninteresting --
it is that the construction API's defaults do not produce a *reproducible*
one. ``_make_block_shb`` takes the section's byte order from
:data:`sys.byteorder` unless given ``byteorder``, and the TLS and WireGuard
key-log writers stamp the running pcapkit version into the block body. A
fixture built this way would differ between a little-endian and a big-endian
host, and the two key-log types would differ between one release and the next.

The PCAP-NG option space is not left uncovered by that decision:
:file:`examples/generators/pcapng.py` already builds ``profile.pcapng``,
``test.pcapng`` and ``many_interfaces.pcapng`` over it, hand-rolling every
octet with :func:`struct.pack` for exactly this reason. What is added here is
the half that generator cannot reach, since it never calls the construction
API at all: whether ``_make_block_*`` and ``_make_option_*`` can produce what
``_read_block_*`` and ``_read_option_*`` consume.

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

#: Fixed PCAP-NG timestamp, the same instant :file:`pcapng.py` uses. Not
#: optional: leaving ``timestamp`` unset reaches ``self._info`` before
#: ``__post_init__`` has assigned it, so the "now" default is unreachable as
#: well as non-deterministic.
PCAPNG_TIME = 1500000000

#: A minimal Ethernet frame for the packet-carrying blocks: destination and
#: source address, an unassigned EtherType, and two octets of body.
#:
#: It has to be non-empty. A ``PayloadField`` whose computed length is
#: legitimately zero reads the whole remainder of the block instead of nothing,
#: which swallows the option area -- so an empty packet would silently take the
#: whole ``epb_*`` and ``pack_*`` option space with it. Sixteen octets rather
#: than the bare 14-octet header, so the Ethernet dissector does not under-run.
#: 6 octets of destination, 6 of source, the EtherType, then the body.
PCAPNG_PACKET = bytes.fromhex('02000000000102000000000288b50000')

#: A systemd journal export entry whose length is a multiple of four, so that
#: ``_make_block_systemd`` has no padding to add to it.
PCAPNG_JOURNAL = (b'__REALTIME_TIMESTAMP=1500000000000000\n_TRANSPORT=journal\n'
                  b'PRIORITY=6\nMESSAGE=probe.....\n\n')


def _pcapng_context() -> 'tuple[Any, Any]':
    """A one-section PCAP-NG context with one Ethernet interface in it.

    Every block other than a Section Header Block is read and written relative
    to a section, and the packet-carrying blocks resolve their snap length
    through the section's interface list, so there has to be one.

    Returns:
        The :class:`~pcapkit.foundation.engines.pcapng.Context` and the
        interface-description block registered in it.

    """
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.protocols.misc.pcapng import PCAPNG

    section = PCAPNG(num=0, sct=1, ctx=None,
                     type=Enum_BlockType.Section_Header_Block, block={})
    # ``Protocol.info`` is annotated as the generic data model for the protocol,
    # so a checker cannot see that a Section Header Block's is the one ``Context``
    # wants. The engine does exactly this, in ``PCAPNG.run`` of
    # pcapkit/foundation/engines/pcapng.py.
    section_info = section.info  # type: Any
    context = Context(section_info)
    interface = PCAPNG(num=1, sct=1, ctx=context,
                       type=Enum_BlockType.Interface_Description_Block,
                       block={'linktype': Enum_LinkType.ETHERNET, 'snaplen': 0x40000})
    interface_info = interface.info  # type: Any
    context.interfaces.append(interface_info)
    return context, interface_info


def _pcapng_block(code: 'Any', block: 'dict[str, Any] | Any') -> 'Any':
    """Construct one PCAP-NG block of ``code``.

    A fresh context per call, deliberately. ``PCAPNG.__post_init__`` packs and
    then re-reads *on the same instance*, and the two halves share the
    per-instance option counter, so state left by one case would change the
    next one's result.

    Args:
        code: Block type.
        block: Block body, as a mapping of constructor arguments or as the
            parsed data model.

    Returns:
        The constructed block.

    """
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.protocols.misc.pcapng import PCAPNG

    # A Section Header Block is what *starts* a section, so it is the one block
    # the engine reads with no context at all.
    context = None if code == Enum_BlockType.Section_Header_Block else _pcapng_context()[0]
    return PCAPNG(num=2, sct=1, ctx=context, type=code, block=block)


#: Block type of a Section Header Block, as it appears on the wire. The value
#: is byte-order independent by design -- that is what lets a reader work out a
#: section's endianness -- so it can be recognised before the byte order is
#: known, which is exactly what :func:`_pcapng_parse` needs.
PCAPNG_SHB_MAGIC = bytes.fromhex('0a0d0d0a')


def _pcapng_parse(octets: 'bytes') -> 'Any':
    """Parse one PCAP-NG block back from its own octets.

    The block type is read out of the octets rather than passed in, so that
    this keeps the one-argument shape every other family's ``parse`` has. It is
    the first four octets of any block, and a Section Header Block -- the one
    block read with no section context, because it is what *starts* a
    section -- is recognisable by :data:`PCAPNG_SHB_MAGIC`.

    Args:
        octets: The constructed block.

    Returns:
        The parsed block.

    """
    from pcapkit.protocols.misc.pcapng import PCAPNG

    context = None if octets[:4] == PCAPNG_SHB_MAGIC else _pcapng_context()[0]
    return PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)


def _pcapng_block_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__block__


def _pcapng_block_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
    from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    return {
        Enum_BlockType.Interface_Description_Block: {
            'linktype': Enum_LinkType.ETHERNET, 'snaplen': 0x40000},
        Enum_BlockType.Enhanced_Packet_Block: {
            'timestamp': PCAPNG_TIME, 'packet_data': PCAPNG_PACKET},
        Enum_BlockType.Simple_Packet_Block: {'packet_data': PCAPNG_PACKET},
        # Without the terminating record the records field consumes the whole
        # block and the option area disappears.
        Enum_BlockType.Name_Resolution_Block: {
            'records': [(Enum_RecordType.nrb_record_end, {})]},
        Enum_BlockType.Interface_Statistics_Block: {'timestamp': PCAPNG_TIME},
        Enum_BlockType.systemd_Journal_Export_Block: {'entries': PCAPNG_JOURNAL},
        # ZigBee rather than the default TLS key log: the default empty
        # ``secrets_data`` does not read back as a key log.
        Enum_BlockType.Decryption_Secrets_Block: {
            'secrets_type': Enum_SecretsType.ZigBee_NWK_Key,
            'secrets_data': {'nwk_key': bytes(range(16)), 'pan_id': 0x1234}},
        Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files: {
            'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files: {
            'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        Enum_BlockType.Packet_Block: {
            'timestamp': PCAPNG_TIME, 'packet_data': PCAPNG_PACKET},
    }


def _pcapng_block_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    return _pcapng_block(code, dict(kwargs))


def _pcapng_block_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _pcapng_block_rebuild(info: 'Any') -> 'Any':
    return _pcapng_block(info.type, info)


#: Which block hosts each block-option namespace, and that host's own
#: arguments. The namespace is the part of the ``_option_key`` tuple's first
#: element before the first underscore.
PCAPNG_OPTION_HOSTS = {
    'opt': 'Section_Header_Block',
    'if': 'Interface_Description_Block',
    'epb': 'Enhanced_Packet_Block',
    'ns': 'Name_Resolution_Block',
    'isb': 'Interface_Statistics_Block',
    'pack': 'Packet_Block',
}


def _pcapng_option_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__option__


def _pcapng_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
    from pcapkit.protocols.misc.pcapng import _option_key
    return {
        _option_key(Enum_OptionType.opt_comment): {'comment': 'probe'},
        _option_key(Enum_OptionType.opt_custom_2988): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.opt_custom_2989): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.opt_custom_19372): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.opt_custom_19373): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.if_name): {'name': 'eth0'},
        _option_key(Enum_OptionType.if_description): {'description': 'probe interface'},
        _option_key(Enum_OptionType.if_IPv4addr): {'interface': '10.0.0.1/255.255.255.0'},
        _option_key(Enum_OptionType.if_IPv6addr): {
            'interface': '2001:db8:85a3:8d3:1319:8a2e:370:7344/64'},
        _option_key(Enum_OptionType.if_MACaddr): {'interface': '02:00:00:00:00:01'},
        _option_key(Enum_OptionType.if_EUIaddr): {'interface': '02:00:00:FF:FE:00:00:01'},
        _option_key(Enum_OptionType.if_speed): {'speed': 1000000000},
        _option_key(Enum_OptionType.if_tsresol): {'resolution': 1000000},
        _option_key(Enum_OptionType.if_tzone): {'tzone': 0},
        _option_key(Enum_OptionType.if_filter): {'expression': b'udp port 67'},
        # ``if_os`` and ``if_hardware`` default to the live platform strings, so
        # leaving them unset would make the case machine-dependent.
        _option_key(Enum_OptionType.if_os): {'os': 'probe OS'},
        _option_key(Enum_OptionType.if_hardware): {'hardware': 'probe adapter'},
        _option_key(Enum_OptionType.if_fcslen): {'fcs_length': 4},
        _option_key(Enum_OptionType.if_tsoffset): {'offset': 0},
        _option_key(Enum_OptionType.if_txspeed): {'speed': 1000000000},
        _option_key(Enum_OptionType.if_rxspeed): {'speed': 1000000000},
        _option_key(Enum_OptionType.epb_hash): {'hash': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.epb_verdict): {'value': b'\x01'},
        _option_key(Enum_OptionType.ns_dnsname): {'name': 'resolver.example'},
        _option_key(Enum_OptionType.ns_dnsIP4addr): {'ip': '10.0.0.53'},
        # The default is the IPv4 literal ``'8.8.8.8'``, which the v6 field
        # rejects outright.
        _option_key(Enum_OptionType.ns_dnsIP6addr): {'ip': '2001:db8::35'},
        _option_key(Enum_OptionType.isb_starttime): {'timestamp': PCAPNG_TIME},
        _option_key(Enum_OptionType.isb_endtime): {'timestamp': PCAPNG_TIME},
        _option_key(Enum_OptionType.isb_ifrecv): {'packets': 4},
        _option_key(Enum_OptionType.isb_ifdrop): {'packets': 1},
        _option_key(Enum_OptionType.isb_filteraccept): {'packets': 4},
        _option_key(Enum_OptionType.isb_osdrop): {'packets': 0},
        _option_key(Enum_OptionType.isb_usrdeliv): {'packets': 3},
        _option_key(Enum_OptionType.pack_hash): {'hash': b'\x01\x02\x03\x04'},
    }


def _pcapng_option_enum(key: 'Any') -> 'Any':
    """The enumeration member behind an ``_option_key`` tuple.

    ``PCAPNG.__option__`` is keyed by ``(name, value)`` tuples because the same
    numeric option code means different things in different block types, but
    the construction API takes the enumeration member.

    Args:
        key: The ``(str, int)`` registry key.

    Returns:
        The matching :class:`~pcapkit.const.pcapng.option_type.OptionType`.

    Raises:
        KeyError: If no member matches, which would mean the registry and the
            enumeration have diverged.

    """
    from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
    from pcapkit.protocols.misc.pcapng import _option_key

    # The enumeration is an :mod:`aenum` one, whose metaclass does not advertise
    # ``__iter__`` to a type checker even though it iterates perfectly well.
    members = Enum_OptionType  # type: Any
    for member in members:
        if _option_key(member) == key:
            return member
    raise KeyError(f'no OptionType matches registry key {key!r}')


def _pcapng_option_host(key: 'Any') -> 'tuple[Any, dict[str, Any]]':
    """The block type that carries option ``key``, and its own arguments."""
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType

    namespace = str(key[0]).split('_', 1)[0]
    name = PCAPNG_OPTION_HOSTS[namespace]
    code = getattr(Enum_BlockType, name)
    return code, dict(_pcapng_block_overrides().get(code, {}))


def _pcapng_option_build(key: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    code, block = _pcapng_option_host(key)
    block['options'] = [(_pcapng_option_enum(key), dict(kwargs))]
    return _pcapng_block(code, block)


def _pcapng_option_rebuild(info: 'Any') -> 'Any':
    """Rebuild an option's host block, taking only the options from the parse.

    The host's own fields come from :func:`_pcapng_block_overrides` rather than
    from the parsed block, and that is the point. Reconstructing the whole block
    from ``info`` would drop the captured payload of a packet-carrying block --
    ``_make_block_epb`` and its siblings never restore ``packet_data``, and the
    data model has nowhere to keep it -- so every ``epb_*`` and ``pack_*``
    option would be reported as a mismatch on account of a defect that has
    nothing to do with the option. Re-supplying the host fields isolates the
    option, which is what this family is measuring.

    Args:
        info: The parsed block.

    Returns:
        The reconstructed block.

    """
    block = dict(_pcapng_block_overrides().get(info.type, {}))
    block['options'] = info.options
    return _pcapng_block(info.type, block)


def _pcapng_record_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__record__


def _pcapng_record_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
    return {
        Enum_RecordType.nrb_record_ipv4: {'ip': '10.0.0.1', 'names': ['gateway.example']},
        # The default is the IPv4 literal ``'127.0.0.1'``, which the v6 field
        # rejects outright.
        Enum_RecordType.nrb_record_ipv6: {'ip': '2001:db8::1', 'names': ['v6.example']},
    }


def _pcapng_record_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType

    records = [(code, dict(kwargs))]
    if code != Enum_RecordType.nrb_record_end:
        # A record list has to be terminated, or the records field eats the
        # rest of the block.
        records.append((Enum_RecordType.nrb_record_end, {}))
    return _pcapng_block(Enum_BlockType.Name_Resolution_Block, {'records': records})


def _pcapng_record_extract(parsed: 'Any') -> 'Any':
    return parsed.info.records


def _pcapng_record_rebuild(records: 'Any') -> 'Any':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    return _pcapng_block(Enum_BlockType.Name_Resolution_Block, {'records': records})


def _pcapng_secrets_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__secrets__


def _pcapng_secrets_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
    from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel as Enum_TLSKeyLabel
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.misc.pcapng import WireGuardKeyLabel
    return {
        Enum_SecretsType.TLS_Key_Log: {
            'entries': {Enum_TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict(
                [(bytes(range(0x20, 0x40)), bytes(range(0x40, 0x70)))])}},
        Enum_SecretsType.WireGuard_Key_Log: {
            'entries': OrderedMultiDict(
                [(WireGuardKeyLabel.LOCAL_STATIC_PRIVATE_KEY, bytes(range(32)))])},
        Enum_SecretsType.ZigBee_NWK_Key: {'nwk_key': bytes(range(16)), 'pan_id': 0x1234},
        Enum_SecretsType.ZigBee_APS_Key: {
            'aps_key': bytes(range(16)), 'pan_id': 0x1234, 'short_address': 0xABCD},
    }


def _pcapng_secrets_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    return _pcapng_block(Enum_BlockType.Decryption_Secrets_Block,
                         {'secrets_type': code, 'secrets_data': dict(kwargs)})


#: The families this module adds.
FAMILIES = (
    # The PCAP-NG families write no capture -- see the module docstring for
    # why the construction API's defaults do not make a reproducible one, and
    # what already covers that space instead.
    generator.Family('pcapng-block', _pcapng_block_registry, _pcapng_block_overrides,
                     _pcapng_block_build, _pcapng_parse, _pcapng_block_extract,
                     _pcapng_block_rebuild, capture=None, envelope=None),
    # Both of these reconstruct from the parsed *block* rather than from the
    # option or secrets collection alone, because neither collection records
    # which block type carried it -- but the option family re-supplies the
    # host's own fields on the way, for the reason ``_pcapng_option_rebuild``
    # gives.
    generator.Family('pcapng-option', _pcapng_option_registry, _pcapng_option_overrides,
                     _pcapng_option_build, _pcapng_parse, _pcapng_block_extract,
                     _pcapng_option_rebuild, capture=None, envelope=None),
    generator.Family('pcapng-record', _pcapng_record_registry, _pcapng_record_overrides,
                     _pcapng_record_build, _pcapng_parse, _pcapng_record_extract,
                     _pcapng_record_rebuild, capture=None, envelope=None),
    generator.Family('pcapng-secrets', _pcapng_secrets_registry, _pcapng_secrets_overrides,
                     _pcapng_secrets_build, _pcapng_parse, _pcapng_block_extract,
                     _pcapng_block_rebuild, capture=None, envelope=None),
)
