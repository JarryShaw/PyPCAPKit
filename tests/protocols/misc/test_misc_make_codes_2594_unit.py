# -*- coding: utf-8 -*-
"""GitHub issue #2594: the enumeration fields of the misc makers take a member or a code.

Ruled in review of #2593 (#2489) and on #2594: a ``make()`` field holding an
enumeration takes the member or an :class:`int`, resolved with the
enumeration's ``get``, and no maker takes an ``X_default``, ``X_namespace`` or
``X_reversed`` argument for it; a caller holding a name resolves it with
:meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first. Under #2617 a
code the field cannot carry raises
:exc:`~pcapkit.utilities.exceptions.ProtocolError`, and so does a :obj:`bool`
for a field wider than one bit.

:data:`ROWS` holds one row per migrated field of
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`,
:class:`~pcapkit.protocols.misc.pcap.header.protocol.Header` and
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`: the maker, the
field, its enumeration, its width in bits as the schema declares it, the code
of a member, and the prefix of the refusal's message. The code of each option
and the type of each name resolution record given to a block maker, as a
``(code, args)`` tuple, are such fields too. Each row is checked for:

* the widest code building, and a negative code and ``1 << bits`` raising
  :exc:`~pcapkit.utilities.exceptions.ProtocolError`;
* :data:`True` raising it, every field here being wider than one bit;
* the member and ``int(member)`` building identical octets, and the member's
  name, as a :obj:`str`, raising it.

A code the field carries that no member holds is not refused: the resolver
keeps it as a plain :obj:`int`, so a block type no member holds is written as
given and a parse of it rebuilds byte-exact.

An option maker is reached through its block's ``options``, as a caller
reaches it. Every case builds its own octets in memory and reads no capture.
Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import inspect
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: One row per migrated field: the maker, the field, the module and name of its
#: enumeration, its width in bits, the code of a member, and the message prefix.
ROWS = (
    ('PCAPNG.make', 'type', 'pcapkit.const.pcapng.block_type', 'BlockType', 32,
     0x0A0D0D0A, 'PCAP-NG: invalid block type: '),
    ('PCAPNG._make_block_idb', 'linktype', 'pcapkit.const.reg.linktype', 'LinkType', 16,
     1, 'PCAP-NG: invalid [IDB] linktype: '),
    ('PCAPNG._make_block_dsb', 'secrets_type', 'pcapkit.const.pcapng.secrets_type', 'SecretsType', 32,
     0x5A4E574B, 'PCAP-NG: invalid [DSB] secrets_type: '),
    ('PCAPNG._make_option_if_filter', 'filter', 'pcapkit.const.pcapng.filter_type', 'FilterType', 8,
     1, 'PCAP-NG: invalid [if_filter] filter: '),
    ('PCAPNG._make_option_epb_flags', 'direction', 'pcapkit.protocols.misc.pcapng.protocol', 'PacketDirection', 2,
     1, 'PCAP-NG: invalid [epb_flags] direction: '),
    ('PCAPNG._make_option_epb_flags', 'reception', 'pcapkit.protocols.misc.pcapng.protocol', 'PacketReception', 3,
     2, 'PCAP-NG: invalid [epb_flags] reception: '),
    ('PCAPNG._make_option_epb_hash', 'algorithm', 'pcapkit.const.pcapng.hash_algorithm', 'HashAlgorithm', 8,
     2, 'PCAP-NG: invalid [epb_hash] algorithm: '),
    ('PCAPNG._make_option_epb_verdict', 'verdict', 'pcapkit.const.pcapng.verdict_type', 'VerdictType', 8,
     1, 'PCAP-NG: invalid [epb_verdict] verdict: '),
    ('PCAPNG._make_option_pack_flags', 'direction', 'pcapkit.protocols.misc.pcapng.protocol', 'PacketDirection', 2,
     2, 'PCAP-NG: invalid [pack_flags] direction: '),
    ('PCAPNG._make_option_pack_flags', 'reception', 'pcapkit.protocols.misc.pcapng.protocol', 'PacketReception', 3,
     3, 'PCAP-NG: invalid [pack_flags] reception: '),
    ('PCAPNG._make_option_pack_hash', 'algorithm', 'pcapkit.const.pcapng.hash_algorithm', 'HashAlgorithm', 8,
     2, 'PCAP-NG: invalid [pack_hash] algorithm: '),
    ('Header.make', 'network', 'pcapkit.const.reg.linktype', 'LinkType', 32,
     1, 'PCAP: invalid network: '),
    ('IP_Pseudo.make', 'protocol', 'pcapkit.const.reg.transtype', 'TransType', 8,
     17, 'IP_Pseudo: invalid protocol: '),
    ('PCAPNG._make_pcapng_options', 'code', 'pcapkit.const.pcapng.option_type', 'OptionType', 16,
     1, 'PCAP-NG: invalid option code: '),
    ('PCAPNG._make_nrb_records', 'type', 'pcapkit.const.pcapng.record_type', 'RecordType', 16,
     1, 'PCAP-NG: invalid record type: '),
)

#: The arguments of an IPv4 name resolution record.
IPV4_RECORD = {'ip': '10.0.0.1', 'names': ['host']}

#: Timestamp and packet data of the packet blocks, fixed so that two builds compare.
TIMESTAMP = 1500000000
PACKET = bytes(16)


class MiscMakeCodeTests(unittest.TestCase):
    """Each migrated field takes a member or a code its width carries, and nothing else."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _context(self) -> 'Any':
        """A one-section context with one Ethernet interface, as the engine builds it."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
        context = Context(section.info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        return context

    def _block(self, name: 'str', block: 'dict[str, Any]') -> 'bytes':
        """The octets of the block named ``name``, built from ``block`` in a section."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # the Packet Block is obsolete
            return PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType[name], block=block).data

    def _option(self, name: 'str', option: 'str', args: 'dict[str, Any]') -> 'bytes':
        """The octets of the block named ``name`` carrying the option ``option`` made from ``args``."""
        from pcapkit.const.pcapng.option_type import OptionType

        block = {'options': [(OptionType[option], args)]}  # type: dict[str, Any]
        if name == 'Interface_Description_Block':
            block.update(linktype=1, snaplen=0x40000)
        else:
            block.update(timestamp=TIMESTAMP, packet_data=PACKET)
        return self._block(name, block)

    def _builder(self, maker: 'str', field: 'str') -> 'Callable[[Any], bytes]':
        """How a caller builds octets with ``value`` for ``field`` of ``maker``."""
        from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo
        from pcapkit.protocols.misc.pcap.header.protocol import Header
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        builders = {
            'PCAPNG.make': lambda value: PCAPNG(num=0, sct=1, ctx=None, type=value, block={}).data,
            'PCAPNG._make_block_idb': lambda value: self._block(
                'Interface_Description_Block', {'linktype': value, 'snaplen': 0x40000}),
            'PCAPNG._make_block_dsb': lambda value: self._block(
                'Decryption_Secrets_Block',
                {'secrets_type': value, 'secrets_data': {'nwk_key': bytes(16), 'pan_id': 0x1234}}),
            'PCAPNG._make_option_if_filter': lambda value: self._option(
                'Interface_Description_Block', 'if_filter', {'filter': value, 'expression': b'udp'}),
            'PCAPNG._make_option_epb_flags': lambda value: self._option(
                'Enhanced_Packet_Block', 'epb_flags', {field: value}),
            'PCAPNG._make_option_epb_hash': lambda value: self._option(
                'Enhanced_Packet_Block', 'epb_hash', {'algorithm': value, 'hash': b'\x01\x02\x03\x04'}),
            'PCAPNG._make_option_epb_verdict': lambda value: self._option(
                'Enhanced_Packet_Block', 'epb_verdict', {'verdict': value, 'value': b'\x01'}),
            'PCAPNG._make_option_pack_flags': lambda value: self._option(
                'Packet_Block', 'pack_flags', {field: value}),
            'PCAPNG._make_option_pack_hash': lambda value: self._option(
                'Packet_Block', 'pack_hash', {'algorithm': value, 'hash': b'\x01\x02\x03\x04'}),
            'Header.make': lambda value: Header(network=value, byteorder='little').data,
            'IP_Pseudo.make': lambda value: IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=value,
                                                      upper_length=0).data,
            'PCAPNG._make_pcapng_options': lambda value: self._block(
                'Interface_Description_Block',
                {'linktype': 1, 'snaplen': 0x40000, 'options': [(value, {'comment': 'eth0'})]}),
            'PCAPNG._make_nrb_records': lambda value: self._block(
                'Name_Resolution_Block', {'records': [(value, IPV4_RECORD)]}),
        }  # type: dict[str, Callable[[Any], bytes]]
        return builders[maker]

    def _rows(self) -> 'list[tuple[str, int, Any, str, Callable[[Any], bytes]]]':
        """Each row as its label, its width, its member, its message prefix and its builder."""
        rows = []
        for maker, field, module, enum, bits, code, prefix in ROWS:
            member = getattr(importlib.import_module(module), enum).get(code)
            rows.append((f'{maker} {field}', bits, member, prefix, self._builder(maker, field)))
        return rows

    def assertRefused(self, build: 'Callable[[Any], bytes]', value: 'Any', prefix: 'str') -> None:  # pylint: disable=invalid-name
        """Building with ``value`` raises the field's own ProtocolError, naming ``value``."""
        from pcapkit.utilities.exceptions import ProtocolError

        try:
            build(value)
        except ProtocolError as error:
            self.assertEqual(str(error), f'{prefix}{value!r}')
            return
        except Exception as error:  # pylint: disable=broad-except
            self.fail(f'{value!r} raised {type(error).__name__}, not ProtocolError: {error}')
        self.fail(f'{value!r} was accepted')

    def test_a_code_past_the_field_is_refused(self) -> None:
        for label, bits, _, prefix, build in self._rows():
            with self.subTest(field=label):
                self.assertRefused(build, -1, prefix)
                self.assertRefused(build, 1 << bits, prefix)
                build((1 << bits) - 1)

    def test_a_bool_is_refused(self) -> None:
        for label, bits, _, prefix, build in self._rows():
            with self.subTest(field=label):
                self.assertGreater(bits, 1)
                self.assertRefused(build, True, prefix)

    def test_a_member_and_its_code_build_alike_and_its_name_is_refused(self) -> None:
        for label, _, member, prefix, build in self._rows():
            with self.subTest(field=label):
                self.assertRefused(build, member.name, prefix)
                self.assertEqual(build(member).hex(), build(int(member)).hex())

    def test_a_block_type_no_member_holds_is_written_as_given(self) -> None:
        """An in-range code no member holds builds, and a parse of it rebuilds byte-exact.

        ``0x100`` sits below every range ``BlockType``'s ``_missing_`` resolves,
        so ``get`` misses and ``make`` keeps the code as a plain :obj:`int`.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        with self.assertRaises(ValueError):
            BlockType.get(0x100)
        octets = PCAPNG(num=0, sct=1, ctx=None, type=0x100, block={'data': b'ab'}).data
        self.assertEqual(octets.hex(), '00010000100000006162000010000000')
        parsed = PCAPNG(octets, len(octets), num=0, sct=1, ctx=None)
        self.assertEqual(PCAPNG.from_data(parsed.info, num=0, sct=1, ctx=None).data.hex(), octets.hex())

    def test_an_option_code_resolves_in_its_blocks_namespace(self) -> None:
        """An option code is looked up in the namespace of the block it is given to, as a parse reads it."""
        from pcapkit.const.pcapng.option_type import OptionType

        self.assertEqual(self._option('Interface_Description_Block', 'if_name', {'name': 'eth0'}).hex(),
                         self._block('Interface_Description_Block',
                                     {'linktype': 1, 'snaplen': 0x40000,
                                      'options': [(2, {'name': 'eth0'})]}).hex())
        self.assertEqual(self._block('Interface_Statistics_Block',
                                     {'interface_id': 0, 'timestamp': TIMESTAMP,
                                      'options': [(OptionType.isb_starttime, {'timestamp': TIMESTAMP})]}).hex(),
                         self._block('Interface_Statistics_Block',
                                     {'interface_id': 0, 'timestamp': TIMESTAMP,
                                      'options': [(2, {'timestamp': TIMESTAMP})]}).hex())

    def test_a_parsed_option_or_record_list_has_its_keys_checked(self) -> None:
        """A parsed list rebuilds as it was, and one keyed by a refused code is refused."""
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        cases = (
            ('Interface_Description_Block', {'linktype': 1, 'snaplen': 0x40000}, 'options',
             OptionType.if_name, {'name': 'eth0'}, 16, 'PCAP-NG: invalid option code: '),
            ('Name_Resolution_Block', {}, 'records',
             RecordType.nrb_record_ipv4, IPV4_RECORD, 16, 'PCAP-NG: invalid record type: '),
        )  # type: tuple[tuple[str, dict[str, Any], str, Any, dict[str, Any], int, str], ...]
        for name, fixed, key, member, args, bits, prefix in cases:
            octets = self._block(name, dict(fixed, **{key: [(member, args)]}))
            parsed = getattr(PCAPNG(octets, len(octets), num=2, sct=1, ctx=self._context()).info, key)
            item = next(iter(parsed.items(multi=True)))[1]

            def build(value: 'Any', name: 'str' = name, fixed: 'dict[str, Any]' = fixed,
                      key: 'str' = key, item: 'Any' = item) -> bytes:
                return self._block(name, dict(fixed, **{key: OrderedMultiDict([(value, item)])}))

            with self.subTest(block=name, list=key):
                self.assertEqual(build(member).hex(), octets.hex())
                for value in (1 << bits, -1, True, member.name):
                    self.assertRefused(build, value, prefix)

    def test_no_maker_takes_the_removed_arguments(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo
        from pcapkit.protocols.misc.pcap.header.protocol import Header
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for cls in (PCAPNG, Header, IP_Pseudo):
            for name in vars(cls):
                if name != 'make' and not name.startswith('_make_'):
                    continue
                with self.subTest(maker=f'{cls.__name__}.{name}'):
                    removed = [param for param in inspect.signature(getattr(cls, name)).parameters
                               if param.endswith(('_default', '_namespace', '_reversed'))]
                    self.assertEqual(removed, [])


if __name__ == '__main__':
    unittest.main()
