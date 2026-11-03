# -*- coding: utf-8 -*-
"""A field an :class:`~pcapkit.corekit.infoclass.Info` renamed for clashing with a builtin name is dumped.

GitHub issue #2733. :class:`Info` stores a key named like one of its builtin
names, such as ``items`` or a reassembled datagram's ``packet``, under a renamed
key, and finalisation puts the name in ``__excluded__``. The dumps matched
``__excluded__`` against the name the key is iterated by, so every ``json``,
``plist`` and ``tree`` dump left such a field out, of the info and of its export
alike. The dumps write each under its own name, and leave out an excluded name, a
dunder key ``__excluded__`` names, a dunder key iteration hides and a renamed
dunder key.

A deferred ``packet`` is resolved by the dump, once, as indexing resolves it: the
dump reads the field, and ``to_dict()`` resolves it for an export as well, so the
info and its export dump alike. Nothing before the dump resolves it. A resolved
``packet`` is a protocol object, which the dumps write as its ``info``, as they
write a frame's layers: written by its attributes, it carried the address of its
file object, so the same datagram dumped differently in each process.

Every case builds its input in memory and reads no capture. :mod:`pcapkit` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
or in a fresh interpreter for :class:`FreshProcessDumpTests`.

"""

import importlib
import itertools
import json
import os
import plistlib
import re
import subprocess  # nosec: B404
import sys
import tempfile
import unittest
from ipaddress import ip_address

from tests._support import reimport_once_per_class, scale_timeout

#: Repository root, the working directory of a fresh interpreter.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: Builds a reassembled IPv4 and TCP datagram in memory and dumps both through
#: each writer into the directory ``argv[1]``; prints where :mod:`pcapkit` is from.
SCRIPT = r'''
import os
import struct
import sys
from ipaddress import ip_address

import dictdumper

import pcapkit
from pcapkit.const.reg.transtype import TransType
from pcapkit.dumpkit.common import make_dumper
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.reassembly.ipv4 import IPv4
from pcapkit.foundation.reassembly.tcp import TCP

SRC, DST = ip_address('192.0.2.1'), ip_address('198.51.100.2')
UDP = struct.pack('!HHHH', 1234, 9, 32, 0) + bytes(range(24))
REQUEST = b'GET / HTTP/1.1\r\nHost: example\r\n\r\n'


def ipv4():
    reasm = IPv4()
    for (offset, chunk, mf) in ((0, UDP[:16], True), (16, UDP[16:], False)):
        reasm(IP_Packet(bufid=(SRC, DST, 0x1234, TransType.UDP), num=1 + offset // 16, fo=offset, ihl=20,
                        mf=mf, tl=20 + len(chunk), header=bytes([0x45]) + bytes(19),
                        payload=bytearray(chunk), timestamp=1000.0))
    datagram, = reasm.datagram
    return datagram


def tcp():
    reasm = TCP()
    reasm(TCP_Packet((SRC, 50000, DST, 80), 1, 500, 1, False, True, False, 5, 1, 5, b'',
                     bytearray(REQUEST), 1000.0))
    datagram, = reasm.datagram
    return datagram


for writer in ('JSON', 'PLIST', 'Tree'):
    dumper = make_dumper(getattr(dictdumper, writer))(os.path.join(sys.argv[1], writer))
    dumper(ipv4(), name='ipv4')
    dumper(tcp(), name='tcp')
print(pcapkit.__file__)
'''

#: The :mod:`dictdumper` writers the extractor's ``json``, ``plist``/``xml`` and
#: ``tree``/``text``/``txt`` formats map to.
WRITERS = ('JSON', 'PLIST', 'Tree')

#: Block name every dump is written under.
NAME = 'x'

#: A top-level key of a ``tree`` block, as the writer spells its line.
TREE_KEY = re.compile(r'^  \|-- (\S+)', re.MULTILINE)


class DumpTestCase(unittest.TestCase):
    """Writes a value through each writer and reads the block back."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.count = itertools.count()

    def block(self, writer: 'str', value: 'object') -> 'object':
        """Write ``value`` through ``make_dumper(dictdumper.<writer>)``; return the block.

        A ``json`` or ``plist`` block is the mapping read back, a ``tree`` block
        its text.

        """
        dictdumper = importlib.import_module('dictdumper')
        common = importlib.import_module('pcapkit.dumpkit.common')

        path = os.path.join(self.tmp, f'{writer}-{next(self.count)}.out')
        common.make_dumper(getattr(dictdumper, writer))(path)(value, name=NAME)
        if writer == 'JSON':
            with open(path, encoding='utf-8') as file:
                return json.load(file)[NAME]
        if writer == 'PLIST':
            with open(path, 'rb') as file:
                return plistlib.load(file)[NAME]
        with open(path, encoding='utf-8') as file:
            return file.read()

    def keys(self, writer: 'str', value: 'object') -> 'list[str]':
        """The top-level keys of the block ``writer`` makes of ``value``, in order."""
        block = self.block(writer, value)
        if isinstance(block, str):
            return TREE_KEY.findall(block)
        return list(block)  # type: ignore[call-overload]


class RenamedFieldTests(DumpTestCase):
    """A field named like a builtin name of :class:`Info`."""

    def bag(self) -> 'object':
        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Bag(Info):
            name: 'str'
            items: 'int'

        return Bag(name='x', items=1)

    def test_a_field_named_items_is_dumped_under_its_name(self) -> None:
        bag = self.bag()
        self.assertIn('items', bag.__map__)
        self.assertIn('items', bag.__excluded__)
        for writer in WRITERS:
            for (label, value) in (('info', bag), ('export', bag.to_dict())):
                with self.subTest(writer=writer, value=label):
                    self.assertEqual(self.keys(writer, value), ['name', 'items'])
                    block = self.block(writer, value)
                    if isinstance(block, str):
                        self.assertIn('  |-- items -> 1\n', block)
                    else:
                        self.assertEqual(block['items'], 1)  # type: ignore[index]

    def test_a_nested_renamed_field_is_dumped_too(self) -> None:
        """An info nested in an info, and an export nested in an export."""
        from pcapkit.corekit.infoclass import Info

        inner = Info(name='x', items=1, keys=2)
        outer = Info(inner=inner)
        self.assertEqual(self.block('JSON', outer), {'inner': {'name': 'x', 'items': 1, 'keys': 2}})
        # A nested export is an option list's shape, one single-key mapping per entry.
        self.assertEqual(self.block('JSON', outer.to_dict()),
                         {'inner': [{'name': 'x'}, {'items': 1}, {'keys': 2}]})


class HiddenKeyTests(DumpTestCase):
    """The keys the dumps leave out, held beside a renamed field."""

    def model(self) -> 'object':
        from pcapkit.corekit.infoclass import Info

        class Model(Info):
            __included__ = ['__meta__']
            __excluded__ = ['__meta__', 'secret']

        return Model.from_dict([('name', 'x'), ('items', 1), ('secret', 2), ('__meta__', 3),
                                ('__hidden__', 4), ('__doc__', 5)])

    def test_excluded_and_dunder_keys_stay_out_beside_a_renamed_field(self) -> None:
        """``secret`` is excluded, ``__meta__`` excluded metadata, ``__hidden__``
        a dunder iteration hides, and ``__doc__`` a dunder renamed as ``items``
        is, so the export carries it.

        """
        model = self.model()
        self.assertEqual(sorted(model.__map__), ['__doc__', 'items'])
        self.assertIn('__doc__', [key for (key, _) in model.to_dict().items(multi=True)])
        for writer in WRITERS:
            for (label, value) in (('info', model), ('export', model.to_dict())):
                with self.subTest(writer=writer, value=label):
                    self.assertEqual(self.keys(writer, value), ['name', 'items'])

    def test_the_export_records_every_left_out_name_but_the_renamed_field(self) -> None:
        export = self.model().to_dict()
        self.assertNotIn('items', export.__excluded__)
        for name in ('secret', '__meta__', '__doc__', '__map__'):
            with self.subTest(name=name):
                self.assertIn(name, export.__excluded__)


class Counting:
    """Stands in for an analysis; counts its calls, and answers ``'parsed'``."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: 'object') -> 'str':
        self.calls += 1
        return 'parsed'

    @property
    def datagram(self) -> 'str':
        """What a traced flow's placeholder reads of its reassembler."""
        return self()


class DeferredPacketDumpTests(DumpTestCase):
    """A deferred ``packet`` is dumped, resolved once and only by the dump."""

    @staticmethod
    def tcp_datagram() -> 'object':
        """One complete TCP datagram, its ``packet`` deferred."""
        from pcapkit.foundation.reassembly.data.tcp import Packet
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(Packet((ip_address('192.0.2.1'), 50000, ip_address('198.51.100.2'), 65535),
                     1, 500, 1, False, True, False, 5, 1, 5, b'', bytearray(b'hello'), 1000.0))
        datagram, = reasm.datagram
        return datagram

    @staticmethod
    def held(model: 'object') -> 'object':
        """``model``'s stored ``packet``, without resolving it."""
        return model.__dict__[model.__map__['packet']]  # type: ignore[attr-defined]

    def test_a_reassembled_tcp_datagram_dumps_its_packet(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred

        for writer in WRITERS:
            for label in ('info', 'export'):
                with self.subTest(writer=writer, value=label):
                    datagram = self.tcp_datagram()
                    self.assertIn('packet', datagram.__excluded__)
                    self.assertIsInstance(self.held(datagram), Deferred)

                    value = datagram if label == 'info' else datagram.to_dict()
                    block = self.block(writer, value)
                    keys = TREE_KEY.findall(block) if isinstance(block, str) else list(block)
                    self.assertEqual(keys, list(datagram))
                    self.assertIn('packet', keys)

                    # The dump wrote the parse, and kept it in place of the placeholder.
                    packet = self.held(datagram)
                    self.assertNotIsInstance(packet, Deferred)
                    self.assertIs(datagram['packet'], packet)
                    if not isinstance(block, str):
                        self.assertEqual(block['packet'], self.block(writer, {'packet': packet})['packet'])

    def test_the_dump_resolves_a_deferred_packet_once(self) -> None:
        """Every model with a deferred ``packet``, IP, TCP and DTLS reassembly's and a traced flow's."""
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.data import Deferred as ReassemblyDeferred
        from pcapkit.foundation.reassembly.data.dtls import Datagram as DTLS_Datagram
        from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
        from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
        from pcapkit.foundation.traceflow.data.data import Deferred as TraceFlowDeferred
        from pcapkit.foundation.traceflow.data.tcp import Index

        def datagram(cls: 'type', counting: 'Counting') -> 'object':
            return cls(completed=Completion.COMPLETE, id=None, index=(1,), header=b'', payload=b'payload',
                       packet=ReassemblyDeferred(counting, 'proto', b'payload'), conflict=())

        builders = {
            'ip': lambda counting: datagram(IP_Datagram, counting),
            'tcp': lambda counting: datagram(TCP_Datagram, counting),
            'dtls': lambda counting: DTLS_Datagram(
                completed=Completion.COMPLETE, id=None, index=(1,), message_seq=0, msg_type=None, length=7,
                body=b'payload', packet=ReassemblyDeferred(counting, 'proto', b'payload')),
            'trace': lambda counting: Index(fpout=None, index=(1,), label='label', forward=(1,), reverse=(),
                                            packet=TraceFlowDeferred(counting)),  # type: ignore[arg-type]
        }
        for (label, build) in builders.items():
            with self.subTest(model=label):
                counting = Counting()
                model = build(counting)
                self.assertIn('packet', model)
                self.assertEqual(len(model), len(list(model)))
                self.assertEqual(counting.calls, 0)

                self.assertEqual(self.block('JSON', model)['packet'], 'parsed')  # type: ignore[index]
                self.assertEqual(counting.calls, 1)
                for writer in WRITERS:
                    self.assertIn('packet', self.keys(writer, model))
                self.assertEqual(counting.calls, 1)

    def test_a_resolved_packet_is_dumped_as_its_info(self) -> None:
        datagram = self.tcp_datagram()
        packet = datagram['packet']
        self.assertEqual(self.block('JSON', datagram)['packet'], self.block('JSON', packet.info))  # type: ignore[index]
        # A protocol object handed to the writer itself is written the same way.
        self.assertEqual(self.block('JSON', packet), self.block('JSON', packet.info))


class FreshProcessDumpTests(unittest.TestCase):
    """The same datagrams, dumped in two fresh interpreters, give the same octets."""

    def dump(self) -> 'dict[str, bytes]':
        """Run :data:`SCRIPT` in a fresh interpreter; return each writer's octets."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        proc = subprocess.run([sys.executable, '-c', SCRIPT, tmp.name],  # nosec: B603
                              cwd=ROOT, capture_output=True, text=True, timeout=scale_timeout(120), check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(os.path.dirname(os.path.dirname(proc.stdout.strip())), ROOT)
        octets = {}
        for writer in WRITERS:
            with open(os.path.join(tmp.name, writer), 'rb') as file:
                octets[writer] = file.read()
        return octets

    def test_each_writer_dumps_a_reassembled_datagram_identically(self) -> None:
        first, second = self.dump(), self.dump()
        for writer in WRITERS:
            with self.subTest(writer=writer):
                self.assertIn(b'packet', first[writer])
                self.assertNotIn(b' object at 0x', first[writer])
                self.assertEqual(first[writer], second[writer])


if __name__ == '__main__':
    unittest.main()
