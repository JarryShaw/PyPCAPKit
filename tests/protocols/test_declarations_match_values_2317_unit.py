# -*- coding: utf-8 -*-
"""Declarations agree with the values the code stores. C.f. #2317.

Each annotation and ``__all__`` below disagreed with what the code actually
stores or accepts, so :program:`mypy` and the rendered docs described a value
that never occurs: ``cmpt_bitmap`` annotated :obj:`bytes` while
``_read_opt_calipso`` stores a :obj:`tuple` of :obj:`int`,
``SMFHashBasedDPDOption.post_process`` declaring its sibling's class,
``Optional`` on an ``RR``/``SSR`` ``route`` that is always built,
:attr:`~pcapkit.protocols.protocol.ProtocolBase.protochain` declaring a
:class:`~pcapkit.corekit.protochain.ProtoChain` that
:class:`~pcapkit.protocols.misc.null.NoPayload` does not have, a ``pack_flags``
constructor stub typing the EPB flags, ``ARP._make_addr_resolve`` leaving out
the :obj:`bytearray` its body handles, an undeclared ``entry_raw``, two HIP
parameters missing from both ``__all__`` lists, and a ``version`` that one
``_read_param_*`` took positionally.

Each case pins the declaration against the value, rather than the declaration
alone: a parse shows what is stored, and the declaration is read back from the
source where it lives only under :data:`~typing.TYPE_CHECKING`.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import ast
import inspect
import struct
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Optional

#: Test tier (#1958): pins declarations and in-memory parses, neither of which
#: differs by interpreter.
__tier__ = 'LATEST'

#: Three address slots, the first of which is before a pointer of 8.
SLOTS = bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]) + bytes(4)


def hopopt_bytes(option: 'bytes') -> 'bytes':
    """A HOPOPT header carrying ``option``, padded to a multiple of 8 octets."""
    pad = -(len(option) + 2) % 8
    if pad:
        option += bytes([1, pad - 2]) + bytes(pad - 2) if pad > 1 else bytes([0])
    return bytes([59, (len(option) + 2) // 8 - 1]) + option


def ipv4_bytes(options: 'bytes') -> 'bytes':
    """An IPv4 header carrying ``options``, padded to a multiple of 4 octets."""
    options += bytes(-len(options) % 4)
    length = 20 + len(options)
    return (bytes([0x40 | length // 4, 0]) + length.to_bytes(2, 'big') + bytes(4)
            + bytes([64, 59, 0, 0]) + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]) + options)


def body(module: 'object', name: 'str') -> 'ast.ClassDef':
    """The class definition of ``name`` in ``module``'s source."""
    tree = ast.parse(inspect.getsource(module))  # type: ignore[arg-type]
    return next(node for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef) and node.name == name)


def declared(module: 'object', name: 'str', field: 'str') -> 'Optional[str]':
    """The annotation of ``field`` in ``name``'s class body, as written.

    :data:`None` where the class body does not declare ``field`` at all, so that
    an undeclared field reads as a mismatch rather than as a
    :exc:`StopIteration`.

    """
    node = next((item for item in ast.walk(body(module, name))
                 if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
                 and item.target.id == field), None)
    return None if node is None else ast.literal_eval(node.annotation)


def stubbed(module: 'object', name: 'str', arg: 'str') -> 'str':
    """The annotation of ``arg`` in ``name``'s ``__init__`` stub, as written."""
    stub = next(item for item in ast.walk(body(module, name))
                if isinstance(item, ast.FunctionDef) and item.name == '__init__')
    return ast.literal_eval(next(item for item in stub.args.args if item.arg == arg).annotation)


class CALIPSOBitmapTests(unittest.TestCase):
    """``CALIPSOOption.cmpt_bitmap`` is the tuple of octets that is stored."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    #: A CALIPSO option with a one-word compartment bitmap.
    OPTION = (bytes([7, 12]) + (0x12345678).to_bytes(4, 'big') + bytes([1, 5])
              + b'\xab\xcd' + bytes([0xde, 0xad, 0xbe, 0xef]))

    def test_parsed_bitmap_is_a_tuple_of_ints(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        for protocol in (HOPOPT, IPv6_Opts):
            with self.subTest(protocol=protocol.__name__):
                bitmap = protocol(hopopt_bytes(self.OPTION)).info.options[Option.CALIPSO].cmpt_bitmap
                self.assertEqual(bitmap, (0xde, 0xad, 0xbe, 0xef))
                self.assertIsInstance(bitmap, tuple)
                for octet in bitmap:
                    self.assertIsInstance(octet, int)

    def test_annotation_says_tuple(self) -> None:
        from pcapkit.protocols.data.internet import hopopt, ipv6_opts

        for module in (hopopt, ipv6_opts):
            with self.subTest(module=module.__name__):
                self.assertEqual(declared(module, 'CALIPSOOption', 'cmpt_bitmap'),
                                 'tuple[int, ...]')


class SMFHashBasedDPDTests(unittest.TestCase):
    """``SMFHashBasedDPDOption.post_process`` declares the schema it returns."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    #: An ``SMF_DPD`` option in H-DPD mode, i.e. with the mode bit set.
    OPTION = bytes([8, 5]) + bytes([0x80, 0x11, 0x22, 0x33, 0x44])

    def test_declaration_names_the_schema_returned(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        for protocol in (HOPOPT, IPv6_Opts):
            with self.subTest(protocol=protocol.__name__):
                schema = protocol(hopopt_bytes(self.OPTION)).schema.options[0]
                self.assertEqual(type(schema).__name__, 'SMFHashBasedDPDOption')
                self.assertEqual(type(schema).post_process.__annotations__['return'],
                                 type(schema).__name__)


class RecordRouteTests(unittest.TestCase):
    """``RROption``/``SSROption`` always hold a ``route``, as ``LSROption`` does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parsed_route_is_a_tuple(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        # One header does not hold all three: ``IHL`` caps the options at 40
        # octets, and a route option with three slots is 15.
        for code, kind in ((OptionNumber.RR, 7), (OptionNumber.SSR, 137), (OptionNumber.LSR, 131)):
            with self.subTest(code=code):
                parsed = IPv4(ipv4_bytes(bytes([kind, 15, 8]) + SLOTS)).info.options
                self.assertIsInstance(parsed[code].route, tuple)

    def test_the_three_annotations_agree(self) -> None:
        from pcapkit.protocols.data.internet import ipv4

        for name in ('RROption', 'SSROption', 'LSROption'):
            with self.subTest(name=name):
                self.assertEqual(declared(ipv4, name, 'route'), 'tuple[IPv4Address, ...]')
                self.assertEqual(stubbed(ipv4, name, 'route'), 'tuple[IPv4Address, ...]')


class NoPayloadProtochainTests(unittest.TestCase):
    """``NoPayload`` narrows ``protochain``, as it narrows ``name``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_protochain_is_none_and_says_so(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertIsNone(NoPayload().protochain)
        self.assertEqual(NoPayload.protochain.fget.__annotations__['return'], 'None')
        self.assertEqual(ProtocolBase.protochain.fget.__annotations__['return'], 'ProtoChain')


class PACKFlagsTests(unittest.TestCase):
    """The ``pack_flags`` constructor stub types the flags its field holds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_stub_matches_the_field(self) -> None:
        from pcapkit.protocols.schema.misc import pcapng

        for name, flags in (('PACK_FlagsOption', 'PACKFlags'), ('EPB_FlagsOption', 'EPBFlags')):
            with self.subTest(name=name):
                self.assertEqual(getattr(pcapng, name).__annotations__['flags'], flags)
                self.assertEqual(stubbed(pcapng, name, 'flags'), flags)


class ARPHardwareAddressTests(unittest.TestCase):
    """``ARP._make_addr_resolve`` declares the ``bytearray`` its body accepts."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    #: A well-formed ARP request, as a source of an instance to call.
    PACKET = (bytes([0, 1, 8, 0, 6, 4, 0, 1]) + bytes([1, 2, 3, 4, 5, 6])
              + bytes([10, 0, 0, 1]) + bytes(6) + bytes([10, 0, 0, 2]))

    def test_a_bytearray_resolves(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.arp import ARP

        arp = ARP(self.PACKET)
        self.assertEqual(arp._make_addr_resolve(bytearray(b'aa:bb:cc:dd:ee:ff'),
                                                Hardware.Ethernet), b'\xaa\xbb\xcc\xdd\xee\xff')
        self.assertEqual(arp._make_addr_resolve(bytearray(b'\x01\x02'), Hardware.Frame_Relay),
                         b'\x01\x02')

    def test_annotation_names_bytearray(self) -> None:
        from pcapkit.protocols.link.arp import ARP

        self.assertEqual(ARP._make_addr_resolve.__annotations__['addr'],
                         'str | bytes | bytearray')


class JournalEntryRawTests(unittest.TestCase):
    """``SystemdJournalExportBlock`` declares the ``entry_raw`` it is given.

    The parse that adds it is pinned by
    :mod:`tests.protocols.misc.test_pcapng_journal_binary_overrun_1406_unit`;
    what was missing is the declaration.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_entry_raw_is_declared(self) -> None:
        from pcapkit.protocols.data.misc import pcapng

        self.assertEqual(declared(pcapng, 'SystemdJournalExportBlock', 'entry_raw'), 'bytes')

    def test_the_reader_still_adds_it(self) -> None:
        import warnings

        from pcapkit.protocols.misc.pcapng import PCAPNG

        entry = b'BIN\n' + struct.pack('<Q', 100) + b'abc' + bytes(1)
        octets = struct.pack('<II', 9, len(entry) + 12) + entry + struct.pack('<I', len(entry) + 12)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertEqual(PCAPNG(octets, num=0, sct=0, ctx=None).info.entry_raw, octets[8:-4])


class HIPParameterNameTests(unittest.TestCase):
    """Every HIP parameter schema and data model is listed in its ``__all__``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_all_lists_every_parameter(self) -> None:
        from pcapkit.protocols.data.internet import hip as data_hip
        from pcapkit.protocols.schema.internet import hip as schema_hip

        for module in (schema_hip, data_hip):
            with self.subTest(module=module.__name__):
                parameters = {name for name, item in vars(module).items()
                              if isinstance(item, type) and item.__module__ == module.__name__
                              and issubclass(item, module.Parameter) and item is not module.Parameter}
                self.assertEqual(parameters - set(module.__all__), set())
                self.assertLessEqual({'OverlayTTLParameter', 'ViaRVSParameter'}, parameters)


class HIPReadParameterSignatureTests(unittest.TestCase):
    """Every ``HIP._read_param_*`` takes ``version`` and ``options`` by keyword."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_version_and_options_are_keyword_only(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        readers = [name for name in dir(HIP) if name.startswith('_read_param_')]
        self.assertIn('_read_param_relay_hmac', readers)
        for name in readers:
            with self.subTest(name=name):
                parameters = inspect.signature(getattr(HIP, name)).parameters
                for argument in ('version', 'options'):
                    self.assertEqual(parameters[argument].kind,
                                     inspect.Parameter.KEYWORD_ONLY)


if __name__ == '__main__':
    unittest.main()
