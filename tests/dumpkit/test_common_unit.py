from __future__ import annotations

import datetime
import decimal
import enum
import importlib.util
import io
from ipaddress import ip_address
import pathlib
import struct
import tempfile
import types
import unittest
from unittest import mock
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class PlainEnum(enum.Enum):
    VALUE = 1


class RichEnum(enum.Enum):
    VALUE = 2

    def __init__(self, value: int) -> None:
        self.label = f'value-{value}'


class BaseDumper:
    def object_hook(self, value):
        return {'base': value}

    def _encode_func(self, value):
        def encode(encoded_value, file):
            file.write(repr(encoded_value))

        return encode


class IdentityDumper:
    """A stub whose ``object_hook`` is the identity for anything it is handed.

    Unlike :class:`BaseDumper` -- used to prove the *fallback* is reached at all
    -- this is what :meth:`dictdumper.dumper.Dumper.object_hook` itself does, so
    it is what a non-PLIST format such as ``json``, ``tree`` or ``text``
    actually sees.

    """

    def object_hook(self, value: 'object') -> 'object':
        return value

    def _encode_func(self, value: 'object') -> 'object':
        raise NotImplementedError


class SlotObject:
    __slots__ = ('name',)

    def __init__(self) -> None:
        self.name = 'slot'


#: The raw :class:`bytes` client random :file:`examples/captures/test.pcapng`
#: keys a TLS key log entry by, and the text the PLIST writer interpolates for
#: it. Every character from ``0x20`` to ``0x3F``, so the ``bytes`` repr carries
#: ``&``, ``<`` and ``>`` -- and a quote of each kind, which nothing escapes
#: because neither is special inside an XML text node.
BYTES_KEY = bytes(range(0x20, 0x40))
RAW_BYTES_KEY = """b' !"#$%&\\'()*+,-./0123456789:;<=>?'"""
ESCAPED_BYTES_KEY = """b' !"#$%&amp;\\'()*+,-./0123456789:;&lt;=&gt;?'"""


def plist_like_dumper() -> 'object':
    """A dumper whose ``output`` shares PLIST's class identity, not its file I/O.

    :func:`~pcapkit.dumpkit.common.make_dumper` decides whether to escape from
    ``issubclass(output, dictdumper.plist.PLIST)``, so the stub has to inherit
    the real writer -- but nothing here writes a report, and PLIST's
    ``__init__`` opens a file.

    """
    import dictdumper.plist

    from pcapkit.dumpkit.common import make_dumper

    class PlistLikeDumper(dictdumper.plist.PLIST):
        def __init__(self, *args: 'object', **kwargs: 'object') -> None:  # pylint: disable=super-init-not-called
            pass

    return make_dumper(PlistLikeDumper)('unused')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DumpkitCommonTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_dumper_subclass_registration_is_opt_in(self) -> None:
        """Registration happens if and only if ``fmt`` is given.

        This is the #514 opt-in contract, extended to the fifth pair. Before it,
        an absent ``fmt`` was *inferred* from the subclass'
        :attr:`~dictdumper.dumper.Dumper.kind` property -- which is an instance
        property, so the old code constructed an instance against a
        :func:`tempfile.NamedTemporaryFile` while the ``class`` statement was
        still executing. A class definition no longer touches the filesystem.

        """
        from pcapkit.dumpkit.common import Dumper

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                class ExplicitDumper(Dumper, fmt='CUSTOM', ext='.custom'):
                    pass

        extractor.assert_called_once_with('custom', ExplicitDumper, '.custom')
        traceflow.assert_called_once_with('custom', ExplicitDumper, '.custom')

        # ``ext`` is still inferred from ``fmt`` -- that is a default for a format
        # that *was* given, not a decision to register.
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                class FormatOnlyDumper(Dumper, fmt='FMTONLY'):
                    pass

        extractor.assert_called_once_with('fmtonly', FormatOnlyDumper, '.fmtonly')
        traceflow.assert_called_once_with('fmtonly', FormatOnlyDumper, '.fmtonly')

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                with mock.patch('tempfile.NamedTemporaryFile') as named_temp:
                    class InferredDumper(Dumper):
                        @property
                        def kind(self):
                            return 'AUTO'

        extractor.assert_not_called()
        traceflow.assert_not_called()
        # the old inference path is gone, not merely unused
        named_temp.assert_not_called()

    def test_dumper_subclass_rejects_ext_without_fmt(self) -> None:
        """``ext`` alone cannot register anything, so it raises rather than no-op.

        With registration keyed on ``fmt``, an ``ext`` on its own has no format
        to attach to. Accepting it would silently discard the caller's intent.

        """
        from pcapkit.dumpkit.common import Dumper
        from pcapkit.utilities.exceptions import UnsupportedCall

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with self.assertRaises(UnsupportedCall) as caught:
                class ExtOnly(Dumper, ext='.lonely'):
                    pass

        extractor.assert_not_called()
        self.assertIn('.lonely', str(caught.exception))

    def test_dumper_subclass_rejects_unrecognised_keyword(self) -> None:
        """A misspelled class keyword raises instead of being swallowed."""
        from pcapkit.dumpkit.common import Dumper
        from pcapkit.utilities.exceptions import UnsupportedCall

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with self.assertRaises(UnsupportedCall) as caught:
                class Typo(Dumper, format='wrong-keyword-for-dumper'):
                    pass

        extractor.assert_not_called()
        self.assertIn('format', str(caught.exception))

    def test_make_dumper_object_hook_conversions_and_fallbacks(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.dumpkit.common import make_dumper

        Dumper = make_dumper(BaseDumper)
        dumper = Dumper()

        self.assertEqual(dumper.object_hook(decimal.Decimal('1.25')), '1.25')
        self.assertEqual(dumper.object_hook(datetime.timedelta(seconds=2.5)), 2.5)
        plain_dict = {'plain': 'dict'}
        self.assertIs(dumper.object_hook(plain_dict), plain_dict)
        self.assertEqual(dumper.object_hook(Info(answer=42)), {'answer': 42})
        self.assertEqual(dumper.object_hook(ip_address('192.0.2.1')), '192.0.2.1')

        multidict = MultiDict()
        multidict.add(PlainEnum.VALUE, 'enum-value')
        multidict.add('plain', 'value')
        converted = dumper.object_hook(multidict)
        self.assertEqual(converted['PlainEnum::VALUE [1]'], ['enum-value'])
        self.assertEqual(converted['plain'], ['value'])

        ordered = OrderedMultiDict([('first', 1), ('first', 2)])
        self.assertEqual(dumper.object_hook(ordered)['first'], [1, 2])

        self.assertEqual(dumper.object_hook(PlainEnum.VALUE), 'PlainEnum::VALUE [1]')
        rich = dumper.object_hook(RichEnum.VALUE)
        self.assertEqual(rich['enum'], 'RichEnum::VALUE [2]')
        self.assertEqual(rich['label'], 'value-2')
        self.assertEqual(dumper.object_hook(object())['base'].__class__, object)
        self.assertEqual(dumper.default(object()), 'fallback')

        file = io.StringIO()
        dumper._append_fallback(SlotObject(), file)
        self.assertEqual(file.getvalue(), "{'name': 'slot'}")

        file = io.StringIO()
        dumper._append_fallback(types.SimpleNamespace(name='dict'), file)
        self.assertEqual(file.getvalue(), "{'name': 'dict'}")

        file = io.StringIO()
        dumper._append_fallback(123, file)
        self.assertEqual(file.getvalue(), "'123'")

    def test_make_dumper_escapes_strings_only_for_plist_like_output(self) -> None:
        """GitHub issue #772: no entity escaping anywhere in :mod:`dictdumper`.

        ``dictdumper.plist.PLIST`` (which is also what ``'xml'`` maps to --
        see ``Extractor.__output__``) interpolates every ``<string>``/``<key>``
        value straight into its markup, so a value containing ``&``, ``<`` or
        ``>`` breaks the document it is embedded in. Filed upstream as
        JarryShaw/DictDumper#125. ``json``/``tree``/``text`` have no such
        defect and all three characters are legal there, so the escaping in
        :func:`~pcapkit.dumpkit.common.make_dumper` must fire for a
        PLIST-rooted ``output`` and stay off for anything else -- a plain
        :class:`str`, an enum rendered by :func:`~pcapkit.dumpkit.common.render_enum`,
        and a :class:`~pcapkit.corekit.multidict.MultiDict` key built from one,
        since that key is written by the PLIST writer directly and never
        passed back through this hook the way a value is.

        """
        from pcapkit.corekit.multidict import MultiDict
        from pcapkit.dumpkit.common import make_dumper

        plist_dumper = plist_like_dumper()
        self.assertEqual(plist_dumper.object_hook('a & b <c>'), 'a &amp; b &lt;c&gt;')

        unknown = enum.IntEnum('<unknown>', {'<unassigned>': 1})
        member = getattr(unknown, '<unassigned>')
        self.assertEqual(plist_dumper.object_hook(member),
                          '&lt;unknown&gt;::&lt;unassigned&gt; [1]')

        multidict = MultiDict()
        multidict.add(member, 'value')
        converted = plist_dumper.object_hook(multidict)
        self.assertEqual(converted['&lt;unknown&gt;::&lt;unassigned&gt; [1]'], ['value'])

        plain_dumper = make_dumper(IdentityDumper)()
        self.assertEqual(plain_dumper.object_hook('a & b <c>'), 'a & b <c>')
        self.assertEqual(plain_dumper.object_hook(member), '<unknown>::<unassigned> [1]')

    def test_make_dumper_escapes_mapping_keys_for_plist_like_output(self) -> None:
        """GitHub issue #772, the half the hook above cannot reach.

        ``dictdumper/plist.py:202`` writes a key as
        ``'<key>{item}</key>'.format(item=item)`` and calls ``_encode_value`` on
        the *value* two lines down, never on the key -- so
        :meth:`object_hook` is handed every value the writer interpolates and no
        key at all, and the escaping proven above cannot reach one. Both
        branches that build a mapping therefore escape their own keys:
        :class:`~pcapkit.corekit.multidict.MultiDict`, where only an
        enum-derived key was escaped before, and a plain :class:`dict`, where
        nothing was.

        The :class:`bytes` key is :file:`examples/captures/test.pcapng`'s own,
        and it is the reason that fixture's ``plist`` report did not parse:
        ``&``, ``<`` and ``>`` all inside one key. It is rendered with
        :func:`format`, i.e. the conversion the writer's interpolation already
        applies to it, so the ``<key>`` text is unchanged apart from the
        escaping -- which is what the :data:`RAW_BYTES_KEY` assertion pins,
        since an expected escaping is only as good as the rendering it is
        derived from.

        """
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        plist_dumper = plist_like_dumper()

        # A plain dict: str keys, and the bytes key of the fixture.
        self.assertEqual(format(BYTES_KEY, ''), RAW_BYTES_KEY)
        converted = plist_dumper.object_hook({'a & b <c>': 'value', BYTES_KEY: 'secret'})
        self.assertEqual(list(converted), ['a &amp; b &lt;c&gt;', ESCAPED_BYTES_KEY])
        self.assertEqual(converted['a &amp; b &lt;c&gt;'], 'value')
        self.assertEqual(converted[ESCAPED_BYTES_KEY], 'secret')

        # A MultiDict: a plain-str key was interpolated raw until now, and the
        # bytes key of the fixture arrives through here rather than through the
        # dict branch -- its TLS key log entries are an OrderedMultiDict.
        multidict = OrderedMultiDict()
        multidict.add('a & b <c>', 'value')
        multidict.add(BYTES_KEY, 'secret')
        converted = plist_dumper.object_hook(multidict)
        self.assertEqual(list(converted), ['a &amp; b &lt;c&gt;', ESCAPED_BYTES_KEY])
        self.assertEqual(converted[ESCAPED_BYTES_KEY], ['secret'])

        # An enum-derived key is still escaped exactly once: the escaping moved
        # out of this branch and into one shared helper, so escaping it twice is
        # the shape of mistake that move could have made.
        unknown = enum.IntEnum('<unknown>', {'<unassigned>': 1})
        member = getattr(unknown, '<unassigned>')
        multidict = MultiDict()
        multidict.add(member, 'value')
        converted = plist_dumper.object_hook(multidict)
        self.assertEqual(list(converted), ['&lt;unknown&gt;::&lt;unassigned&gt; [1]'])
        self.assertNotIn('&amp;', ''.join(converted))

    def test_make_dumper_hands_other_output_the_mapping_it_was_given(self) -> None:
        """``json``, ``tree`` and ``text`` take all three characters literally.

        So no key is escaped for them, and -- the stronger statement, and the
        one that keeps this branch free of any risk of double-escaping -- a
        plain :class:`dict` is not even rebuilt: the writer is handed the
        caller's own mapping, with the caller's own key objects in it, exactly
        as it was before #772. A :class:`bytes` key stays :class:`bytes` there,
        which is what ``dictdumper``'s ``json`` writer then breaks on, for
        reasons of its own.

        """
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.dumpkit.common import make_dumper

        plain_dumper = make_dumper(IdentityDumper)()

        mapping = {'a & b <c>': 'value', BYTES_KEY: 'secret'}
        self.assertIs(plain_dumper.object_hook(mapping), mapping)

        multidict = OrderedMultiDict()
        multidict.add('a & b <c>', 'value')
        multidict.add(BYTES_KEY, 'secret')
        converted = plain_dumper.object_hook(multidict)
        self.assertEqual(list(converted), ['a & b <c>', BYTES_KEY])

    def test_an_unassigned_port_dumps_its_addon_keys_in_the_declared_order(self) -> None:
        """GitHub issue #575's fallback must not reorder what it renders.

        :meth:`object_hook` builds a member's addon mapping straight out of its
        :attr:`~object.__dict__`, which preserves insertion order, so the order
        the attributes were *set* in is the order they are dumped in.
        ``AppType.__new__`` sets ``svc``, then ``port``, then ``proto``, while
        :meth:`~pcapkit.corekit.fields.numbers.EnumField._unregistered_member`
        sets them in whatever order its caller passes them -- so a mismatch
        there flips every unassigned port's keys relative to every declared
        one's, in all four output formats, while leaving every value correct
        and every test that reads by key still passing. Measured on
        ``examples/captures/http.pcap``: 1117 rendered port blocks of each
        kind, and with the two keyword arguments the other way round the
        unassigned ones read ``port, svc, proto`` against the declared
        ``svc, port, proto``.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.dumpkit.common import make_dumper
        from pcapkit.protocols.schema.transport import tcp as tcp_schema

        dumper = make_dumper(BaseDumper)()
        field = tcp_schema.PortEnumField(length=2, namespace=AppType)

        declared = dumper.object_hook(AppType.get(80, proto=TransportProtocol.tcp))
        unassigned = dumper.object_hook(field.unpack(b'\xd4\x31', {}))  # 54321

        self.assertEqual(list(declared), ['enum', 'svc', 'port', 'proto'])
        self.assertEqual(list(unassigned), list(declared))
        self.assertEqual(unassigned['svc'], 'unknown')
        self.assertEqual(unassigned['port'], 54321)

    def test_an_undeclared_option_code_dumps_its_addon_keys_in_order_too(self) -> None:
        """The same invariant for PCAP-NG's option types.

        ``OptionType.__new__`` sets ``opt_name`` then ``opt_value``, and
        :class:`~pcapkit.protocols.schema.misc.pcapng.OptionEnumField` already
        passes them that way -- this pins it, since nothing else would notice
        if the two keyword arguments were ever swapped.

        """
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.dumpkit.common import make_dumper
        from pcapkit.protocols.schema.misc import pcapng as pcapng_schema

        dumper = make_dumper(BaseDumper)()
        field = pcapng_schema.OptionEnumField(length=2, namespace='if')

        declared = dumper.object_hook(OptionType.if_tsresol)
        undeclared = dumper.object_hook(field.unpack(b'\x27\x0f', {}))  # 9999

        self.assertEqual(list(declared), ['enum', 'opt_name', 'opt_value'])
        self.assertEqual(list(undeclared), list(declared))
        self.assertEqual(undeclared['opt_name'], 'if_unknown')
        self.assertEqual(undeclared['opt_value'], 9999)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DumpkitIOTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_null_dumper_noops_and_pcap_dumper_writes_file(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        with tempfile.TemporaryDirectory() as tempdir:
            null_path = pathlib.Path(tempdir) / 'null.out'
            null = NotImplementedIO(str(null_path))
            self.assertEqual(null.kind, 'null')
            self.assertIs(null({'ignored': True}), null)
            null._append_value({'ignored': True}, io.StringIO(), '')

            pcap_path = pathlib.Path(tempdir) / 'sample.pcap'
            dumper = PCAPIO(str(pcap_path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)
            self.assertEqual(dumper.kind, 'pcap')
            header_size = pcap_path.stat().st_size
            frame = Frame(
                frame_info=FrameInfo(ts_sec=1, ts_usec=250000,
                                     incl_len=4, orig_len=4),
                time='time',
                number=1,
                time_epoch=1.25,
                len=4,
                cap_len=4,
            )
            frame.__update__(packet=b'abcd')
            self.assertIs(dumper(frame), dumper)
            self.assertGreater(pcap_path.stat().st_size, header_size)

    def test_pcap_dumper_writes_the_record_header_in_the_global_header_byte_order(self) -> None:
        # The dumper writes the 16-octet record header itself instead of building a
        # Frame to pack it, so the byte order of those four uint32 fields is now this
        # module's responsibility rather than the schema's. It has to match the magic
        # number in front of them, and 'big' has to keep working on a little-endian
        # host -- which is exactly what a struct format hardcoded to one endianness
        # would silently get wrong.
        #
        # Values are chosen to be byte-order-visible: every field is asymmetric, so a
        # wrong endianness cannot coincide with a right one.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        payload = bytes(range(6))
        for byteorder, endian in (('little', '<'), ('big', '>')):
            for nanosecond in (False, True):
                with self.subTest(byteorder=byteorder, nanosecond=nanosecond):
                    with tempfile.TemporaryDirectory() as tempdir:
                        path = pathlib.Path(tempdir) / 'sample.pcap'
                        dumper = PCAPIO(str(path), protocol=LinkType.ETHERNET,
                                        byteorder=byteorder, nanosecond=nanosecond)
                        header_size = path.stat().st_size

                        frame = Frame(
                            frame_info=FrameInfo(ts_sec=0x01020304, ts_usec=0x05060708,
                                                 incl_len=len(payload), orig_len=0x0A0B0C0D),
                            time='time', number=1, time_epoch=1.25,
                            len=len(payload), cap_len=0x0A0B0C0D,
                        )
                        frame.__update__(packet=payload)
                        dumper(frame)

                        self.assertEqual(
                            path.read_bytes()[header_size:],
                            struct.pack(f'{endian}IIII', 0x01020304, 0x05060708,
                                        len(payload), 0x0A0B0C0D) + payload,
                        )

    def test_pcap_dumper_truncates_an_out_of_range_record_field(self) -> None:
        # UInt32Field, which used to pack these four fields, masks to the field width
        # in NumberField.pre_process instead of rejecting an out-of-range value, so
        # the dumper silently wrote a wrapped one. struct.pack raises on the same
        # input, so writing the header directly would have turned a written -- if
        # wrong -- record into a struct.error. Pinned so the mask is not mistaken for
        # dead defensiveness and dropped: this is behaviour being preserved, not
        # behaviour being chosen.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / 'sample.pcap'
            dumper = PCAPIO(str(path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)
            header_size = path.stat().st_size

            frame = Frame(
                frame_info=FrameInfo(ts_sec=2 ** 32 + 5, ts_usec=7,
                                     incl_len=2, orig_len=2),
                time='time', number=1, time_epoch=1.0, len=2, cap_len=2,
            )
            frame.__update__(packet=b'ab')
            dumper(frame)

            self.assertEqual(path.read_bytes()[header_size:],
                             struct.pack('<IIII', 5, 7, 2, 2) + b'ab')

    def test_pcap_dumper_appends_each_frame_without_reparsing_it(self) -> None:
        # Successive frames have to accumulate, and each record has to be the caller's
        # own octets verbatim -- the dumper no longer round-trips them through a Frame
        # construction, which packed the record and then dissected it again through
        # the whole protocol stack to reach bytes it had just been handed.
        #
        # The payload here is deliberately not a valid Ethernet frame: under the old
        # rebuild it was dissected anyway, so a dumper that reparses is not merely
        # slower but is doing work that can warn or raise on data it only had to copy.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        def make(number: int, packet: bytes) -> Frame:
            frame = Frame(
                frame_info=FrameInfo(ts_sec=number, ts_usec=0, incl_len=len(packet),
                                     orig_len=len(packet)),
                time='time', number=number, time_epoch=float(number),
                len=len(packet), cap_len=len(packet),
            )
            frame.__update__(packet=packet)
            return frame

        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / 'sample.pcap'
            dumper = PCAPIO(str(path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)
            header_size = path.stat().st_size

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                self.assertIs(dumper(make(1, b'\xff' * 3)), dumper)
                self.assertIs(dumper(make(2, b'\xfe' * 5)), dumper)

            self.assertEqual(
                path.read_bytes()[header_size:],
                struct.pack('<IIII', 1, 0, 3, 3) + b'\xff' * 3
                + struct.pack('<IIII', 2, 0, 5, 5) + b'\xfe' * 5,
            )
            # The frame counter still advances once per frame, and nothing was parsed.
            self.assertEqual(dumper._fnum, 3)
            self.assertEqual([str(entry.message) for entry in caught], [])

    def test_pcap_dumper_cannot_serialise_a_mapping_frame(self) -> None:
        # Why Extractor substitutes a dict-capable trace format for the DPKT, Scapy,
        # PyShark and PyPCAPFile engines: their flow-tracing adapters report each
        # frame as a plain dict from ``packet2dict``, and this dumper reads
        # ``value.packet`` and ``value.frame_info`` off a dissected Frame. Pinned
        # here so the guard's justification is checked rather than asserted in a
        # comment -- if this dumper ever learns to take a mapping, the guard is what
        # should be revisited.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO

        with tempfile.TemporaryDirectory() as tempdir:
            pcap_path = pathlib.Path(tempdir) / 'mapping.pcap'
            dumper = PCAPIO(str(pcap_path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)

            # The shape ``packet2dict`` produces: keys, not attributes.
            with self.assertRaises(AttributeError) as caught:
                dumper({'frame_info': {'ts_sec': 1}, 'packet': b'abcd'}, name='Frame 1')
            self.assertIn('packet', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
