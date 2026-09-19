from __future__ import annotations

import datetime
import importlib.util
import io
from ipaddress import ip_address
import types
import unittest
from unittest import mock
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv4UnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ipv4_index_returns_expected_registry_value(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4

        self.assertEqual(IPv4.__index__(), TransType.IPv4)

    def test_ipv4_make_data_preserves_selected_fields(self) -> None:
        from datetime import timedelta

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4

        class DummyDict(dict):
            __getattr__ = dict.__getitem__

        data = DummyDict(
            tos=DummyDict(pre=0, thr=False, rel=False, ecn=0, **{'del': False}),
            id=7,
            flags=DummyDict(df=True, mf=False),
            offset=0,
            ttl=timedelta(seconds=64),
            protocol=TransType.TCP,
            checksum=b'\x12\x34',
            src='192.0.2.10',
            dst='198.51.100.20',
            options=[],
            __next_type__=None,
        )

        values = IPv4._make_data(data)
        self.assertEqual(values['id'], 7)
        self.assertEqual(values['df'], True)
        self.assertEqual(values['mf'], False)
        self.assertEqual(values['protocol'], TransType.TCP)
        self.assertEqual(values['src'], '192.0.2.10')
        self.assertEqual(values['dst'], '198.51.100.20')
        self.assertIn('payload', values)

    def test_ipv4_make_data_scales_offset_and_defaults_missing_options(self) -> None:
        """Regression test for #494.

        Two defects live in :meth:`IPv4._make_data
        <pcapkit.protocols.internet.ipv4.IPv4._make_data>`: the fragment
        ``offset`` was handed back in octets to a parameter that
        :meth:`IPv4.make <pcapkit.protocols.internet.ipv4.IPv4.make>` takes in
        on-wire 8-octet units (:rfc:`791`), and ``data.options`` was read
        unconditionally even though :meth:`IPv4.read
        <pcapkit.protocols.internet.ipv4.IPv4.read>` only sets it when
        ``hdr_len`` exceeds the fixed 20-octet header.

        The two interact: the missing-``options`` ``AttributeError`` fires
        before the unscaled ``offset`` can even be returned, so a fixture
        that always supplies ``options`` -- like the ``DummyDict`` one above,
        which also uses ``offset=0``, the one value for which the missing
        ``// 8`` is invisible -- cannot catch either. This test uses a
        non-zero offset *and* a real packet with no options, so both
        defects are exercised together, exactly as the issue's own repro
        does.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = object.__new__(IPv4)

        # Wire Fragment Offset of 5 (8-octet units), no options -> hdr_len
        # stays at the fixed 20 octets and read() never sets ``.options``.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw = proto.make(offset=5, protocol=6, payload=b'\xaa' * 8).pack()
            data = IPv4(io.BytesIO(raw), len(raw)).info

        self.assertFalse(hasattr(data, 'options'))
        self.assertEqual(data.offset, 40)  # read() scales wire units to octets

        values = IPv4._make_data(data)
        self.assertEqual(values['offset'], 5)  # scaled back down to wire units
        self.assertIsNone(values['options'])

        # Full round trip: re-packing with the recovered offset must
        # reproduce the exact original wire bytes.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw2 = proto.make(offset=values['offset'], protocol=6,
                              payload=b'\xaa' * 8).pack()
        self.assertEqual(raw, raw2)

    def test_ipv4_properties_read_and_make_cover_packet_paths(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)
        proto._info = types.SimpleNamespace(
            hdr_len=20,
            protocol=TransType.TCP,
            src=ip_address('192.0.2.1'),
            dst=ip_address('198.51.100.1'),
        )
        self.assertEqual(proto.name, 'Internet Protocol version 4')
        self.assertEqual(proto.length, 20)
        self.assertEqual(proto.protocol, TransType.TCP)
        self.assertEqual(proto.src, ip_address('192.0.2.1'))
        self.assertEqual(proto.dst, ip_address('198.51.100.1'))
        self.assertEqual(proto.__length_hint__(), 20)
        self.assertEqual(IPv4.id(), ('IPv4',))

        proto.__header__ = ipv4_schema.IPv4(
            vihl={'version': 4, 'ihl': 7},
            tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
            length=32,
            id=7,
            flags={'df': 1, 'mf': 0, 'offset': 1},
            ttl=64,
            proto=TransType.TCP,
            chksum=b'\x12\x34',
            src='192.0.2.1',
            dst='198.51.100.1',
            options=[
                ipv4_schema.SIDOption(type=OptionNumber.SID, length=4, sid=55),
                ipv4_schema.EOOLOption(type=OptionNumber.EOOL),
            ],
            payload=b'data',
        )
        proto._data = b'\x00' * 32
        proto.__cached__ = {}
        proto._decode_next_layer = mock.Mock(return_value='decoded')

        self.assertEqual(proto.read(), 'decoded')
        decoded_ip, next_type, payload_length = proto._decode_next_layer.call_args.args
        self.assertEqual(decoded_ip.hdr_len, 28)
        self.assertEqual(decoded_ip.options[OptionNumber.SID].sid, 55)
        self.assertEqual(decoded_ip.offset, 8)
        self.assertEqual(next_type, TransType.TCP)
        self.assertEqual(payload_length, 4)

        proto.__header__ = ipv4_schema.IPv4(
            vihl={'version': 4, 'ihl': 5},
            tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
            length=24,
            id=8,
            flags={'df': 0, 'mf': 0, 'offset': 0},
            ttl=32,
            proto=TransType.UDP,
            chksum=b'\x00\x00',
            src='192.0.2.2',
            dst='198.51.100.2',
            options=[],
            payload=b'data',
        )
        proto._decode_next_layer.reset_mock()
        self.assertEqual(proto.read(length=24), 'decoded')
        decoded_no_options = proto._decode_next_layer.call_args.args[0]
        self.assertFalse(hasattr(decoded_no_options, 'options'))

        proto.__header__ = ipv4_schema.IPv4(
            vihl={'version': 6, 'ihl': 5},
            tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
            length=20,
            id=1,
            flags={'df': 0, 'mf': 0, 'offset': 0},
            ttl=1,
            proto=TransType.UDP,
            chksum=b'\x00\x00',
            src='192.0.2.1',
            dst='198.51.100.1',
            options=[],
            payload=b'',
        )
        with self.assertRaises(ProtocolError):
            proto.read(length=20)

        made = proto.make(
            ttl=datetime.timedelta(seconds=64),
            protocol=TransType.TCP,
            src='192.0.2.1',
            dst='198.51.100.1',
            options=[(OptionNumber.SID, {'sid': 5})],
            payload=b'data',
        )
        self.assertEqual(made.length, 32)
        self.assertEqual(made.vihl['ihl'], 7)
        self.assertEqual(made.ttl, 64)
        self.assertEqual(made.proto, TransType.TCP)

        no_options = proto.make(options=None, payload=b'')
        self.assertEqual(no_options.length, 20)
        self.assertEqual(no_options.vihl['ihl'], 5)

    def test_ipv4_register_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        registry = IPv4.__dict__['__option__']

        original = registry[OptionNumber.EOOL]
        try:
            with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                IPv4.register_option(OptionNumber.EOOL, 'eool')
            warn.assert_called_once()
            self.assertEqual(registry[OptionNumber.EOOL], 'eool')
        finally:
            registry[OptionNumber.EOOL] = original

        # An unregistered code carries no entry, so registering one is not an
        # overwrite. The setattr form could not tell the two apart: it keyed the
        # warning on ``hasattr(cls, f'_read_opt_{name}')``, which is true of every
        # shipped handler as well as of anything a user had already installed.
        custom = OptionNumber.get(31)
        self.assertNotIn(custom, registry)
        try:
            with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                IPv4.register_option(custom, 'unassigned')
            warn.assert_not_called()
            self.assertEqual(registry[custom], 'unassigned')

            with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                IPv4.register_option(custom, 'unassigned')
            warn.assert_called_once()
        finally:
            registry.pop(custom, None)

    def test_ipv4_register_option_dispatches_a_registered_callable_pair(self) -> None:
        """A ``(parser, constructor)`` pair must reach both dispatch directions.

        The pair is called with the signatures :data:`OptionParser` and
        :data:`OptionConstructor` declare -- ``(schema, *, options)`` and
        ``(code, option=None, **kwargs)`` -- i.e. as plain callables rather than
        as methods with an implicit ``self``. That is the calling convention
        every other dispatch family uses, and the reason the registry form
        replaced ``setattr``: installing the callable on the class made it a
        descriptor, so dispatch passed ``self`` as the first positional argument
        and a handler written to the declared signature could not be called at
        all.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import ipv4 as ipv4_data
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema

        registry = IPv4.__dict__['__option__']
        custom = OptionNumber.get(31)
        proto = object.__new__(IPv4)
        seen = []  # type: list[str]

        def read_option(schema, *, options):
            seen.append('read')
            return ipv4_data.UnassignedOption(
                code=schema.type,
                type=proto._read_ipv4_opt_type(schema.type),
                length=schema.length,
                data=schema.data,
            )

        def make_option(code, option=None, *, data=b'', **kwargs):
            seen.append('make')
            if option is not None:
                data = option.data
            return ipv4_schema.UnassignedOption(type=code, length=len(data) + 2,
                                                data=data)

        self.assertNotIn(custom, registry)
        try:
            IPv4.register_option(custom, (read_option, make_option))
            self.assertEqual(registry[custom], (read_option, make_option))

            proto.__header__ = types.SimpleNamespace(
                options=[ipv4_schema.UnassignedOption(type=custom, length=4,
                                                      data=b'xx')],
            )
            parsed = proto._read_ipv4_options(4)
            self.assertEqual(seen, ['read'])
            self.assertEqual(parsed[custom].data, b'xx')

            # the list-of-tuples branch of the constructor
            seen.clear()
            made_list, list_len = proto._make_ipv4_options([(custom, {'data': b'yy'})])
            self.assertEqual(seen, ['make'])
            self.assertEqual(made_list[0].data, b'yy')
            self.assertEqual(list_len, 4)

            # ... and the OrderedMultiDict branch, which the two halves of an
            # issue like this are equally easy to fix one of and forget the other
            seen.clear()
            made_dict, dict_len = proto._make_ipv4_options(
                OrderedMultiDict([(custom, parsed[custom])]))
            self.assertEqual(seen, ['make'])
            self.assertEqual(made_dict[0].data, b'xx')
            self.assertEqual(dict_len, 4)
        finally:
            registry.pop(custom, None)

    def test_ipv4_option_registry_covers_every_shipped_handler(self) -> None:
        """Every ``_read_opt_*`` / ``_make_opt_*`` pair must be reachable.

        The setattr form derived the handler name from ``code.name.lower()``, so
        a handler was reachable by construction and "what is registered?" had no
        direct answer. Under the registry the mapping is explicit data, which
        means a handler added without its registry entry becomes dead code --
        this pins the two sides together.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        registry = IPv4.__dict__['__option__']
        fallback = registry.default_factory()
        self.assertEqual(fallback, 'unassigned')

        registered = set(registry.values()) | {fallback}
        shipped = {name[len('_read_opt_'):] for name in vars(IPv4)
                   if name.startswith('_read_opt_')}
        self.assertEqual(shipped, registered)
        self.assertEqual(
            {name[len('_make_opt_'):] for name in vars(IPv4)
             if name.startswith('_make_opt_')},
            registered,
        )

        # every key is a real option number, and every value names real methods
        for code, name in registry.items():
            with self.subTest(code=code):
                self.assertIsInstance(code, OptionNumber)
                self.assertTrue(hasattr(IPv4, f'_read_opt_{name}'))
                self.assertTrue(hasattr(IPv4, f'_make_opt_{name}'))

    def test_ipv4_unregistered_option_code_does_not_mutate_the_registry(self) -> None:
        """Parsing must not write to the shared IPv4 option registry.

        :attr:`IPv4.__option__ <pcapkit.protocols.internet.ipv4.IPv4.__option__>`
        is a :class:`collections.defaultdict` on a class attribute shared by
        every instance in the process, so ``registry[code]`` would insert each
        code it missed -- the leak #428 swept out of the sixteen registries that
        already existed. This one is new, so the guard has to be pinned here too:
        the reads go through
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._lookup_registry`.

        Option number 31 is unassigned in IANA's registry and 134 is ``CIPSO``,
        which is assigned but has no parser, so both take the fallback.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema

        registry = IPv4.__dict__['__option__']
        proto = object.__new__(IPv4)

        for code in (OptionNumber.get(31), OptionNumber.CIPSO):
            with self.subTest(code=code):
                before = set(registry)
                self.assertNotIn(code, before)

                proto.__header__ = types.SimpleNamespace(
                    options=[ipv4_schema.UnassignedOption(type=code, length=4,
                                                          data=b'xx')],
                )
                proto._read_ipv4_options(4)
                self.assertEqual(set(registry), before)

                # both constructor branches, since either can leak on its own
                proto._make_ipv4_options([(code, {'data': b'xx'})])
                self.assertEqual(set(registry), before)

                # The OrderedMultiDict branch cannot get as far as building the
                # option: :meth:`IPv4._make_opt_unassigned
                # <pcapkit.protocols.internet.ipv4.IPv4._make_opt_unassigned>`
                # declares ``data`` keyword-only with no default, where every
                # sibling fallback constructor defaults it to ``b''``, so it
                # raises before reading the payload out of ``option.data``. That
                # predates the registry migration and is left alone here; what
                # this asserts is that the *lookup* which runs first still does
                # not insert.
                with self.assertRaises(TypeError):
                    proto._make_ipv4_options(OrderedMultiDict([
                        (code, types.SimpleNamespace(data=b'xx')),
                    ]))
                self.assertEqual(set(registry), before)

                # a leak would make the next genuine registration warn
                with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                    try:
                        IPv4.register_option(code, 'unassigned')
                        warn.assert_not_called()
                    finally:
                        registry.pop(code, None)

    def test_ipv4_option_constructors_cover_common_and_error_branches(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)

        unknown = proto._make_opt_unassigned(OptionNumber.get(31), data=b'abc')
        self.assertEqual(unknown.to_dict()['length'], 3)
        self.assertEqual(unknown.to_dict()['data'], b'abc')

        self.assertEqual(proto._make_opt_eool(OptionNumber.EOOL).to_dict()['length'], 1)
        self.assertEqual(proto._make_opt_nop(OptionNumber.NOP).to_dict()['length'], 1)

        sec = proto._make_opt_sec(
            OptionNumber.SEC,
            authorities=[ProtectionAuthority.GENSER, ProtectionAuthority.Field_Termination_Indicator],
        )
        self.assertEqual(sec.to_dict()['length'], 4)
        self.assertEqual(sec.to_dict()['data'], b'\x81')

        loose = proto._make_opt_lsr(OptionNumber.LSR, counts=2, route=['192.0.2.1'])
        self.assertEqual(loose.to_dict()['length'], 11)
        self.assertEqual(loose.to_dict()['pointer'], 8)

        ts_only = proto._make_opt_ts(OptionNumber.TS, counts=2,
                                     timestamp=[datetime.timedelta(seconds=1), 2])
        self.assertEqual(ts_only.to_dict()['length'], 12)
        self.assertEqual(ts_only.to_dict()['flags']['flag'], TSFlag.Timestamp_Only)

        ts_with_ip = proto._make_opt_ts(
            OptionNumber.TS,
            counts=2,
            timestamp={
                ip_address('192.0.2.1'): 0,
                ip_address('192.0.2.2'): datetime.timedelta(seconds=3),
            },
        )
        self.assertEqual(ts_with_ip.to_dict()['length'], 20)
        self.assertEqual(ts_with_ip.to_dict()['flags']['flag'], TSFlag.Prespecified_IP_with_Timestamp)

        self.assertEqual(proto._make_opt_e_sec(OptionNumber.E_SEC, format=1,
                                               info=b'info').to_dict()['length'], 7)
        self.assertEqual(proto._make_opt_rr(OptionNumber.RR, counts=2,
                                            route=['192.0.2.1', '192.0.2.2']).to_dict()['pointer'], 12)
        self.assertEqual(proto._make_opt_sid(OptionNumber.SID, sid=123).to_dict()['sid'], 123)
        self.assertEqual(proto._make_opt_ssr(OptionNumber.SSR, counts=2,
                                             route=['192.0.2.1']).to_dict()['pointer'], 8)
        self.assertEqual(proto._make_opt_mtup(OptionNumber.MTUP, mtu=1500).to_dict()['mtu'], 1500)
        self.assertEqual(proto._make_opt_mtur(OptionNumber.MTUR, mtu=1500).to_dict()['mtu'], 1500)
        self.assertEqual(proto._make_opt_tr(OptionNumber.TR, id=1, out=2, ret=3,
                                            origin='192.0.2.9').to_dict()['origin'], '192.0.2.9')
        self.assertEqual(proto._make_opt_rtralt(OptionNumber.RTRALT, alert=0).to_dict()['alert'], 0)

        request = proto._make_opt_qs(OptionNumber.QS, func=QSFunction.Quick_Start_Request,
                                     rate=80, ttl=datetime.timedelta(seconds=7), nonce=3)
        self.assertEqual(request.to_dict()['ttl'], 7)
        self.assertEqual(request.to_dict()['flags']['rate'], 1)

        report = proto._make_opt_qs(OptionNumber.QS, func=QSFunction.Report_of_Approved_Rate,
                                    rate=80, nonce=3)
        self.assertEqual(report.to_dict()['flags']['func'], QSFunction.Report_of_Approved_Rate)

        options, total_length = proto._make_ipv4_options([
            b'\x1fabc',
            (OptionNumber.SID, {'sid': 5}),
            (OptionNumber.NOP, {}),
        ])
        self.assertEqual(total_length, 12)
        self.assertEqual([type(item).__name__ for item in options], ['bytes', 'SIDOption', 'NOPOption', 'OptionNumber'])
        self.assertEqual(options[-1], OptionNumber.EOOL)

        with self.assertRaises(ProtocolError):
            proto._make_opt_ts(OptionNumber.TS, timestamp=None)
        with self.assertRaises(ProtocolError):
            proto._make_opt_qs(OptionNumber.QS, func=99)

    def test_ipv4_option_constructors_cover_data_model_and_mapping_paths(self) -> None:
        from pcapkit.const.ipv4.classification_level import ClassificationLevel
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.router_alert import RouterAlert
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import ipv4 as ipv4_data
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = object.__new__(IPv4)

        def opt_type(code):
            return proto._read_ipv4_opt_type(code)

        unassigned = ipv4_data.UnassignedOption(
            code=OptionNumber.get(31),
            type=opt_type(OptionNumber.get(31)),
            length=5,
            data=b'abcde',
        )
        self.assertEqual(proto._make_opt_unassigned(
            OptionNumber.get(31),
            unassigned,
            data=b'ignored',
        ).data, b'abcde')

        sec = ipv4_data.SECOption(
            code=OptionNumber.SEC,
            type=opt_type(OptionNumber.SEC),
            length=4,
            level=ClassificationLevel.Unclassified,
            flags=(ProtectionAuthority.GENSER, ProtectionAuthority.Field_Termination_Indicator),
        )
        self.assertEqual(proto._make_opt_sec(OptionNumber.SEC, sec).level,
                         ClassificationLevel.Unclassified)
        self.assertEqual(proto._make_opt_sec(OptionNumber.SEC).data, b'')

        lsr = ipv4_data.LSROption(
            code=OptionNumber.LSR,
            type=opt_type(OptionNumber.LSR),
            length=7,
            pointer=8,
            route=[ip_address('192.0.2.1')],
        )
        rr = ipv4_data.RROption(
            code=OptionNumber.RR,
            type=opt_type(OptionNumber.RR),
            length=11,
            pointer=12,
            route=[ip_address('192.0.2.1'), ip_address('192.0.2.2')],
        )
        ssr = ipv4_data.SSROption(
            code=OptionNumber.SSR,
            type=opt_type(OptionNumber.SSR),
            length=7,
            pointer=8,
            route=[ip_address('192.0.2.3')],
        )
        self.assertEqual(proto._make_opt_lsr(OptionNumber.LSR, lsr).pointer, 8)
        self.assertEqual(proto._make_opt_rr(OptionNumber.RR, rr).pointer, 12)
        self.assertEqual(proto._make_opt_ssr(OptionNumber.SSR, ssr).pointer, 8)

        ts_tuple = ipv4_data.TSOption(
            code=OptionNumber.TS,
            type=opt_type(OptionNumber.TS),
            length=12,
            pointer=12,
            overflow=1,
            flag=TSFlag.Timestamp_Only,
            timestamp=(datetime.timedelta(seconds=1), 0x80000000),
        )
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            ts_schema = proto._make_opt_ts(OptionNumber.TS, ts_tuple)
        self.assertEqual(ts_schema.flags['oflw'], 1)
        warn.assert_called_once()

        ts_map = OrderedMultiDict([
            (ip_address('192.0.2.10'), datetime.timedelta(seconds=2)),
            (ip_address('192.0.2.11'), 0x80000000),
        ])
        ts_prespecified = ipv4_data.TSOption(
            code=OptionNumber.TS,
            type=opt_type(OptionNumber.TS),
            length=20,
            pointer=20,
            overflow=0,
            flag=TSFlag.Prespecified_IP_with_Timestamp,
            timestamp=ts_map,
        )
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            self.assertEqual(proto._make_opt_ts(OptionNumber.TS, ts_prespecified).flags['flag'],
                             TSFlag.Prespecified_IP_with_Timestamp)
        warn.assert_called_once()

        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1, timestamp=[1, 2])
        warn.assert_called_once()
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1, timestamp=[0x80000000])
        warn.assert_called_once()
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1, timestamp={
                ip_address('192.0.2.20'): 1,
                ip_address('192.0.2.21'): 2,
            })
        warn.assert_called_once()
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1,
                               timestamp={ip_address('192.0.2.22'): 0x80000000})
        warn.assert_called_once()

        e_sec = ipv4_data.ESECOption(
            code=OptionNumber.E_SEC,
            type=opt_type(OptionNumber.E_SEC),
            length=7,
            format=1,
            info=b'info',
        )
        sid = ipv4_data.SIDOption(
            code=OptionNumber.SID,
            type=opt_type(OptionNumber.SID),
            length=4,
            sid=123,
        )
        mtup = ipv4_data.MTUPOption(
            code=OptionNumber.MTUP,
            type=opt_type(OptionNumber.MTUP),
            length=4,
            mtu=1500,
        )
        mtur = ipv4_data.MTUROption(
            code=OptionNumber.MTUR,
            type=opt_type(OptionNumber.MTUR),
            length=4,
            mtu=1400,
        )
        tr = ipv4_data.TROption.from_dict({
            'code': OptionNumber.TR,
            'type': opt_type(OptionNumber.TR),
            'length': 12,
            'id': 1,
            'outbound': 2,
            'return': 3,
            'originator': ip_address('192.0.2.30'),
        })
        rtralt = ipv4_data.RTRALTOption(
            code=OptionNumber.RTRALT,
            type=opt_type(OptionNumber.RTRALT),
            length=4,
            alert=RouterAlert.Aggregated_Reservation_Nesting_Level_0,
        )
        self.assertEqual(proto._make_opt_e_sec(OptionNumber.E_SEC, e_sec).info, b'info')
        self.assertEqual(proto._make_opt_sid(OptionNumber.SID, sid).sid, 123)
        self.assertEqual(proto._make_opt_mtup(OptionNumber.MTUP, mtup).mtu, 1500)
        self.assertEqual(proto._make_opt_mtur(OptionNumber.MTUR, mtur).mtu, 1400)
        self.assertEqual(proto._make_opt_tr(OptionNumber.TR, tr).ret, 3)
        self.assertEqual(proto._make_opt_rtralt(OptionNumber.RTRALT, rtralt).alert,
                         RouterAlert.Aggregated_Reservation_Nesting_Level_0)

        qs_request = ipv4_data.QuickStartRequestOption(
            code=OptionNumber.QS,
            type=opt_type(OptionNumber.QS),
            length=8,
            func=QSFunction.Quick_Start_Request,
            rate=80,
            ttl=datetime.timedelta(seconds=7),
            nonce=3,
        )
        self.assertEqual(proto._make_opt_qs(OptionNumber.QS, qs_request).ttl, 7)
        qs_report = ipv4_data.QuickStartReportOption(
            code=OptionNumber.QS,
            type=opt_type(OptionNumber.QS),
            length=8,
            func=QSFunction.Report_of_Approved_Rate,
            rate=80,
            nonce=3,
        )
        self.assertEqual(proto._make_opt_qs(OptionNumber.QS, qs_report).nonce['nonce'], 3)

        schema_options, schema_total = proto._make_ipv4_options([
            bytes([OptionNumber.NOP]),
            proto._make_opt_nop(OptionNumber.NOP),
            proto._make_opt_sid(OptionNumber.SID, sid=9),
        ])
        self.assertEqual(schema_total, 8)
        self.assertEqual(len(schema_options), 3)
        self.assertEqual(schema_options[0].sid, 9)

        option_map = OrderedMultiDict([
            (OptionNumber.NOP, ipv4_data.NOPOption(
                code=OptionNumber.NOP,
                type=opt_type(OptionNumber.NOP),
                length=1,
            )),
            (OptionNumber.SID, sid),
            (OptionNumber.LSR, lsr),
            (OptionNumber.MTUP, mtup),
        ])
        mapped_options, mapped_total = proto._make_ipv4_options(option_map)
        self.assertEqual(mapped_total, 20)
        self.assertEqual(mapped_options[0].sid, 123)
        self.assertIn(OptionNumber.EOOL, mapped_options)
        self.assertEqual(mapped_options[-1].mtu, 1500)

    def test_ipv4_option_readers_cover_common_and_error_branches(self) -> None:
        from pcapkit.const.ipv4.classification_level import ClassificationLevel
        from pcapkit.const.ipv4.option_class import OptionClass
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet.ipv4 import (
            EOOLOption,
            ESECOption,
            LSROption,
            MTUROption,
            MTUPOption,
            NOPOption,
            QuickStartReportOption,
            QuickStartRequestOption,
            RROption,
            RTRALTOption,
            SECOption,
            SIDOption,
            SSROption,
            TROption,
            TSOption,
            UnassignedOption,
        )
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)
        options = OrderedMultiDict()

        def assert_bad(reader, schema) -> None:
            with self.assertRaises(ProtocolError):
                reader(schema, options=options)

        proto._read_fileng = lambda length: b'\xc0\x00\x02\x01'
        self.assertEqual(str(proto._read_ipv4_addr()), '192.0.2.1')

        opt_type = proto._read_ipv4_opt_type(OptionNumber.SEC)
        self.assertTrue(opt_type.change)
        self.assertEqual(opt_type.to_dict()['class'], OptionClass.control)
        self.assertEqual(opt_type.number, 2)

        unknown = proto._read_opt_unassigned(
            UnassignedOption(type=OptionNumber.get(31), length=3, data=b'x'),
            options=options,
        )
        self.assertEqual(unknown.data, b'x')
        self.assertEqual(proto._read_opt_eool(EOOLOption(type=OptionNumber.EOOL),
                                              options=options).length, 1)
        self.assertEqual(proto._read_opt_nop(NOPOption(type=OptionNumber.NOP),
                                             options=options).length, 1)

        sec = proto._read_opt_sec(
            SECOption(type=OptionNumber.SEC, length=4,
                      level=ClassificationLevel.Unclassified, data=b'\x81'),
            options=options,
        )
        self.assertEqual(sec.level, ClassificationLevel.Unclassified)
        self.assertEqual(sec.flags, (ProtectionAuthority.GENSER,))
        self.assertEqual(proto._read_opt_sec(
            SECOption(type=OptionNumber.SEC, length=3,
                      level=ClassificationLevel.Unclassified, data=b''),
            options=options,
        ).flags, ())
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._read_opt_sec(
                SECOption(type=OptionNumber.SEC, length=5,
                          level=ClassificationLevel.Unclassified,
                          data=b'\x05\x00'),
                options=options,
            )
        self.assertEqual(warn.call_count, 3)

        lsr = proto._read_opt_lsr(
            LSROption(type=OptionNumber.LSR, length=7, pointer=8,
                      route=[ip_address('192.0.2.1')]),
            options=options,
        )
        self.assertEqual([str(route) for route in lsr.route], ['192.0.2.1'])

        ts_schema = TSOption(type=OptionNumber.TS, length=12, pointer=12,
                             flags={'oflw': 0, 'flag': TSFlag.Timestamp_Only},
                             ts_data=[1000, 2000])
        object.__setattr__(ts_schema, 'ts_flag', TSFlag.Timestamp_Only)
        object.__setattr__(ts_schema, 'timestamp', (
            datetime.timedelta(seconds=1),
            datetime.timedelta(seconds=2),
        ))
        ts = proto._read_opt_ts(ts_schema, options=options)
        self.assertEqual(ts.flag, TSFlag.Timestamp_Only)
        self.assertEqual(ts.timestamp[0], datetime.timedelta(seconds=1))

        e_sec = proto._read_opt_e_sec(
            ESECOption(type=OptionNumber.E_SEC, length=7, format=1, info=b'info'),
            options=options,
        )
        self.assertEqual(e_sec.info, b'info')

        rr = proto._read_opt_rr(
            RROption(type=OptionNumber.RR, length=11, pointer=12,
                     route=[ip_address('192.0.2.1'), ip_address('192.0.2.2')]),
            options=options,
        )
        self.assertEqual(len(rr.route), 2)
        self.assertEqual(proto._read_opt_sid(SIDOption(type=OptionNumber.SID, length=4, sid=123),
                                             options=options).sid, 123)

        ssr = proto._read_opt_ssr(
            SSROption(type=OptionNumber.SSR, length=7, pointer=8,
                      route=[ip_address('192.0.2.1')]),
            options=options,
        )
        self.assertEqual([str(route) for route in ssr.route], ['192.0.2.1'])
        self.assertEqual(proto._read_opt_mtup(MTUPOption(type=OptionNumber.MTUP, length=4,
                                                         mtu=1500), options=options).mtu, 1500)
        self.assertEqual(proto._read_opt_mtur(MTUROption(type=OptionNumber.MTUR, length=4,
                                                         mtu=1400), options=options).mtu, 1400)
        tr = proto._read_opt_tr(
            TROption(type=OptionNumber.TR, length=12, id=1, out=2, ret=3,
                     origin=ip_address('192.0.2.9')),
            options=options,
        )
        self.assertEqual(tr.to_dict()['return'], 3)
        self.assertEqual(str(tr.originator), '192.0.2.9')
        self.assertEqual(proto._read_opt_rtralt(RTRALTOption(type=OptionNumber.RTRALT,
                                                             length=4, alert=0),
                                                options=options).alert, 0)

        qs_request = QuickStartRequestOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_request, 'func', QSFunction.Quick_Start_Request)
        qs_req = proto._read_opt_qs(qs_request, options=options)
        self.assertEqual(qs_req.rate, 80.0)
        self.assertEqual(qs_req.ttl, datetime.timedelta(seconds=7))

        qs_report = QuickStartReportOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Report_of_Approved_Rate, 'rate': 1},
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_report, 'func', QSFunction.Report_of_Approved_Rate)
        qs_rep = proto._read_opt_qs(qs_report, options=options)
        self.assertEqual(qs_rep.rate, 80.0)
        self.assertEqual(qs_rep.nonce, 3)

        proto.__header__ = types.SimpleNamespace(options=[
            proto._make_opt_sid(OptionNumber.SID, sid=5),
            proto._make_opt_nop(OptionNumber.NOP),
            proto._make_opt_eool(OptionNumber.EOOL),
            proto._make_opt_mtup(OptionNumber.MTUP, mtu=1500),
        ])
        parsed = proto._read_ipv4_options(6)
        self.assertEqual(list(parsed.keys()), [OptionNumber.SID, OptionNumber.NOP, OptionNumber.EOOL])
        self.assertEqual(list(parsed.values())[0].sid, 5)
        proto.__header__ = types.SimpleNamespace(options=[
            proto._make_opt_sid(OptionNumber.SID, sid=6),
        ])
        parsed_without_eool = proto._read_ipv4_options(4)
        self.assertEqual(parsed_without_eool[OptionNumber.SID].sid, 6)
        with self.assertRaises(ProtocolError):
            proto._read_ipv4_options(3)

        assert_bad(proto._read_opt_unassigned, UnassignedOption(type=OptionNumber.get(31),
                                                               length=2, data=b''))
        assert_bad(proto._read_opt_sec, SECOption(type=OptionNumber.SEC, length=2,
                                                  level=ClassificationLevel.Unclassified,
                                                  data=b''))
        assert_bad(proto._read_opt_lsr, LSROption(type=OptionNumber.LSR, length=6,
                                                  pointer=8, route=[]))
        assert_bad(proto._read_opt_lsr, LSROption(type=OptionNumber.LSR, length=7,
                                                  pointer=3, route=[]))
        assert_bad(proto._read_opt_ts, TSOption(type=OptionNumber.TS, length=41,
                                                pointer=12, flags={'oflw': 0,
                                                                   'flag': TSFlag.Timestamp_Only},
                                                ts_data=[]))
        assert_bad(proto._read_opt_ts, TSOption(type=OptionNumber.TS, length=12,
                                                pointer=4, flags={'oflw': 0,
                                                                  'flag': TSFlag.Timestamp_Only},
                                                ts_data=[]))
        assert_bad(proto._read_opt_e_sec, ESECOption(type=OptionNumber.E_SEC,
                                                     length=2, format=1, info=b''))
        assert_bad(proto._read_opt_rr, RROption(type=OptionNumber.RR, length=6,
                                                pointer=8, route=[]))
        assert_bad(proto._read_opt_rr, RROption(type=OptionNumber.RR, length=7,
                                                pointer=3, route=[]))
        assert_bad(proto._read_opt_sid, SIDOption(type=OptionNumber.SID, length=3, sid=123))
        assert_bad(proto._read_opt_ssr, SSROption(type=OptionNumber.SSR, length=6,
                                                  pointer=8, route=[]))
        assert_bad(proto._read_opt_ssr, SSROption(type=OptionNumber.SSR, length=7,
                                                  pointer=3, route=[]))
        assert_bad(proto._read_opt_mtup, MTUPOption(type=OptionNumber.MTUP, length=3,
                                                    mtu=1500))
        assert_bad(proto._read_opt_mtur, MTUROption(type=OptionNumber.MTUR, length=3,
                                                    mtu=1500))
        assert_bad(proto._read_opt_tr, TROption(type=OptionNumber.TR, length=11,
                                                id=1, out=2, ret=3,
                                                origin=ip_address('192.0.2.9')))
        assert_bad(proto._read_opt_rtralt, RTRALTOption(type=OptionNumber.RTRALT,
                                                        length=3, alert=0))
        assert_bad(proto._read_opt_qs, QuickStartRequestOption(
            type=OptionNumber.QS,
            length=7,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        ))
        qs_unknown = QuickStartRequestOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_unknown, 'func', QSFunction.get(1))
        assert_bad(proto._read_opt_qs, qs_unknown)

    def test_ipv4_schema_helpers_and_post_process_branches(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema
        from pcapkit.utilities.exceptions import FieldValueError

        eool = ipv4_schema.EOOLOption(type=OptionNumber.EOOL, length=99)
        self.assertEqual(eool.post_process({}).length, 1)
        nop = ipv4_schema.NOPOption(type=OptionNumber.NOP, length=99)
        self.assertEqual(nop.post_process({}).length, 1)
        custom = ipv4_schema.UnassignedOption(type=OptionNumber.get(31), length=3, data=b'x')
        self.assertEqual(custom.post_process({}).length, 3)

        packet = {'flags': {'func': QSFunction.Quick_Start_Request.value}}
        request_field = ipv4_schema.quick_start_data_selector(packet)
        self.assertIs(request_field.schema, ipv4_schema.QuickStartRequestOption)
        self.assertIs(packet['flags']['func'], QSFunction.Quick_Start_Request)

        report_field = ipv4_schema.quick_start_data_selector({
            'flags': {'func': QSFunction.Report_of_Approved_Rate.value},
        })
        self.assertIs(report_field.schema, ipv4_schema.QuickStartReportOption)
        with self.assertRaises(FieldValueError):
            ipv4_schema.quick_start_data_selector({'flags': {'func': 1}})

        wrapped_qs = ipv4_schema.QuickStartReportOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Report_of_Approved_Rate, 'rate': 1},
            nonce={'nonce': 7},
        )
        wrapper = object.__new__(ipv4_schema._QSOption)
        object.__setattr__(wrapper, 'data', wrapped_qs)
        object.__setattr__(wrapper, 'flags', {'func': QSFunction.Report_of_Approved_Rate.value})
        processed = ipv4_schema._QSOption.post_process(wrapper, {})
        self.assertIs(processed, wrapped_qs)
        self.assertIs(processed.func, QSFunction.Report_of_Approved_Rate)

        ts_only = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=12,
            pointer=13,
            flags={'oflw': 0, 'flag': TSFlag.Timestamp_Only},
            ts_data=[1000, 0x80000005],
        )
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            ts_only.post_process({})
        self.assertEqual(ts_only.ts_flag, TSFlag.Timestamp_Only)
        self.assertEqual(ts_only.data, [1000, 0x80000005])
        self.assertEqual(ts_only.timestamp[0], datetime.timedelta(seconds=1))
        self.assertEqual(ts_only.timestamp[1], 5)
        warn.assert_called_once()

        ip_ts = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=20,
            pointer=21,
            flags={'oflw': 0, 'flag': TSFlag.IP_with_Timestamp},
            ts_data=[
                int(ip_address('192.0.2.1')),
                2000,
                int(ip_address('192.0.2.4')),
                0x80000007,
            ],
        )
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            ip_ts.post_process({})
        self.assertIsInstance(ip_ts.data, OrderedMultiDict)
        self.assertEqual(ip_ts.timestamp[ip_address('192.0.2.1')],
                         datetime.timedelta(seconds=2))
        self.assertEqual(ip_ts.timestamp[ip_address('192.0.2.4')], 7)
        warn.assert_called_once()

        pre_ts = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=20,
            pointer=21,
            flags={'oflw': 0, 'flag': TSFlag.Prespecified_IP_with_Timestamp},
            ts_data=[
                int(ip_address('192.0.2.2')),
                0x80000006,
                int(ip_address('192.0.2.5')),
                3000,
            ],
        )
        pre_ts.remainder = ip_address('192.0.2.3').packed + b'\x00\x00\x00\x00'
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            pre_ts.post_process({})
        self.assertEqual(pre_ts.timestamp[ip_address('192.0.2.2')], 6)
        self.assertEqual(pre_ts.timestamp[ip_address('192.0.2.5')],
                         datetime.timedelta(seconds=3))
        self.assertEqual(pre_ts.data[ip_address('192.0.2.3')], 0)
        warn.assert_called_once()

        unknown = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=8,
            pointer=9,
            flags={'oflw': 0, 'flag': 2},
            ts_data=[1],
        )
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            unknown.post_process({})
        self.assertEqual(tuple(unknown.timestamp), (1,))
        warn.assert_called_once()

    def test_an_option_area_longer_than_the_datagram_still_parses(self) -> None:
        """An ``ihl`` promising more options than are there is tolerated.

        The header below sets ``ihl`` to 10 -- a 20-octet option area -- and stops
        after the fixed 20 octets, so there are no option octets at all. Reading
        past them yields ``b''``, which decodes the option number as 0, and 0 is
        IPv4's end-of-option-list, so the option loop breaks there and reports the
        whole area as padding. That is how a datagram cut short by the snapshot
        length parses at all, and it is why :meth:`OptionField.unpack
        <pcapkit.corekit.fields.collections.OptionField.unpack>` checks each
        option's progress *after* its end-of-option-list break rather than before:
        checking first turns every such header into an error. C.f. #431.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4
        from tests._support import time_limit

        raw = bytes.fromhex('4a00001800010000400600000a0000010a000002')
        with time_limit(5):
            proto = IPv4(raw, len(raw))

        self.assertEqual(proto.info.hdr_len, 40)
        self.assertEqual(
            [(code, opt.length) for code, opt in proto.info.options.items(multi=True)],
            [(OptionNumber.EOOL, 1)],
        )


if __name__ == '__main__':
    unittest.main()
