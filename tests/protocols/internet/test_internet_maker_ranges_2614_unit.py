# -*- coding: utf-8 -*-
"""The IPv6 extension, IPv4, MH and HIP makers refuse what a field cannot carry.

GitHub issue #2614: the makers range-check their fixed-width fields through
:meth:`~pcapkit.protocols.protocol.Protocol._make_uint` and
:meth:`~pcapkit.protocols.protocol.Protocol._make_sint`. Unchecked, a number
field wraps a negative or too-wide value and writes a :obj:`bool` as ``0`` or
``1``, a bit field raises a bare :exc:`ValueError` for a negative value, and an
inline check that tests only the upper bound lets a negative value through.
Every refusal here is a :exc:`~pcapkit.utilities.exceptions.ProtocolError`
naming the field.

The MH and HIP sweeps are tables of every integer argument of their makers;
``test_every_integer_argument_is_swept`` finds those arguments from the maker
signatures, so a new one needs a row or a recorded reason. The option makers'
registry codes, and the MH options' octet arguments that an ``Option Length``
counts, are found from the signatures as well and need no row. Each row's maximum
builds and survives parse -> rebuild, and the values each field does carry are
checked against the specification: the ILNP nonce's ``Opt Data Len``
(:rfc:`6744`) and the two's-complement geo-location degrees
(:rfc:`6757#section-3.1.2`).

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import enum
import inspect
import io
import re
import sys
import unittest

import aenum

from tests._support import reimport_once_per_class

#: Annotation fragments that mark a keyword argument as something other than a
#: plain integer: a registry code, an address, octets or text.
NOT_AN_INTEGER = ('Enum', 'Address', 'bytes', 'str')


def _takes_enumeration(func: 'object', param: 'inspect.Parameter') -> 'bool':
    """Whether ``param`` of ``func`` takes a registry code.

    Its annotation's head, past an ``Optional[``, names an enumeration in the module
    defining ``func``, as ``Enum_ToSPrecedence | int`` does (#2594).

    """
    head = re.match(r'(?:Optional\[)?(\w+)', str(param.annotation))
    module = vars(sys.modules[func.__module__])  # type: ignore[attr-defined]
    kind = module.get(head.group(1)) if head is not None else None
    return isinstance(kind, type) and issubclass(kind, (enum.Enum, aenum.Enum))


def integer_arguments(func: 'object') -> 'list[str]':
    """Keyword arguments of ``func`` that take a plain integer."""
    names = []
    for param in inspect.signature(func).parameters.values():  # type: ignore[arg-type]
        if param.kind not in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY):
            continue
        if _takes_enumeration(func, param):
            continue
        ann = str(param.annotation)
        default = param.default
        if not ((isinstance(default, int) and not isinstance(default, bool))
                or ann.startswith(('int', 'Optional[int'))):
            continue
        if any(part in ann for part in NOT_AN_INTEGER):
            continue
        names.append(param.name)
    return names


def registry_arguments(func: 'object') -> 'list[str]':
    """Keyword-only arguments of ``func`` that take a registry code."""
    return [param.name for param in inspect.signature(func).parameters.values()  # type: ignore[arg-type]
            if param.kind is param.KEYWORD_ONLY and _takes_enumeration(func, param)]


def octet_arguments(func: 'object') -> 'list[str]':
    """Keyword arguments of ``func`` that take only octets or text, other than reserved octets."""
    return [param.name for param in inspect.signature(func).parameters.values()  # type: ignore[arg-type]
            if param.kind is param.KEYWORD_ONLY and param.name != 'reserved'
            and str(param.annotation) in ('bytes', 'str')]


def option_makers(cls: 'type') -> 'dict[str, object]':
    """``{maker name: option code}`` for each ``_make_opt_*`` of ``cls`` its registry reaches."""
    makers = {}  # type: dict[str, object]
    for code, name in cls.__option__.items():  # type: ignore[attr-defined]
        if isinstance(name, str) and hasattr(cls, f'_make_opt_{name}'):
            makers.setdefault(f'_make_opt_{name}', code)
    return makers


class _Case(unittest.TestCase):
    """Fresh :mod:`pcapkit` once per class, and the refusal checks."""

    #: Rows whose maximum the reader cannot parse, and why. A protocol parses
    #: what it makes, so their maximum is not built.
    UNPARSED_MAXIMA = {}  # type: dict[str, str]

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRefused(self, message: 'str', func: 'object', *args: 'object', **kwargs: 'object') -> None:
        """``func(*args, **kwargs)`` raises a ProtocolError saying exactly ``message``."""
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            func(*args, **kwargs)  # type: ignore[operator]
        self.assertEqual(str(caught.exception), message)

    def assertSwept(self, alias: 'str', rows: 'list[tuple]', rebuild: 'object') -> None:
        """Each ``(label, build, maximum, name)`` row refuses -1, a bool and maximum + 1.

        ``build(value)`` makes the octets with ``value`` in the row's field. A
        one-bit field takes a :obj:`bool`, and a ``maximum`` of :data:`None`
        marks a field as wide as its value, so only the sign and the type are
        checked. ``rebuild(octets)`` parses and rebuilds the octets made with
        the maximum, unless :attr:`UNPARSED_MAXIMA` names the row.
        """
        from pcapkit.utilities.exceptions import ProtocolError

        for label, build, maximum, name in rows:
            with self.subTest(row=label, value=-1):
                self.assertRefused(f'{alias}: invalid {name}: -1', build, -1)
            if maximum != 1:
                with self.subTest(row=label, value=True):
                    self.assertRefused(f'{alias}: invalid {name}: True', build, True)
            if maximum is None:
                continue
            with self.subTest(row=label, value=maximum + 1):
                with self.assertRaises(ProtocolError):
                    build(maximum + 1)
            if label in self.UNPARSED_MAXIMA:
                continue
            with self.subTest(row=label, value=maximum):
                data = build(maximum)
                self.assertEqual(rebuild(data), data)  # type: ignore[operator]


class IPv6OptionMakerTests(_Case):
    """HOPOPT and IPv6-Opts option makers, which share their code."""

    #: ``(option, arguments, field name, value)``: one refused value per field.
    REFUSED = (
        ('RPL_Option_0x63', {'reserved': True}, 'RPL reserved flags', True),
        ('RPL_Option_0x63', {'reserved': 32}, 'RPL reserved flags', 32),
        ('RPL_Option_0x63', {'id': 256}, 'RPL instance ID', 256),
        ('RPL_Option_0x63', {'rank': -1}, 'RPL sender rank', -1),
        ('MPL_Option', {'seed': -1}, 'MPL seed ID', -1),
        ('MPL_Option', {'seed': 1 << 16, 'seed_type': 1}, 'MPL seed ID', 1 << 16),
        ('MPL_Option', {'seed': 1, 'seq': -1}, 'MPL sequence number', -1),
        ('MPL_Option', {'seed': 1, 'reserved': True}, 'MPL reserved bits', True),
        ('ILNP_Nonce', {'nonce': -1}, 'ILNP nonce', -1),
        ('Tunnel_Encapsulation_Limit', {'limit': 256}, 'tunnel encapsulation limit', 256),
        ('CALIPSO', {'domain': -1}, 'CALIPSO domain of interpretation', -1),
        ('CALIPSO', {'level': 256}, 'CALIPSO sensitivity level', 256),
        ('Jumbo_Payload', {'len': 1 << 32}, 'jumbo payload length', 1 << 32),
        ('IP_DFF', {'version': 4}, 'DFF version', 4),
        ('IP_DFF', {'reserved': True}, 'DFF reserved bits', True),
        ('IP_DFF', {'seq': 1 << 16}, 'DFF sequence number', 1 << 16),
        ('PDM', {'psntp': 1 << 16}, 'PDM PSN this packet', 1 << 16),
        ('PDM', {'psnlr': -1}, 'PDM PSN last received', -1),
        ('PDM', {'deltatlr': -1}, 'PDM delta time last received', -1),
        ('PDM', {'deltatls': 1 << 16, 'scaledtls': 0}, 'PDM delta time last sent', 1 << 16),
        ('PDM', {'deltatls': True}, 'PDM delta time last sent', True),
        # No one-octet scale brings this delta into two octets.
        ('PDM', {'deltatlr': 1 << 300}, 'PDM delta time last received', 1 << 300),
        ('PDM', {'scaledtlr': 256}, 'PDM scale of delta time last received', 256),
        ('PDM', {'scaledtlr': -1}, 'PDM scale of delta time last received', -1),
        ('PDM', {'scaledtlr': True}, 'PDM scale of delta time last received', True),
        ('PDM', {'scaledtls': 1 << 200}, 'PDM scale of delta time last sent', 1 << 200),
        ('PDM', {'scaledtls': True}, 'PDM scale of delta time last sent', True),
        ('Quick_Start', {'func': True}, 'QS function', True),
        ('Line_Identification_Option', {'id': bytes(255)}, 'Opt Data Len', 256),
        ('SMF_DPD', {'id': bytes(255)}, 'Opt Data Len', 256),
        ('SMF_DPD', {'mode': 1, 'hav': bytes(256)}, 'Opt Data Len', 256),
        # An unassigned option, which _make_opt_none makes.
        ('RFC3692_style_Experiment_0x1E', {'data': bytes(256)}, 'Opt Data Len', 256),
    )

    def _classes(self) -> 'dict[str, type]':
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        return {'HOPOPT': HOPOPT, 'IPv6-Opts': IPv6_Opts}

    def test_out_of_range_values_are_refused(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for alias, cls in self._classes().items():
            for option, args, name, value in self.REFUSED:
                with self.subTest(protocol=alias, option=option, args=args):
                    self.assertRefused(f'{alias}: invalid {name}: {value!r}',
                                       cls, next=59, options=[(Option[option], args)])

    def test_field_maxima_build(self) -> None:
        from pcapkit.const.ipv6.option import Option

        cases = (
            ('RPL_Option_0x63', {'reserved': 31, 'id': 255, 'rank': 0xFFFF}, '63041fffffff'),
            ('MPL_Option', {'seed': 0xFFFF, 'seq': 255, 'reserved': 15}, '6d044fffffff'),
            ('PDM', {'deltatlr': 0xFFFF, 'scaledtlr': 0, 'deltatls': 0xFFFF << 3, 'scaledtls': 3},
             '0f0a000300000000ffffffff'),
            # RFC 8250 section 3.2: the widest delta, at the widest scale.
            ('PDM', {'deltatlr': 0xFFFF << 255}, '0f0aff0000000000ffff0000'),
        )
        for alias, cls in self._classes().items():
            for option, args, octets in cases:
                with self.subTest(protocol=alias, option=option):
                    data = cls(next=59, options=[(Option[option], args)]).data
                    self.assertEqual(data[2:2 + len(octets) // 2].hex(), octets)
                    parsed = cls(data, len(data), extension=True)
                    self.assertEqual(cls.from_data(parsed.info).data, data)

    def test_option_data_reaches_its_one_octet_length(self) -> None:
        # RFC 8200 section 4.2: Opt Data Len is one octet, so 255 octets of
        # option data at most.
        from pcapkit.const.ipv6.option import Option

        for alias, cls in self._classes().items():
            for option, args in (('Line_Identification_Option', {'id': bytes(254)}),
                                 ('SMF_DPD', {'id': bytes(254)}),
                                 ('SMF_DPD', {'mode': 1, 'hav': bytes(255)}),
                                 ('RFC3692_style_Experiment_0x1E', {'data': bytes(255)})):
                with self.subTest(protocol=alias, option=option, args=sorted(args)):
                    data = cls(next=59, options=[(Option[option], args)]).data
                    self.assertEqual(data[2:4], bytes([Option[option], 255]))
                    parsed = cls(data, len(data), extension=True)
                    self.assertEqual(cls.from_data(parsed.info).data, data)

    def test_ilnp_nonce_fills_whole_octets(self) -> None:
        # RFC 6744: Opt Data Len is the nonce's length in octets, and a nonce
        # of 0 still fills its Nonce Value field.
        from pcapkit.const.ipv6.option import Option

        for alias, cls in self._classes().items():
            for nonce, size in ((0, 1), (0xFF, 1), (0x100, 2), (1 << 64, 9)):
                with self.subTest(protocol=alias, nonce=nonce):
                    data = cls(next=59, options=[(Option.ILNP_Nonce, {'nonce': nonce})]).data
                    self.assertEqual(data[2:4], bytes([Option.ILNP_Nonce, size]))
                    self.assertEqual(int.from_bytes(data[4:4 + size], 'big'), nonce)

    def test_header_too_long_for_hdr_ext_len_is_refused(self) -> None:
        # RFC 8200 section 4.3: Hdr Ext Len counts 8-octet units after the
        # first 8, in one octet. Each tunnel limit option is aligned to 8.
        from pcapkit.const.ipv6.option import Option

        tun = (Option.Tunnel_Encapsulation_Limit, {'limit': 1})
        for alias, cls in self._classes().items():
            with self.subTest(protocol=alias):
                data = cls(next=59, options=[tun] * 256).data
                self.assertEqual((len(data), data[1]), (2048, 255))
                self.assertEqual(cls.from_data(cls(data, len(data), extension=True).info).data, data)
                self.assertRefused(f'{alias}: invalid Hdr Ext Len: 256', cls, next=59, options=[tun] * 257)
                self.assertRefused(f'{alias}: invalid Hdr Ext Len: 499', cls, next=59, options=[tun] * 500)

    def test_calipso_bitmap_octets_are_refused_out_of_range(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for alias, cls in self._classes().items():
            for octet in (-1, 256, True):
                with self.subTest(protocol=alias, octet=octet):
                    self.assertRefused(f'{alias}: invalid CALIPSO bitmap octet: {octet!r}', cls, next=59,
                                       options=[(Option.CALIPSO, {'bitmap': (octet, 0, 0, 0)})])

    def test_pad_length_is_refused_out_of_range(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for alias, cls in self._classes().items():
            proto = cls.__new__(cls)
            for length in (-1, 256, True):
                with self.subTest(protocol=alias, length=length):
                    self.assertRefused(f'{alias}: invalid Opt Data Len: {length!r}',
                                       proto._make_opt_pad, Option.PadN, length=length)
            self.assertEqual(proto._make_opt_pad(Option.PadN, length=255).pack(), b'\x01\xff' + bytes(255))


class IPv4MakerTests(_Case):
    """IPv4's header maker and its fixed-width option makers."""

    def test_header_fields_are_refused_out_of_range(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        for args, name, value in (({'id': 1 << 16}, 'identification', 1 << 16),
                                  ({'id': True}, 'identification', True),
                                  ({'reserved': 2}, 'reserved flag', 2),
                                  ({'offset': 1 << 13}, 'fragment offset', 1 << 13),
                                  ({'ttl': 256}, 'TTL', 256),
                                  ({'ttl': -1}, 'TTL', -1),
                                  ({'total_length': 1 << 16}, 'total length', 1 << 16)):
            with self.subTest(args=args):
                self.assertRefused(f'IPv4: invalid {name}: {value!r}', IPv4, protocol=253, **args)

    def test_option_fields_are_refused_out_of_range(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.protocols.internet.ipv4 import IPv4

        report = {'func': QSFunction.Report_of_Approved_Rate}
        for code, args, name, value in (
                (OptionNumber.SID, {'sid': 1 << 16}, 'stream ID', 1 << 16),
                (OptionNumber.MTUP, {'mtu': -1}, 'MTU', -1),
                (OptionNumber.MTUR, {'mtu': True}, 'MTU', True),
                (OptionNumber.TR, {'id': 1 << 16}, 'traceroute ID number', 1 << 16),
                (OptionNumber.TR, {'out': -1}, 'traceroute outbound hop count', -1),
                (OptionNumber.TR, {'ret': True}, 'traceroute return hop count', True),
                (OptionNumber.QS, {'func': True}, 'QS function', True),
                (OptionNumber.QS, {**report, 'unused': -1}, 'Quick-Start not-used octet', -1),
                (OptionNumber.QS, {**report, 'unused': 256}, 'Quick-Start not-used octet', 256),
                (OptionNumber.QS, {**report, 'unused': True}, 'Quick-Start not-used octet', True),
                (OptionNumber.TS, {'overflow': -1}, 'timestamp overflow count', -1),
                (OptionNumber.TS, {'overflow': 16}, 'timestamp overflow count', 16),
                (OptionNumber.TS, {'overflow': True}, 'timestamp overflow count', True),
                (OptionNumber.E_SEC, {'format': -1}, 'E-SEC format code', -1),
                (OptionNumber.E_SEC, {'format': 256}, 'E-SEC format code', 256),
                (OptionNumber.E_SEC, {'format': True}, 'E-SEC format code', True),
                (OptionNumber.RR, {'counts': 1 << 64}, 'address count', 1 << 64),
                (OptionNumber.RR, {'counts': True}, 'address count', True),
                (OptionNumber.LSR, {'counts': 64}, 'address count', 64),
                (OptionNumber.LSR, {'counts': True}, 'address count', True),
                (OptionNumber.SSR, {'counts': 64}, 'address count', 64),
                (OptionNumber.SSR, {'counts': True}, 'address count', True),
                (OptionNumber.TS, {'counts': True}, 'timestamp count', True),
                (OptionNumber.TS, {'counts': -1}, 'timestamp count', -1),
                (OptionNumber.TS, {'counts': 1, 'timestamp': [True]}, 'timestamp slot', True),
                (OptionNumber.TS, {'counts': 1, 'timestamp': [1 << 32]}, 'timestamp slot', 1 << 32),
                (OptionNumber.TS, {'counts': 1, 'timestamp': {'192.0.2.1': -1}}, 'timestamp slot', -1),
                (OptionNumber.TS, {'counts': 1, 'remaining': [True]}, 'timestamp slot', True),
                (OptionNumber.SEC, {'authorities': [-1]}, 'protection authority', -1),
                (OptionNumber.SEC, {'authorities': [True]}, 'protection authority', True),
                (OptionNumber.SEC, {'authorities': [1 << 200]}, 'protection authority', 1 << 200)):
            with self.subTest(code=code, args=args):
                self.assertRefused(f'IPv4: invalid {name}: {value!r}',
                                   IPv4, options=[(code, args)], protocol=253)

    def test_counted_options_reach_their_one_octet_length(self) -> None:
        # RFC 791: each option's length is one octet. A route option holds 63
        # addresses at most, and a security option 252 octets of flags, whose
        # last bit is a field termination bit rather than an authority (RFC 1108).
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = IPv4.__new__(IPv4)
        for code, maker in ((OptionNumber.RR, proto._make_opt_rr), (OptionNumber.LSR, proto._make_opt_lsr),
                            (OptionNumber.SSR, proto._make_opt_ssr)):
            with self.subTest(code=code):
                self.assertEqual(maker(code, counts=63).pack()[:2], bytes([code, 255]))
        self.assertEqual(proto._make_opt_sec(OptionNumber.SEC, authorities=[252 * 8 - 2]).pack()[1], 255)
        self.assertRefused('IPv4: invalid option length: 256', proto._make_opt_sec, OptionNumber.SEC,
                           authorities=[252 * 8])

    def test_options_too_long_for_ihl_are_refused(self) -> None:
        # RFC 791: IHL counts 32-bit words in four bits, so 40 octets of
        # options at most; the route options' default of ten slots is 43.
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        data = IPv4(protocol=253, options=[(OptionNumber.RR, {'counts': 9})]).data
        self.assertEqual(data[0], 0x4F)
        self.assertRefused('IPv4: invalid IHL: 16', IPv4, protocol=253,
                           options=[(OptionNumber.RR, {'counts': 10})])

    def test_field_maxima_build(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.protocols.internet.ipv4 import IPv4

        data = IPv4(id=0xFFFF, reserved=True, offset=0x1FFF, ttl=255, protocol=253,
                    options=[(OptionNumber.SID, {'sid': 0xFFFF})]).data
        # RFC 791: Identification, then the flags above the 13-bit offset.
        self.assertEqual(data[4:9].hex(), 'ffff9fffff')
        self.assertEqual(data[20:24].hex(), '8804ffff')
        self.assertEqual(IPv4.from_data(IPv4(data).info).data, data)

        for code, args, offset, octets in (
                (OptionNumber.TS, {'overflow': 15, 'counts': 1}, 23, 'f0'),
                (OptionNumber.E_SEC, {'format': 255}, 22, 'ff'),
                (OptionNumber.QS, {'func': QSFunction.Report_of_Approved_Rate, 'unused': 255}, 23, 'ff')):
            with self.subTest(code=code):
                data = IPv4(protocol=253, options=[(code, args)]).data
                self.assertEqual(data[offset:offset + 1].hex(), octets)
                self.assertEqual(IPv4.from_data(IPv4(data).info).data, data)


class IPv6RouteMakerTests(_Case):
    """IPv6-Route's header maker and its RPL source route maker."""

    def test_out_of_range_values_are_refused(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        for args, name, value in (({'seg_left': 256}, 'Segments Left', 256),
                                  ({'seg_left': True}, 'Segments Left', True),
                                  ({'hdr_ext_len': -1}, 'Hdr Ext Len', -1)):
            with self.subTest(args=args):
                self.assertRefused(f'IPv6-Route: invalid {name}: {value!r}', IPv6_Route, **args)
        for reserved in (1 << 20, -1, True):
            with self.subTest(reserved=reserved):
                self.assertRefused(f'IPv6-Route: invalid RPL reserved bits: {reserved!r}', IPv6_Route,
                                   type=3, data={'ip': ['2001:db8::1'], 'reserved': reserved})

    def test_rpl_reserved_maximum_round_trips(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        data = IPv6_Route(type=3, data={'ip': ['2001:db8::1'], 'reserved': 0xFFFFF}).data
        # RFC 6554 section 3: Pad in the top four bits, then 20 reserved bits.
        self.assertEqual(data[5:8].hex(), '0fffff')
        self.assertEqual(IPv6_Route.from_data(IPv6_Route(data, len(data), extension=True).info).data, data)


class MHMakerTests(_Case):
    """MH's header maker and its message, option and sub-option makers."""

    #: Messages by maker suffix: ``{suffix: (packet, {argument: (maximum, name)})}``.
    #: Widths per RFC 6275 section 6.1, RFC 5568 section 6.2, RFC 5847, RFC
    #: 5268, RFC 5846, RFC 6705, RFC 7077, RFC 7388 and RFC 7161.
    MESSAGES = {
        'brr': ('Binding_Refresh_Request', {'msg_reserved': (0xFFFF, 'reserved bits')}),
        'hot': ('Home_Test', {'nonce_index': (0xFFFF, 'nonce index')}),
        'cot': ('Care_of_Test', {'nonce_index': (0xFFFF, 'nonce index')}),
        'bu': ('Binding_Update', {'seq': (0xFFFF, 'sequence number'),
                                  'flags_reserved': (0xF, 'reserved bits'),
                                  'lifetime': (0xFFFF * 4, 'lifetime')}),
        'ba': ('Binding_Acknowledgement', {'seq': (0xFFFF, 'sequence number'),
                                           'flags_reserved': (1, 'reserved bits'),
                                           'lifetime': (0xFFFF * 4, 'lifetime')}),
        'fbu': ('Fast_Binding_Update', {'seq': (0xFFFF, 'sequence number'),
                                        'flags_reserved': (0xFFF, 'reserved bits'),
                                        'lifetime': (0xFFFF, 'lifetime')}),
        'fback': ('Fast_Binding_Acknowledgment', {'seq': (0xFFFF, 'sequence number'),
                                                  'flags_reserved': (0x7F, 'reserved bits'),
                                                  'lifetime': (0xFFFF, 'lifetime')}),
        'hi': ('Handover_Initiate_Message', {'seq': (0xFFFF, 'sequence number'),
                                             'flags_reserved': (0xF, 'reserved bits')}),
        'hack': ('Handover_Acknowledge_Message', {'seq': (0xFFFF, 'sequence number'),
                                                  'flags_reserved': (0x1F, 'reserved bits')}),
        'hb': ('Heartbeat_Message', {'seq': (0xFFFFFFFF, 'sequence number'),
                                     'flags_reserved': (0x3FFF, 'reserved bits')}),
        'brm': ('Binding_Revocation_Message', {'seq': (0xFFFF, 'sequence number'),
                                               'flags_reserved': (0x1FFF, 'reserved bits')}),
        'lri': ('Localized_Routing_Initiation', {'seq': (0xFFFF, 'sequence number'),
                                                 'lifetime': (0xFFFF, 'lifetime')}),
        'lra': ('Localized_Routing_Acknowledgment', {'seq': (0xFFFF, 'sequence number'),
                                                     'flags_reserved': (0x7F, 'reserved bits'),
                                                     'lifetime': (0xFFFF, 'lifetime')}),
        'upn': ('Update_Notification', {'seq': (0xFFFF, 'sequence number'),
                                        'flags_reserved': (0x3FFF, 'reserved bits')}),
        'upa': ('Update_Notification_Acknowledgement', {'seq': (0xFFFF, 'sequence number')}),
        'fbm': ('Flow_Binding_Message', {'seq': (0xFFFF, 'sequence number'),
                                         'flags_reserved': (0x7F, 'reserved bits')}),
        'sq': ('Subscription_Query', {'seq': (0xFF, 'sequence number')}),
        'sr': ('Subscription_Response', {'seq': (0xFF, 'sequence number'),
                                         'flags_reserved': (0x7F, 'reserved bits')}),
    }

    #: Options by maker suffix: ``{suffix: (option, base arguments, {argument: (maximum, name)})}``.
    #: A prefix length's maximum is the address width where the maker checks it
    #: past the field width, and the field width where it does not (#2684).
    OPTIONS = {
        'pad': ('PadN', {}, {'length': (0xFF, 'Option Length')}),
        'bra': ('Binding_Refresh_Advice', {}, {'interval': (0xFFFF, 'refresh interval')}),
        'ni': ('Nonce_Indices', {}, {'home': (0xFFFF, 'home nonce index'),
                                     'careof': (0xFFFF, 'care-of nonce index')}),
        'mnp': ('Mobile_Network_Prefix_Option', {}, {'prefix_length': (0xFF, 'prefix length')}),
        'auth': ('AUTH_OPTION_TYPE', {'data': b'\x00\x00'}, {'spi': (0xFFFFFFFF, 'SPI')}),
        'badf': ('Binding_Authorization_Data_for_FMIPv6', {'data': b'\x00'},
                 {'spi': (0xFFFFFFFF, 'SPI')}),
        'ipv6_ap': ('Mobility_Header_IPv6_Address_Prefix', {}, {'prefix_length': (128, 'prefix length')}),
        'dns': ('DNS_UPDATE_TYPE', {}, {'reserved': (0x7F, 'reserved bits')}),
        'vendor': ('Vendor_Specific_Mobility_Option', {}, {'vendor': (0xFFFFFFFF, 'vendor ID'),
                                                           'subtype': (0xFF, 'vendor subtype')}),
        'hnp': ('Home_Network_Prefix_Option', {}, {'prefix_length': (0xFF, 'prefix length')}),
        'hi': ('Handoff_Indicator_Option', {}, {'reserved': (0xFF, 'reserved octet')}),
        'timestamp': ('Timestamp_Option', {}, {'seconds': ((1 << 48) - 1, 'timestamp seconds'),
                                               'fraction': (0xFFFF, 'timestamp fraction')}),
        'restart': ('Restart_Counter', {}, {'counter': (0xFFFFFFFF, 'restart counter')}),
        'ipv4_hoa': ('IPv4_Home_Address', {}, {'prefix_length': (32, 'prefix length'),
                                               'reserved': (0x1FF, 'reserved bits')}),
        'ipv4_ack': ('IPv4_Address_Acknowledgement', {}, {'prefix_length': (0x3F, 'prefix length'),
                                                          'reserved': (0x3, 'reserved bits')}),
        'nat': ('NAT_Detection', {}, {'refresh': (0xFFFFFFFF, 'refresh interval'),
                                      'reserved': (0x7FFF, 'reserved bits')}),
        'gre': ('GRE_Key_Option', {}, {'key': (0xFFFFFFFF, 'GRE key')}),
        'bid': ('Binding_Identifier', {}, {'bid': (0xFFFF, 'binding identifier'),
                                           'bid_pri': (0x7F, 'binding priority')}),
        'ipv4_hoa_req': ('IPv4_Home_Address_Request', {}, {'prefix_length': (0x3F, 'prefix length'),
                                                           'reserved': (0x3FF, 'reserved bits')}),
        'ipv4_hoa_rep': ('IPv4_Home_Address_Reply', {}, {'prefix_length': (0x3F, 'prefix length'),
                                                         'reserved': (0x3, 'reserved bits')}),
        'ipv4_dhcp': ('IPv4_DHCP_Support_Mode', {}, {'reserved': (0x7FFF, 'reserved bits')}),
        'transient': ('Transient_Binding', {}, {'lifetime': (0xFF, 'lifetime'),
                                                'reserved': (0x7F, 'reserved bits')}),
        'fid': ('Flow_Identification_Mobility_Option', {}, {'fid': (0xFFFF, 'flow identifier'),
                                                            'fid_pri': (0xFFFF, 'flow identifier priority')}),
        'redirect': ('Redirect_Mobility_Option', {'ipv6': '2001:db8::1'},
                     {'reserved': (0x3FFF, 'reserved bits')}),
        'load': ('Load_Information_Mobility_Option', {}, {
            'priority': (0xFFFF, 'priority'),
            'sessions_in_use': (0xFFFFFFFF, 'sessions in use'),
            'max_sessions': (0xFFFFFFFF, 'maximum sessions'),
            'used_capacity': (0xFFFFFFFF, 'used capacity'),
            'max_capacity': (0xFFFFFFFF, 'maximum capacity')}),
        'mn_group': ('Mobile_Node_Group_Identifier', {}, {'group_id': (0xFFFFFFFF, 'group identifier')}),
        'mag_addr': ('MAG_IPv6_Address', {}, {'address_length': (0xFF, 'address length')}),
        'offload': ('IPv4_Traffic_Offload_Selector', {}, {'reserved': (0x7FFFFFFF, 'reserved bits')}),
        'mcast_sel': ('Dynamic_IP_Multicast_Selector', {}, {'protocol': (0xFF, 'protocol'),
                                                            'records': (0xFFFF, 'number of records'),
                                                            'reserved': (0x7F, 'reserved bits')}),
        'dmnp': ('Delegated_Mobile_Network_Prefix', {}, {'prefix_length': (0xFF, 'prefix length'),
                                                         'reserved': (0x7F, 'reserved bits')}),
        'ams4': ('Active_Multicast_Subscription_IPv4', {}, {'igmp_type': (0xFF, 'IGMP type')}),
        'ams6': ('Active_Multicast_Subscription_IPv6', {}, {'mld_type': (0xFF, 'MLD type')}),
        'qos': ('Quality_of_Service', {}, {'sr_id': (0xFF, 'service request identifier'),
                                           'dscp': (0x3F, 'DSCP'),
                                           'tc_reserved': (0x3, 'traffic class reserved bits'),
                                           'oc': (0xFF, 'operational code')}),
        'mcast': ('Multicast_Mobility_Option', {}, {'code': (0xFF, 'code')}),
        'mcast_ack': ('Multicast_Acknowledgement_Option', {}, {'code': (0xFF, 'code'),
                                                               'status': (0xFF, 'status')}),
        'mag_mp': ('MAG_Multipath_Binding', {}, {'label': (0xFF, 'interface label'),
                                                 'bid': (0xFF, 'binding identifier'),
                                                 'reserved': ((1 << 22) - 1, 'reserved bits')}),
        'anchored': ('Anchored_Prefix', {}, {'prefix_length': (128, 'prefix length')}),
        'local_prefix': ('Local_Prefix', {}, {'prefix_length': (128, 'prefix length')}),
        'prev_maar': ('Previous_MAAR', {}, {'prefix_length': (128, 'prefix length')}),
    }

    #: Sub-options and list entries, which no maker signature declares:
    #: ``(label, option, base arguments, path to the value, maximum, name)``.
    NESTED = (
        ('fs.fid[]', 'Flow_Summary_Mobility_Option', {}, ('fid', []), 0xFFFF, 'flow identifier'),
        ('fid.BID_Reference.bid[]', 'Flow_Identification_Mobility_Option', {},
         ('suboptions', 'BID_Reference', 'bid', []), 0xFFFF, 'binding identifier'),
        ('ani.Network_Identifier.reserved', 'Access_Network_Identifier', {},
         ('suboptions', 'Network_Identifier', 'reserved'), 0x7F, 'reserved bits'),
        ('ani.Civic_Location.format', 'Access_Network_Identifier', {},
         ('suboptions', 'Civic_Location', 'format'), 0xFF, 'civic location format'),
        ('ani.MAG_Group_Identifier.group_id', 'Access_Network_Identifier', {},
         ('suboptions', 'MAG_Group_Identifier', 'group_id'), 0xFFFF, 'MAG group identifier'),
        ('ani.ANI_Update_Timer.timer', 'Access_Network_Identifier', {},
         ('suboptions', 'ANI_Update_Timer', 'timer'), 0xFFFF, 'ANI update timer'),
        ('qos.Per_Session_Agg_Max_DL_Bit_Rate.reserved', 'Quality_of_Service', {},
         ('attributes', 'Per_Session_Agg_Max_DL_Bit_Rate', 'reserved'), 0x3FFF, 'reserved bits'),
        ('qos.Per_Session_Agg_Max_DL_Bit_Rate.rate', 'Quality_of_Service', {},
         ('attributes', 'Per_Session_Agg_Max_DL_Bit_Rate', 'rate'), 0xFFFFFFFF, 'bit rate'),
        ('qos.Guaranteed_DL_Bit_Rate.rate', 'Quality_of_Service', {},
         ('attributes', 'Guaranteed_DL_Bit_Rate', 'rate'), 0xFFFFFFFF, 'bit rate'),
        ('qos.Allocation_Retention_Priority.priority_level', 'Quality_of_Service', {},
         ('attributes', 'Allocation_Retention_Priority', 'priority_level'), 0xF, 'priority level'),
        ('qos.Allocation_Retention_Priority.preemption_capability', 'Quality_of_Service', {},
         ('attributes', 'Allocation_Retention_Priority', 'preemption_capability'), 0x3,
         'preemption capability'),
        ('qos.Allocation_Retention_Priority.preemption_vulnerability', 'Quality_of_Service', {},
         ('attributes', 'Allocation_Retention_Priority', 'preemption_vulnerability'), 0x3,
         'preemption vulnerability'),
        ('qos.QoS_Vendor_Specific_Attribute.vendor', 'Quality_of_Service', {},
         ('attributes', 'QoS_Vendor_Specific_Attribute', 'vendor'), 0xFFFFFFFF, 'vendor ID'),
        ('qos.QoS_Vendor_Specific_Attribute.subtype', 'Quality_of_Service', {},
         ('attributes', 'QoS_Vendor_Specific_Attribute', 'subtype'), 0xFF, 'vendor subtype'),
        ('lcmp.Binding_Re_registration_Control.start_time', 'LMA_Controlled_MAG_Parameters', {},
         ('suboptions', 'Binding_Re_registration_Control', 'start_time'), 0xFFFF,
         're-registration start time'),
        ('lcmp.Binding_Re_registration_Control.initial_retransmission',
         'LMA_Controlled_MAG_Parameters', {},
         ('suboptions', 'Binding_Re_registration_Control', 'initial_retransmission'), 0xFFFF,
         'initial retransmission timer'),
        ('lcmp.Binding_Re_registration_Control.max_retransmission',
         'LMA_Controlled_MAG_Parameters', {},
         ('suboptions', 'Binding_Re_registration_Control', 'max_retransmission'), 0xFFFF,
         'maximum retransmission timer'),
        ('lcmp.Heartbeat_Control.interval', 'LMA_Controlled_MAG_Parameters', {},
         ('suboptions', 'Heartbeat_Control', 'interval'), 0xFFFF, 'heartbeat interval'),
        ('lcmp.Heartbeat_Control.retransmission_delay', 'LMA_Controlled_MAG_Parameters', {},
         ('suboptions', 'Heartbeat_Control', 'retransmission_delay'), 0xFFFF, 'retransmission delay'),
        ('lcmp.Heartbeat_Control.max_retransmissions', 'LMA_Controlled_MAG_Parameters', {},
         ('suboptions', 'Heartbeat_Control', 'max_retransmissions'), 0xFFFF,
         'maximum retransmissions'),
    )

    #: Integer arguments outside the sweep, and why.
    EXEMPT = {
        # The CGA extension makers are reached only through a CGA parameter
        # schema; ``test_cga_multi_prefix_extension_fields_are_refused`` calls them.
        '_make_ext_multiprefix.reserved',
    }

    def _make(self, *options: 'tuple[str, dict[str, object]]', **kwargs: 'object') -> 'bytes':
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        return bytes(MH(next=TransType.IPv6_NoNxt, type=Packet.Binding_Refresh_Request,
                        data={'options': [(Option[name], args) for name, args in options]}, **kwargs))

    def _rebuild(self, data: 'bytes') -> 'bytes':
        from pcapkit.protocols.internet.mh import MH

        return MH.from_data(MH(io.BytesIO(data), len(data), extension=True).info).data

    def _rows(self) -> 'list[tuple]':
        from pcapkit.const.mh.ani_suboption import ANISuboption
        from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption
        from pcapkit.const.mh.lma_mag_suboption import LMAControlledMAGSuboption
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.mh.qos_attribute import QoSAttribute
        from pcapkit.protocols.internet.mh import MH

        def message(packet: 'str', arg: 'str') -> 'object':
            return lambda value: bytes(MH(next=59, type=Packet[packet], data={arg: value}))

        def option(code: 'str', base: 'dict', arg: 'str') -> 'object':
            return lambda value: self._make((code, {**base, arg: value}))

        enums = {'suboptions': (FlowIDSuboption, ANISuboption, LMAControlledMAGSuboption),
                 'attributes': (QoSAttribute,)}

        def nested(code: 'str', base: 'dict', path: 'tuple') -> 'object':
            def build(value: 'object') -> 'bytes':
                if len(path) == 2:
                    return self._make((code, {**base, path[0]: [value]}))
                key, sub, arg, *listed = path
                enum = next(e for e in enums[key] if sub in e.__members__)
                return self._make((code, {**base, key: [(enum[sub], {arg: [value] if listed else value})]}))
            return build

        rows = [('make.reserved', lambda value: self._make(reserved=value), 0xFF, 'reserved octet')]
        for suffix, (packet, args) in self.MESSAGES.items():
            for arg, (maximum, name) in args.items():
                rows.append((f'_make_msg_{suffix}.{arg}', message(packet, arg), maximum, name))
        for suffix, (code, base, args) in self.OPTIONS.items():
            for arg, (maximum, name) in args.items():
                rows.append((f'_make_opt_{suffix}.{arg}', option(code, base, arg), maximum, name))
        for label, code, base, path, maximum, name in self.NESTED:
            rows.append((label, nested(code, base, path), maximum, name))
        return rows

    def test_integer_arguments_are_swept(self) -> None:
        self.assertSwept('MH', self._rows(), self._rebuild)

    def test_every_integer_argument_is_swept(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        swept = {label for label, *_ in self._rows()} | self.EXEMPT
        for name in sorted(vars(MH)):
            if name != 'make' and not name.startswith(('_make_msg_', '_make_opt_', '_make_ext_')):
                continue
            for arg in integer_arguments(getattr(MH, name)):
                with self.subTest(maker=name, argument=arg):
                    self.assertIn(f'{name}.{arg}', swept)

    def test_header_too_long_for_header_length_is_refused(self) -> None:
        # RFC 6275 section 6.1.1: Header Len counts 8-octet units after the
        # first 8, in one octet, so the header is 2048 octets at most.
        vendor = ('Vendor_Specific_Mobility_Option', {'data': bytes(250)})
        data = self._make(*[vendor] * 7)
        self.assertEqual((len(data), data[1]), (1808, 225))
        self.assertEqual(self._rebuild(data), data)
        self.assertRefused('MH: invalid header length: 257', self._make, *[vendor] * 8)

    #: Octet arguments that never reach an ``Option Length``, and why.
    UNCOUNTED = {
        # The Option Length is ``length``, which the sweep checks; ``data``
        # fills that many octets.
        '_make_opt_pad.data',
        # A fixed eight-octet field (RFC 5949), refused at any other width.
        '_make_opt_mn_lla_iid.iid',
    }

    #: Options whose ``Option Length`` counts 32-bit words (RFC 7411 section 5.3).
    IN_WORDS = {'_make_opt_mcast', '_make_opt_mcast_ack'}

    #: Options whose ``Option Length`` sums a list, given one item too long for it.
    SUMMED = (
        ('Access_Network_Identifier', {'suboptions': [bytes(300)]}),
        ('CGA_Parameters', {'parameters': [bytes(300)]}),
        ('Context_Request_Option', {'requests': [(1, bytes(200)), (1, bytes(200))]}),
        ('Flow_Identification_Mobility_Option', {'suboptions': [bytes(300)]}),
        ('Flow_Summary_Mobility_Option', {'fid': [1] * 128}),
        ('IPv4_Traffic_Offload_Selector', {'selector': [bytes(300)]}),
        ('LMA_Controlled_MAG_Parameters', {'suboptions': [bytes(300)]}),
        ('Quality_of_Service', {'attributes': [bytes(300)]}),
    )

    def test_option_lengths_past_one_octet_are_refused(self) -> None:
        # RFC 6275 section 6.2: Option Length is one octet. Each size of a
        # run of eight crosses it whatever the option's alignment, so one of
        # them at least reaches the length check rather than another refusal.
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        swept = set()
        for maker, code in sorted(option_makers(MH).items()):
            unit = 4 if maker in self.IN_WORDS else 1
            for arg in octet_arguments(getattr(MH, maker)):
                if f'{maker}.{arg}' in self.UNCOUNTED:
                    continue
                swept.add(f'{maker}.{arg}')
                text = str(inspect.signature(getattr(MH, maker)).parameters[arg].annotation) == 'str'
                messages = []
                for size in range(256 * unit, 256 * unit + 8):
                    with self.subTest(maker=maker, argument=arg, size=size):
                        with self.assertRaises(ProtocolError) as caught:
                            self._make((Option(code).name, {arg: 'x' * size if text else bytes(size)}))
                        messages.append(str(caught.exception))
                with self.subTest(maker=maker, argument=arg):
                    self.assertTrue(any(message.startswith('MH: invalid Option Length: ')
                                        for message in messages), messages)
        self.assertIn('_make_opt_vendor.data', swept)
        for name, args in self.SUMMED:
            with self.subTest(option=name):
                with self.assertRaises(ProtocolError) as caught:
                    self._make((name, args))
                self.assertRegex(str(caught.exception), r'^MH: invalid Option Length: \d+$')
        self.assertRefused('MH: invalid Option Length: 256', MH.__new__(MH)._make_opt_none,
                           Option.PadN, data=bytes(256))

    def test_option_lengths_reach_one_octet(self) -> None:
        # Each option at the widest its Option Length counts builds and
        # survives parse -> rebuild; it follows the 8-octet Binding Refresh
        # Request, so its Option Length is octet 9.
        for name, args, length in (('DNS_UPDATE_TYPE', {'identity': bytes(253)}, 255),
                                   ('Service_Selection_Mobility_Option', {'identifier': 'x' * 255}, 255),
                                   ('Multicast_Mobility_Option', {'data': bytes(1020)}, 255)):
            with self.subTest(option=name):
                data = self._make((name, args))
                self.assertEqual(data[9], length)
                self.assertEqual(self._rebuild(data), data)

    def test_dhcp_support_mode_is_refused_out_of_range(self) -> None:
        # The mode is a registry code, given as a member or an int (#2593),
        # and fills the one-bit S flag of RFC 5844 section 3.4.
        for mode in (-1, 2):
            with self.subTest(mode=mode):
                self.assertRefused(f'MH: invalid DHCP support mode: {mode}', self._make,
                                   ('IPv4_DHCP_Support_Mode', {'mode': mode}))
        data = self._make(('IPv4_DHCP_Support_Mode', {'mode': 1}))
        self.assertEqual(self._rebuild(data), data)

    def test_geo_location_degrees_are_twos_complement(self) -> None:
        # RFC 6757 section 3.1.2: 24-bit two's-complement degrees.
        from pcapkit.const.mh.ani_suboption import ANISuboption

        for field in ('latitude', 'longitude'):
            for raw in (1 << 23, -(1 << 23) - 1, True):
                with self.subTest(field=field, raw=raw):
                    self.assertRefused(f'MH: invalid ANI geo-location {field}: {raw!r}', self._make,
                                       ('Access_Network_Identifier', {'suboptions': [
                                           (ANISuboption.Geo_Location, {f'raw_{field}': raw})]}))

        data = self._make(('Access_Network_Identifier', {'suboptions': [
            (ANISuboption.Geo_Location, {'raw_latitude': -1, 'raw_longitude': (1 << 23) - 1})]}))
        self.assertIn(bytes.fromhex('0206ffffff7fffff'), data)
        self.assertEqual(self._rebuild(data), data)

    def test_cga_multi_prefix_extension_fields_are_refused(self) -> None:
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.protocols.internet.mh import MH

        proto = MH.__new__(MH)
        maker = proto._make_ext_multiprefix
        for args, name, value in (({'reserved': -1}, 'reserved bits', -1),
                                  ({'reserved': 1 << 31}, 'reserved bits', 1 << 31),
                                  ({'reserved': True}, 'reserved bits', True),
                                  ({'prefixes': [-1]}, 'prefix', -1),
                                  ({'prefixes': [1 << 64]}, 'prefix', 1 << 64),
                                  ({'prefixes': [True]}, 'prefix', True)):
            with self.subTest(args=args):
                self.assertRefused(f'MH: invalid {name}: {value!r}', maker, CGAExtension.Multi_Prefix, **args)
        self.assertEqual(
            maker(CGAExtension.Multi_Prefix, reserved=(1 << 31) - 1, prefixes=[(1 << 64) - 1]).pack(),
            bytes.fromhex('0012000c7fffffffffffffffffffffff'))


class HIPMakerTests(_Case):
    """HIP's header maker and its parameter makers."""

    #: Parameters by maker suffix: ``{suffix: (code, base arguments, {argument: (maximum, name)})}``.
    #: A ``maximum`` of :data:`None` is a field as wide as its value. Widths
    #: per RFC 7401 section 5.2, RFC 7402 section 5.1.1, RFC 5770, RFC 6078,
    #: RFC 6079, RFC 6028, RFC 6261 and RFC 8004.
    PARAMETERS = {
        'esp_info': ('ESP_INFO', {}, {'reserved': (0xFFFF, 'reserved bits'),
                                      'index': (0xFFFF, 'KEYMAT index'),
                                      'old_spi': (0xFFFFFFFF, 'old SPI'),
                                      'new_spi': (0xFFFFFFFF, 'new SPI')}),
        'r1_counter': ('R1_COUNTER', {}, {'counter': ((1 << 64) - 1, 'R1 generation counter')}),
        'puzzle': ('PUZZLE', {'lifetime': 1}, {'index': (0xFF, 'puzzle difficulty'),
                                               'random': (None, 'puzzle random')}),
        'solution': ('SOLUTION', {}, {'index': (0xFF, 'puzzle difficulty'),
                                      'reserved': (0xFF, 'reserved octet'),
                                      'random': (None, 'puzzle random'),
                                      'solution': (None, 'puzzle solution')}),
        'seq': ('SEQ', {}, {'update_id': (0xFFFFFFFF, 'update ID')}),
        'diffie_hellman': ('DIFFIE_HELLMAN', {}, {'pub_val': (None, 'public value')}),
        'transaction_pacing': ('TRANSACTION_PACING', {}, {'min_ta': (0xFFFFFFFF, 'Min Ta')}),
        'cert': ('CERT', {}, {'cert_group': (0xFF, 'certificate group'),
                              'cert_count': (0xFF, 'certificate count'),
                              'cert_id': (0xFF, 'certificate ID')}),
        'reg_from': ('REG_FROM', {}, {'port': (0xFFFF, 'port')}),
        'seq_data': ('SEQ_DATA', {}, {'seq': (0xFFFFFFFF, 'sequence number')}),
        'route_dst': ('ROUTE_DST', {}, {'flags_reserved': (0x3FFF, 'reserved bits')}),
        'hip_transport_mode': ('HIP_TRANSPORT_MODE', {}, {'port': (0xFFFF, 'port')}),
        'relay_from': ('RELAY_FROM', {}, {'port': (0xFFFF, 'port')}),
        'relay_to': ('RELAY_TO', {}, {'port': (0xFFFF, 'port')}),
        'overlay_ttl': ('OVERLAY_TTL', {}, {'ttl': (0xFFFF, 'TTL')}),
        'route_via': ('ROUTE_VIA', {}, {'flags_reserved': (0x3FFF, 'reserved bits')}),
    }

    #: Header fields of :meth:`HIP.make`: ``{argument: (maximum, name)}``.
    HEADER = {
        'packet_fixed': (1, 'packet type fixed bit'),
        'version_reserved': (0x7, 'version reserved bits'),
        'version_fixed': (1, 'version fixed bit'),
        'controls_reserved': (0x7FFF, 'controls reserved bits'),
        'shit': ((1 << 128) - 1, 'sender HIT'),
        'rhit': ((1 << 128) - 1, 'receiver HIT'),
    }

    #: List entries and locator fields, which no maker signature declares:
    #: ``(label, build arguments from the value, maximum, name)``.
    NESTED = (
        ('ack.update_id[]', 'ACK', lambda value: {'update_id': [value]}, 0xFFFFFFFF, 'update ID'),
        ('ack_data.ack[]', 'ACK_DATA', lambda value: {'ack': [value]}, 0xFFFFFFFF,
         'acknowledged sequence number'),
        ('locator.traffic', 'LOCATOR_SET', lambda value: {'locator_set': [{'traffic': value}]}, 0xFF,
         'traffic type'),
        ('locator.reserved', 'LOCATOR_SET', lambda value: {'locator_set': [{'reserved': value}]}, 0x7F,
         'reserved bits'),
        ('locator.lifetime', 'LOCATOR_SET', lambda value: {'locator_set': [{'lifetime': value}]},
         0xFFFFFFFF, 'locator lifetime'),
        ('locator.spi', 'LOCATOR_SET', lambda value: {'locator_set': [{'spi': value}]}, 0xFFFFFFFF, 'SPI'),
    )

    #: Integer arguments outside the sweep, and why.
    EXEMPT = {
        # ``version`` is the HIP version, which HIP.make passes to every maker.
        *(f'_make_param_{suffix}.version' for suffix in (
            'ack', 'ack_data', 'cert', 'dh_group_list', 'diffie_hellman', 'echo_request_signed',
            'echo_request_unsigned', 'echo_response_signed', 'echo_response_unsigned', 'encrypted',
            'esp_info', 'esp_transform', 'from', 'hip_cipher', 'hip_mac', 'hip_mac_2',
            'hip_signature', 'hip_signature_2', 'hip_transform', 'hip_transport_mode',
            'hit_suite_list', 'host_id', 'locator_set', 'nat_traversal_mode', 'notification',
            'overlay_id', 'overlay_ttl', 'payload_mic', 'puzzle', 'r1_counter', 'reg_failed',
            'reg_from', 'reg_info', 'reg_request', 'reg_response', 'relay_from', 'relay_hmac',
            'relay_to', 'route_dst', 'route_via', 'rvs_hmac', 'seq', 'seq_data', 'solution',
            'transaction_id', 'transaction_pacing', 'transport_format_list', 'unassigned',
            'via_rvs')),
        # Seconds, which the lifetime helpers encode as the one-octet exponent.
        '_make_param_puzzle.lifetime', '_make_param_reg_info.min_lifetime',
        '_make_param_reg_info.max_lifetime', '_make_param_reg_request.lifetime',
        '_make_param_reg_response.lifetime',
        # Field widths, which _make_puzzle_field_width and _make_identifier_width check.
        '_make_param_puzzle.rhash_len', '_make_param_solution.rhash_len',
        '_make_param_transaction_id.id_len', '_make_param_overlay_id.id_len',
        # The lifetime octets and identifiers test_lifetimes_and_identifiers_are_refused covers.
        '_make_param_puzzle.lifetime_exponent', '_make_param_reg_info.min_lifetime_exponent',
        '_make_param_reg_info.max_lifetime_exponent', '_make_param_reg_request.lifetime_exponent',
        '_make_param_reg_response.lifetime_exponent', '_make_param_transaction_id.id',
        '_make_param_overlay_id.id',
        # The version names the protocol in every message; test_version_is_refused covers it.
        'make.version',
    }

    def _rebuild(self, data: 'bytes') -> 'bytes':
        from pcapkit.protocols.internet.hip import HIP

        return HIP.from_data(HIP(data).info).data

    def _rows(self) -> 'list[tuple]':
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        def header(arg: 'str') -> 'object':
            return lambda value: bytes(HIP(version=2, **{arg: value}))

        def parameter(code: 'str', args: 'object') -> 'object':
            return lambda value: bytes(HIP(version=2, parameters=[
                (Parameter[code], args(value))]))  # type: ignore[operator]

        rows = []
        for arg, (maximum, name) in self.HEADER.items():
            rows.append((f'make.{arg}', header(arg), maximum, name))
        for suffix, (code, base, args) in self.PARAMETERS.items():
            for arg, (maximum, name) in args.items():
                rows.append((f'_make_param_{suffix}.{arg}',
                             parameter(code, lambda value, base=base, arg=arg: {**base, arg: value}),
                             maximum, name))
        for label, code, args, maximum, name in self.NESTED:
            rows.append((label, parameter(code, args), maximum, name))
        return rows

    def test_integer_arguments_are_swept(self) -> None:
        self.assertSwept('HIPv2', self._rows(), self._rebuild)

    def test_every_integer_argument_is_swept(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        swept = {label for label, *_ in self._rows()} | self.EXEMPT
        for name in sorted(vars(HIP)):
            if name != 'make' and not name.startswith('_make_param_'):
                continue
            for arg in integer_arguments(getattr(HIP, name)):
                with self.subTest(maker=name, argument=arg):
                    self.assertIn(f'{name}.{arg}', swept)

    def test_version_is_refused(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for version in (-1, 16, True):
            with self.subTest(version=version):
                self.assertRefused(f'HIPv{version}: invalid version: {version!r}', HIP, version=version)

    def test_header_too_long_for_header_length_is_refused(self) -> None:
        # RFC 7401 section 5.1: Header Length counts 8-octet units after the
        # first 8, in one octet; the two HITs are 4 of them, a SEQ is 1.
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        seq = (Parameter.SEQ, {'update_id': 1})
        data = HIP(version=2, parameters=[seq] * 251).data
        self.assertEqual((len(data), data[1]), (2048, 255))
        self.assertEqual(self._rebuild(data), data)
        self.assertRefused('HIPv2: invalid header length: 256', HIP, version=2, parameters=[seq] * 252)

    def test_locator_type_is_refused_out_of_range(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        for kind in (-1, 256):
            with self.subTest(type=kind):
                self.assertRefused(f'HIPv2: invalid locator type: {kind}', HIP, version=2, parameters=[
                    (Parameter.LOCATOR_SET, {'locator_set': [{'type': kind}]})])

    def test_lifetimes_and_identifiers_are_refused(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        proto = HIP.__new__(HIP)
        self.assertRefused('HIPv2: invalid lifetime: True', proto._make_param_puzzle,
                           Parameter.PUZZLE, version=2, lifetime_exponent=True, random=1 << 63)
        self.assertRefused('HIPv2: invalid lifetime: True', proto._make_param_reg_request,
                           Parameter.REG_REQUEST, version=2, lifetime_exponent=True, reg_request=[1])
        for code in (Parameter.TRANSACTION_ID, Parameter.OVERLAY_ID):
            maker = proto._make_param_transaction_id if code == Parameter.TRANSACTION_ID \
                else proto._make_param_overlay_id
            with self.subTest(code=code):
                self.assertRefused('HIPv2: invalid identifier: -1', maker, code, version=2, id=-1)
                self.assertRefused('HIPv2: invalid identifier: True', maker, code, version=2, id=True)
                self.assertRefused('HIPv2: invalid identifier width: True', maker, code,
                                   version=2, id=1, id_len=True)

    def test_lifetime_seconds_are_refused_unless_finite_numbers(self) -> None:
        # ``True`` would be one second, a lifetime each field holds.
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        for code, arg in (('PUZZLE', 'lifetime'), ('REG_INFO', 'min_lifetime'), ('REG_INFO', 'max_lifetime'),
                          ('REG_REQUEST', 'lifetime'), ('REG_RESPONSE', 'lifetime')):
            for value in (True, float('inf'), float('nan'), '1'):
                with self.subTest(code=code, argument=arg, value=value):
                    with self.assertRaises(ProtocolError) as caught:
                        HIP(version=2, parameters=[(Parameter[code], {arg: value})])
                    self.assertIn(f'invalid lifetime: {value!r} is not a ', str(caught.exception))

    def test_rhash_len_is_refused_unless_a_width_the_length_counts(self) -> None:
        # RFC 7401 section 5.2.4: Length is two octets, so RHASH_len / 8 is
        # 65535 at most. ``8.0`` is refused although 8 bits is a width.
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        for code, base in (('PUZZLE', {'lifetime': 1}), ('SOLUTION', {})):
            for value in (True, 8.0, -8, 8 << 16, 1 << 200):
                with self.subTest(code=code, rhash_len=value):
                    self.assertRefused(f'HIPv2: invalid RHASH_len: {value!r}', HIP, version=2,
                                       parameters=[(Parameter[code], {**base, 'rhash_len': value})])


class OptionCodeTests(_Case):
    """The option makers refuse a registry code their field cannot carry."""

    #: One-bit codes, which take a :obj:`bool` as ``_make_uint`` lets one-bit fields.
    ONE_BIT = {'HOPOPT._make_opt_smf_dpd.mode', 'IPv6_Opts._make_opt_smf_dpd.mode',
               'MH._make_opt_ipv4_dhcp.mode'}

    def _builders(self) -> 'list[tuple[type, object]]':
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.internet.mh import MH

        return [
            (HOPOPT, lambda code, args: HOPOPT(next=59, options=[(code, args)])),
            (IPv6_Opts, lambda code, args: IPv6_Opts(next=59, options=[(code, args)])),
            (IPv4, lambda code, args: IPv4(protocol=253, options=[(code, args)])),
            (MH, lambda code, args: MH(next=59, type=Packet.Binding_Refresh_Request,
                                       data={'options': [(code, args)]})),
        ]

    def test_registry_codes_are_refused_out_of_range(self) -> None:
        # The codes are found from the maker signatures, so a new one is swept
        # without a row: -1, a value no field holds, and a bool in range.
        from pcapkit.utilities.exceptions import ProtocolError

        for cls, build in self._builders():
            swept = []
            for maker, code in sorted(option_makers(cls).items()):
                for arg in registry_arguments(getattr(cls, maker)):
                    label = f'{cls.__name__}.{maker}.{arg}'
                    swept.append(label)
                    for value in (-1, 1 << 200) if label in self.ONE_BIT else (-1, 1 << 200, True):
                        with self.subTest(maker=label, value=value):
                            with self.assertRaises(ProtocolError):
                                build(code, {arg: value})  # type: ignore[operator]
            with self.subTest(protocol=cls.__name__):
                self.assertTrue(swept)


if __name__ == '__main__':
    unittest.main()
