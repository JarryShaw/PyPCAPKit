# -*- coding: utf-8 -*-
"""The IPv6, IPv6 extension header, AH and ESP makers take an enumeration
field as a member or an :class:`int` code, and refuse what the field cannot carry.

GitHub issue #2594: each enumeration field of these makers is resolved with the
enumeration's ``get`` through
:meth:`~pcapkit.protocols.protocol.Protocol._make_index`, rather than through a
``X_default`` / ``X_namespace`` / ``X_reversed`` group and an enumeration
inferred from the caller's frame. A name, a :obj:`bool` for a field wider than
one bit, and a code too wide for the field each raise
:exc:`~pcapkit.utilities.exceptions.ProtocolError` naming the field (#2617).
Unchecked, ``IPv6_Route(next=256)`` and ``IPv6_Route(type=256)`` wrote ``0x00``
(#2676).

:data:`HEADER_ROWS` and :data:`OPTION_ROWS` hold one row per field. The option
makers' fields are reached through ``make(options=...)``, as a caller reaches
them, in both HOPOPT and IPv6-Opts, which share their code. Each field's width is the one its schema
declares and its RFC gives. ``test_every_enumeration_argument_has_a_row`` finds
the enumeration arguments from the maker signatures, so every one of them needs a
row and every row needs one.

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import inspect
import unittest

from tests._support import reimport_once_per_class

#: ``(class, argument, enumeration module, member, bits, field name)``: one row
#: per enumeration field. ``options`` stands for the type of an option given to
#: ``make``. HOPOPT and IPv6-Opts share every option row, see :data:`OPTION_ROWS`.
HEADER_ROWS = (
    # RFC 8200 sections 4.3 to 4.6: Next Header is 8 bits in each extension header.
    ('HOPOPT', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    ('IPv6_Opts', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    ('IPv6_Route', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    # RFC 8200 section 4.4: Routing Type is 8 bits.
    ('IPv6_Route', 'type', 'ipv6.routing', 'Routing.Nimrod', 8, 'routing type'),
    ('IPv6_Frag', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    # RFC 8200 section 3: Next Header is 8 bits.
    ('IPv6', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    # RFC 6564 section 4: the generic header's Next Header is 8 bits.
    ('IPv6_Ext', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    # RFC 4302 section 2.1 and RFC 4303 section 2.6: Next Header is 8 bits.
    ('AH', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
    ('ESP', 'next', 'reg.transtype', 'TransType.IPv6_NoNxt', 8, 'next header'),
)

#: ``(option, argument, enumeration module, member, bits, field name, other
#: arguments, data attribute)`` for the option makers of HOPOPT and IPv6-Opts.
#: The data attribute is where the parsed option keeps the field.
OPTION_ROWS = (
    # RFC 8200 section 4.2: Option Type is 8 bits.
    (None, 'options', 'ipv6.option', 'Option.Router_Alert', 8, 'option type', {}, None),
    # RFC 2711 section 2.1: Value is 2 octets.
    ('Router_Alert', 'alert', 'ipv6.router_alert', 'RouterAlert.Aggregated_Reservation_Nesting_Level_1',
     16, 'router alert value', {}, 'value'),
    # RFC 6621 section 6.1.1: the H bit is 1 bit, TidTy 3 bits.
    ('SMF_DPD', 'mode', 'ipv6.smf_dpd_mode', 'SMFDPDMode.H_DPD', 1, 'DPD mode',
     {'hav': b'\x01', 'id': b'\xaa'}, 'dpd_type'),
    ('SMF_DPD', 'tid_type', 'ipv6.tagger_id', 'TaggerID.DEFAULT', 3, 'TaggerID type',
     {'tid': b'\x0a\x0b\x0c\x0d', 'id': b'\xaa\xbb'}, 'tid_type'),
    # RFC 4782 section 3.1: Function is 4 bits.
    ('Quick_Start', 'func', 'ipv6.qs_function', 'QSFunction.Report_of_Approved_Rate', 4,
     'QS function', {}, 'func'),
    # RFC 7731 section 6.1: S is 2 bits.
    ('MPL_Option', 'seed_type', 'ipv6.seed_id', 'SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER', 2,
     'MPL seed-id type', {'seed': 5}, 'seed_type'),
)

#: ``{class: (module, alias)}`` of the makers under test.
CLASSES = {
    'HOPOPT': ('hopopt', 'HOPOPT'),
    'IPv6_Opts': ('ipv6_opts', 'IPv6-Opts'),
    'IPv6_Route': ('ipv6_route', 'IPv6-Route'),
    'IPv6_Frag': ('ipv6_frag', 'IPv6-Frag'),
    'IPv6': ('ipv6', 'IPv6'),
    'IPv6_Ext': ('ipv6_ext', 'IPv6-Ext'),
    'AH': ('ah', 'AH'),
    'ESP': ('esp', 'ESP'),
}


def _class(name: 'str') -> 'type':
    module = __import__(f'pcapkit.protocols.internet.{CLASSES[name][0]}', fromlist=[name])
    return getattr(module, name)


def _member(module: 'str', member: 'str') -> 'object':
    enum_name, attr = member.split('.')
    return getattr(getattr(__import__(f'pcapkit.const.{module}', fromlist=[enum_name]), enum_name), attr)


def _esp_context() -> 'object':
    from pcapkit.corekit.context import ContextRegistry
    from pcapkit.protocols.internet.esp import ESPContext, SecurityAssociation

    # NOTE: An ENCR_NULL association with no integrity algorithm, so that
    # ``encrypt=True`` writes ``next`` into the trailer without the cryptography package.
    return ContextRegistry.make(ESPContext(SecurityAssociation(spi=1)))


class _Row:
    """One enumeration field: how to build it, and how to read it back."""

    def __init__(self, cls: 'str', argument: 'str', module: 'str', member: 'str', bits: 'int',
                 field: 'str', option: 'object' = None, extra: 'object' = None,
                 attribute: 'object' = None) -> 'None':
        self.cls = cls
        self.argument = argument
        self.member = _member(module, member)
        self.bits = bits
        self.field = field
        self.option = option
        self.extra = extra or {}
        self.attribute = attribute

    @property
    def label(self) -> 'str':
        return f'{self.cls}.{self.argument}'

    @property
    def message(self) -> 'str':
        return f'{CLASSES[self.cls][1]}: invalid {self.field}'

    def build(self, value: 'object') -> 'bytes':
        from pcapkit.const.ipv6.option import Option

        cls = _class(self.cls)
        if self.argument == 'options':
            return cls(next=59, options=[(value, {})]).data
        if self.option is not None:
            args = {**self.extra, self.argument: value}
            return cls(next=59, options=[(Option[self.option], args)]).data
        if self.cls == 'ESP':
            return cls(spi=1, seq=1, next=value, encrypt=True, payload=b'abcd',
                       __context__=_esp_context()).data
        if self.cls == 'IPv6_Ext':
            return cls(next=value, len=0, data=bytes(6)).data
        return cls(**{self.argument: value}).data

    def read(self, octets: 'bytes') -> 'object':
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.ipv6.option import Option

        cls = _class(self.cls)
        if self.cls == 'IPv6':
            return cls(octets, len(octets)).info.next
        if self.cls == 'ESP':
            return cls(octets, len(octets), __context__=_esp_context()).info.next
        if self.cls == 'IPv6_Ext':
            return cls(octets, len(octets), extension=True, alias=ExtensionHeader.Shim6).info.next
        info = cls(octets, len(octets), extension=True).info
        if self.argument == 'options':
            return list(info.options.keys())[0]
        if self.option is not None:
            return getattr(info.options[Option[self.option]], self.attribute)
        return getattr(info, self.argument)


def _rows() -> 'list[_Row]':
    rows = [_Row(*row) for row in HEADER_ROWS]
    for cls in ('HOPOPT', 'IPv6_Opts'):
        for option, argument, module, member, bits, field, extra, attribute in OPTION_ROWS:
            rows.append(_Row(cls, argument, module, member, bits, field, option, extra, attribute))
    return rows


class TestEnumerationFieldCodes(unittest.TestCase):
    """Each enumeration field takes a member or a code, and refuses the rest."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRefused(self, row: '_Row', value: 'object') -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            row.build(value)
        self.assertEqual(str(caught.exception), f'{row.message}: {value!r}')

    def test_code_too_wide_for_its_field_is_refused(self) -> None:
        for row in _rows():
            with self.subTest(row=row.label, bits=row.bits):
                self.assertRefused(row, 1 << row.bits)

    def test_bool_is_refused_where_the_field_is_wider_than_one_bit(self) -> None:
        for row in _rows():
            if row.bits == 1:
                continue
            with self.subTest(row=row.label):
                self.assertRefused(row, True)

    def test_member_name_is_refused(self) -> None:
        for row in _rows():
            with self.subTest(row=row.label):
                self.assertRefused(row, row.member.name)

    def test_member_and_code_build_identical_octets(self) -> None:
        for row in _rows():
            with self.subTest(row=row.label):
                octets = row.build(row.member)
                self.assertEqual(row.build(int(row.member)), octets)
                self.assertEqual(row.read(octets), row.member)

    def test_every_enumeration_argument_has_a_row(self) -> None:
        # The arguments are found from the signatures: every argument of
        # ``make`` and every keyword-only argument of an option maker whose
        # annotation names an enumeration. A row naming no such argument fails too.
        rows = {row.label for row in _rows()}
        swept = set()
        for name in CLASSES:
            cls = _class(name)
            makers = [(cls.make, False)]
            for meth in getattr(cls, '__option__', {}).values():
                if isinstance(meth, str) and hasattr(cls, f'_make_opt_{meth}'):
                    makers.append((getattr(cls, f'_make_opt_{meth}'), True))
            for func, keyword_only in makers:
                for param in inspect.signature(func).parameters.values():
                    if keyword_only and param.kind is not param.KEYWORD_ONLY:
                        continue
                    if 'Enum_' in str(param.annotation):
                        swept.add(f'{name}.{param.name}')
        self.assertEqual(sorted(swept), sorted(rows))


if __name__ == '__main__':
    unittest.main()
