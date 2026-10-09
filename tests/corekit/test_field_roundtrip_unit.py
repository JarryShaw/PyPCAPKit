# -*- coding: utf-8 -*-
"""Every corekit field packs and unpacks symmetrically. C.f. #1202.

For each concrete field class under :mod:`pcapkit.corekit.fields`, two
directions are checked on representative and boundary inputs:

* **value**: ``unpack(pack(v)) == v``, and packing the result again gives the
  same octets;
* **wire**: ``pack(unpack(b)) == b``.

A field that a schema only ever uses in context -- a forward match, a
conditional, a nested schema left with a remainder, an option list followed by
its padding -- is also checked inside a minimal schema, as
``Schema.unpack(b).pack() == b`` and ``from_dict(to_dict())`` packing ``b``.

Malformed wire input a field is entitled to refuse is listed in
:data:`REJECTED` and must raise an in-library exception. Every other failing
case is a defect, listed in ``KNOWN_FAILURES`` by root cause (see
:mod:`tests.corekit._roundtrip`).

Nothing here imports :mod:`pcapkit` at module level; the cases are built inside
each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import collections
import enum
import inspect
import ipaddress
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import reimport_once_per_class
from tests.corekit._roundtrip import (OK, Gap, KnownFailureTable, Outcome, describe, diff, run,
                                      skip_without_runtime)

if TYPE_CHECKING:
    from typing import Any, Callable


class FieldCase(NamedTuple):
    """One field and the inputs it is round-tripped on."""

    #: Unique label prefix, ``FieldClass/variant``.
    label: 'str'
    #: Builds the (unresolved) field.
    make: 'Callable[[], Any]'
    #: Values for the value direction.
    values: 'tuple[Any, ...]' = ()
    #: Octets for the wire direction.
    wires: 'tuple[bytes, ...]' = ()
    #: Packet context the field is resolved and (un)packed with.
    packet: 'dict[str, Any]' = {}


class SchemaCase(NamedTuple):
    """One minimal schema exercising a field in context, and its wire input."""

    #: Unique label, ``schema/what``.
    label: 'str'
    #: Builds the schema class.
    make: 'Callable[[], Any]'
    #: Wire octets.
    raw: 'bytes'


#: Field classes that are not round-tripped on their own, and why.
NOT_CONCRETE = {
    'FieldBase': 'internal base class; its template is the placeholder ``0s``',
    'Field': 'base class: ``Field.__init__`` sets no ``_template``, so a bare '
             '``Field`` cannot be packed; every concrete subclass sets one',
}

#: Wire labels a field must refuse with an in-library exception, to that
#: exception's class name.
REJECTED = {
    'IPv6InterfaceField/prefix/wire/' + '00' * 16 + '81': 'FieldValueError',
    'IPv6InterfaceField/prefix/wire/' + '00' * 16 + 'ff': 'FieldValueError',
}


def named(field: 'Any', name: 'str' = 'items') -> 'Any':
    """Name ``field`` as a schema class body would (``__set_name__``).

    :class:`~pcapkit.corekit.fields.collections.ListField` replaces
    ``FieldBase.__init__`` without setting a placeholder name, and
    :meth:`OptionField.unpack <pcapkit.corekit.fields.collections.OptionField.unpack>`
    reads ``self.name``, so a list field used outside a schema needs one
    (#1491).

    """
    field.name = name
    return field


def _bounds(width: 'int', signed: 'bool') -> 'tuple[int, ...]':
    """The boundary values of a ``width``-octet integer, and one inside."""
    bits = width * 8
    if signed:
        return (0, 1, -1, (1 << (bits - 1)) - 1, -(1 << (bits - 1)))
    return (0, 1, (1 << bits) - 1, 1 << (bits - 1))


def _wires(width: 'int') -> 'tuple[bytes, ...]':
    """Representative octets of a ``width``-octet field."""
    if width == 0:
        return (b'',)
    return (bytes(width), b'\xff' * width, b'\x80' + bytes(width - 1),
            bytes(range(1, width + 1)))


def field_cases() -> 'tuple[FieldCase, ...]':  # pylint: disable=too-many-locals,too-many-statements
    """Every field case, built against the current :mod:`pcapkit` import."""
    import aenum

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.fields import collections as fcoll
    from pcapkit.corekit.fields import ipaddress as fip
    from pcapkit.corekit.fields import misc as fmisc
    from pcapkit.corekit.fields import numbers as fnum
    from pcapkit.corekit.fields import strings as fstr
    from pcapkit.protocols.misc.raw import Raw
    from pcapkit.protocols.schema.schema import Schema, schema_final

    cases = []  # type: list[FieldCase]

    # -- numbers ------------------------------------------------------------
    fixed = {'Int8Field': 1, 'UInt8Field': 1, 'Int16Field': 2, 'UInt16Field': 2,
             'Int32Field': 4, 'UInt32Field': 4, 'Int64Field': 8, 'UInt64Field': 8}
    for name, width in fixed.items():
        cls = getattr(fnum, name)
        for order in ('big', 'little'):
            cases.append(FieldCase(
                f'{name}/{order}', lambda cls=cls, order=order: cls(byteorder=order),
                _bounds(width, cls.__signed__), _wires(width)))

    for width in (1, 2, 3, 4, 5, 7, 8, 9, 16):
        for signed in (False, True):
            for order in ('big', 'little'):
                sign = 'signed' if signed else 'unsigned'
                cases.append(FieldCase(
                    f'NumberField/{width}-{sign}-{order}',
                    lambda width=width, signed=signed, order=order: fnum.NumberField(
                        length=lambda pkt: pkt['n'], signed=signed, byteorder=order),
                    _bounds(width, signed), _wires(width), {'n': width}))
    cases.append(FieldCase(
        'NumberField/3-fixed', lambda: fnum.NumberField(length=3),
        _bounds(3, False), _wires(3)))
    cases.append(FieldCase(
        'NumberField/bit-length-12', lambda: fnum.UInt16Field(bit_length=12),
        (0, 1, 0xFFF), (b'\x00\x00', b'\x0f\xff', b'\xff\xff', b'\xf0\x00')))

    class Stdlib(enum.IntEnum):
        """A stdlib registry with gaps."""
        A = 0
        B = 1
        C = 255

    class Aenum(aenum.IntEnum):
        """An :mod:`aenum` registry with gaps."""
        A = 0
        B = 2

    for label, namespace, values in (('stdlib', Stdlib, tuple(Stdlib)),
                                     ('aenum', Aenum, tuple(Aenum)),
                                     ('none', None, (0, 7, 255)),
                                     ('transtype', TransType, (TransType.TCP, TransType.UDP))):
        cases.append(FieldCase(
            f'EnumField/{label}',
            lambda namespace=namespace: fnum.EnumField(length=1, namespace=namespace),
            values, (b'\x00', b'\x01', b'\x02', b'\x06', b'\x7f', b'\x90', b'\xff')))
    cases.append(FieldCase(
        'EnumField/2-octet', lambda: fnum.EnumField(length=2, namespace=TransType),
        (TransType.TCP,), (b'\x00\x06', b'\x01\x00', b'\xff\xff')))
    cases.append(FieldCase(
        'EnumField/bit-length-3', lambda: fnum.EnumField(length=1, bit_length=3, namespace=None),
        (0, 7), (b'\x00', b'\x07', b'\xff')))

    # -- strings ------------------------------------------------------------
    for width in (0, 1, 4):
        cases.append(FieldCase(
            f'BytesField/{width}', lambda width=width: fstr.BytesField(length=width),
            (bytes(width), b'\xff' * width), _wires(width)))
    cases.append(FieldCase(
        'BytesField/callable', lambda: fstr.BytesField(length=lambda pkt: pkt['n']),
        (b'abcde', bytes(5)), _wires(5), {'n': 5}))

    texts = {
        '': b'', 'abc': b'abc', 'utf-8': 'café'.encode(), 'latin-1': 'café'.encode('latin-1'),
        'invalid': b'\xff\xfe\x00', 'nul': b'\x00\x00', 'embedded-nul': b'a\x00b',
        'all-octets': bytes(range(256)),
    }
    for label, raw in texts.items():
        cases.append(FieldCase(
            f'StringField/detect-{label or "empty"}',
            lambda raw=raw: fstr.StringField(length=len(raw)), (), (raw,)))
    for encoding, values, wires in (
            ('utf-8', ('', 'abc', 'café', '€', '\U0001f600'), (b'\xc3', b'\xe2\x82', b'\xff')),
            ('ascii', ('', 'abc'), (b'\x80', b'abc\xff')),
            ('latin-1', ('', 'café', 'ÿ'), (b'\xff\xfe',)),
            ('utf-16', ('abc', '€'), (b'\xff\xfea\x00', b'a\x00', b'\x00'))):
        for value in values:
            raw = value.encode(encoding)
            cases.append(FieldCase(
                f'StringField/{encoding}/{value.encode("unicode_escape").decode() or "empty"}',
                lambda encoding=encoding, raw=raw: fstr.StringField(length=len(raw), encoding=encoding),
                (value,), (raw,)))
        for raw in wires:
            cases.append(FieldCase(
                f'StringField/{encoding}/bad-{raw.hex()}',
                lambda encoding=encoding, raw=raw: fstr.StringField(length=len(raw), encoding=encoding),
                (), (raw,)))
    for errors in ('ignore', 'replace'):
        for raw in (b'abc', b'\xff\xfe', b'caf\xe9'):
            cases.append(FieldCase(
                f'StringField/errors-{errors}/{raw.hex()}',
                lambda errors=errors, raw=raw: fstr.StringField(length=len(raw), encoding='utf-8',
                                                                errors=errors),
                (), (raw,)))
    for raw in (b'a%20b', b'%zz', b'%41', b'+', b'%E9', b'a b', b'%25', b'%C3%A9'):
        cases.append(FieldCase(
            f'StringField/unquote/{raw.decode()}',
            lambda raw=raw: fstr.StringField(length=len(raw), unquote=True), (), (raw,)))
    for value in ('a b', 'café', '%', '/x?y=1&z'):
        import urllib.parse  # pylint: disable=import-outside-toplevel
        raw = urllib.parse.quote(value).encode()
        cases.append(FieldCase(
            f'StringField/unquote-value/{urllib.parse.quote(value)}',
            lambda raw=raw: fstr.StringField(length=len(raw), unquote=True), (value,), ()))

    full = {'a': (0, 1), 'b': (1, 3), 'c': (4, 4)}
    cases.append(FieldCase(
        'BitField/1-octet', lambda: fstr.BitField(length=1, namespace=full),
        ({'a': 0, 'b': 0, 'c': 0}, {'a': 1, 'b': 7, 'c': 15}, {'a': 1, 'b': 2, 'c': 5}),
        _wires(1) + (b'\xa5',)))
    wide = {'flag': (0, 1), 'id': (1, 31)}
    cases.append(FieldCase(
        'BitField/4-octet', lambda: fstr.BitField(length=4, namespace=wide),
        ({'flag': 0, 'id': 0}, {'flag': 1, 'id': (1 << 31) - 1}), _wires(4)))
    partial = {'a': (0, 1), 'c': (8, 4)}
    cases.append(FieldCase(
        'BitField/partial', lambda: fstr.BitField(length=2, namespace=partial),
        ({'a': 1, 'c': 15},), (b'\x00\x00', b'\x80\xf0', b'\xff\xff', b'\x01\x00')))

    for width in (0, 3):
        cases.append(FieldCase(
            f'PaddingField/{width}', lambda width=width: fstr.PaddingField(length=width),
            (bytes(width), b'\x01' * width), _wires(width)))
    cases.append(FieldCase(
        'PaddingField/callable', lambda: fstr.PaddingField(length=lambda pkt: pkt['n']),
        (b'\xde\xad',), _wires(2), {'n': 2}))

    # -- addresses ----------------------------------------------------------
    cases.append(FieldCase(
        'IPv4AddressField/plain', fip.IPv4AddressField,
        tuple(ipaddress.IPv4Address(a) for a in ('0.0.0.0', '255.255.255.255', '10.0.0.1')),
        _wires(4)))
    cases.append(FieldCase(
        'IPv6AddressField/plain', fip.IPv6AddressField,
        tuple(ipaddress.IPv6Address(a) for a in ('::', 'fe80::1', '::ffff:1.2.3.4',
                                                 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')),
        _wires(16)))
    cases.append(FieldCase(
        'IPv4InterfaceField/masks', fip.IPv4InterfaceField,
        tuple(ipaddress.IPv4Interface(a) for a in ('0.0.0.0/0', '10.0.0.1/24', '10.0.0.1/32',
                                                   '255.255.255.255/1')),
        tuple(bytes.fromhex(h) for h in (
            '0000000000000000', '0a000001ffffff00', '0a000001000000ff', '0a000001ff00ff00',
            'ffffffffffffffff', '0a00000100000000', '0a0000017fffffff', '0a00000180000001'))))
    cases.append(FieldCase(
        'IPv6InterfaceField/prefix', fip.IPv6InterfaceField,
        tuple(ipaddress.IPv6Interface(a) for a in ('::/0', 'fe80::1/64', '::1/128')),
        tuple(fill + bytes([prefix]) for fill in (bytes(16), b'\xff' * 16)
              for prefix in (0, 1, 64, 127, 128)) + (bytes(16) + b'\x81', bytes(16) + b'\xff')))

    # -- misc ---------------------------------------------------------------
    cases.append(FieldCase('NoValueField/plain', fmisc.NoValueField, (None,), (b'',)))
    cases.append(FieldCase(
        'ConditionalField/true',
        lambda: fmisc.ConditionalField(fnum.UInt16Field(), lambda pkt: pkt['flag']),
        _bounds(2, False), _wires(2), {'flag': True}))
    cases.append(FieldCase(
        'ConditionalField/false',
        lambda: fmisc.ConditionalField(fnum.UInt16Field(default=7), lambda pkt: pkt['flag']),
        (), (b'',), {'flag': False}))
    cases.append(FieldCase(
        'PayloadField/bytes', fmisc.PayloadField, (b'', b'abc'), (b'', b'abc', bytes(64))))
    cases.append(FieldCase(
        'PayloadField/raw', lambda: fmisc.PayloadField(protocol=Raw), (), (b'abc', bytes(64))))

    def switch() -> 'Any':
        return fmisc.SwitchField(selector=lambda pkt: (
            fnum.UInt16Field() if pkt['kind'] == 0 else fstr.BytesField(length=3)))

    cases.append(FieldCase('SwitchField/number', switch, (0, 0xFFFF), _wires(2), {'kind': 0}))
    cases.append(FieldCase('SwitchField/bytes', switch, (b'abc',), _wires(3), {'kind': 1}))
    cases.append(FieldCase(
        'ForwardMatchField/inner', lambda: fmisc.ForwardMatchField(fnum.UInt16Field()),
        (), _wires(2)))

    @schema_final
    class Inner(Schema):
        """Three octets: a byte and a short."""

        x: 'int' = fnum.UInt8Field()
        y: 'int' = fnum.UInt16Field()

    cases.append(FieldCase(
        'SchemaField/fixed', lambda: fmisc.SchemaField(length=3, schema=Inner),
        (Inner(x=1, y=2), Inner(x=0xFF, y=0xFFFF)), _wires(3)))
    cases.append(FieldCase(
        'SchemaField/variable', lambda: fmisc.SchemaField(schema=Inner),
        (Inner(x=0, y=0),), _wires(3)))

    cases.append(FieldCase(
        'ListField/bytes', lambda: named(fcoll.ListField(length=lambda pkt: pkt['n'])),
        (b'abcd',), _wires(4), {'n': 4}))
    cases.append(FieldCase(
        'ListField/numbers',
        lambda: named(fcoll.ListField(length=lambda pkt: pkt['n'], item_type=fnum.UInt16Field())),
        ([0, 1, 0xFFFF],), _wires(6), {'n': 6}))
    cases.append(FieldCase(
        'ListField/schemas',
        lambda: named(fcoll.ListField(length=lambda pkt: pkt['n'],
                                      item_type=fmisc.SchemaField(length=3, schema=Inner))),
        ([Inner(x=1, y=2), Inner(x=3, y=4)],), _wires(6), {'n': 6}))

    class Base(Schema):
        """Option header: a one-octet type and a one-octet body length."""

        kind: 'int' = fnum.UInt8Field()
        size: 'int' = fnum.UInt8Field()

    @schema_final
    class Body(Base):
        """An option carrying ``size`` octets."""

        body: 'bytes' = fstr.BytesField(length=lambda pkt: pkt['size'])

    @schema_final
    class End(Base):
        """End of option list."""

    registry = collections.defaultdict(lambda: Body, {0: End, 1: Body})

    cases.append(FieldCase(
        'OptionField/tlv',
        lambda: named(fcoll.OptionField(length=lambda pkt: pkt['n'], base_schema=Base,
                                        type_name='kind', registry=registry, eool=0)),
        ([Body(kind=1, size=2, body=b'ab'), End(kind=0, size=0)],),
        (b'\x01\x02ab\x00\x00', b'\x01\x00\x05\x01z', b'\x00\x00'), {'n': 6}))
    return tuple(cases)


def schema_cases() -> 'tuple[SchemaCase, ...]':
    """Minimal schemas holding the fields that only make sense in context."""
    from pcapkit.corekit.fields import collections as fcoll
    from pcapkit.corekit.fields import misc as fmisc
    from pcapkit.corekit.fields import numbers as fnum
    from pcapkit.corekit.fields import strings as fstr
    from pcapkit.protocols.schema.schema import Schema, schema_final

    def forward() -> 'Any':
        @schema_final
        class Forward(Schema):
            """A forward match sizing the field after it."""

            test: 'int' = fmisc.ForwardMatchField(fnum.UInt8Field())
            size: 'int' = fnum.UInt8Field()
            body: 'bytes' = fstr.BytesField(length=lambda pkt: pkt['test'])
        return Forward

    def conditional() -> 'Any':
        @schema_final
        class Conditional(Schema):
            """A field present only when a flag is set."""

            flag: 'int' = fnum.UInt8Field()
            extra: 'int' = fmisc.ConditionalField(fnum.UInt16Field(), lambda pkt: pkt['flag'] == 1)
            tail: 'int' = fnum.UInt8Field()
        return Conditional

    def remainder() -> 'Any':
        @schema_final
        class Inner(Schema):
            """Two octets."""

            x: 'int' = fnum.UInt16Field()

        @schema_final
        class Outer(Schema):
            """A nested schema whose span holds more than it reads (#1380)."""

            size: 'int' = fnum.UInt8Field()
            inner: 'Inner' = fmisc.SchemaField(length=lambda pkt: pkt['size'], schema=Inner)
            tail: 'int' = fnum.UInt8Field()
        return Outer

    def options() -> 'Any':
        class Base(Schema):
            """Option header."""

            kind: 'int' = fnum.UInt8Field()
            size: 'int' = fnum.UInt8Field()

        @schema_final
        class Body(Base):
            """An option carrying ``size`` octets."""

            body: 'bytes' = fstr.BytesField(length=lambda pkt: pkt['size'])

        @schema_final
        class End(Base):
            """End of option list."""

        registry = collections.defaultdict(lambda: Body, {0: End, 1: Body})

        @schema_final
        class Options(Schema):
            """An option area of eight octets, then its padding (#1289)."""

            options: 'list[Base]' = fcoll.OptionField(
                length=8, base_schema=Base, type_name='kind', registry=registry, eool=0)
            padding: 'bytes' = fstr.PaddingField(
                length=lambda pkt: pkt.get('__option_padding__', 0))
        return Options

    def payload() -> 'Any':
        @schema_final
        class Header(Schema):
            """A header and its payload."""

            size: 'int' = fnum.UInt16Field()
            payload: 'bytes' = fmisc.PayloadField(length=lambda pkt: pkt['size'])
        return Header

    def short() -> 'Any':
        @schema_final
        class Short(Schema):
            """Fixed fields, for a truncated read (#1458)."""

            a: 'int' = fnum.UInt16Field()
            b: 'int' = fnum.UInt32Field()
            c: 'int' = fnum.UInt16Field()
        return Short

    return (
        SchemaCase('forward/empty', forward, b'\x00'),
        SchemaCase('forward/body', forward, b'\x03abc'),
        SchemaCase('conditional/absent', conditional, b'\x00\x09'),
        SchemaCase('conditional/present', conditional, b'\x01\xbe\xef\x09'),
        SchemaCase('remainder/none', remainder, b'\x02\x12\x34\x09'),
        SchemaCase('remainder/kept', remainder, b'\x04\x12\x34\xaa\xbb\x09'),
        SchemaCase('remainder/zero-filled', remainder, b'\x04\x12\x34\x00\x00\x09'),
        SchemaCase('options/eool-then-padding', options, b'\x01\x02ab\x00\x00\xde\xad'),
        SchemaCase('options/full', options, b'\x01\x06abcdef'),
        SchemaCase('payload/empty', payload, b'\x00\x00'),
        SchemaCase('payload/bytes', payload, b'\x00\x03abc'),
        SchemaCase('short/inside-second', short, b'\x00\x01\x02\x03'),
        SchemaCase('short/inside-last', short, b'\x00\x01\x02\x03\x04\x05\x06'),
    )


def _in_library(exc: 'BaseException') -> 'bool':
    from pcapkit.utilities.exceptions import BaseError
    return isinstance(exc, BaseError)


def _hex(raw: 'bytes') -> 'str':
    return raw.hex() or 'empty'


def check_value(case: 'FieldCase', value: 'Any') -> 'Outcome':
    """``unpack(pack(v)) == v``, and the result packs to the same octets."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            packed = case.make()(dict(case.packet)).pack(value, dict(case.packet))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('PACK', describe(exc))
        try:
            got = case.make()(dict(case.packet)).unpack(packed, dict(case.packet))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('UNPACK', describe(exc))
        if got != value:
            return Outcome('VALUE', f'{got!r} != {value!r} (packed {packed.hex()})')
        try:
            again = case.make()(dict(case.packet)).pack(got, dict(case.packet))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REPACK', describe(exc))
    if again != packed:
        return Outcome('REPACK', diff(again, packed))
    return OK


def check_wire(case: 'FieldCase', raw: 'bytes') -> 'Outcome':
    """``pack(unpack(b)) == b``."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            value = case.make()(dict(case.packet)).unpack(raw, dict(case.packet))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REJECTED' if _in_library(exc) else 'UNPACK', describe(exc))
        if case.label.startswith('ForwardMatchField/'):
            # A forward match is non-capturing: it reads what its inner field
            # reads and packs nothing, leaving the octets to the next field.
            inner = case.make().field(dict(case.packet)).unpack(raw, dict(case.packet))
            if value != inner:
                return Outcome('VALUE', f'{value!r} != {inner!r}')
            return OK
        try:
            packed = case.make()(dict(case.packet)).pack(value, dict(case.packet))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('PACK', describe(exc))
    if packed != raw:
        return Outcome('WIRE', diff(packed, raw))
    return OK


def check_schema(case: 'SchemaCase') -> 'Outcome':
    """``unpack(b).pack() == b``, and ``from_dict(to_dict())`` packs ``b``."""
    cls = case.make()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            parsed = cls.unpack(case.raw, len(case.raw), None)
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('UNPACK', describe(exc))
        try:
            packed = parsed.pack()
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('PACK', describe(exc))
        if packed != case.raw:
            return Outcome('WIRE', diff(packed, case.raw))
        try:
            rebuilt = type(parsed).from_dict(parsed.to_dict()).pack()
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('DICT', describe(exc))
    if rebuilt != case.raw:
        return Outcome('DICT', diff(rebuilt, case.raw))
    return OK


class FieldRoundTripTests(KnownFailureTable, unittest.TestCase):
    """Field ``pack``/``unpack`` symmetry, in both directions."""

    STATUSES = ('OK', 'PACK', 'UNPACK', 'VALUE', 'REPACK', 'WIRE', 'DICT', 'REJECTED', 'TIMEOUT')

    KNOWN_FAILURES = (
        Gap(1487, 'BitField.post_process reads only the bits its namespace names, and '
               'pre_process seeds the rest as zeros, so octets with a bit outside every '
               'subfield set pack back with it cleared '
               '(pcapkit/corekit/fields/strings.py:311, :334). Not reachable from a shipped '
               'schema: all 102 BitFields cover every bit '
               '(test_every_schema_bitfield_covers_every_bit)',
            'WIRE', '', ('BitField/partial/wire/ffff', 'BitField/partial/wire/0100')),
        Gap(1488, 'NumberField with bit_length narrower than its octets masks the unpacked value '
               'to bit_length bits, so set high bits are dropped and pack writes them as '
               'zeros (pcapkit/corekit/fields/numbers.py:318, :322). Shipped use: vlan.TCI '
               '(pcapkit/protocols/schema/link/vlan.py:47-51), which no protocol parses with',
            'WIRE', '', ('NumberField/bit-length-12/wire/ffff', 'NumberField/bit-length-12/wire/f000',
                         'EnumField/bit-length-3/wire/ff')),
    )

    def setUp(self) -> None:
        skip_without_runtime(self)
        reimport_once_per_class(self)

    # -- labels -------------------------------------------------------------

    @staticmethod
    def _value_labels(cases: 'tuple[FieldCase, ...]') -> 'list[tuple[str, FieldCase, Any]]':
        return [(f'{case.label}/value/{index}', case, value)
                for case in cases for index, value in enumerate(case.values)]

    @staticmethod
    def _wire_labels(cases: 'tuple[FieldCase, ...]') -> 'list[tuple[str, FieldCase, bytes]]':
        return [(f'{case.label}/wire/{_hex(raw)}', case, raw)
                for case in cases for raw in case.wires]

    def _labels(self) -> 'list[str]':
        cases = field_cases()
        return ([label for label, _, _ in self._value_labels(cases)]
                + [label for label, _, _ in self._wire_labels(cases)]
                + [f'schema/{case.label}' for case in schema_cases()])

    # -- the tables ---------------------------------------------------------

    def test_tables_name_real_cases(self) -> None:
        labels = self._labels()
        self.check_table(labels)
        self.assertEqual(sorted(set(REJECTED) - set(labels)), [], 'stale REJECTED labels')
        self.assertEqual(sorted(set(self.gap_table(labels)) & set(REJECTED)), [],
                         'a label cannot be both rejected and a known failure')

    def test_every_concrete_field_class_has_a_case(self) -> None:
        """A field class added tomorrow fails here until it gets a case."""
        import pcapkit.corekit.fields as package
        from pcapkit.corekit.fields.field import FieldBase

        classes = set()
        for module in ('field', 'numbers', 'strings', 'ipaddress', 'misc', 'collections'):
            mod = getattr(package, module)
            for name, obj in vars(mod).items():
                if (inspect.isclass(obj) and issubclass(obj, FieldBase)
                        and obj.__module__ == mod.__name__ and not name.startswith('_')):
                    classes.add(name)
        covered = {case.label.split('/')[0] for case in field_cases()}
        self.assertEqual(sorted(classes - covered - set(NOT_CONCRETE)), [])
        self.assertEqual(sorted(set(NOT_CONCRETE) & covered), [])
        self.assertEqual(sorted(set(NOT_CONCRETE) - classes), [], 'stale NOT_CONCRETE entries')

    def test_every_schema_bitfield_covers_every_bit(self) -> None:
        """Why the partial-namespace gap above is unreachable from the library."""
        import importlib
        import pkgutil

        import pcapkit.protocols.schema as package
        from pcapkit.corekit.fields.misc import ConditionalField, ForwardMatchField
        from pcapkit.corekit.fields.strings import BitField
        from pcapkit.protocols.schema.schema import Schema

        total, uncovered = 0, []
        for info in pkgutil.walk_packages(package.__path__, f'{package.__name__}.'):
            module = importlib.import_module(info.name)
            for obj in vars(module).values():
                if not (inspect.isclass(obj) and issubclass(obj, Schema) and obj.__module__ == module.__name__):
                    continue
                for name, field in obj.__fields__.items():
                    if isinstance(field, ForwardMatchField):
                        # A forward match peeks and packs nothing; its bits are
                        # read again, for real, by the fields after it.
                        continue
                    if isinstance(field, ConditionalField):
                        field = field.field
                    if not isinstance(field, BitField):
                        continue
                    total += 1
                    bits = set()
                    for start, size in field._namespace.values():  # pylint: disable=protected-access
                        bits.update(range(start, start + size))
                    if len(bits) != field.length * 8:
                        uncovered.append(f'{obj.__qualname__}.{name}')
        self.assertGreater(total, 0)
        self.assertEqual(uncovered, [])

    # -- the checks ---------------------------------------------------------

    def test_unpack_of_pack_is_the_value(self) -> None:
        cases = field_cases()
        gaps = self.gap_table(self._labels())
        for label, case, value in self._value_labels(cases):
            with self.subTest(case=label):
                self.check_outcome(label, run(check_value, case, value), gaps)

    def test_pack_of_unpack_is_the_wire(self) -> None:
        cases = field_cases()
        gaps = self.gap_table(self._labels())
        for label, case, raw in self._wire_labels(cases):
            if label in REJECTED:
                continue
            with self.subTest(case=label):
                self.check_outcome(label, run(check_wire, case, raw), gaps)

    def test_malformed_wire_is_rejected_in_library(self) -> None:
        cases = {label: (case, raw) for label, case, raw in self._wire_labels(field_cases())}
        for label, exc in REJECTED.items():
            case, raw = cases[label]
            with self.subTest(case=label):
                outcome = run(check_wire, case, raw)
                self.assertEqual(outcome.status, 'REJECTED', outcome.detail)
                self.assertTrue(outcome.detail.startswith(f'{exc}: '), outcome.detail)

    def test_fields_in_a_schema_round_trip(self) -> None:
        gaps = self.gap_table(self._labels())
        for case in schema_cases():
            label = f'schema/{case.label}'
            with self.subTest(case=label):
                self.check_outcome(label, run(check_schema, case), gaps)

    def test_a_decoded_string_keeps_its_octets(self) -> None:
        """The lossless decode the string cases rely on (#1336), checked directly."""
        from pcapkit.corekit.fields.strings import DecodedString, StringField

        value = StringField(length=4)({}).unpack(b'caf\xe9', {})
        self.assertIsInstance(value, DecodedString)
        self.assertEqual(value.raw, b'caf\xe9')


if __name__ == '__main__':
    unittest.main()
