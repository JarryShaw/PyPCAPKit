# -*- coding: utf-8 -*-
"""Every protocol schema packs, unpacks and re-packs to the same octets. C.f. #1202.

Each concrete :class:`~pcapkit.protocols.schema.schema.Schema` subclass under
:mod:`pcapkit.protocols.schema` is enumerated, so a schema added tomorrow gets a
case tomorrow. For each one a **minimal valid instance** ``s`` is built and
packed to ``b``, and four things must hold:

* ``Schema.unpack(b)`` succeeds and accounts for exactly ``b`` (``SELF``);
* the parsed schema, packed again, is ``b`` (``REPACK``);
* ``from_dict(to_dict())`` of the parsed schema packs ``b`` (``DICT``);
* ``from_dict(to_dict())`` of ``s`` itself packs ``b`` (``DICT``).

The minimal instance is built from the field types: zero for a number, the
first registry member (or the schema's own code) for an enumeration, empty for a
variable-width field, zeros for a fixed one, a nested minimal instance for a
:class:`~pcapkit.corekit.fields.misc.SchemaField`. A number another field's
length, condition or selector reads -- found by reading the names those
callbacks subscript -- is a *driver*, and the drivers are searched over small
values until the instance closes; a name the schema reads from its enclosing
layer is supplied the same way, as packet context. Where none closes, the first
instance that packed is the one reported. :data:`OVERRIDES` holds the few
values no field type implies (a magic number, a NUL-terminated name).

A *dispatcher* -- a schema whose ``post_process`` returns the schema it
selected, such as TCP's ``_MPTCP`` -- is checked through its targets instead:
each target's minimal octets, parsed through the dispatcher, must come back as
that target and pack the same octets.

A case that does not close is a defect and goes in ``KNOWN_FAILURES`` (see
:mod:`tests.corekit._roundtrip`). Nothing imports :mod:`pcapkit` at module
level.

"""

from __future__ import annotations

import importlib
import inspect
import ipaddress
import itertools
import pkgutil
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.corekit._roundtrip import (OK, Gap, KnownFailureTable, Outcome, describe, diff, run,
                                      skip_without_runtime)

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

#: Package prefix stripped from a schema's module to make its label.
PREFIX = 'pcapkit.protocols.schema.'

#: Driver values tried for one driver, for two, and for three or more.
ONE_DRIVER = tuple(range(65))
TWO_DRIVERS = (0, 1, 2, 3, 4, 6, 8, 12, 16, 20, 24, 32)
MANY_DRIVERS = (0, 1, 2, 4, 8, 16)
#: Ceiling on driver combinations tried per schema.
MAX_COMBINATIONS = 400

#: Field values no field type implies, by schema label. A value is either the
#: value itself or a callable taking the schema's module.
OVERRIDES = {
    'misc.pcap.header:Header': {'magic_number': b'\xa1\xb2\xc3\xd4'},
    # ``match`` left unset, so ``pre_pack`` seeds the byte-order magic.
    'misc.pcapng:SectionHeaderBlock': {'match': None, 'magic': 0x1A2B3C4D},
    'misc.pcapng:IPv4Record': {'resol': 'a\x00'},
    'misc.pcapng:IPv6Record': {'resol': 'a\x00'},
    # The hash-assist value's first bit is the H-DPD mode bit [RFC 6621].
    'internet.hopopt:SMFHashBasedDPDOption': {'hav': b'\x80'},
    'internet.ipv6_opts:SMFHashBasedDPDOption': {'hav': b'\x80'},
}  # type: dict[str, dict[str, Any]]

#: Packet context a dispatch target needs from its enclosing layer.
DISPATCH_CONTEXT = {
    'transport.tcp:MPTCPJoinSYN': {'flags': {'syn': 1, 'ack': 0}},
    'transport.tcp:MPTCPJoinSYNACK': {'flags': {'syn': 1, 'ack': 1}},
    'transport.tcp:MPTCPJoinACK': {'flags': {'syn': 0, 'ack': 1}},
}  # type: dict[str, dict[str, Any]]

#: Dispatchers, to the base class whose concrete subclasses they select.
DISPATCHERS = {
    'internet.hopopt:_QuickStartOption': 'internet.hopopt:QuickStartOption',
    'internet.hopopt:_SMFDPDOption': 'internet.hopopt:SMFDPDOption',
    'internet.ipv6_opts:_QuickStartOption': 'internet.ipv6_opts:QuickStartOption',
    'internet.ipv6_opts:_SMFDPDOption': 'internet.ipv6_opts:SMFDPDOption',
    'internet.ipv4:_QSOption': 'internet.ipv4:QSOption',
    'transport.tcp:_MPTCP': 'transport.tcp:MPTCP',
}

#: Names of a bit-field subfield that carries a schema's own registry code.
CODE_SUBFIELDS = ('subtype', 'func', 'mode')

#: Schemas no minimal instance can be built for, to why. Each must still fail
#: to build, so one that starts building leaves this table.
UNBUILDABLE = {}  # type: dict[str, str]


class AutoZero(int):
    """An :obj:`int` that answers any subscript with zero.

    It stands in for a name a schema reads from its enclosing layer, whose
    shape the schema alone does not say: ``pkt['flags']['bit_3']`` and
    ``pkt['length'] - 2`` both work on it.

    """

    def __getitem__(self, key: 'Any') -> 'int':
        return 0

    def get(self, key: 'Any', default: 'Any' = None) -> 'int':  # pylint: disable=unused-argument
        """Zero, as for a subscript."""
        return 0


def label_of(cls: 'type') -> 'str':
    """``module:Qualname``, relative to :data:`PREFIX`."""
    return f'{cls.__module__.replace(PREFIX, "")}:{cls.__qualname__}'


def schema_classes() -> 'dict[str, type]':
    """Every :class:`Schema` subclass defined under :mod:`pcapkit.protocols.schema`."""
    import pcapkit.protocols.schema as package
    from pcapkit.protocols.schema.schema import Schema

    found = {}  # type: dict[str, type]
    for info in pkgutil.walk_packages(package.__path__, f'{package.__name__}.'):
        module = importlib.import_module(info.name)
        for obj in vars(module).values():
            if inspect.isclass(obj) and issubclass(obj, Schema) and obj.__module__ == module.__name__:
                found[label_of(obj)] = obj
    return found


def _strings(fn: 'Any', depth: 'int' = 0, out: 'Optional[set[str]]' = None) -> 'set[str]':
    """The string constants and names a callback's code mentions."""
    out = set() if out is None else out
    code = getattr(fn, '__code__', None)
    if depth > 4 or code is None:
        return out
    stack, names = [code], set()  # type: list[Any], set[str]
    while stack:
        current = stack.pop()
        names.update(current.co_names)
        for const in current.co_consts:
            if isinstance(const, str):
                out.add(const)
            elif hasattr(const, 'co_consts'):
                stack.append(const)
    out.update(names)
    for cell in getattr(fn, '__closure__', None) or ():
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        if callable(value):
            _strings(value, depth + 1, out)
    # a callback may only bind a shared helper's parameters, as the HOPOPT and
    # IPv6-Opts ones do (#1519), so read what it calls through a module too
    scope = getattr(fn, '__globals__', {})
    for owner in {id(module): module for module in (scope.get(name) for name in names)
                  if inspect.ismodule(module)}.values():
        for name in names:
            if inspect.isfunction(getattr(owner, name, None)):
                _strings(getattr(owner, name), depth + 1, out)
    return out


def _callbacks(field: 'Any') -> 'list[Any]':
    from pcapkit.corekit.fields.field import FieldBase

    found = [getattr(field, attr) for attr in ('_length_callback', '_condition', '_selector', '_callback')
             if getattr(field, attr, None) is not None]
    inner = getattr(field, '_field', None)
    if isinstance(inner, FieldBase):
        found.extend(_callbacks(inner))
    return found


def _unwrap(field: 'Any') -> 'Any':
    from pcapkit.corekit.fields.misc import ConditionalField

    return field.field if isinstance(field, ConditionalField) else field


def drivers(cls: 'type') -> 'list[tuple[str, Optional[str], int]]':
    """``(field, subfield, max)`` for every number another field's callback reads."""
    from pcapkit.corekit.fields.numbers import EnumField, NumberField
    from pcapkit.corekit.fields.strings import BitField

    names = set()  # type: set[str]
    for field in cls.__fields__.values():
        for fn in _callbacks(field):
            names |= _strings(fn)

    found = []  # type: list[tuple[str, Optional[str], int]]
    for name, field in cls.__fields__.items():
        field = _unwrap(field)
        if name not in names or (isinstance(field, EnumField) and field._namespace is not None):  # pylint: disable=protected-access
            continue
        if isinstance(field, NumberField) and not hasattr(field, '_flags'):
            width = field._bit_length if field._bit_length >= 0 else 8 * max(field._length, 1)  # pylint: disable=protected-access
            found.append((name, None, (1 << width) - 1))
        elif isinstance(field, BitField):
            for sub, (_, size) in field._namespace.items():  # pylint: disable=protected-access
                if sub in names:
                    found.append((name, sub, (1 << size) - 1))
    return found


def own_code(cls: 'type') -> 'Any':
    """The registry code ``cls`` is registered under, or an unassigned one."""
    from pcapkit.protocols.schema.schema import EnumSchema

    if not issubclass(cls, EnumSchema):
        return None
    try:
        registry = cls.registry
    except Exception:  # pylint: disable=broad-except
        return None
    for code, target in list(registry.items()):
        if target is cls:
            return code
    try:
        default = registry.default_factory() if registry.default_factory else None
    except Exception:  # pylint: disable=broad-except
        default = None
    if default is cls:
        taken = {int(code) for code in registry if isinstance(code, int)}
        return next(value for value in itertools.count(1) if value not in taken)
    return None


def registered_code(cls: 'type') -> 'Any':
    """The code ``cls`` or its nearest registered ancestor is registered under."""
    for base in cls.__mro__:
        try:
            items = list(cls.registry.items())
        except Exception:  # pylint: disable=broad-except
            return None
        for code, target in items:
            if target is base:
                return code
    return None


def _code_type(cls: 'type') -> 'Optional[type]':
    try:
        return type(next(iter(cls.registry)))
    except Exception:  # pylint: disable=broad-except
        return None


def outer_code(cls: 'type') -> 'Any':
    """The code a dispatcher is registered under in its own module's registries."""
    from pcapkit.protocols.schema.schema import EnumSchema

    module = importlib.import_module(cls.__module__)
    for obj in vars(module).values():
        if inspect.isclass(obj) and issubclass(obj, EnumSchema) and obj is not EnumSchema:
            try:
                items = list(obj.registry.items())
            except Exception:  # pylint: disable=broad-except
                continue
            for code, target in items:
                if target is cls:
                    return code
    return None


def minimal(field: 'Any', cls: 'type', depth: 'int', ctx: 'dict[str, Any]') -> 'Any':  # pylint: disable=too-many-return-statements,too-many-branches
    """The minimal value of ``field``, as the field type implies it."""
    from pcapkit.corekit.fields import ipaddress as fip
    from pcapkit.corekit.fields.collections import ListField
    from pcapkit.corekit.fields.field import NO_VALUE
    from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, NoValueField,
                                             PayloadField, SchemaField, SwitchField)
    from pcapkit.corekit.fields.numbers import EnumField, NumberField
    from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField, StringField

    if isinstance(field, (ConditionalField, ForwardMatchField)):
        return minimal(field.field, cls, depth, ctx)
    if isinstance(field, NoValueField):
        return None
    if isinstance(field, SwitchField):
        try:
            return minimal(field._selector(ctx), cls, depth, ctx)  # pylint: disable=protected-access
        except Exception:  # pylint: disable=broad-except
            return None
    if field.default is not NO_VALUE and not isinstance(field, SchemaField):
        return field.default
    if hasattr(field, '_flags'):
        return {name: 0 for name in field._flags}  # pylint: disable=protected-access
    if isinstance(field, EnumField):
        namespace = field._namespace  # pylint: disable=protected-access
        code, kind = own_code(cls), _code_type(cls)
        if code is not None and namespace is not None and kind is not None and (
                issubclass(kind, namespace) or issubclass(namespace, kind)):
            return code
        if namespace is None:
            return 0
        members = getattr(namespace, '_value2member_map_', {})
        return members[0] if 0 in members else next(iter(namespace), 0)
    if isinstance(field, NumberField):
        return 0
    if isinstance(field, BitField):
        return {name: 0 for name in field._namespace}  # pylint: disable=protected-access
    if isinstance(field, PaddingField):
        return b''
    if isinstance(field, (StringField, BytesField)):
        width = field._length if field._length_callback is None else -1  # pylint: disable=protected-access
        if isinstance(field, StringField):
            return '\x00' * max(width, 0)
        return bytes(max(width, 0))
    for kind, value in ((fip.IPv4AddressField, ipaddress.IPv4Address(0)),
                        (fip.IPv6AddressField, ipaddress.IPv6Address(0)),
                        (fip.IPv4InterfaceField, ipaddress.IPv4Interface('0.0.0.0/0')),
                        (fip.IPv6InterfaceField, ipaddress.IPv6Interface('::/0'))):
        if isinstance(field, kind):
            return value
    if isinstance(field, ListField):
        # A declared area is filled with zeros, which every option registry here
        # reads as padding or end-of-option-list; an undeclared one is empty.
        try:
            width = field(ctx).length
        except Exception:  # pylint: disable=broad-except
            width = -1
        return bytes(width) if width > 0 else []
    if isinstance(field, PayloadField):
        return b''
    if isinstance(field, SchemaField):
        if field.default is not NO_VALUE:
            return field.default
        if depth > 3:
            return None
        try:
            return build(field.schema, depth + 1)[0]
        except Exception:  # pylint: disable=broad-except
            return None
    return None


def _base_values(cls: 'type', depth: 'int', ctx: 'dict[str, Any]') -> 'dict[str, Any]':
    from pcapkit.corekit.fields.numbers import EnumField
    from pcapkit.corekit.fields.strings import BitField

    values = {}  # type: dict[str, Any]
    for name, field in cls.__fields__.items():
        values[name] = minimal(field, cls, depth, {**ctx, **values, '__length__': -1})

    # A dispatch target carries the dispatcher's code in its type field, and its
    # own code in the bit-field subfield the dispatcher selects on.
    for dispatcher, base in DISPATCHERS.items():
        if not label_of(cls).startswith(dispatcher.split(':')[0] + ':'):
            continue
        base_cls = getattr(importlib.import_module(cls.__module__), base.split(':')[1])
        if not issubclass(cls, base_cls):
            continue
        outer = outer_code(getattr(importlib.import_module(cls.__module__), dispatcher.split(':')[1]))
        code = registered_code(cls)
        code = own_code(cls) if code is None else code
        for name, field in cls.__fields__.items():
            field = _unwrap(field)
            if outer is not None and isinstance(field, EnumField) and field._namespace is not None \
                    and isinstance(outer, field._namespace):  # pylint: disable=protected-access
                values[name] = outer
            if code is not None and isinstance(field, BitField):
                for sub in CODE_SUBFIELDS:
                    if sub in field._namespace:  # pylint: disable=protected-access
                        values[name] = {**values[name], sub: int(code)}

    module = importlib.import_module(cls.__module__)
    for name, value in OVERRIDES.get(label_of(cls), {}).items():
        values[name] = value(module) if callable(value) else value
    return values


def _attempt(cls: 'type', depth: 'int', ctx: 'dict[str, Any]', combo: 'tuple[int, ...]',
             drv: 'list[tuple[str, Optional[str], int]]') -> 'tuple[Any, bytes, dict[str, Any]]':
    packet = dict(ctx)
    for (name, _, _), value in zip(drv, combo):
        if name in ctx:
            packet[name] = AutoZero(value)
    values = _base_values(cls, depth, packet)
    for (name, sub, _), value in zip(drv, combo):
        if name not in cls.__fields__:
            continue
        if sub is None:
            values[name] = value
        else:
            values[name] = {**values[name], sub: value}
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        schema = cls.from_dict({key: value for key, value in values.items() if value is not None})
        raw = schema.pack(dict(packet))
    return schema, raw, packet


def build(cls: 'type', depth: 'int' = 0, extra: 'Optional[dict[str, Any]]' = None,
          lengths: 'bool' = False, accept: 'Optional[Callable[..., Outcome]]' = None) -> 'Any':
    """``(schema, octets, context)`` for a minimal instance of ``cls``.

    At ``depth`` 0 the first driver combination whose instance closes -- by
    :func:`check`, or by ``accept`` -- is returned; if none closes,
    ``(schema, outcome)`` of the first that packed. ``lengths`` adds the
    schema's own ``length``/``len`` field to the drivers, for a dispatch target
    whose length only the dispatcher reads.

    Raises:
        RuntimeError: If no combination packs at all.

    """
    ctx = dict(extra or {})
    first = None  # type: Any
    for _ in range(6):
        drv = drivers(cls) + [(name, None, 0xFFFF) for name in ctx if name not in (extra or {})]
        if lengths:
            drv += [(name, None, 0xFF) for name in ('length', 'len')
                    if name in cls.__fields__ and all(name != item[0] for item in drv)]
        choices = ONE_DRIVER if len(drv) == 1 else TWO_DRIVERS if len(drv) == 2 else MANY_DRIVERS
        missing = None
        tried = 0
        for combo in itertools.product(choices, repeat=len(drv)):
            if any(value > top for (_, _, top), value in zip(drv, combo)):
                continue
            tried += 1
            if tried > MAX_COMBINATIONS:
                break
            try:
                schema, raw, packet = _attempt(cls, depth, ctx, combo, drv)
            except KeyError as exc:
                key = exc.args[0] if exc.args else None
                if isinstance(key, str) and key not in ctx and key not in cls.__fields__:
                    missing = key
                    break
                first = first if first is not None else exc
                continue
            except Exception as exc:  # pylint: disable=broad-except
                first = first if first is not None else exc
                continue
            if depth:
                return schema, raw, packet
            outcome = (accept or check)(cls, schema, raw, packet)
            if outcome.status == 'OK':
                return schema, raw, packet
            if not isinstance(first, tuple):
                first = (schema, outcome)
        if missing is None:
            break
        ctx[missing] = AutoZero(0)
    if not depth and isinstance(first, tuple):
        return first
    raise RuntimeError(f'no minimal instance packs (context {sorted(ctx)}): '
                       f'{describe(first) if isinstance(first, BaseException) else first}')


def check(cls: 'type', schema: 'Any', raw: 'bytes', ctx: 'dict[str, Any]') -> 'Outcome':
    """The four assertions of the module docstring, for one built instance."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            parsed = cls.unpack(raw, len(raw), dict(ctx))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REPARSE', describe(exc))
        if bytes(parsed) != raw:
            return Outcome('SELF', diff(bytes(parsed), raw))
        try:
            repacked = parsed.pack(dict(ctx))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REPACK', describe(exc))
        if repacked != raw:
            return Outcome('REPACK', diff(repacked, raw))
        for what, source in (('parsed', parsed), ('built', schema)):
            try:
                rebuilt = type(source).from_dict(source.to_dict()).pack(dict(ctx))
            except Exception as exc:  # pylint: disable=broad-except
                return Outcome('DICT', f'{what}: {describe(exc)}')
            if rebuilt != raw:
                return Outcome('DICT', f'{what}: {diff(rebuilt, raw)}')
    return OK


def _referenced(cls: 'type') -> 'set[str]':
    """Every name a callback of any schema in ``cls``'s module reads.

    The whole module rather than ``cls`` alone, since a nested schema reads its
    enclosing schema's fields through the packet context -- HTTP/2's ``DATA``
    frame reads the frame header's ``flags``.

    """
    from pcapkit.protocols.schema.schema import Schema

    names = set(OVERRIDES.get(label_of(cls), ()))
    for obj in vars(importlib.import_module(cls.__module__)).values():
        if inspect.isclass(obj) and issubclass(obj, Schema):
            for field in obj.__fields__.values():
                for fn in _callbacks(field):
                    names |= _strings(fn)
    return names


def patterned(cls: 'type', schema: 'Any', ctx: 'dict[str, Any]') -> 'Outcome':
    """The minimal instance with every free value made non-zero, checked again.

    Zeros survive a reversed, shifted or dropped octet unchanged, so a minimal
    instance alone cannot see such a defect. A value is *free* when no callback
    in the schema's module reads its name and :data:`OVERRIDES` does not set it: a plain number becomes ``1``, a fixed-width
    octet string ``01 02 ...``, every subfield of a bit field ``1``, an address
    ``10.0.0.1`` or ``fe80::1``.

    """
    from pcapkit.corekit.fields import ipaddress as fip
    from pcapkit.corekit.fields.numbers import EnumField, NumberField
    from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField

    names = _referenced(cls)
    values = dict(schema.to_dict())
    for name, field in cls.__fields__.items():
        field = _unwrap(field)
        if name in names or name not in values or values[name] is None:
            continue
        if isinstance(field, EnumField) or hasattr(field, '_flags'):
            continue
        if isinstance(field, NumberField):
            values[name] = 1
        elif isinstance(field, BitField):
            values[name] = {sub: 1 for sub in field._namespace}  # pylint: disable=protected-access
        elif isinstance(field, BytesField) and not isinstance(field, PaddingField) \
                and field._length_callback is None and field._length > 0:  # pylint: disable=protected-access
            values[name] = bytes(index % 255 + 1 for index in range(field._length))  # pylint: disable=protected-access
        elif isinstance(field, fip.IPv4AddressField):
            values[name] = ipaddress.IPv4Address('10.0.0.1')
        elif isinstance(field, fip.IPv6AddressField):
            values[name] = ipaddress.IPv6Address('fe80::1')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            built = type(schema).from_dict(values)
            raw = built.pack(dict(ctx))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('MAKE', describe(exc))
    return check(type(schema), built, raw, ctx)


def run_patterned(cls: 'type') -> 'Outcome':
    """Build ``cls`` and check its patterned variant."""
    try:
        out = build(cls)
    except RuntimeError as exc:
        return Outcome('UNBUILT', str(exc))
    if len(out) == 2:
        return Outcome('UNBUILT', f'minimal instance does not close: {out[1].status}')
    return patterned(cls, out[0], out[2])


def run_schema(cls: 'type') -> 'Outcome':
    """Build ``cls`` and check it."""
    try:
        out = build(cls)
    except RuntimeError as exc:
        return Outcome('UNBUILT', str(exc))
    if len(out) == 2:
        return out[1]
    return OK


def check_dispatch(dispatcher: 'type', target: 'type', raw: 'bytes', ctx: 'dict[str, Any]') -> 'Outcome':
    """``raw``, parsed through ``dispatcher``, is ``target`` and packs ``raw``."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            parsed = dispatcher.unpack(raw, len(raw), dict(ctx))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('DISPATCH', describe(exc))
        if type(parsed) is not target:
            return Outcome('DISPATCH', f'parsed as {type(parsed).__qualname__}')
        try:
            repacked = parsed.pack(dict(ctx))
            rebuilt = type(parsed).from_dict(parsed.to_dict()).pack(dict(ctx))
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('REPACK', describe(exc))
    if repacked != raw:
        return Outcome('REPACK', diff(repacked, raw))
    if rebuilt != raw:
        return Outcome('DICT', diff(rebuilt, raw))
    return OK


def run_dispatch(dispatcher: 'type', target: 'type') -> 'Outcome':
    """A minimal ``target`` that closes on its own, parsed through ``dispatcher``."""
    def accept(cls: 'type', schema: 'Any', raw: 'bytes', ctx: 'dict[str, Any]') -> 'Outcome':
        outcome = check(cls, schema, raw, ctx)
        return check_dispatch(dispatcher, cls, raw, ctx) if outcome.status == 'OK' else outcome

    try:
        out = build(target, extra=DISPATCH_CONTEXT.get(label_of(target), {}), lengths=True, accept=accept)
    except RuntimeError as exc:
        return Outcome('UNBUILT', str(exc))
    return out[1] if len(out) == 2 else OK


class SchemaRoundTripTests(KnownFailureTable, unittest.TestCase):
    """Schema ``pack``/``unpack`` and ``from_dict``/``to_dict`` symmetry."""

    STATUSES = ('OK', 'UNBUILT', 'MAKE', 'REPARSE', 'SELF', 'REPACK', 'DICT', 'DISPATCH', 'TIMEOUT')

    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]

    def setUp(self) -> None:
        skip_without_runtime(self)
        reimport_once_per_class(self)

    def _cases(self) -> 'tuple[dict[str, type], dict[str, tuple[type, type]]]':
        classes = schema_classes()
        plain = {label: cls for label, cls in classes.items()
                 if cls.__fields__ and label not in DISPATCHERS}
        dispatch = {}  # type: dict[str, tuple[type, type]]
        for dispatcher, base in DISPATCHERS.items():
            for label, cls in classes.items():
                if cls.__fields__ and issubclass(cls, classes[base]) and cls.__dict__.get('__final__'):
                    dispatch[f'dispatch/{dispatcher}/{label}'] = (classes[dispatcher], cls)
        return plain, dispatch

    def _labels(self) -> 'list[str]':
        plain, dispatch = self._cases()
        return list(plain) + [f'{label}/patterned' for label in plain] + list(dispatch)

    def test_tables_name_real_cases(self) -> None:
        labels = self._labels()
        self.check_table(labels)
        _, dispatch = self._cases()
        classes = schema_classes()
        for table in (OVERRIDES, DISPATCHERS, DISPATCH_CONTEXT, UNBUILDABLE):
            self.assertEqual(sorted(set(table) - set(classes)), [], 'stale table entries')
        self.assertEqual(sorted(set(DISPATCHERS.values()) - set(classes)), [])
        for dispatcher in DISPATCHERS:
            self.assertTrue(any(label.startswith(f'dispatch/{dispatcher}/') for label in dispatch),
                            f'{dispatcher} has no targets')

    def test_the_census_is_the_whole_package(self) -> None:
        """Every schema with fields is a case, a dispatcher, or the base classes."""
        plain, _ = self._cases()
        classes = schema_classes()
        fieldless = sorted(label for label, cls in classes.items() if not cls.__fields__)
        self.assertEqual(len(plain) + len(DISPATCHERS) + len(fieldless), len(classes))
        self.assertGreater(len(plain), 400)

    def test_minimal_instance_round_trips(self) -> None:
        plain, _ = self._cases()
        gaps = self.gap_table(self._labels())
        for label, cls in sorted(plain.items()):
            with self.subTest(case=label):
                outcome = run(run_schema, cls)
                if label in UNBUILDABLE:
                    self.assertEqual(outcome.status, 'UNBUILT', f'{label} builds now: drop it from UNBUILDABLE')
                    continue
                self.check_outcome(label, outcome, gaps)

    def test_patterned_instance_round_trips(self) -> None:
        plain, _ = self._cases()
        gaps = self.gap_table(self._labels())
        for label, cls in sorted(plain.items()):
            if label in UNBUILDABLE:
                continue
            with self.subTest(case=f'{label}/patterned'):
                self.check_outcome(f'{label}/patterned', run(run_patterned, cls), gaps)

    def test_dispatchers_select_and_rebuild_each_target(self) -> None:
        _, dispatch = self._cases()
        gaps = self.gap_table(self._labels())
        for label, (dispatcher, target) in sorted(dispatch.items()):
            with self.subTest(case=label):
                self.check_outcome(label, run(run_dispatch, dispatcher, target), gaps)


if __name__ == '__main__':
    unittest.main()
