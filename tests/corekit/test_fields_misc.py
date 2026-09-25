from __future__ import annotations

import copy
import unittest

from tests._support import purge_modules

#: Every address-typed branch of every address-typed
#: :class:`~pcapkit.corekit.fields.misc.SwitchField` in the schema tree, as
#: ``(module, class, attribute, label, packet)``. The ``packet`` is a selector
#: input that resolves that switch to an address field.
#:
#: This table is **enumerated rather than sampled**, and
#: :meth:`SwitchFieldBoolDispatchTests.test_the_address_typed_switch_table_is_complete`
#: holds it to that by rediscovering the switches programmatically and comparing.
#: So a new address-typed switch added to any schema module fails that test until
#: it is listed here -- which is the point, since #491 and #508 were both the same
#: defect surviving at a site nobody had thought of.
ADDRESS_TYPED_SWITCH_BRANCHES = [
    ('pcapkit.protocols.schema.internet.hip', 'Locator', 'value',
     'hip locator IPv6', {'type': 0, 'len': 4}),

    # ``tid_type`` 2 is ``TaggerID.IPv4`` and 3 is ``TaggerID.IPv6``; the
    # selector also demands the matching ``len``, 3 and 15 respectively.
    ('pcapkit.protocols.schema.internet.hopopt', 'SMFIdentificationBasedDPDOption', 'tid',
     'hopopt smf tid IPv4', {'info': {'type': 2, 'len': 3}}),
    ('pcapkit.protocols.schema.internet.hopopt', 'SMFIdentificationBasedDPDOption', 'tid',
     'hopopt smf tid IPv6', {'info': {'type': 3, 'len': 15}}),
    ('pcapkit.protocols.schema.internet.ipv6_opts', 'SMFIdentificationBasedDPDOption', 'tid',
     'ipv6_opts smf tid IPv4', {'info': {'type': 2, 'len': 3}}),
    ('pcapkit.protocols.schema.internet.ipv6_opts', 'SMFIdentificationBasedDPDOption', 'tid',
     'ipv6_opts smf tid IPv6', {'info': {'type': 3, 'len': 15}}),

    ('pcapkit.protocols.schema.internet.mh', 'BindingIdentifierOption', 'address',
     'mh bid IPv4', {'length': 8}),
    ('pcapkit.protocols.schema.internet.mh', 'BindingIdentifierOption', 'address',
     'mh bid IPv6', {'length': 20}),
    ('pcapkit.protocols.schema.internet.mh', 'DelegatedMNPOption', 'prefix',
     'mh dmnp IPv4', {'flags': {'V': 1}}),
    ('pcapkit.protocols.schema.internet.mh', 'DelegatedMNPOption', 'prefix',
     'mh dmnp IPv6', {'flags': {'V': 0}}),
    ('pcapkit.protocols.schema.internet.mh', 'LMAAddressOption', 'address',
     'mh lmaa IPv4', {'length': 6}),
    ('pcapkit.protocols.schema.internet.mh', 'LMAAddressOption', 'address',
     'mh lmaa IPv6', {'length': 18}),
    ('pcapkit.protocols.schema.internet.mh', 'LMAUserPlaneAddressOption', 'address',
     'mh lma_up IPv4', {'length': 6}),
    ('pcapkit.protocols.schema.internet.mh', 'LMAUserPlaneAddressOption', 'address',
     'mh lma_up IPv6', {'length': 18}),
    ('pcapkit.protocols.schema.internet.mh', 'MNIDOption', 'identifier',
     'mh mn_id IPv6', {'subtype': 2, 'length': 17}),
    ('pcapkit.protocols.schema.internet.mh', 'TargetCareofAddressSuboption', 'address',
     'mh tcoa IPv4', {'length': 6}),
    ('pcapkit.protocols.schema.internet.mh', 'TargetCareofAddressSuboption', 'address',
     'mh tcoa IPv6', {'length': 18}),

    ('pcapkit.protocols.schema.transport.tcp', 'MPTCPAddAddress', 'address',
     'tcp mptcp add_addr IPv4', {'test': {'version': 4}}),
    ('pcapkit.protocols.schema.transport.tcp', 'MPTCPAddAddress', 'address',
     'tcp mptcp add_addr IPv6', {'test': {'version': 6}}),
]


def discover_address_typed_switches() -> 'set[tuple[str, str, str]]':
    """Find every address-typed :class:`SwitchField` declaration in the schema tree.

    Walks :attr:`Schema.__fields__` for every :class:`Schema` subclass rather than
    grepping annotations, because three of the switches --
    ``mh.BindingIdentifierOption.address`` and both
    ``SMFIdentificationBasedDPDOption.tid`` -- are wrapped in a
    :class:`~pcapkit.corekit.fields.misc.ConditionalField` and so are invisible to
    a grep for a ``SwitchField`` annotation. #508's own table listed seven for
    exactly that reason; there are ten.

    Returns:
        ``(module, class, attribute)`` for each distinct declaration. Declarations
        are deduplicated by field-object identity, since a subclass inherits its
        bases' ``__fields__`` entries rather than re-declaring them.

    """
    import importlib
    import inspect
    import pkgutil

    import pcapkit.protocols.schema as schema_pkg
    from pcapkit.corekit.fields.misc import (ConditionalField,
                                             ForwardMatchField, SwitchField)
    from pcapkit.protocols.schema.schema import Schema

    for module in pkgutil.walk_packages(schema_pkg.__path__, schema_pkg.__name__ + '.'):
        importlib.import_module(module.name)

    subclasses, stack = set(), [Schema]
    while stack:
        for sub in stack.pop().__subclasses__():
            if sub not in subclasses:
                subclasses.add(sub)
                stack.append(sub)

    found, seen = set(), set()
    for cls in subclasses:
        for attr, field in getattr(cls, '__fields__', {}).items():
            while isinstance(field, (ConditionalField, ForwardMatchField)):
                field = field.field
            if not isinstance(field, SwitchField) or id(field) in seen:
                continue
            seen.add(id(field))

            # an address-typed switch is one that can *return* an address field;
            # read off the selector's own source, since the branch actually taken
            # depends on a packet this function does not have
            try:
                source = inspect.getsource(field._selector)
            except (OSError, TypeError):  # pragma: no cover
                continue
            if any(name in source for name in
                   ('IPv4AddressField', 'IPv6AddressField',
                    'IPv4InterfaceField', 'IPv6InterfaceField')):
                found.add((cls.__module__, cls.__qualname__, attr))
    return found


class SchemaFieldDefaultTests(unittest.TestCase):
    """Regression coverage for `#444 <https://github.com/JarryShaw/PyPCAPKit/issues/444>`__.

    :class:`~pcapkit.corekit.fields.misc.SchemaField` accepts a documented,
    typed ``default: bytes`` constructor argument and unpacks it eagerly, via
    ``schema.unpack(default)`` -- a single positional argument. That call
    shape reached
    :func:`~pcapkit.utilities.decorators.prepare`, which read ``length`` and
    ``packet`` out of ``args[2]``/``args[3]`` unconditionally, so any call
    shorter than three positional arguments raised ``IndexError`` instead of
    falling back to the documented ``None`` default -- making
    ``SchemaField(schema=..., default=b'...')`` unusable for exactly the
    ``bytes`` default it exists to accept.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class TwoField(Schema):
            a: 'int' = UInt8Field()
            b: 'int' = UInt8Field()

        self.SchemaField = SchemaField
        self.TwoField = TwoField

    def test_schema_field_accepts_a_bytes_default(self) -> None:
        field = self.SchemaField(schema=self.TwoField, default=b'\x01\x02')

        self.assertIsInstance(field.default, self.TwoField)
        self.assertEqual(field.default.a, 1)
        self.assertEqual(field.default.b, 2)


class SwitchFieldBoolDispatchTests(unittest.TestCase):
    """Why #508's guard is *not* in :class:`~pcapkit.corekit.fields.misc.SwitchField`.

    #508 read the defect as a dispatch problem: because
    :class:`~pcapkit.corekit.fields.misc.SwitchField` picks the concrete field at
    runtime, the reasoning went, a :obj:`bool` never reaches
    :meth:`~pcapkit.corekit.fields.ipaddress._IPAddressField.pre_process` and so
    #500's guard cannot fire -- which would put the fix in ``SwitchField``.
    Measured, that is not what happens.
    :meth:`SwitchField.pre_process <pcapkit.corekit.fields.misc.SwitchField.pre_process>`
    delegates straight to the resolved field, so a :obj:`bool` that actually
    arrives at an address-selecting switch is already rejected, on *every*
    address-typed branch of every such switch. The real cause is upstream of the
    schema entirely: the ``_make_*`` converts the argument itself, to size the
    option, and so destroys the :obj:`bool` before the schema is built.

    Both halves are pinned here, because both are load-bearing for the choice of
    fix location:

    * a guard in ``SwitchField`` would be dead code for the address-typed
      branches, since the resolved field already raises, and
    * a *blanket* one would be actively wrong for the integer-typed branches,
      where a :obj:`bool` legitimately means ``0``/``1`` -- the same ruling that
      keeps ``NonceIndicesOption.home`` accepting one.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @staticmethod
    def _resolve(module: 'str', name: 'str', attr: 'str') -> 'tuple[object, object]':
        """Return ``(declared field, inner SwitchField)`` for one table entry."""
        import importlib

        from pcapkit.corekit.fields.misc import (ConditionalField,
                                                 ForwardMatchField)

        declared = getattr(importlib.import_module(module), name).__fields__[attr]
        inner = declared
        while isinstance(inner, (ConditionalField, ForwardMatchField)):
            inner = inner.field
        return declared, inner

    def test_address_typed_switch_branches_already_reject_a_bool(self) -> None:
        """Every address-typed branch of every address-typed switch already refuses a bool.

        Eighteen branches over ten switches in four protocol modules -- not just
        :mod:`~pcapkit.protocols.schema.internet.mh`'s six -- because the claim
        being pinned is about ``SwitchField`` in general, so a fix scoped to one
        module would not settle it. Measured on ``main`` at ``27bb315d5``, i.e.
        *before* #508's fix: all thirty-six probes (eighteen branches x
        ``True``/``False``) raised, and none was laundered. That is what makes a
        guard in ``SwitchField`` dead code.
        """
        from pcapkit.corekit.fields.misc import SwitchField
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        for module, name, attr, label, packet in ADDRESS_TYPED_SWITCH_BRANCHES:
            _, inner = self._resolve(module, name, attr)
            self.assertIsInstance(inner, SwitchField, msg=label)

            for value in (True, False):
                with self.subTest(branch=label, value=value):
                    field = SwitchField(selector=inner._selector)  # type: ignore[attr-defined]
                    field.name = 'probe'
                    # deep-copied per probe because ``smf_i_dpd_tid_selector``
                    # writes the resolved enum back into ``pkt['info']['type']``
                    with self.assertRaises(FieldValueError) as context:
                        field(copy.deepcopy(packet)).pack(value, copy.deepcopy(packet))
                    self.assertIsInstance(context.exception, BaseError)
                    self.assertIn('must not be a bool', str(context.exception))

    def test_the_address_typed_switch_table_is_complete(self) -> None:
        """:data:`ADDRESS_TYPED_SWITCH_BRANCHES` must name every address-typed switch.

        The table above is hand-written, so on its own it proves nothing about
        switches nobody listed -- which is the failure mode #491 and #508 share.
        Rediscovering them from ``Schema.__fields__`` and comparing closes that:
        ten declarations, three of which a ``SwitchField`` annotation grep cannot
        see because they are ``ConditionalField``-wrapped.
        """
        discovered = discover_address_typed_switches()
        tabled = {(module, name, attr)
                  for module, name, attr, _, _ in ADDRESS_TYPED_SWITCH_BRANCHES}

        self.assertEqual(
            discovered, tabled,
            msg='address-typed SwitchField declarations and the table have diverged; '
                f'only discovered: {sorted(discovered - tabled)}; '
                f'only tabled: {sorted(tabled - discovered)}')
        self.assertEqual(len(discovered), 10)

        # and the three that an annotation grep misses really are wrapped
        from pcapkit.corekit.fields.misc import ConditionalField

        wrapped = {(module, name, attr)
                   for module, name, attr in discovered
                   if isinstance(self._resolve(module, name, attr)[0], ConditionalField)}
        self.assertEqual(wrapped, {
            ('pcapkit.protocols.schema.internet.hopopt',
             'SMFIdentificationBasedDPDOption', 'tid'),
            ('pcapkit.protocols.schema.internet.ipv6_opts',
             'SMFIdentificationBasedDPDOption', 'tid'),
            ('pcapkit.protocols.schema.internet.mh',
             'BindingIdentifierOption', 'address'),
        })

    def test_address_typed_switch_branches_still_take_a_real_address(self) -> None:
        """The rejection is of :obj:`bool` specifically, and every branch still packs.

        Also pins an asymmetry that is easy to trip over, and that
        :func:`~pcapkit.corekit.fields.ipaddress._reject_bool` already describes:
        the ``int(...)`` escape hatch the error message advertises works on an
        **IPv4** branch and not on an IPv6 one. ``_IPAddressField.pre_process``
        converts with the family-agnostic :func:`ipaddress.ip_address`, so ``1``
        becomes ``0.0.0.1`` and is then refused by an IPv6-typed field for
        mismatching version -- whereas
        :func:`~pcapkit.corekit.fields.ipaddress.parse_ip_address` called with
        ``version=6``, which is how the ``_make_*`` sites reach the same guard,
        widens ``1`` to ``::1`` instead. Both behaviours are deliberate; they just
        are not the same behaviour, and only the maker path honours the message
        for IPv6.
        """
        import ipaddress

        from pcapkit.corekit.fields.misc import SwitchField
        from pcapkit.utilities.exceptions import FieldValueError

        for module, name, attr, label, packet in ADDRESS_TYPED_SWITCH_BRANCHES:
            _, inner = self._resolve(module, name, attr)
            field = SwitchField(selector=inner._selector)  # type: ignore[attr-defined]
            field.name = 'probe'
            resolved = field(copy.deepcopy(packet))

            ipv4 = label.endswith('IPv4')
            address = ipaddress.IPv4Address(1) if ipv4 else ipaddress.IPv6Address(1)

            with self.subTest(branch=label):
                # an actual address object always packs, on either family
                self.assertEqual(resolved.pack(address, copy.deepcopy(packet)),
                                 address.packed)
                self.assertEqual(resolved.pack(str(address), copy.deepcopy(packet)),
                                 address.packed)

                if ipv4:
                    self.assertEqual(resolved.pack(int(True), copy.deepcopy(packet)),
                                     ipaddress.IPv4Address('0.0.0.1').packed)
                else:
                    # ``ip_address(1)`` is IPv4, so an IPv6-typed field refuses it
                    with self.assertRaises(FieldValueError) as context:
                        resolved.pack(int(True), copy.deepcopy(packet))
                    self.assertIn('IP version mismatch: 4 != 6', str(context.exception))

    def test_parse_ip_address_widens_an_int_where_a_bare_field_would_not(self) -> None:
        """The other half of the asymmetry above, stated from the maker's side.

        This is why :func:`~pcapkit.corekit.fields.ipaddress.parse_ip_address` takes
        a ``version`` at all: the maker sites that pin the family need ``1`` to mean
        ``::1``, which the family-agnostic conversion in the field cannot give them.
        """
        import ipaddress

        from pcapkit.corekit.fields.ipaddress import (IPv6AddressField,
                                                      parse_ip_address)
        from pcapkit.utilities.exceptions import FieldValueError

        self.assertEqual(parse_ip_address(1, 'x', 6), ipaddress.IPv6Address('::1'))
        self.assertEqual(parse_ip_address(1, 'x', 4), ipaddress.IPv4Address('0.0.0.1'))
        self.assertEqual(parse_ip_address(1, 'x'), ipaddress.IPv4Address('0.0.0.1'))

        with self.assertRaises(FieldValueError):
            IPv6AddressField().pre_process(1, {})

    def test_integer_typed_switch_branch_still_coerces_a_bool_to_zero_or_one(self) -> None:
        import pcapkit.protocols.schema.internet.mh as schema_mh
        from pcapkit.const.mh.binding_revocation import BindingRevocation
        from pcapkit.corekit.fields.misc import SwitchField

        # ``BindingRevocationMessage.code`` is a switch too, but over two enum
        # registries rather than two address families, so its branches are
        # ``EnumField``s -- and a bool in an integer field means 0/1, exactly as
        # ``NonceIndicesOption.home`` (a ``UInt16Field``) does. A blanket bool
        # rejection in ``SwitchField`` would break this.
        packet = {'br_type': BindingRevocation.Binding_Revocation_Indication}
        field = SwitchField(selector=schema_mh.br_code_selector)
        field.name = 'probe'
        bound = field(dict(packet))

        self.assertEqual(bound.pack(True, dict(packet)), bound.pack(1, dict(packet)))
        self.assertEqual(bound.pack(True, dict(packet)), b'\x01')
        self.assertEqual(bound.pack(False, dict(packet)), bound.pack(0, dict(packet)))
        self.assertEqual(bound.pack(False, dict(packet)), b'\x00')

    def test_every_enum_typed_switch_branch_still_coerces_a_bool(self) -> None:
        """Both halves of both enum switches, so "not a blanket rejection" is pinned whole.

        ``br_code_selector`` and ``fb_code_selector`` each pick between *two* enum
        registries -- a trigger in an indication and a status code in an
        acknowledgement -- so each has two branches, and a blanket :obj:`bool`
        rejection in ``SwitchField`` would break all four. The ruling this follows is
        the owner's on ``NonceIndicesOption.home``: a :obj:`bool` in an integer field
        means ``0``/``1`` and that is correct.
        """
        import pcapkit.protocols.schema.internet.mh as schema_mh
        from pcapkit.const.mh.binding_revocation import BindingRevocation
        from pcapkit.const.mh.fb_type import FlowBindingType
        from pcapkit.corekit.fields.misc import SwitchField
        from pcapkit.corekit.fields.numbers import EnumField

        cases = [
            ('br indication', schema_mh.br_code_selector,
             {'br_type': BindingRevocation.Binding_Revocation_Indication}),
            ('br acknowledgement', schema_mh.br_code_selector,
             {'br_type': BindingRevocation.Binding_Revocation_Acknowledgement}),
            ('fb indication', schema_mh.fb_code_selector,
             {'fb_type': FlowBindingType.Indication}),
            ('fb acknowledgement', schema_mh.fb_code_selector,
             {'fb_type': FlowBindingType.Acknowledgement}),
        ]

        for label, selector, packet in cases:
            with self.subTest(branch=label):
                self.assertIsInstance(selector(dict(packet)), EnumField)

                field = SwitchField(selector=selector)
                field.name = 'probe'
                bound = field(dict(packet))

                self.assertEqual(bound.pack(True, dict(packet)), b'\x01')
                self.assertEqual(bound.pack(True, dict(packet)),
                                 bound.pack(1, dict(packet)))
                self.assertEqual(bound.pack(False, dict(packet)), b'\x00')
                self.assertEqual(bound.pack(False, dict(packet)),
                                 bound.pack(0, dict(packet)))


class PayloadFieldProtocolNameTests(unittest.TestCase):
    """Resolving :class:`~pcapkit.corekit.fields.misc.PayloadField`'s ``protocol``
    from a name, per `#787 <https://github.com/JarryShaw/PyPCAPKit/issues/787>`__.

    :data:`pcapkit.protocols.__proto__` is keyed on ``__name__.upper()``, both
    where it is seeded and in
    :func:`~pcapkit.foundation.registry.protocols.register_protocol`. The setter
    looked the name up as given, so anything not already upper-cased missed --
    and a miss is indistinguishable from an unparsed payload, because
    :obj:`None` is what the getter turns into
    :class:`~pcapkit.protocols.misc.raw.Raw`.

    The constructor was worse, and is the path the issue's own reproduction
    takes: it assigned ``_protocol`` directly, bypassing the setter, so the
    :obj:`str` was stored verbatim and handed straight back.
    ``PayloadField(protocol='http').protocol`` was therefore ``'http'`` -- not
    HTTP, and not even ``Raw`` -- and ``protocol='HTTP'`` was no better, so case
    was never what that path went wrong on.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_a_protocol_name_resolves_whatever_its_case(self) -> None:
        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.protocols.application.http import HTTP

        for name in ('HTTP', 'http', 'Http', 'hTTp'):
            with self.subTest(name=name, path='constructor'):
                self.assertIs(PayloadField(protocol=name).protocol, HTTP)

            with self.subTest(name=name, path='setter'):
                field = PayloadField()
                field.protocol = name
                self.assertIs(field.protocol, HTTP)

    def test_an_unregistered_name_warns_and_still_falls_back_to_raw(self) -> None:
        """A name the registry does not hold is a caller's mistake, so it warns.

        The fallback itself is kept: refusing the assignment would reject a
        lenient spelling the field has always accepted, and :obj:`None` -- hence
        :class:`~pcapkit.protocols.misc.raw.Raw` -- remains a legitimate state
        for a payload whose protocol is genuinely not known. What was wrong was
        only that nothing said so.

        """
        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.warnings import RegistryWarning

        for path, build in (('constructor', lambda: PayloadField(protocol='NoSuchProtocol')),
                            ('setter', None)):
            with self.subTest(path=path):
                if build is None:
                    field = PayloadField()
                    with self.assertWarns(RegistryWarning):
                        field.protocol = 'NoSuchProtocol'
                else:
                    with self.assertWarns(RegistryWarning):
                        field = build()

                self.assertIs(field.protocol, Raw)

    def test_a_class_or_an_absent_protocol_is_left_alone_and_silent(self) -> None:
        """Neither of the two shapes the library itself uses may warn.

        Every in-library ``PayloadField`` either names no protocol at all or is
        assigned one by a callback -- ``schema/link/ethernet.py``'s, which hands
        over whatever ``_lookup_next_layer`` returned, a class or a
        :class:`~pcapkit.corekit.module.ModuleDescriptor`, never a :obj:`str`.
        So routing the constructor through the setter must leave both untouched,
        and in particular must not make importing a schema module warn.

        """
        import warnings

        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.misc.raw import Raw

        descriptor = ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')
        cases = (
            ('class, constructor', lambda: PayloadField(protocol=HTTP), HTTP),
            ('absent', PayloadField, Raw),
            ('none, explicit', lambda: PayloadField(protocol=None), Raw),
        )

        for label, build, expected in cases:
            with self.subTest(case=label):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    field = build()
                self.assertIs(field.protocol, expected)
                self.assertEqual(caught, [])

        with self.subTest(case='class, setter'):
            field = PayloadField()
            field.protocol = HTTP
            self.assertIs(field.protocol, HTTP)

        with self.subTest(case='module descriptor, setter'):
            field = PayloadField()
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                field.protocol = descriptor
            self.assertIs(field.protocol, descriptor)
            self.assertEqual(caught, [])


if __name__ == '__main__':
    unittest.main()
