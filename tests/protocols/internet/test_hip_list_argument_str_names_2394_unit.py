# -*- coding: utf-8 -*-
"""A HIP list argument refuses a :obj:`str` enumeration member name.

GitHub issue #2394, the third of the family #2356 and #2393 opened, and settled
by #2594. Some HIP parameters carry a *list* of enumeration values rather than
one, and build it item by item. A list item is no ``make()`` argument, so no
enumeration can be inferred for a name in one from an argument's default (#2394).

Under #2594 nothing is inferred: every item of these lists is a member or an
:class:`int` code, resolved with the enumeration's ``get``, and a name is
refused with :exc:`~pcapkit.utilities.exceptions.ProtocolError` wherever it sits
in the list. A caller holding a name resolves it first, with
:meth:`~pcapkit.protocols.protocol.Protocol.resolve_index`, which takes the
name, default, namespace and reversed group explicitly; resolved one item at a
time, it builds the octets the member does.

:meth:`HIPListArgumentStrNameTests.test_every_list_argument_maker_has_a_case`
reads the list-item sites off ``hip.py`` itself rather than trusting the table
below, so a further parameter added with the same shape cannot land without a
case here.

Every case builds its own packet in memory and reads no capture. :class:`HIP`
and the enumerations are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Test tier (#1958): hand-picked cases, one per maker, not a sweep.
__tier__ = 'ALL'

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: HIP version each version-bound parameter demands: ``HIP_TRANSFORM`` (577) is
#: :rfc:`5201` only, as :data:`examples.generators.option_families.hip.HIP_VERSION` records,
#: and the rest are refused at version 1 or indifferent to it.
HIP_VERSION = {577: 1}

#: One case per maker: ``{maker: (parameter name, list keyword, enum module and
#: class, member name, the other keywords the parameter needs)}``. Each member is
#: a non-zero one the maker would not arrive at on its own, so an octet string
#: carrying it is evidence the item reached the wire rather than that a default
#: survived. Keyed by maker rather than by parameter because
#: :meth:`HIPListArgumentStrNameTests.test_every_list_argument_maker_has_a_case`
#: compares these keys against the makers it finds in ``hip.py``.
CASES = {
    '_make_param_dh_group_list': (
        'DH_GROUP_LIST', 'groups', 'pcapkit.const.hip.group.Group',
        'NIST_P_256', {}),
    '_make_param_hip_transform': (
        'HIP_TRANSFORM', 'suites', 'pcapkit.const.hip.suite.Suite',
        'BLOWFISH_CBC_with_HMAC_SHA1', {}),
    '_make_param_hip_cipher': (
        'HIP_CIPHER', 'ciphers', 'pcapkit.const.hip.cipher.Cipher',
        'AES_256_CBC', {}),
    '_make_param_nat_traversal_mode': (
        'NAT_TRAVERSAL_MODE', 'modes', 'pcapkit.const.hip.nat_traversal.NATTraversal',
        'ICE_HIP_UDP', {}),
    '_make_param_hit_suite_list': (
        'HIT_SUITE_LIST', 'suites', 'pcapkit.const.hip.hit_suite.HITSuite',
        'ECDSA_SHA_384', {}),
    '_make_param_reg_info': (
        'REG_INFO', 'reg_info', 'pcapkit.const.hip.registration.Registration',
        'RELAY_UDP_ESP', {'min_lifetime': 5, 'max_lifetime': 200}),
    '_make_param_reg_request': (
        'REG_REQUEST', 'reg_request', 'pcapkit.const.hip.registration.Registration',
        'CANDIDATE_DISCOVERY', {'lifetime': 42}),
    '_make_param_reg_response': (
        'REG_RESPONSE', 'reg_response', 'pcapkit.const.hip.registration.Registration',
        'RELAY_UDP_HIP', {'lifetime': 42}),
    # ``reg_failed`` takes registration types, not failure types (#2309); the
    # scalar sibling ``failure_type`` is covered by
    # :meth:`test_a_scalar_sibling_takes_a_resolved_name_too`.
    '_make_param_reg_failed': (
        'REG_FAILED', 'reg_failed', 'pcapkit.const.hip.registration.Registration',
        'RENDEZVOUS', {'failure_type': 1}),
    # The only one of these whose list holds parameter codes rather than a
    # namespace of its own, so its enumeration is the same ``Parameter`` the
    # ``code`` argument carries.
    '_make_param_transport_format_list': (
        'TRANSPORT_FORMAT_LIST', 'formats', 'pcapkit.const.hip.parameter.Parameter',
        'ESP_TRANSFORM', {}),
    '_make_param_esp_transform': (
        'ESP_TRANSFORM', 'suites',
        'pcapkit.const.hip.esp_transform_suite.ESPTransformSuite',
        'NULL_with_HMAC_SHA_256', {}),
    '_make_param_hip_transport_mode': (
        'HIP_TRANSPORT_MODE', 'modes', 'pcapkit.const.hip.transport.Transport',
        'ESP_TCP', {'port': 1234}),
}


def _attr(path: 'str') -> 'Any':
    """Import ``path`` and return the attribute it names.

    Args:
        path: dotted path whose last component is an attribute of the module
            the rest of it names

    Returns:
        The named attribute.

    """
    import importlib

    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPListArgumentStrNameTests(unittest.TestCase):
    """A member name in a list argument is refused; a resolved one builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _build(code: 'object', value: 'object') -> 'bytes':
        """One HIP packet carrying ``code`` built from ``value``.

        Args:
            code: parameter code
            value: the parameter's own keywords

        Returns:
            The packet's octets.

        """
        from pcapkit.protocols.internet.hip.protocol import HIP

        base = dict(HIP_BASE)
        # ``extension=True`` keeps ``HIP.alias`` off ``self._info``, which
        # ``__post_init__`` assigns only once ``read`` has returned (#1184).
        base['version'] = HIP_VERSION.get(int(code), 2)  # type: ignore[call-overload]
        return HIP(parameters=[(code, value)], extension=True,
                   **base).data

    def test_a_member_name_in_a_list_is_refused(self) -> None:
        """#2594: a name in a list raises ``ProtocolError``, for every maker.

        Each maker names its enumeration at the call (#2394), and resolves a
        list item against it as a member or a code, never as a name.

        """
        error = _attr('pcapkit.utilities.exceptions.ProtocolError')
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')

        for maker, (name, keyword, _, member, extra) in CASES.items():
            with self.subTest(maker=maker):
                with self.assertRaises(error):
                    self._build(getattr(parameter, name), {**extra, keyword: [member]})

    def test_resolve_index_builds_what_the_member_builds(self) -> None:
        """#2594: a name resolved first builds the member's octets, item by item.

        The member, its :class:`int` code and the name passed through
        :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` agree octet for
        octet, and none of them is what an absent list builds.

        """
        from pcapkit.protocols.protocol import Protocol

        parameter = _attr('pcapkit.const.hip.parameter.Parameter')

        for maker, (name, keyword, enum_path, member, extra) in CASES.items():
            with self.subTest(maker=maker):
                code = getattr(parameter, name)
                namespace = _attr(enum_path)
                value = getattr(namespace, member)

                expected = self._build(code, {**extra, keyword: [value]})
                resolved = Protocol.resolve_index(member, namespace=namespace)
                self.assertIs(resolved, value)
                self.assertEqual(self._build(code, {**extra, keyword: [resolved]}).hex(),
                                 expected.hex())
                self.assertEqual(self._build(code, {**extra, keyword: [int(value)]}).hex(),
                                 expected.hex())

                # the member is not what an absent list produces, so an item
                # that never arrived cannot pass as one that was written
                self.assertNotEqual(self._build(code, dict(extra)).hex(), expected.hex())

    def test_a_list_is_checked_item_by_item(self) -> None:
        """#2594: a name is refused wherever it sits, mixed in with other forms.

        A list is not checked as a whole: a name in the second position is
        refused as readily as one in the first, and the same list with that item
        resolved builds what the members build.

        """
        from pcapkit.protocols.protocol import Protocol

        error = _attr('pcapkit.utilities.exceptions.ProtocolError')
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')
        transport = _attr('pcapkit.const.hip.transport.Transport')

        code = parameter.HIP_TRANSPORT_MODE
        expected = self._build(code, {'port': 1234, 'modes': [
            transport.DEFAULT, transport.ESP, transport.ESP_TCP]})

        with self.assertRaises(error):
            self._build(code, {'port': 1234, 'modes': [1, 'ESP', transport.ESP_TCP]})

        resolved = [Protocol.resolve_index(item, namespace=transport)
                    for item in (1, 'ESP', transport.ESP_TCP)]
        self.assertEqual(self._build(code, {'port': 1234, 'modes': resolved}).hex(),
                         expected.hex())

    def test_resolve_index_takes_the_group_explicitly(self) -> None:
        """#2594: ``resolve_index`` takes the name, default, namespace and reversed group.

        Each case builds the octets the member builds: a name looked up in
        another enumeration, a ``str -> int`` mapping with ``reversed``, and a
        ``default`` for a name the namespace lacks. A name with neither a match
        nor a ``default`` raises ``ProtocolNotImplemented``.

        """
        from pcapkit.protocols.protocol import Protocol

        missing = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')
        group = _attr('pcapkit.const.hip.group.Group')
        registration = _attr('pcapkit.const.hip.registration.Registration')

        def build(item: 'object') -> 'str':
            return self._build(parameter.DH_GROUP_LIST, {'groups': [item]})[40:].hex()

        # ``RENDEZVOUS`` is a registration type, not a Diffie-Hellman group
        self.assertEqual(build(Protocol.resolve_index('RENDEZVOUS', namespace=registration)),
                         '01ff000101000000')
        self.assertEqual(build(Protocol.resolve_index('mine', namespace={'mine': 9},
                                                      reversed=True)),
                         '01ff000109000000')
        self.assertEqual(build(Protocol.resolve_index('No_Such_Group', 4, namespace=group)),
                         '01ff000104000000')

        with self.assertRaises(missing):
            Protocol.resolve_index('No_Such_Group', namespace=group)

    def test_a_scalar_sibling_takes_a_resolved_name_too(self) -> None:
        """``REG_FAILED``'s ``failure_type`` refuses a name, as its list does.

        It is a scalar whose default is a
        :class:`~pcapkit.const.hip.registration_failure.RegistrationFailure`
        member, a shape an inference from argument defaults would resolve; #2594
        refuses the name there as well. Resolved against their own
        enumerations, the two arguments build the octets their members build in
        the same call.

        """
        from pcapkit.protocols.protocol import Protocol

        error = _attr('pcapkit.utilities.exceptions.ProtocolError')
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')
        failure = _attr('pcapkit.const.hip.registration_failure.RegistrationFailure')
        registration = _attr('pcapkit.const.hip.registration.Registration')

        expected = self._build(parameter.REG_FAILED, {
            'failure_type': failure.Registration_type_unavailable,
            'reg_failed': [registration.RENDEZVOUS],
        })
        with self.assertRaises(error):
            self._build(parameter.REG_FAILED, {
                'failure_type': 'Registration_type_unavailable',
                'reg_failed': [registration.RENDEZVOUS],
            })
        self.assertEqual(self._build(parameter.REG_FAILED, {
            'failure_type': Protocol.resolve_index('Registration_type_unavailable',
                                                   namespace=failure),
            'reg_failed': [Protocol.resolve_index('RENDEZVOUS', namespace=registration)],
        }).hex(), expected.hex())
        self.assertEqual(expected[40:].hex(), '03a8000201010000')

    def test_every_list_argument_maker_has_a_case(self) -> None:
        """Every list-item ``_make_index`` site in ``hip.py`` has a case.

        The set is read off the makers rather than listed: a site is a call to
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` whose value
        is a name that is not an argument of the maker, the item of a list
        argument. A further parameter of that shape gets a case here.

        """
        from pcapkit.protocols.internet.hip.protocol import HIP

        found = set()
        for name, method in vars(HIP).items():
            if not name.startswith('_make_param_'):
                continue
            tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
            params = {
                arg.arg
                for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                for arg in [*node.args.args, *node.args.kwonlyargs]
            }
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == '_make_index' and node.args
                        and isinstance(node.args[0], ast.Name)
                        and node.args[0].id not in params):
                    found.add(name)

        self.assertEqual(found, set(CASES),
                         'a HIP maker resolves a list item and has no case in CASES (#2394)')

    def test_the_named_enumerations_are_imported_at_runtime(self) -> None:
        """#2394: the enumerations the list makers resolve against are runtime names.

        ``Suite``, ``NATTraversal``, ``Registration``, ``ESPTransformSuite`` and
        ``Transport`` are imported at module level rather than under
        ``TYPE_CHECKING`` alone (#2394), since each list maker passes its
        enumeration to ``_make_index`` at run time.
        They sit in :mod:`pcapkit.const.hip`, which imports nothing from
        :mod:`pcapkit.protocols`, so naming them at runtime closes no cycle.

        """
        from pcapkit.protocols.internet.hip import protocol as hip

        for name in ('Enum_Suite', 'Enum_NATTraversal', 'Enum_Registration',
                     'Enum_ESPTransformSuite', 'Enum_Transport'):
            with self.subTest(enum=name):
                self.assertTrue(hasattr(hip, name))


if __name__ == '__main__':
    unittest.main()
