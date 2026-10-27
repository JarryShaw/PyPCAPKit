# -*- coding: utf-8 -*-
"""A HIP list argument resolves a :obj:`str` enumeration member name.

GitHub issue #2394, the third of the family #2356 and #2393 opened.
:meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` infers the
enumeration a bare member name belongs to from the *default value* of the
``make()`` argument the name arrived as -- so an argument whose default is an
enumeration member resolves a name on its own, and one whose default is
:data:`None` has nothing to read.

Twelve HIP parameters carry a *list* of enumeration values rather than one, and
build it in a loop. The value handed to ``_make_index`` is therefore the loop
variable, which is no argument of the maker at all, so the inference cannot
reach the list argument's annotation and a name goes unresolved however the
list argument is declared. Measured before the fix: the member and integer
forms of each of these twelve built the correct octets, and the member-name
form raised ``ProtocolNotImplemented: protocol 'RENDEZVOUS' not implemented``.
Each maker now names its own enumeration, which is what #2393 did for the
scalar case -- just ahead of the loop rather than at the call, so that the
decision is taken once per parameter instead of once per item.

:meth:`HIPListArgumentStrNameTests.test_every_list_argument_maker_has_a_case`
reads the loop-variable sites off ``hip.py`` itself rather than trusting the
list of twelve, so a thirteenth parameter added with the same shape cannot land
without a case here.

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

from tests._support import reimport_once_per_class

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
#: :rfc:`5201` only, as :data:`examples.generators.options.HIP_VERSION` records,
#: and the rest of the twelve are refused at version 1 or indifferent to it.
HIP_VERSION = {577: 1}

#: One case per maker: ``{maker: (parameter name, list keyword, enum module and
#: class, member name, the other keywords the parameter needs)}``. Each member is
#: a non-zero one the maker would not arrive at on its own, so an octet string
#: carrying it is evidence the name resolved rather than that a default survived.
#: Keyed by maker rather than by parameter because
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
    # sibling ``failure_type`` is a scalar whose own default is a member, so it
    # resolved a name all along and is pinned by
    # :meth:`test_a_scalar_sibling_still_resolves_by_inference`.
    '_make_param_reg_failed': (
        'REG_FAILED', 'reg_failed', 'pcapkit.const.hip.registration.Registration',
        'RENDEZVOUS', {'failure_type': 1}),
    # The only one of the twelve whose list holds parameter codes rather than a
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


def _attr(path: 'str') -> 'object':
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
    """A member name in a list argument resolves against its enumeration."""

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
        from pcapkit.protocols.internet.hip import HIP

        base = dict(HIP_BASE)
        # ``extension=True`` keeps ``HIP.alias`` off ``self._info``, which
        # ``__post_init__`` assigns only once ``read`` has returned (#1184).
        base['version'] = HIP_VERSION.get(int(code), 2)  # type: ignore[call-overload]
        return HIP(parameters=[(code, value)], extension=True,
                   **base).data  # type: ignore[arg-type]

    def test_a_member_name_in_a_list_builds_what_the_member_builds(self) -> None:
        """#2394: the three forms of a list item agree, octet for octet.

        The member-name form raised ``ProtocolNotImplemented`` for all twelve
        before the fix, while the member and integer forms built these very
        octets, so this is the fail-without-fix assertion and the
        no-regression one at once.

        """
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')

        for maker, (name, keyword, enum_path, member, extra) in CASES.items():
            with self.subTest(maker=maker):
                code = getattr(parameter, name)
                value = getattr(_attr(enum_path), member)

                expected = self._build(code, {**extra, keyword: [value]})
                self.assertEqual(self._build(code, {**extra, keyword: [member]}).hex(),
                                 expected.hex())
                self.assertEqual(self._build(code, {**extra, keyword: [int(value)]}).hex(),
                                 expected.hex())

                # the member is not what an absent list produces, so an item
                # that never arrived cannot pass as one that resolved
                self.assertNotEqual(self._build(code, dict(extra)).hex(), expected.hex())

    def test_a_list_resolves_every_item_it_holds(self) -> None:
        """#2394: a name resolves wherever it sits, mixed in with other forms.

        The fix is inside the loop rather than ahead of it, so a list is not
        resolved as a whole: a name in the second position has to resolve as
        readily as one in the first, and alongside the member and integer forms.

        """
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')
        transport = _attr('pcapkit.const.hip.transport.Transport')

        code = parameter.HIP_TRANSPORT_MODE
        expected = self._build(code, {'port': 1234, 'modes': [
            transport.DEFAULT, transport.ESP, transport.ESP_TCP]})

        self.assertEqual(
            self._build(code, {'port': 1234, 'modes': [1, 'ESP', transport.ESP_TCP]}).hex(),
            expected.hex())
        self.assertEqual(
            self._build(code, {'port': 1234, 'modes': ['DEFAULT', 'ESP', 'ESP_TCP']}).hex(),
            expected.hex())

    def test_an_explicit_namespace_still_wins(self) -> None:
        """A ``*_namespace`` keyword overrides the enumeration the maker names.

        The fix names an enumeration only where the caller named none, so that
        the documented ``*_namespace`` keyword keeps resolving a name the
        parameter's own enumeration does not carry.

        """
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')
        registration = _attr('pcapkit.const.hip.registration.Registration')

        # ``RENDEZVOUS`` is a registration type, not a Diffie-Hellman group
        octets = self._build(parameter.DH_GROUP_LIST,
                             {'groups': ['RENDEZVOUS'], 'group_namespace': registration})
        self.assertEqual(octets[40:].hex(), '01ff000101000000')

        # a ``str -> int`` mapping needs ``*_reversed``, and still resolves
        octets = self._build(parameter.DH_GROUP_LIST,
                             {'groups': ['mine'], 'group_namespace': {'mine': 9},
                              'group_reversed': True})
        self.assertEqual(octets[40:].hex(), '01ff000109000000')

    def test_a_scalar_sibling_still_resolves_by_inference(self) -> None:
        """``REG_FAILED``'s ``failure_type`` resolves from its own default.

        It is a scalar whose default is a
        :class:`~pcapkit.const.hip.registration_failure.RegistrationFailure`
        member, so the inference #2394 cannot perform for a list item works for
        it, and the two arguments resolve against *different* enumerations in
        the same call.

        """
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')
        failure = _attr('pcapkit.const.hip.registration_failure.RegistrationFailure')
        registration = _attr('pcapkit.const.hip.registration.Registration')

        expected = self._build(parameter.REG_FAILED, {
            'failure_type': failure.Registration_type_unavailable,
            'reg_failed': [registration.RENDEZVOUS],
        })
        self.assertEqual(self._build(parameter.REG_FAILED, {
            'failure_type': 'Registration_type_unavailable',
            'reg_failed': ['RENDEZVOUS'],
        }).hex(), expected.hex())
        self.assertEqual(expected[40:].hex(), '03a8000201010000')

    def test_an_unresolvable_name_still_raises_or_falls_back(self) -> None:
        """Naming the enumeration does not make every string resolve.

        The enumeration is named, not bypassed, so a string that is no member
        of it still raises -- or takes the ``*_default`` the caller gave, which
        is the documented escape.

        """
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        parameter = _attr('pcapkit.const.hip.parameter.Parameter')

        with self.assertRaises(exc):
            self._build(parameter.DH_GROUP_LIST, {'groups': ['No_Such_Group']})

        octets = self._build(parameter.DH_GROUP_LIST,
                             {'groups': ['No_Such_Group'], 'group_default': 4})
        self.assertEqual(octets[40:].hex(), '01ff000104000000')

    def test_every_list_argument_maker_has_a_case(self) -> None:
        """Every loop-variable ``_make_index`` site in ``hip.py`` has a case.

        The set is read off the makers rather than listed, because the bug is a
        property of the *shape* of the call: the value handed to
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` is a name
        that is not an argument of the maker, so nothing is there for the
        namespace to be inferred from. A thirteenth parameter of that shape
        would be broken in exactly the same way and is caught here.

        """
        from pcapkit.protocols.internet.hip import HIP

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
                         'a HIP maker resolves a name that is not one of its own '
                         'arguments and has no case in CASES (#2394)')
        self.assertEqual(len(found), 12)

    def test_the_named_enumerations_are_imported_at_runtime(self) -> None:
        """#2394: the five enumerations the fix needs are no longer type-only.

        ``Suite``, ``NATTraversal``, ``Registration``, ``ESPTransformSuite`` and
        ``Transport`` were imported under ``TYPE_CHECKING`` alone, which is why
        the fix is not a one-line patch. They sit in
        :mod:`pcapkit.const.hip`, which imports nothing from
        :mod:`pcapkit.protocols`, so naming them at runtime closes no cycle --
        their sibling
        :class:`~pcapkit.const.hip.registration_failure.RegistrationFailure` was
        imported at runtime all along.

        """
        from pcapkit.protocols.internet import hip

        for name in ('Enum_Suite', 'Enum_NATTraversal', 'Enum_Registration',
                     'Enum_ESPTransformSuite', 'Enum_Transport'):
            with self.subTest(enum=name):
                self.assertTrue(hasattr(hip, name))


if __name__ == '__main__':
    unittest.main()
