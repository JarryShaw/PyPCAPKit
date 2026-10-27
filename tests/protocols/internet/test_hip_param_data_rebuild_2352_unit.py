# -*- coding: utf-8 -*-
"""A HIP ``(code, data)`` pair rebuilds the parameter it was parsed from.

GitHub issue #2352. ``HIP(parameters=[(code, parsed_data)], ...)`` expanded the
parsed parameter as ``**kwargs`` into its ``_make_param_*`` constructor, so
every field whose constructor keyword is spelled differently never arrived and
the parameter came back with that value at its default -- ``HIP_TRANSFORM``
keeps its suites in ``suite_id`` and ``_make_param_hip_transform`` takes them as
``suites``, which rebuilt the parameter empty, as ``0241000000000000``. The
constructor now takes the data model positionally, as the
``parameters=parsed.info.parameters`` path already did.

The mismatch is not confined to ``HIP_TRANSFORM``:
:meth:`HIPParameterDataRebuildTests.cases` carries one non-default value for
each parameter the bug reached, and
:meth:`HIPParameterDataRebuildTests.test_every_renaming_parameter_has_a_case`
compares that list against the constructors, so a parameter that starts
spelling a *top-level* field differently tomorrow cannot land without a
round-trip case here.

That comparison is only partly mechanical, though, so three cases are listed by
hand rather than caught by it and a fourth parameter needs a second case the
check cannot ask for. What it does mechanically is read each constructor's
keyword-only parameters against its data model's own annotations. Everything
else is by name or by hand:

* :data:`DERIVED` exempts ``flags`` and ``lifetime`` *by name*, rather than
  establishing that the constructor takes a nested model apart into one keyword
  per member. ``ROUTE_DST`` and ``ROUTE_VIA`` keep ``symmetric`` and
  ``must_follow`` inside a nested ``flags`` model that ``**param`` dropped
  wholesale, and that exemption is why they are listed here instead of derived.
* A *nested* collision is invisible to it. ``LOCATOR_SET``'s keyword and field
  are both spelled ``locator_set``, so the check passes it over, yet expanding
  the parsed parameter handed each nested
  :class:`~pcapkit.protocols.data.internet.hip.Locator`'s own ``locator`` key
  to ``_make_locator``'s ``locator`` parameter and raised ``AttributeError:
  'IPv6Address' object has no attribute 'locator'``.
* ``HOST_ID`` the check does find -- it renames ``algorithm`` to
  ``hi_algorithm`` -- but a case built on an ECDSA-curve host identity hides
  the loss, because the constructor re-derives the algorithm from the curve.
  Only a raw-``hi`` host identity, carrying no curve to re-derive from, loses
  it, so both shapes are here.

Every case builds its own octets in memory and reads no capture. :class:`HIP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import re
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: HIP version each version-bound parameter demands: ``HIP_TRANSFORM`` (577)
#: and ``R1_Counter`` (128) are :rfc:`5201` only, as
#: :data:`examples.generators.options.HIP_VERSION` records.
HIP_VERSION = {128: 1, 577: 1}

#: Fields a constructor derives rather than accepting, so that a data model
#: holding them is not evidence of a renamed keyword: ``Length`` octets are
#: computed from the value they measure, and a nested flags or lifetime model
#: is taken apart into one keyword per member. Maintained by hand --
#: :meth:`HIPParameterDataRebuildTests.test_every_renaming_parameter_has_a_case`
#: exempts these names, it does not work out that they are derived.
DERIVED = frozenset({'hi_len', 'di_len', 'pub_len', 'flags', 'lifetime'})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPParameterDataRebuildTests(unittest.TestCase):
    """Parameters whose constructor keyword differs from their data field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def cases() -> 'dict[str, tuple[object, dict[str, object]]]':
        """One non-default value per parameter the bug reached.

        Keyed by case name rather than by parameter code, because ``HOST_ID``
        needs two: the ECDSA-curve one, which round-tripped by accident, and
        the raw-``hi`` one, which did not.

        A default is useless here: an empty suite list rebuilds as an empty
        suite list whether or not the value reached the constructor, which is
        exactly why the sweep in
        :mod:`tests.protocols.test_option_roundtrip_unit` could not see this.

        """
        from pcapkit.const.hip.ecdsa_curve import ECDSACurve
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.const.hip.parameter import Parameter

        return {
            'SEQ': (Parameter.SEQ, {'update_id': 0x11223344}),
            'DH_GROUP_LIST': (Parameter.DH_GROUP_LIST, {'groups': [1, 2, 3]}),
            'DIFFIE_HELLMAN': (Parameter.DIFFIE_HELLMAN,
                               {'group': 3, 'pub_val': 0xdeadbeef}),
            'HIP_TRANSFORM': (Parameter.HIP_TRANSFORM, {'suites': [1, 2]}),
            'HIP_CIPHER': (Parameter.HIP_CIPHER, {'ciphers': [1, 2, 4]}),
            'NAT_TRAVERSAL_MODE': (Parameter.NAT_TRAVERSAL_MODE, {'modes': [1, 2]}),
            # The algorithm reaches the rebuild through the curve rather than
            # through the renamed ``algorithm`` field, so this case round-trips
            # with or without the fix. The raw-``hi`` case below is the one
            # that pins the rename.
            'HOST_ID (ECDSA curve)': (Parameter.HOST_ID,
                                      {'hi_algorithm': 7, 'hi_curve': ECDSACurve.NIST_P_256,
                                       'hi_pub_key': b'\x01\x02\x03\x04',
                                       'di_type': 1, 'di': b'host'}),
            # A raw host identity carries no curve to re-derive the algorithm
            # from, so ``algorithm`` -> ``hi_algorithm`` is load-bearing here:
            # expanding the parsed parameter dropped it and rebuilt the
            # parameter as ``NULL_ENCRYPT`` (1) instead of ``DSA`` (3).
            'HOST_ID (raw hi)': (Parameter.HOST_ID,
                                 {'hi': b'\xaa\xbb\xcc\xdd', 'hi_algorithm': HIAlgorithm.DSA,
                                  'di_type': 1, 'di': b'host'}),
            'HIT_SUITE_LIST': (Parameter.HIT_SUITE_LIST, {'suites': [1, 2]}),
            'REG_INFO': (Parameter.REG_INFO,
                         {'min_lifetime': 5, 'max_lifetime': 200, 'reg_info': [1, 2]}),
            'REG_REQUEST': (Parameter.REG_REQUEST, {'lifetime': 42, 'reg_request': [1, 2]}),
            'REG_RESPONSE': (Parameter.REG_RESPONSE, {'lifetime': 42, 'reg_response': [1, 2]}),
            'REG_FAILED': (Parameter.REG_FAILED, {'failure_type': 1, 'reg_failed': [1, 2, 3]}),
            'TRANSPORT_FORMAT_LIST': (Parameter.TRANSPORT_FORMAT_LIST, {'formats': [1, 2]}),
            'ESP_TRANSFORM': (Parameter.ESP_TRANSFORM, {'suites': [1, 2]}),
            # ``symmetric`` and ``must_follow`` live in a nested ``flags``
            # model that ``**param`` dropped wholesale, and ``flags`` is in
            # :data:`DERIVED`, so these two are listed rather than derived.
            'ROUTE_DST': (Parameter.ROUTE_DST,
                          {'symmetric': True, 'must_follow': True,
                           'hit': [ipaddress.ip_address('::1')]}),
            'HIP_TRANSPORT_MODE': (Parameter.HIP_TRANSPORT_MODE, {'port': 1234, 'modes': [1, 2]}),
            'ROUTE_VIA': (Parameter.ROUTE_VIA,
                          {'symmetric': True, 'must_follow': False,
                           'hit': [ipaddress.ip_address('::2')]}),
            # Not a renamed keyword -- ``locator_set`` is spelled the same on
            # both sides, which is why
            # :meth:`test_every_renaming_parameter_has_a_case` cannot find it.
            # The collision is one level down: expanding the parsed parameter
            # passed each nested ``Locator``'s ``locator`` key to
            # ``_make_locator``'s ``locator`` parameter, which then read
            # ``locator.locator`` off an :class:`~ipaddress.IPv6Address`. Both
            # locator shapes are here, the bare address and the ``LocatorData``
            # the SPI form produces.
            'LOCATOR_SET': (Parameter.LOCATOR_SET,
                            {'locator_set': [
                                {'traffic': 1, 'type': 0, 'preferred': True,
                                 'lifetime': 180, 'ip': '2001:db8::1'},
                                {'traffic': 2, 'type': 1, 'preferred': False,
                                 'lifetime': 60, 'ip': '2001:db8::2',
                                 'spi': 0x11223344},
                            ]}),
        }

    @staticmethod
    def _base(code: 'object') -> 'dict[str, object]':
        base = dict(HIP_BASE)
        base['version'] = HIP_VERSION.get(int(code), 2)  # type: ignore[call-overload]
        return base

    def _build(self, code: 'object', value: 'object') -> 'bytes':
        from pcapkit.protocols.internet.hip import HIP

        # ``extension=True`` keeps ``HIP.alias`` off ``self._info``, which
        # ``__post_init__`` assigns only once ``read`` has returned (#1184).
        return HIP(parameters=[(code, value)], extension=True,
                   **self._base(code)).data  # type: ignore[arg-type]

    def test_a_parsed_parameter_rebuilds_byte_for_byte(self) -> None:
        """#2352: the pair form reproduces the octets it was parsed from."""
        from pcapkit.protocols.internet.hip import HIP

        for name, (code, kwargs) in self.cases().items():
            with self.subTest(case=name):
                octets = self._build(code, kwargs)
                parsed = HIP(octets, len(octets), extension=True)
                param = parsed.info.parameters[code]  # type: ignore[index]

                self.assertEqual(self._build(code, param).hex(), octets.hex())

    def test_the_pair_form_agrees_with_the_whole_collection(self) -> None:
        """#2352: ``[(code, data)]`` and ``parsed.info.parameters`` agree.

        The collection form passed each parameter positionally all along, so it
        rebuilt correctly while the pair form did not. Pinning the two against
        each other is what keeps them from drifting apart again.

        """
        from pcapkit.protocols.internet.hip import HIP

        for name, (code, kwargs) in self.cases().items():
            with self.subTest(case=name):
                octets = self._build(code, kwargs)
                parameters = HIP(octets, len(octets), extension=True).info.parameters

                whole = HIP(parameters=parameters, extension=True,
                            **self._base(code)).data  # type: ignore[arg-type]
                pairs = HIP(parameters=list(parameters.items(multi=True)), extension=True,
                            **self._base(code)).data  # type: ignore[arg-type]
                self.assertEqual(pairs.hex(), whole.hex())

    def test_hip_transform_keeps_its_suites(self) -> None:
        """#2352: the reported case, down to the octets it used to produce."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        octets = self._build(Parameter.HIP_TRANSFORM, {'suites': [1, 2]})
        self.assertEqual(octets[40:].hex(), '0241000400010002')

        param = HIP(octets, len(octets), extension=True).info.parameters[Parameter.HIP_TRANSFORM]
        rebuilt = self._build(Parameter.HIP_TRANSFORM, param)

        self.assertEqual(rebuilt[40:].hex(), '0241000400010002')
        # The empty parameter the dropped ``suite_id`` used to produce.
        self.assertNotEqual(rebuilt[40:].hex(), '0241000000000000')

    def test_the_keyword_form_still_builds_from_constructor_keywords(self) -> None:
        """A mapping is still expanded as keyword arguments, as documented."""
        from pcapkit.const.hip.parameter import Parameter

        self.assertEqual(
            self._build(Parameter.SEQ, {'update_id': 0x11223344})[40:].hex(),
            '0181000411223344',
        )
        self.assertEqual(
            self._build(Parameter.HIP_CIPHER, {'ciphers': [1, 2, 4]})[40:].hex(),
            '02430006000100020004000000000000',
        )

    def test_every_renaming_parameter_has_a_case(self) -> None:
        """Every renaming constructor is covered by :meth:`cases`.

        The renaming set is read off the constructors rather than listed, so
        that a parameter which starts spelling a *top-level* field differently
        is caught here instead of silently dropping the value again. Two things
        are not mechanical, and the cases for them are listed in :meth:`cases`
        by hand: :data:`DERIVED` exempts fields by name rather than by
        establishing that the constructor derives them, and a *nested*
        collision -- ``LOCATOR_SET``'s -- is invisible here, because the
        keyword and the field agree at the top level and only the data model
        one level down disagrees.

        """
        import inspect

        from pcapkit.protocols.internet import hip as hip_module
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.compat import get_annotations

        registry = HIP.__dict__['__parameter__']
        covered = {registry[code] for code, _ in self.cases().values()}

        renaming = set()
        for name in set(registry.values()) | {registry.default_factory()}:
            signature = inspect.signature(getattr(HIP, f'_make_param_{name}'))
            keywords = {key for key, value in signature.parameters.items()
                        if value.kind is value.KEYWORD_ONLY}

            annotation = signature.parameters['param'].annotation
            match = re.search(r'Data_\w+', annotation)
            self.assertIsNotNone(match, f'_make_param_{name} has no data model')
            model = getattr(hip_module, match.group())  # type: ignore[union-attr]

            if set(get_annotations(model)) - keywords - DERIVED:
                renaming.add(name)

        self.assertEqual(renaming - covered, set())


if __name__ == '__main__':
    unittest.main()
