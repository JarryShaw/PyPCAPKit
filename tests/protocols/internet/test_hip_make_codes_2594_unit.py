# -*- coding: utf-8 -*-
"""Each enumeration field of the HIP makers takes a member or a code, and nothing else.

GitHub issue #2594, carrying out the ruling given in review of #2593: a field of
``make()`` that holds an enumeration takes the member or an :class:`int` code,
resolved with the enumeration's ``get``, and no maker takes a ``*_default``,
``*_namespace`` or ``*_reversed`` keyword. #2617 adds that a code too wide for
its field, or a :obj:`bool` for a field wider than one bit, raises
``ProtocolError`` rather than being masked or written as another value.

:data:`ROWS` holds one row per (maker, field, enumeration, width) of
:class:`~pcapkit.protocols.internet.hip.HIP`. Each width is the field's in
:mod:`pcapkit.protocols.schema.internet.hip` -- ``EnumField(length=1)`` is 8
bits, ``length=2`` is 16, a bit-field item its declared bits -- which matches
the RFC each parameter cites. Every row is reached the way a caller reaches it,
through ``HIP(parameters=[(code, value)])`` or the header keyword itself, and
asserts:

* ``1 << bits`` raises ``ProtocolError`` naming the field;
* :data:`True` raises ``ProtocolError`` (no field here is one bit wide);
* the member's name as a :obj:`str` raises ``ProtocolError``;
* the member and ``int(member)`` build identical octets, and not the octets the
  maker builds without the argument;
* ``(1 << bits) - 1`` builds, parses back and rebuilds byte for byte, also
  where no member holds it and the enumeration's own range is narrower than the
  field, as for the mode IDs of ``HIP_TRANSPORT_MODE`` and the suite IDs of
  ``HIT_SUITE_LIST``, whose parsed values :data:`PARSED` gives back to ``make``.

The type of each parameter is such a field in both forms ``parameters`` takes
it in, a ``(code, value)`` pair and the key of parsed data, and refuses a
negative code there too.

:meth:`HIPMakeCodeTests.test_every_enumeration_argument_has_a_row` reads the
enumeration arguments off the makers' signatures, so a further one cannot land
without a row.

Every case builds its own packet in memory and reads no capture. :class:`HIP`
and the enumerations are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import importlib
import importlib.util
import inspect
import io
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``make.next`` and ``make.packet`` are header keywords of :meth:`HIP.make`, and
#: ``make.parameters`` is the code of a ``(code, value)`` pair, which
#: ``_make_hip_param`` resolves before it dispatches to a parameter maker.
HEADER = 'make'

#: ``(maker, argument, enumeration, member, bits, field name, parameter code,
#: other arguments, list)``: one row per enumeration field. ``parameter code`` is
#: the parameter carrying the field, or :data:`None` for a header keyword; a
#: ``list`` row puts the value in a one-item list. Each member is one the maker
#: would not arrive at on its own.
ROWS = (
    (HEADER, 'next', 'pcapkit.const.reg.transtype.TransType', 'TCP', 8,
     'next header', None, {}, False),
    (HEADER, 'packet', 'pcapkit.const.hip.packet.Packet', 'I2', 7,
     'packet type', None, {}, False),
    (HEADER, 'parameters', 'pcapkit.const.hip.parameter.Parameter', 'SEQ', 16,
     'parameter type', None, {'update_id': 1}, False),
    ('_make_param_dh_group_list', 'groups', 'pcapkit.const.hip.group.Group',
     'Group_3072_bit_MODP_group', 8, 'DH group ID', 'DH_GROUP_LIST', {}, True),
    ('_make_param_diffie_hellman', 'group', 'pcapkit.const.hip.group.Group',
     'Group_3072_bit_MODP_group', 8, 'group ID', 'DIFFIE_HELLMAN', {'pub_val': 1}, False),
    ('_make_param_hip_transform', 'suites', 'pcapkit.const.hip.suite.Suite',
     'BLOWFISH_CBC_with_HMAC_SHA1', 16, 'suite ID', 'HIP_TRANSFORM', {}, True),
    ('_make_param_hip_cipher', 'ciphers', 'pcapkit.const.hip.cipher.Cipher',
     'AES_256_CBC', 16, 'cipher ID', 'HIP_CIPHER', {}, True),
    ('_make_param_nat_traversal_mode', 'modes', 'pcapkit.const.hip.nat_traversal.NATTraversal',
     'ICE_HIP_UDP', 16, 'mode ID', 'NAT_TRAVERSAL_MODE', {}, True),
    # ``ENCRYPTED`` carries no cipher ID of its own; the cipher decides whether
    # the IV is written, and its width is the one ``HIP_CIPHER`` carries it in.
    ('_make_param_encrypted', 'cipher', 'pcapkit.const.hip.cipher.Cipher',
     'AES_256_CBC', 16, 'cipher ID', 'ENCRYPTED', {'iv': bytes(16), 'data': b'x'}, False),
    # ``hi`` as octets, since a curve sets the algorithm itself.
    ('_make_param_host_id', 'hi_algorithm', 'pcapkit.const.hip.hi_algorithm.HIAlgorithm',
     'RSA', 16, 'algorithm', 'HOST_ID', {'hi': b'\x01\x02'}, False),
    ('_make_param_host_id', 'di_type', 'pcapkit.const.hip.di.DITypes',
     'FQDN', 4, 'DI-type', 'HOST_ID', {'hi': b'\x01\x02', 'di': b'host'}, False),
    ('_make_param_hit_suite_list', 'suites', 'pcapkit.const.hip.hit_suite.HITSuite',
     'ECDSA_SHA_384', 8, 'HIT suite ID', 'HIT_SUITE_LIST', {}, True),
    ('_make_param_cert', 'cert_type', 'pcapkit.const.hip.certificate.Certificate',
     'Hash_and_URL_of_X_509_v3', 8, 'certificate type', 'CERT', {}, False),
    ('_make_param_notification', 'msg_type', 'pcapkit.const.hip.notify_message.NotifyMessage',
     'INVALID_SYNTAX', 16, 'notify message type', 'NOTIFICATION', {}, False),
    ('_make_param_reg_info', 'reg_info', 'pcapkit.const.hip.registration.Registration',
     'RELAY_UDP_ESP', 8, 'registration type', 'REG_INFO',
     {'min_lifetime': 5, 'max_lifetime': 200}, True),
    ('_make_param_reg_request', 'reg_request', 'pcapkit.const.hip.registration.Registration',
     'CANDIDATE_DISCOVERY', 8, 'registration type', 'REG_REQUEST', {'lifetime': 42}, True),
    ('_make_param_reg_response', 'reg_response', 'pcapkit.const.hip.registration.Registration',
     'RELAY_UDP_HIP', 8, 'registration type', 'REG_RESPONSE', {'lifetime': 42}, True),
    ('_make_param_reg_failed', 'failure_type',
     'pcapkit.const.hip.registration_failure.RegistrationFailure',
     'Insufficient_resources', 8, 'failure type', 'REG_FAILED', {}, False),
    ('_make_param_reg_failed', 'reg_failed', 'pcapkit.const.hip.registration.Registration',
     'RENDEZVOUS', 8, 'registration type', 'REG_FAILED', {}, True),
    ('_make_param_reg_from', 'protocol', 'pcapkit.const.reg.transtype.TransType',
     'TCP', 8, 'protocol', 'REG_FROM', {}, False),
    ('_make_param_transport_format_list', 'formats', 'pcapkit.const.hip.parameter.Parameter',
     'ESP_TRANSFORM', 16, 'transport format type', 'TRANSPORT_FORMAT_LIST', {}, True),
    ('_make_param_esp_transform', 'suites',
     'pcapkit.const.hip.esp_transform_suite.ESPTransformSuite',
     'AES_128_CBC_with_HMAC_SHA1', 16, 'suite ID', 'ESP_TRANSFORM', {}, True),
    ('_make_param_payload_mic', 'next', 'pcapkit.const.reg.transtype.TransType',
     'TCP', 8, 'next header', 'PAYLOAD_MIC', {}, False),
    ('_make_param_hip_transport_mode', 'modes', 'pcapkit.const.hip.transport.Transport',
     'ESP_TCP', 16, 'mode ID', 'HIP_TRANSPORT_MODE', {}, True),
    ('_make_param_hip_signature_2', 'algorithm', 'pcapkit.const.hip.hi_algorithm.HIAlgorithm',
     'RSA', 16, 'signature algorithm', 'HIP_SIGNATURE_2', {}, False),
    ('_make_param_hip_signature', 'algorithm', 'pcapkit.const.hip.hi_algorithm.HIAlgorithm',
     'RSA', 16, 'signature algorithm', 'HIP_SIGNATURE', {}, False),
    ('_make_param_relay_from', 'protocol', 'pcapkit.const.reg.transtype.TransType',
     'TCP', 8, 'protocol', 'RELAY_FROM', {}, False),
    ('_make_param_relay_to', 'protocol', 'pcapkit.const.reg.transtype.TransType',
     'TCP', 8, 'protocol', 'RELAY_TO', {}, False),
)

#: Enumeration arguments with no row, and why.
EXEMPT = {
    # Member-only: the curve's class picks the algorithm and the curve
    # registry, so an ``int`` names no enumeration to resolve against.
    '_make_param_host_id.hi_curve',
}

#: ``HIP_TRANSFORM`` is :rfc:`5201` only; every other parameter here is built
#: at version 2.
VERSION = {'HIP_TRANSFORM': 1}

#: Other arguments a row's widest code needs: a cipher ID no member holds
#: carries no IV.
WIDEST_EXTRA = {
    '_make_param_encrypted.cipher': {'iv': None},
}

#: Other arguments a row needs to build without its own: the default cipher,
#: ``NULL_ENCRYPT``, refuses an IV (#2708).
BARE_EXTRA = {
    '_make_param_encrypted.cipher': {'iv': None},
}

#: ``maker.argument`` to the attribute its parameter's data model keeps the
#: parsed values in, for the rows whose enumeration is narrower than the field.
PARSED = {
    '_make_param_hip_transport_mode.modes': 'mode_id',
    '_make_param_hit_suite_list.suites': 'suite_id',
}


def _attr(path: 'str') -> 'Any':
    """Import ``path`` and return the attribute it names.

    Args:
        path: dotted path whose last component is an attribute of the module
            the rest of it names

    Returns:
        The named attribute.

    """
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPMakeCodeTests(unittest.TestCase):
    """An enumeration field takes a member or a code it can carry, nothing else."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _builder(argument: 'str', code: 'Any', extra: 'dict[str, Any]',
                 listed: 'bool') -> 'tuple[int, Callable[..., bytes]]':
        """The HIP version a row builds at, and a builder for its value.

        Args:
            argument: the row's argument
            code: name of the parameter carrying the field, or :data:`None`
            extra: the other arguments the row needs
            listed: if the argument takes a list

        Returns:
            The version, and a function building the packet's octets from a
            value, or from no value at all when given :data:`None`.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        version = VERSION.get(code, 2)

        def build(value: 'Any' = None) -> 'bytes':
            # ``extension=True`` keeps ``HIP.alias`` off ``self._info``, which
            # ``__post_init__`` assigns only once ``read`` has returned (#1184).
            if code is None and argument == 'parameters' and value is not None:
                return HIP(version=version, parameters=[(value, dict(extra))],
                           extension=True).data
            if code is None:
                kwargs = {} if value is None else {argument: value}
                return HIP(version=version, extension=True, **kwargs).data
            args = dict(extra)
            if value is not None:
                args[argument] = [value] if listed else value
            return HIP(version=version, parameters=[(Parameter[code], args)],
                       extension=True).data

        return version, build

    def _rows(self) -> 'list[tuple[str, Any, int, str, int, Callable[..., bytes]]]':
        """``(label, member, bits, field name, version, build)`` for each row."""
        rows = []
        for maker, argument, enum_path, member, bits, name, code, extra, listed in ROWS:
            version, build = self._builder(argument, code, extra, listed)
            rows.append((f'{maker}.{argument}', getattr(_attr(enum_path), member),
                         bits, name, version, build))
        return rows

    @staticmethod
    def _parse(octets: 'bytes') -> 'Any':
        """The HIP packet ``octets`` parse into."""
        from pcapkit.protocols.internet.hip import HIP

        return HIP(io.BytesIO(octets), len(octets), extension=True)

    def assertRefused(self, message: 'str', build: 'Callable[..., bytes]', value: 'Any') -> None:
        """``build(value)`` raises a ``ProtocolError`` saying exactly ``message``.

        Any other outcome fails by assertion, naming what happened instead, so
        that a value written or raised as something else reads as a failure
        rather than as an error in the test.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        try:
            build(value)
        except ProtocolError as error:
            self.assertEqual(str(error), message)
        except Exception as error:  # pylint: disable=broad-except
            self.fail(f'{value!r} raised {type(error).__name__}: {error}; '
                      f'expected ProtocolError: {message}')
        else:
            self.fail(f'{value!r} was accepted; expected ProtocolError: {message}')

    def test_a_code_too_wide_for_its_field_is_refused(self) -> None:
        """#2617: ``1 << bits`` raises ``ProtocolError`` naming the field."""
        for label, _, bits, name, version, build in self._rows():
            with self.subTest(row=label, bits=bits):
                self.assertRefused(f'HIPv{version}: invalid {name}: {1 << bits!r}',
                                   build, 1 << bits)

    def test_a_bool_is_refused(self) -> None:
        """#2617: no field here is one bit wide, so :data:`True` is refused."""
        for label, _, bits, name, version, build in self._rows():
            self.assertGreater(bits, 1, label)
            with self.subTest(row=label):
                self.assertRefused(f'HIPv{version}: invalid {name}: True', build, True)

    def test_a_member_name_is_refused(self) -> None:
        """#2594: a name is refused rather than resolved against an inferred enumeration."""
        for label, member, _, name, version, build in self._rows():
            with self.subTest(row=label):
                self.assertRefused(f'HIPv{version}: invalid {name}: {member.name!r}',
                                   build, member.name)

    def test_the_member_and_its_code_build_the_same_octets(self) -> None:
        """#2594: the member and ``int(member)`` resolve with ``get`` to one field value."""
        rows = {f'{maker}.{argument}': (argument, code, extra, listed)
                for maker, argument, _, _, _, _, code, extra, listed in ROWS}
        for label, member, _, _, _, build in self._rows():
            with self.subTest(row=label):
                expected = build(member)
                self.assertEqual(build(int(member)).hex(), expected.hex())
                # the member is not what the maker builds without it, so a
                # value that never reached the packet cannot pass
                bare = build
                if label in BARE_EXTRA:
                    argument, code, extra, listed = rows[label]
                    _, bare = self._builder(argument, code, {**extra, **BARE_EXTRA[label]}, listed)
                self.assertNotEqual(bare().hex(), expected.hex())

    def test_the_widest_code_builds_parses_back_and_rebuilds(self) -> None:
        """#2594: the field width decides what is refused, so ``(1 << bits) - 1`` builds."""
        from pcapkit.protocols.internet.hip import HIP

        for maker, argument, _, _, bits, _, code, extra, listed in ROWS:
            label = f'{maker}.{argument}'
            _, build = self._builder(argument, code, {**extra, **WIDEST_EXTRA.get(label, {})},
                                     listed)
            with self.subTest(row=label, code=(1 << bits) - 1):
                octets = build((1 << bits) - 1)
                self.assertEqual(HIP.from_data(self._parse(octets).info).data.hex(), octets.hex())

    def test_a_parsed_code_builds_the_same_octets(self) -> None:
        """#2594: ``make`` takes the codes a parse hands back, where no member holds them too."""
        from pcapkit.const.hip.parameter import Parameter

        rows = {f'{maker}.{argument}': (bits, code, extra)
                for maker, argument, _, _, bits, _, code, extra, _ in ROWS}
        for label, attribute in PARSED.items():
            bits, code, extra = rows[label]
            _, build = self._builder(label.partition('.')[2], code, extra, False)
            with self.subTest(row=label):
                octets = build([(1 << bits) - 1, 1])
                info = self._parse(octets).info
                parsed = list(getattr(info.parameters[getattr(Parameter, str(code))], attribute))
                self.assertEqual([int(value) for value in parsed], [(1 << bits) - 1, 1])
                self.assertEqual(build(parsed).hex(), octets.hex())

    def _parameter_builders(self) -> 'dict[str, Callable[[Any], bytes]]':
        """A builder for each form ``parameters`` takes a parameter's type in."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.hip import HIP

        def pair(value: 'Any') -> 'bytes':
            return HIP(version=2, parameters=[(value, {'contents': b'\x01'})],
                       extension=True).data

        # the parsed data of an unassigned parameter, which any code takes
        _, param = list(self._parse(pair(0xFFFF)).info.parameters.items(multi=True))[0]
        self.assertEqual(param.type, Parameter.get(0xFFFF))
        return {
            'pair': pair,
            'parsed': lambda value: HIP(version=2, parameters=OrderedMultiDict([(value, param)]),
                                        extension=True).data,
        }

    def test_a_parameter_type_the_field_cannot_carry_is_refused(self) -> None:
        """#2594: the type of a parameter is checked before anything reads it as a registry key."""
        for form, build in self._parameter_builders().items():
            for value in (1 << 16, -1, True, 'SEQ'):
                with self.subTest(form=form, value=value):
                    self.assertRefused(f'HIPv2: invalid parameter type: {value!r}', build, value)

    def test_the_widest_parameter_type_builds_parses_back_and_rebuilds(self) -> None:
        """#2594: a parameter type no member holds builds in either form, and rebuilds."""
        from pcapkit.protocols.internet.hip import HIP

        for form, build in self._parameter_builders().items():
            with self.subTest(form=form):
                octets = build(0xFFFF)
                info = self._parse(octets).info
                self.assertEqual([int(code) for code in info.parameters], [0xFFFF])
                self.assertEqual(HIP.from_data(info).data.hex(), octets.hex())

    def test_every_enumeration_argument_has_a_row(self) -> None:
        """Each enumeration-typed argument of :meth:`HIP.make` and the parameter makers has a row.

        Read off the signatures rather than listed, so a further enumeration
        argument gets a row here or an entry in :data:`EXEMPT`. A parameter
        maker's positional ``code`` is the code ``make.parameters`` resolves.

        """
        from pcapkit.protocols.internet.hip import HIP

        found = set()
        for name in vars(HIP):
            if name != 'make' and not name.startswith('_make_param_'):
                continue
            for arg, param in inspect.signature(getattr(HIP, name)).parameters.items():
                if arg in ('self', 'code', 'param') or 'Enum_' not in str(param.annotation):
                    continue
                found.add(f'{name}.{arg}')

        self.assertEqual(found - EXEMPT, {f'{maker}.{argument}' for maker, argument, *_ in ROWS})

    def test_no_maker_takes_a_removed_keyword(self) -> None:
        """#2594: no maker's signature declares a ``*_default``, ``*_namespace`` or ``*_reversed`` keyword."""
        from pcapkit.protocols.internet.hip import HIP

        for name in vars(HIP):
            if name != 'make' and not name.startswith('_make_'):
                continue
            with self.subTest(maker=name):
                removed = [arg for arg in inspect.signature(getattr(HIP, name)).parameters
                           if arg.endswith(('_default', '_namespace', '_reversed'))]
                self.assertEqual(removed, [])


if __name__ == '__main__':
    unittest.main()
