# -*- coding: utf-8 -*-
"""MH parses its options' foreign payloads through registries of their own. C.f. #2937.

The traffic selectors of :rfc:`6089` and :rfc:`7222` are keyed on ``ts_format``
in ``MH.__selector__``, and the MLD and IGMP records of the multicast options on
the option type and its format octet in ``MH.__multicast__``: ``protocol`` of
option 54 (:rfc:`7028`), ``igmp_type`` and ``mld_type`` of 56 and 57 (:rfc:`7161`),
and ``code`` of 60 and 61 (:rfc:`7411`). Each payload is the protocol class the
registry holds, ``Raw`` until a dissector registers, parsed apart from the frame.
A format octet its RFC rules out warns and keeps the payload raw, and the
``register_mh_selector`` and ``register_mh_multicast`` wrappers refuse to
register one.

Every case builds its own octets in memory and reads no capture; the protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel

import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): field-by-field behaviour of one protocol, pure Python.
__tier__ = 'LATEST'

#: Header fields of every built Mobility Header; ``next`` is IPv6-NoNxt.
BASE = {'next': 59, 'checksum': b'\x00\x00', 'payload': b''}

#: 224.0.0.251 and ff02::fb, and records holding them: an IGMPv3 group record
#: [RFC 3376 section 4.2] and an MLDv2 address record [RFC 3810 section 5.2].
GROUP_V4 = bytes.fromhex('e00000fb')
GROUP_V6 = bytes.fromhex('ff0200000000000000000000000000fb')
IGMPV3_RECORD = b'\x01\x00\x00\x00' + GROUP_V4
MLDV2_RECORD = b'\x01\x00\x00\x00' + GROUP_V6

#: ``(option name, format field, payload field, payload, formats its RFC defines)``.
#: The formats are RFC 7028 sections 5.1.2 and 8, RFC 7161 sections 6.1, 4.1.2
#: and 4.1.3, and RFC 7411 sections 5.3 and 5.4.
MULTICAST = (
    ('Dynamic_IP_Multicast_Selector', 'protocol', 'data', MLDV2_RECORD, {0x12, 0x16, 0x22, 131, 143}),
    ('Active_Multicast_Subscription_IPv4', 'igmp_type', 'context', IGMPV3_RECORD, {0x12, 0x16, 0x22}),
    ('Active_Multicast_Subscription_IPv6', 'mld_type', 'context', MLDV2_RECORD, {131, 143}),
    ('Multicast_Mobility_Option', 'code', 'data', b'\x00\x00\x00\x01' + MLDV2_RECORD, {1, 2, 3, 4}),
    ('Multicast_Acknowledgement_Option', 'code', 'data', b'\x00\x00\x00\x00', {0}),
)

#: An RFC 6088 binary traffic selector selecting nothing [RFC 6088 section 3].
SELECTOR = b'\x00\x00\x00\x00'


def _carrier() -> 'Any':
    from pcapkit.const.mh.packet import Packet
    return Packet.Binding_Refresh_Request


def _build(options: 'list[Any]') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH.from_fields(type=_carrier(), data={'options': options}, **BASE)


def _parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.mh.protocol import MH
    return MH(octets, len(octets), extension=True)


def _multicast(name: 'str', field: 'str', payload_field: 'str', code: 'int', payload: 'bytes') -> 'Any':
    from pcapkit.const.mh.option import Option
    kwargs = {field: code, payload_field: payload}  # type: dict[str, Any]
    if name == 'Dynamic_IP_Multicast_Selector':
        kwargs['records'] = 1
    return (Option[name], kwargs)


def _selectors(code: 'Any', selector: 'Any' = SELECTOR) -> 'list[Any]':
    from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption
    from pcapkit.const.mh.option import Option
    from pcapkit.const.mh.qos_attribute import QoSAttribute
    entry = {'ts_format': code, 'selector': selector}
    return [(Option.Flow_Identification_Mobility_Option,
             {'suboptions': [(FlowIDSuboption.Traffic_Selector, dict(entry))]}),
            (Option.Quality_of_Service,
             {'attributes': [(QoSAttribute.QoS_Traffic_Selector, dict(entry))]})]


def _selector_payloads(parsed: 'Any') -> 'list[Any]':
    from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption
    from pcapkit.const.mh.option import Option
    from pcapkit.const.mh.qos_attribute import QoSAttribute
    options = parsed.info.options
    return [options[Option.Flow_Identification_Mobility_Option].suboptions[FlowIDSuboption.Traffic_Selector].selector,
            options[Option.Quality_of_Service].attributes[QoSAttribute.QoS_Traffic_Selector].selector]


class _Records:
    """A namespace for the dissector classes the registration cases register."""

    @staticmethod
    def make(refuse: 'bool' = False) -> 'type':
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        def read(self: 'Any', length: 'Any' = None, **kwargs: 'Any') -> 'Any':
            if refuse:
                raise ProtocolError('records refused')
            return Raw.read(self, length, **kwargs)

        return type('RecordsUnderTest', (Raw,), {'__module__': __name__, 'read': read})


class MHPayloadRegistryTests(unittest.TestCase):
    """The payload registries, their RFC check and their registrars."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_registries_hold_exactly_the_formats_the_rfcs_define(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.traffic_selector import TrafficSelector
        from pcapkit.protocols.internet.mh.protocol import MH

        expected = {(Option[name], code) for name, _, _, _, codes in MULTICAST for code in codes}
        self.assertEqual(set(MH.__multicast__), expected)
        self.assertEqual(set(MH.__selector__), {TrafficSelector.IPv4_Binary_Traffic_Selector,
                                                TrafficSelector.IPv6_Binary_Traffic_Selector})
        for registry in (MH.__multicast__, MH.__selector__):
            for key in registry:
                self.assertEqual(MH._lookup_next_layer(registry, key).__name__, 'Raw')

    def test_multicast_payloads_parse_as_raw_and_rebuild(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.misc.raw.protocol import Raw

        for name, field, payload_field, payload, codes in MULTICAST:
            for code in sorted(codes):
                with self.subTest(option=name, code=code), warnings.catch_warnings():
                    warnings.simplefilter('error')
                    built = _build([_multicast(name, field, payload_field, code, payload)])
                    parsed = _parse(built.data)
                    option = parsed.info.options[Option[name]]
                    value = getattr(option, payload_field)
                    self.assertIsInstance(value, Raw)
                    self.assertEqual(value.data, payload)
                    self.assertEqual(value.info.protocol, code)
                    self.assertIsNone(value.info.error)
                    self.assertEqual(_build(parsed.info.options).data, built.data)

    def test_traffic_selectors_parse_as_raw_in_both_carriers(self) -> None:
        from pcapkit.const.mh.traffic_selector import TrafficSelector
        from pcapkit.protocols.misc.raw.protocol import Raw

        for code in (TrafficSelector.IPv4_Binary_Traffic_Selector, TrafficSelector.IPv6_Binary_Traffic_Selector):
            with self.subTest(code=code), warnings.catch_warnings():
                warnings.simplefilter('error')
                built = _build(_selectors(code))
                parsed = _parse(built.data)
                for value in _selector_payloads(parsed):
                    self.assertIsInstance(value, Raw)
                    self.assertEqual(value.data, SELECTOR)
                    self.assertEqual(value.info.protocol, code)
                self.assertEqual(_build(parsed.info.options).data, built.data)

    def test_a_format_the_rfc_rules_out_warns_and_stays_raw(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.utilities.warnings import ProtocolWarning

        # The octet each option's neighbour uses is still not one it defines.
        outside = {'Dynamic_IP_Multicast_Selector': (0, 0x11, 130), 'Active_Multicast_Subscription_IPv4': (143,),
                   'Active_Multicast_Subscription_IPv6': (0x22,), 'Multicast_Mobility_Option': (0, 5),
                   'Multicast_Acknowledgement_Option': (1,)}
        for name, field, payload_field, payload, _ in MULTICAST:
            for code in outside[name]:
                with self.subTest(option=name, code=code):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        built = _build([_multicast(name, field, payload_field, code, payload)])
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        parsed = _parse(built.data)
                    messages = [str(entry.message) for entry in caught if entry.category is ProtocolWarning]
                    self.assertEqual(messages, [f'MH: [Opt {Option[name]}] payload format {code} '
                                                'is not one its RFC defines'])
                    value = getattr(parsed.info.options[Option[name]], payload_field)
                    self.assertEqual(value.__class__.__name__, 'Raw')
                    self.assertEqual(value.info.error, messages[0])
                    self.assertEqual(value.data, payload)
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertEqual(_build(parsed.info.options).data, built.data)

    def test_the_reserved_traffic_selector_format_warns_and_stays_raw(self) -> None:
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            built = _build(_selectors(0))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = _parse(built.data)
        messages = [str(entry.message) for entry in caught if entry.category is ProtocolWarning]
        self.assertEqual(messages, ['MH: TS format 0 is reserved and must not be used'] * 2)
        for value in _selector_payloads(parsed):
            self.assertEqual(value.info.error, messages[0])
            self.assertEqual(value.data, SELECTOR)

    def test_an_unassigned_traffic_selector_format_is_raw_without_a_warning(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            parsed = _parse(_build(_selectors(251)).data)
        for value in _selector_payloads(parsed):
            self.assertIsNone(value.info.error)
            self.assertEqual(value.data, SELECTOR)

    def test_an_empty_payload_is_no_payload(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload

        parsed = _parse(_build([(Option.Active_Multicast_Subscription_IPv6, {'mld_type': 143})]).data)
        self.assertIsInstance(parsed.info.options[Option.Active_Multicast_Subscription_IPv6].context, NoPayload)

    def test_makers_take_a_parsed_payload(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        for name, field, payload_field, payload, codes in MULTICAST:
            code = min(codes)
            with self.subTest(option=name):
                octets = _build([_multicast(name, field, payload_field, code, payload)]).data
                again = _build([_multicast(name, field, payload_field, code, Raw(payload))]).data
                self.assertEqual(again, octets)
        octets = _build(_selectors(1)).data
        self.assertEqual(_build(_selectors(1, Raw(SELECTOR))).data, octets)

    def test_a_registered_dissector_parses_the_payload_outside_the_chain(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.traffic_selector import TrafficSelector
        from pcapkit.foundation.registry import register_mh_multicast, register_mh_selector
        from pcapkit.protocols.internet.mh.protocol import MH

        records = _Records.make()
        multicast, selector = dict(MH.__multicast__), dict(MH.__selector__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_mh_multicast(143, records, option=Option.Dynamic_IP_Multicast_Selector)
                register_mh_selector(TrafficSelector.IPv6_Binary_Traffic_Selector, records)
            built = _build([_multicast('Dynamic_IP_Multicast_Selector', 'protocol', 'data', 143, MLDV2_RECORD),
                            *_selectors(TrafficSelector.IPv6_Binary_Traffic_Selector)])
            parsed = _parse(built.data)
            value = parsed.info.options[Option.Dynamic_IP_Multicast_Selector].data
            self.assertIsInstance(value, records)
            for item in _selector_payloads(parsed):
                self.assertIsInstance(item, records)
            self.assertEqual(_build(parsed.info.options).data, built.data)
            # Parsed apart from the frame: the header's own chain is just itself.
            alone = MH(built.data, len(built.data))
            self.assertEqual([name for name, _ in alone.protochain], ['MH'])
        finally:
            MH.__multicast__.clear()
            MH.__multicast__.update(multicast)
            MH.__selector__.clear()
            MH.__selector__.update(selector)

    def test_a_dissector_that_refuses_leaves_the_payload_raw(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.protocol import MH

        records = _Records.make(refuse=True)
        multicast = dict(MH.__multicast__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                MH.register_multicast(2, records, option=Option.Multicast_Mobility_Option)
            payload = b'\x00\x00\x00\x01' + MLDV2_RECORD
            parsed = _parse(_build([_multicast('Multicast_Mobility_Option', 'code', 'data', 2, payload)]).data)
            value = parsed.info.options[Option.Multicast_Mobility_Option].data
            self.assertEqual(type(value).__name__, 'Raw')
            self.assertEqual(value.info.error, 'records refused')
            self.assertEqual(value.data, payload)
        finally:
            MH.__multicast__.clear()
            MH.__multicast__.update(multicast)

    def test_the_registrars_refuse_what_the_rfcs_rule_out(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.traffic_selector import TrafficSelector
        from pcapkit.foundation.registry import register_mh_multicast, register_mh_selector
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import RegistryError

        multicast, selector = dict(MH.__multicast__), dict(MH.__selector__)
        cases = (
            lambda: register_mh_selector(TrafficSelector.Reserved_0, Raw),
            lambda: MH.register_selector(TrafficSelector.Reserved_0, Raw),
            lambda: register_mh_selector(1, Raw),  # type: ignore[arg-type]
            lambda: register_mh_selector(TrafficSelector.IPv4_Binary_Traffic_Selector, int),  # type: ignore[arg-type]
            lambda: register_mh_multicast(0, Raw, option=Option.Dynamic_IP_Multicast_Selector),
            lambda: register_mh_multicast(143, Raw, option=Option.Active_Multicast_Subscription_IPv4),
            lambda: register_mh_multicast(1, Raw, option=Option.Multicast_Acknowledgement_Option),
            lambda: register_mh_multicast(0, Raw, option=Option.Pad1),
            lambda: register_mh_multicast(143, Raw, option=57),  # type: ignore[arg-type]
            lambda: register_mh_multicast(True, Raw, option=Option.Multicast_Acknowledgement_Option),
            lambda: register_mh_multicast(143, object, option=Option.Active_Multicast_Subscription_IPv6),
        )
        for index, case in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(RegistryError):
                case()
            self.assertEqual(MH.__multicast__, multicast)
            self.assertEqual(MH.__selector__, selector)

    def test_an_override_warns_and_the_shipped_entry_restores_it(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.traffic_selector import TrafficSelector
        from pcapkit.foundation.registry import register_mh_multicast, register_mh_selector
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.warnings import RegistryWarning

        records = _Records.make()
        key = (Option.Active_Multicast_Subscription_IPv4, 0x22)
        code = TrafficSelector.IPv4_Binary_Traffic_Selector
        multicast, selector = dict(MH.__multicast__), dict(MH.__selector__)
        try:
            with self.assertWarns(RegistryWarning):
                register_mh_multicast(0x22, records, option=key[0])
            with self.assertWarns(RegistryWarning):
                register_mh_selector(code, records)
            self.assertIs(MH.__multicast__[key], records)
            self.assertIs(MH.__selector__[code], records)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_mh_multicast(0x22, multicast[key], option=key[0])
                register_mh_selector(code, selector[code])
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_mh_multicast(0x22, multicast[key], option=key[0])
                register_mh_selector(code, selector[code])
            self.assertEqual(set(MH.__multicast__), set(multicast))
            self.assertIs(MH.__multicast__[key], multicast[key])
            self.assertIs(MH.__selector__[code], selector[code])
        finally:
            MH.__multicast__.clear()
            MH.__multicast__.update(multicast)
            MH.__selector__.clear()
            MH.__selector__.update(selector)

    def test_a_new_traffic_selector_format_registers_without_a_warning(self) -> None:
        from pcapkit.const.mh.traffic_selector import TrafficSelector
        from pcapkit.foundation.registry import register_mh_selector
        from pcapkit.protocols.internet.mh.protocol import MH

        # An experimental format [RFC 6089 section 8] has no shipped entry to displace.
        code = TrafficSelector.get(251)
        records = _Records.make()
        selector = dict(MH.__selector__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_mh_selector(code, records)
                parsed = _parse(_build(_selectors(code)).data)
            self.assertIs(MH.__selector__[code], records)
            for value in _selector_payloads(parsed):
                self.assertIsInstance(value, records)
        finally:
            MH.__selector__.clear()
            MH.__selector__.update(selector)

    def test_a_miss_does_not_grow_the_registries(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH

        sizes = len(MH.__multicast__), len(MH.__selector__)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            _parse(_build([_multicast('Dynamic_IP_Multicast_Selector', 'protocol', 'data', 7, GROUP_V4),
                           *_selectors(9)]).data)
        self.assertEqual((len(MH.__multicast__), len(MH.__selector__)), sizes)


if __name__ == '__main__':
    unittest.main()
