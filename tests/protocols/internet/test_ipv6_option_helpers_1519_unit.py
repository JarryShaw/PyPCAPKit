# -*- coding: utf-8 -*-
"""The IPv6 option helpers HOPOPT and IPv6-Opts share.

GitHub issue #1519. The nine field helpers of the HOPOPT and IPv6-Opts option
schemas were two copies differing only in the error prefix and in which
module's option schemas the selectors return. They now live once, in
:mod:`pcapkit.protocols.schema.internet.ipv6_option`, and each header module
binds its own prefix and schemas. This module pins the shared helpers under
both prefixes, that each header delegates to them with its own, and that every
error message keeps its exact text.

The modules are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so that they belong to the
:mod:`pcapkit` import that is live when the test runs.

"""

import collections
import copy
import importlib
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

SHARED = 'pcapkit.protocols.schema.internet.ipv6_option'

#: Each header's schema module, and the prefix its errors carry.
HEADERS = (
    ('pcapkit.protocols.schema.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.schema.internet.ipv6_opts', 'IPv6-Opts'),
)

#: ``(helper, packet, message after the prefix)`` for every ``raise`` in the
#: helpers whose packet alone triggers it.
ERRORS = (
    ('mpl_opt_seed_id_len', {'flags': {'type': 4}}, 'invalid MPL Seed-ID type: 4'),
    ('smf_i_dpd_id_len', {'len': 0, 'info': {'type': 0, 'len': 0}},
     'invalid SMF I-DPD option length: 0'),
    ('smf_i_dpd_id_len', {'len': 3, 'info': {'type': 2, 'len': 3}},
     'invalid SMF I-DPD option length: 3'),
    ('smf_dpd_data_selector', {'test': {'len': 0, 'mode': 0}},
     'invalid SMF DPD option length: 0'),
    ('smf_i_dpd_tid_selector', {'info': {'type': 0, 'len': 1}}, 'invalid TaggerID length: 1'),
    ('smf_i_dpd_tid_selector', {'info': {'type': 2, 'len': 4}}, 'invalid TaggerID length: 4'),
    ('smf_i_dpd_tid_selector', {'info': {'type': 3, 'len': 16}}, 'invalid TaggerID length: 16'),
    ('calipso_pad_len', {'len': 11, 'cmpt_len': 1}, 'invalid CALIPSO option length: 11'),
    ('mpl_opt_pad_len', {'len': 3, 'flags': {'type': 1}}, 'invalid MPL option length: 3'),
    ('mpl_opt_pad_len', {'len': 1, 'flags': {'type': 0}}, 'invalid MPL option length: 1'),
)

#: The helpers each header binds, and the keywords it binds them with beyond
#: ``prefix`` -- by attribute name of the header's schema module.
BOUND = {
    'mpl_opt_seed_id_len': {},
    'smf_i_dpd_id_len': {},
    'smf_dpd_data_selector': {'base': 'SMFDPDOption'},
    'smf_i_dpd_tid_selector': {},
    'calipso_pad_len': {},
    'mpl_opt_pad_len': {},
}

#: The helpers both headers use unchanged.
UNBOUND = ('rpl_opt_sub_tlv_len', 'pad_opt_data_len')


class TestIPv6OptionHelpers(unittest.TestCase):
    """Pin the shared helpers, and the header modules' use of them."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _shared(self) -> 'object':
        return importlib.import_module(SHARED)

    def _headers(self) -> 'list[tuple[object, str]]':
        return [(importlib.import_module(name), prefix) for name, prefix in HEADERS]

    def test_shared_module_holds_all_nine_helpers(self) -> None:
        shared = self._shared()
        self.assertEqual(sorted(shared.__all__), sorted([*BOUND, 'quick_start_data_selector', *UNBOUND]))

    def test_shared_helpers_report_the_prefix_they_are_given(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        shared = self._shared()
        hopopt = importlib.import_module(HEADERS[0][0])
        for prefix in ('HOPOPT', 'IPv6-Opts', 'any-header'):
            for name, packet, message in ERRORS:
                extra = {'base': hopopt.SMFDPDOption} if name == 'smf_dpd_data_selector' else {}
                with self.subTest(prefix=prefix, helper=name, packet=packet):
                    with self.assertRaises(FieldValueError) as caught:
                        getattr(shared, name)(copy.deepcopy(packet), prefix=prefix, **extra)
                    self.assertEqual(str(caught.exception), f'{prefix}: {message}')

    def test_shared_dpd_selector_reports_an_unregistered_mode(self) -> None:
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.utilities.exceptions import FieldValueError

        shared = self._shared()
        empty = mock.Mock(registry=collections.defaultdict(lambda: None))
        for prefix in ('HOPOPT', 'IPv6-Opts'):
            with self.subTest(prefix=prefix):
                with self.assertRaises(FieldValueError) as caught:
                    shared.smf_dpd_data_selector({'test': {'len': 4, 'mode': 1}},
                                                 prefix=prefix, base=empty)
                self.assertEqual(str(caught.exception),
                                 f'{prefix}: invalid SMF DPD mode: {SMFDPDMode.H_DPD}')

    def test_shared_length_helpers(self) -> None:
        from pcapkit.corekit.fields.field import NO_VALUE

        shared = self._shared()
        self.assertEqual(shared.rpl_opt_sub_tlv_len({'len': 9}), 5)
        self.assertEqual(shared.rpl_opt_sub_tlv_len({'len': 2}), 0)
        self.assertEqual(shared.pad_opt_data_len({'len': 3}), 3)
        self.assertEqual(shared.pad_opt_data_len({}), 0)
        self.assertEqual(shared.pad_opt_data_len({'len': NO_VALUE}), 0)
        self.assertEqual(shared.pad_opt_data_len({'len': None}), 0)
        for s_type, length in ((0, 0), (1, 2), (2, 8), (3, 16)):
            self.assertEqual(shared.mpl_opt_seed_id_len({'flags': {'type': s_type}}, prefix='X'), length)
        self.assertEqual(shared.smf_i_dpd_id_len({'len': 5, 'info': {'type': 0, 'len': 0}}, prefix='X'), 4)
        self.assertEqual(shared.smf_i_dpd_id_len({'len': 7, 'info': {'type': 2, 'len': 3}}, prefix='X'), 2)
        self.assertEqual(shared.calipso_pad_len({'len': 14, 'cmpt_len': 1}, prefix='X'), 2)
        self.assertEqual(shared.mpl_opt_pad_len({'len': 6, 'flags': {'type': 0}}, prefix='X'), 4)
        self.assertEqual(shared.mpl_opt_pad_len({'len': 6, 'flags': {'type': 1}}, prefix='X'), 2)

    def test_shared_tid_selector_fields_and_type_update(self) -> None:
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
        from pcapkit.corekit.fields.misc import NoValueField
        from pcapkit.corekit.fields.strings import BytesField

        shared = self._shared()
        for tid_type, tid_len, kind in ((0, 0, NoValueField), (2, 3, IPv4AddressField),
                                        (3, 15, IPv6AddressField), (1, 4, BytesField)):
            packet = {'info': {'type': tid_type, 'len': tid_len}}
            with self.subTest(tid_type=tid_type):
                self.assertIs(type(shared.smf_i_dpd_tid_selector(packet, prefix='X')), kind)
                self.assertIs(packet['info']['type'], TaggerID.get(tid_type))
        self.assertEqual(shared.smf_i_dpd_tid_selector({'info': {'type': 1, 'len': 4}}, prefix='X').length, 5)

    def test_shared_selectors_return_the_schemas_they_are_given(self) -> None:
        shared = self._shared()
        for module, _ in self._headers():
            with self.subTest(module=module.__name__):
                for mode, schema in ((0, module.SMFIdentificationBasedDPDOption),
                                     (1, module.SMFHashBasedDPDOption)):
                    field = shared.smf_dpd_data_selector({'test': {'len': 4, 'mode': mode}},
                                                         prefix='X', base=module.SMFDPDOption)
                    self.assertIs(field.schema, schema)
                    self.assertEqual(field.length, 6)
                for func, schema, length in ((0, module.QuickStartRequestOption, 8),
                                             (8, module.QuickStartReportOption, 8),
                                             (1, module.UnassignedOption, 5)):
                    field = shared.quick_start_data_selector(
                        {'flags': {'func': func, 'len': 3}},
                        base=module.QuickStartOption, unassigned=module.UnassignedOption,
                    )
                    self.assertIs(field.schema, schema)
                    self.assertEqual(field.length, length)

    def test_headers_keep_their_exact_error_text(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for module, prefix in self._headers():
            for name, packet, message in ERRORS:
                with self.subTest(module=module.__name__, helper=name, packet=packet):
                    with self.assertRaises(FieldValueError) as caught:
                        getattr(module, name)(copy.deepcopy(packet))
                    self.assertEqual(str(caught.exception), f'{prefix}: {message}')

    def test_headers_delegate_with_their_own_prefix_and_schemas(self) -> None:
        shared = self._shared()
        for module, prefix in self._headers():
            for name, extra in BOUND.items():
                packet = {'probe': name}
                with self.subTest(module=module.__name__, helper=name):
                    with mock.patch.object(shared, name, return_value=mock.sentinel.out) as stub:
                        self.assertIs(getattr(module, name)(packet), mock.sentinel.out)
                    stub.assert_called_once_with(packet, prefix=prefix, **{
                        key: getattr(module, value) for key, value in extra.items()
                    })
            with self.subTest(module=module.__name__, helper='quick_start_data_selector'):
                packet = {'probe': 'quick_start_data_selector'}
                with mock.patch.object(shared, 'quick_start_data_selector',
                                       return_value=mock.sentinel.out) as stub:
                    self.assertIs(module.quick_start_data_selector(packet), mock.sentinel.out)
                stub.assert_called_once_with(packet, base=module.QuickStartOption,
                                             unassigned=module.UnassignedOption)

    def test_headers_use_the_identical_helpers_unchanged(self) -> None:
        shared = self._shared()
        for module, _ in self._headers():
            for name in UNBOUND:
                with self.subTest(module=module.__name__, helper=name):
                    self.assertIs(getattr(module, name), getattr(shared, name))

    def test_header_selectors_return_their_own_modules_schemas(self) -> None:
        hopopt, ipv6_opts = (module for module, _ in self._headers())
        self.assertIsNot(hopopt.SMFHashBasedDPDOption, ipv6_opts.SMFHashBasedDPDOption)
        for module in (hopopt, ipv6_opts):
            with self.subTest(module=module.__name__):
                self.assertIs(module.smf_dpd_data_selector({'test': {'len': 4, 'mode': 1}}).schema,
                              module.SMFHashBasedDPDOption)
                self.assertIs(module.quick_start_data_selector({'flags': {'func': 8, 'len': 6}}).schema,
                              module.QuickStartReportOption)
                self.assertIs(module.quick_start_data_selector({'flags': {'func': 1, 'len': 6}}).schema,
                              module.UnassignedOption)


if __name__ == '__main__':
    unittest.main()
