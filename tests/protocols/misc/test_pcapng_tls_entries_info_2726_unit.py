# -*- coding: utf-8 -*-
"""A TLS key log's entries are a data model, not a plain ``dict`` (#2726).

:attr:`TLSKeyLog.entries <pcapkit.protocols.data.misc.pcapng.TLSKeyLog.entries>`
maps each label to its client random to secret pairs. It was a plain
:class:`dict` held on the data model; the owner ruled on #2726 that a field in
:mod:`pcapkit.protocols.data` holds an ``Info`` or a data model instead, so it is
a :class:`~pcapkit.protocols.data.misc.pcapng.TLSKeyLogEntries`. These tests pin
the model, what ``to_dict`` exports and ``from_dict`` rebuilds, what the dumpers
write, a byte-exact rebuild, and pickles that hold the entries as the
:class:`dict`, so they load on either side of the change.

"""

import copy
import os
import pickle
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests.protocols.misc.test_pcapng_dsb_secrets_dict_2698_unit import TLS, _dsb
from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'

#: Every pickle protocol, ``0`` and ``1`` included.
PROTOCOLS = tuple(range(pickle.HIGHEST_PROTOCOL + 1))

#: A key log with a comment, a label held twice and a second label.
SECRETS = (b'# keys\nCLIENT_RANDOM 00112233 aabbccdd\nCLIENT_RANDOM 4455 eeff\n'
           b'EXPORTER_SECRET 0102 0304\n')
OCTETS = _dsb(TLS, SECRETS)

#: The pairs each label holds, in log order.
PAIRS = {
    'CLIENT_RANDOM': [(bytes.fromhex('00112233'), bytes.fromhex('aabbccdd')),
                      (bytes.fromhex('4455'), bytes.fromhex('eeff'))],
    'EXPORTER_SECRET': [(bytes.fromhex('0102'), bytes.fromhex('0304'))],
}


class _TLSTestCase(PCAPNGTestCase):
    """Parse :data:`OCTETS` after the per-class import."""

    def _block(self) -> 'Any':
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return self._parse(OCTETS).info

    def _assert_entries(self, entries: 'Any') -> None:
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.corekit.infoclass import OrderedMultiInfo
        from pcapkit.protocols.data.misc.pcapng import TLSKeyLogEntries

        self.assertIs(type(entries), TLSKeyLogEntries)
        self.assertEqual([type(label) for label in entries], [TLSKeyLabel] * len(PAIRS))
        self.assertEqual({label.name: list(pairs.items(multi=True)) for label, pairs in entries.items()},
                         PAIRS)
        for pairs in entries.values():
            self.assertIs(type(pairs), OrderedMultiInfo)


class TLSKeyLogEntriesTests(_TLSTestCase):
    """The entries as a data model: the mapping, ``to_dict``, dumps and a rebuild."""

    def test_entries_are_a_data_model_keyed_by_label(self) -> None:
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.protocols.data.data import Data
        from pcapkit.utilities.exceptions import UnsupportedCall

        entries = self._block().secrets_data.entries
        self._assert_entries(entries)
        self.assertIsInstance(entries, Data)
        self.assertNotIsInstance(entries, dict)
        self.assertIn(TLSKeyLabel.CLIENT_RANDOM, entries)
        self.assertIs(entries.CLIENT_RANDOM, entries[TLSKeyLabel.CLIENT_RANDOM])
        with self.assertRaises(UnsupportedCall):
            entries.CLIENT_RANDOM = None

    def test_a_mapping_given_for_entries_is_stored_as_the_model(self) -> None:
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.misc.pcapng import TLSKeyLog

        pairs = {TLSKeyLabel[name]: OrderedMultiDict(items) for name, items in PAIRS.items()}
        self._assert_entries(TLSKeyLog(entries=pairs).entries)

    def test_to_dict_exports_the_entries_and_from_dict_rebuilds_them(self) -> None:
        # NOTE: a nested model exports as an OrderedMultiDict at every level (#1484).
        from pcapkit.corekit.infoclass import _OrderedMultiDict
        from pcapkit.protocols.data.misc.pcapng import TLSKeyLog

        block = self._block()
        tls = block.secrets_data
        export = tls.to_dict()['entries']
        self.assertIs(type(export), _OrderedMultiDict)
        self.assertEqual([type(pairs) for pairs in export.values()], [_OrderedMultiDict] * len(PAIRS))
        self.assertEqual({label.name: list(pairs.items(multi=True)) for label, pairs in export.items()},
                         PAIRS)
        self.assertIs(type(block.to_dict()['secrets_data']['entries']), _OrderedMultiDict)
        rebuilt = TLSKeyLog.from_dict(tls.to_dict())
        self._assert_entries(rebuilt.entries)
        self.assertEqual(rebuilt.entries, tls.entries)

    def test_the_block_rebuilds_exactly_from_its_model_and_its_dict(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        block = self._block()
        for path, data in (('model', block), ('dict', block.to_dict())):
            with self.subTest(path=path):
                rebuilt = PCAPNG.from_data(data, num=2, sct=1, ctx=self._context()).data
                self.assertEqual(rebuilt.hex(), OCTETS.hex())

    def test_every_dumper_writes_the_entries_as_the_dict(self) -> None:
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper

        tls = self._block().secrets_data
        held = copy.copy(tls)
        held.__dict__['entries'] = dict(tls.entries)
        for kind in (dictdumper.JSON, dictdumper.PLIST, dictdumper.Tree):
            with self.subTest(dumper=kind.__name__), tempfile.TemporaryDirectory() as tmp:
                texts = []
                for name, value in (('model', tls), ('dict', held)):
                    path = os.path.join(tmp, name)
                    dumper = make_dumper(kind)(path)
                    dumper(value, name='Secrets')
                    del dumper
                    with open(path, encoding='utf-8') as file:
                        texts.append(file.read())
                self.assertEqual(texts[0], texts[1])


class TLSKeyLogPickleTests(_TLSTestCase):
    """Pickles hold the entries as a :class:`dict`, and load them as the model."""

    def test_a_pickle_holds_the_entries_as_a_dict(self) -> None:
        block = self._block()
        tls = block.secrets_data
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                state = tls.__reduce_ex__(protocol)[2]
                self.assertIs(type(state['entries']), dict)
                for value in (tls, block):
                    payload = pickle.dumps(value, protocol=protocol)
                    self.assertNotIn(b'TLSKeyLogEntries', payload)
                    clone = pickle.loads(payload)
                    entries = clone.entries if value is tls else clone.secrets_data.entries
                    self._assert_entries(entries)
                    self.assertEqual(entries, tls.entries)

    def test_a_pickle_holding_a_dict_loads_as_the_model(self) -> None:
        # NOTE: the state of a model holding its entries as a dict, as one with
        # no __getstate__ of its own pickles it.
        tls = self._block().secrets_data
        state = dict(tls.__dict__)
        state['entries'] = dict(tls.entries)
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                with mock.patch.object(type(tls), '__getstate__', lambda self: state, create=True):
                    payload = pickle.dumps(tls, protocol=protocol)
                clone = pickle.loads(payload)
                self._assert_entries(clone.entries)
                self.assertEqual(clone.data, SECRETS.decode())

    def test_the_model_alone_pickles_as_itself(self) -> None:
        entries = self._block().secrets_data.entries
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                clone = pickle.loads(pickle.dumps(entries, protocol=protocol))
                self._assert_entries(clone)
                self.assertEqual(clone, entries)


if __name__ == '__main__':
    unittest.main()
