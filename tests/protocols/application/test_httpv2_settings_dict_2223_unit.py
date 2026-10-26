# -*- coding: utf-8 -*-
"""HTTP/2 ``SETTINGS`` frames build from a plain :obj:`dict`.

GitHub issue #2223: ``HTTP._make_http_settings`` accepted a :obj:`dict` but
called ``settings.items(multi=True)``, which only
:class:`~pcapkit.corekit.multidict.MultiDict` supports, so a plain :obj:`dict`
raised a stdlib :exc:`TypeError` instead of building the frame. A plain
:obj:`dict` builds the same octets as the equivalent list of pairs, and an
:class:`~pcapkit.corekit.multidict.OrderedMultiDict` keeps its repeated
identifiers.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: ``HEADER_TABLE_SIZE = 2`` as a ``SETTINGS`` frame on stream 0.
ONE_PAIR = bytes.fromhex('000006040000000000000100000002')


class TestHTTPv2SettingsPlainDict(unittest.TestCase):
    """Pin ``SETTINGS`` construction from each accepted mapping type."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def build(self, settings: 'object') -> 'bytes':
        """Build a ``SETTINGS`` frame from ``settings``."""
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP

        return bytes(HTTP(type=Frame.SETTINGS, frame={'settings': settings}))

    def test_plain_dict_builds_the_list_octets(self) -> None:
        from pcapkit.const.http.setting import Setting

        self.assertEqual(self.build([(Setting.HEADER_TABLE_SIZE, 2)]), ONE_PAIR)
        for name, settings in (('int key', {1: 2}),
                               ('enum key', {Setting.HEADER_TABLE_SIZE: 2})):
            with self.subTest(settings=name):
                self.assertEqual(self.build(settings), ONE_PAIR)

    def test_plain_dict_keeps_insertion_order(self) -> None:
        settings = {3: 100, 1: 4096, 4: 65535}
        self.assertEqual(self.build(settings), self.build(list(settings.items())))

    def test_plain_dict_frame_parses_back(self) -> None:
        import io

        from pcapkit.protocols.application.httpv2 import HTTP

        raw = self.build({1: 4096, 3: 100})
        info = HTTP(io.BytesIO(raw), len(raw)).info
        self.assertEqual([(int(k), v) for k, v in info.settings.items(multi=True)],
                         [(1, 4096), (3, 100)])

    def test_ordered_multidict_keeps_repeated_identifiers(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict

        pairs = [(1, 4096), (1, 2)]
        self.assertEqual(self.build(OrderedMultiDict(pairs)), self.build(pairs))

    def test_empty_plain_dict_builds_an_empty_frame(self) -> None:
        self.assertEqual(self.build({}), bytes.fromhex('000000040000000000'))


if __name__ == '__main__':
    unittest.main()
