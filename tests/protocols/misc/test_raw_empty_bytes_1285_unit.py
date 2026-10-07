# -*- coding: utf-8 -*-
"""``Raw`` accepts an empty byte string on the parsing path too.

GitHub issue #1285: ``Raw(b"")`` left the length for
:func:`~pcapkit.utilities.decorators.prepare` to derive, and a derived zero
is the end-of-stream signal, so it raised
:exc:`~pcapkit.utilities.exceptions.StreamEOFError` while ``Raw(packet=b"")``
worked.

Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class


class TestRawEmptyBytes(unittest.TestCase):
    """Pin that both construction forms accept an empty payload."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_bytes_parse(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for source in (b'', io.BytesIO(b'')):
            with self.subTest(source=type(source).__name__):
                raw = Raw(source)
                self.assertEqual(raw.data, b'')
                self.assertIsNone(raw.info.protocol)
                self.assertEqual(Raw.from_data(raw.info).data, b'')

    def test_both_forms_agree(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for payload in (b'', b'abc'):
            with self.subTest(payload=payload):
                self.assertEqual(Raw(payload).data, Raw(packet=payload).data)


if __name__ == '__main__':
    unittest.main()
