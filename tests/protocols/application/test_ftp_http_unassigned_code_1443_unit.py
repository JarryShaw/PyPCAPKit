# -*- coding: utf-8 -*-
"""FTP reply codes and HTTP status codes parse and rebuild for every three digits.

GitHub issue #1443: :class:`~pcapkit.const.ftp.return_code.ReturnCode` resolved
only 100 to 659 and :class:`~pcapkit.const.http.status_code.StatusCode` only
100 to 599, so a reply such as ``999 hi`` or a status line such as
``HTTP/1.1 999 X`` raised :exc:`~pcapkit.utilities.exceptions.EnumValueError`
and could not be parsed at all. Both wire fields are three digits, so every
value from 000 to 999 now resolves, to ``Unassigned`` inside the registry's
range and ``Unknown`` outside it, and the packet rebuilds byte for byte.
``make()`` also writes the code as three digits, so ``099`` keeps its zero.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they match the live
:mod:`pcapkit` import.

"""

import unittest

from tests._support import reimport_once_per_class


class TestFTPReturnCodeEveryValue(unittest.TestCase):
    """Pin FTP replies across the whole three-digit range."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_three_digit_reply_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        for code in range(1000):
            raw = b'%03d hi\r\n' % code
            with self.subTest(code=raw):
                parsed = FTP(raw, len(raw))
                self.assertEqual(int(parsed.info.code), code)
                self.assertEqual(FTP.from_data(parsed.info).data, raw)

    def test_multi_line_unassigned_reply_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        for raw in (b'777-first\r\nmiddle\r\n777 last\r\n', b'099-a\r\n099 b\r\n'):
            with self.subTest(raw=raw):
                parsed = FTP(raw, len(raw))
                self.assertEqual(FTP.from_data(parsed.info).data, raw)

    def test_unassigned_and_unknown_pseudo_members(self) -> None:
        from pcapkit.const.ftp.return_code import ReturnCode

        cases = ((199, 'Unassigned', 1, 9), (659, 'Unassigned', 6, 5),
                 (777, 'Unknown', 7, 7), (99, 'Unknown', 0, 9), (0, 'Unknown', 0, 0))
        for value, name, kind, group in cases:
            with self.subTest(value=value):
                member = ReturnCode.get(value)
                self.assertEqual(int(member), value)
                self.assertEqual(member.name, name)
                self.assertEqual(int(member.kind), kind)
                self.assertEqual(int(member.group), group)
                self.assertNotIn(name, ReturnCode.__members__)
                self.assertEqual(str(member), '[%d] None' % value)

    def test_value_outside_three_digits_still_raises(self) -> None:
        from pcapkit.const.ftp.return_code import ReturnCode

        for value in (-1, 1000):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, r'%d is not a valid ReturnCode' % value):
                    ReturnCode.get(value)

    def test_make_keeps_the_leading_zero(self) -> None:
        from pcapkit.protocols.application.ftp import FTP

        proto = FTP(code=99, args='x')
        self.assertEqual(proto.data, b'099 x\r\n')
        self.assertEqual(FTP(proto.data, len(proto.data)).data, b'099 x\r\n')


class TestHTTPStatusCodeEveryValue(unittest.TestCase):
    """Pin HTTP/1.1 status lines across the whole three-digit range."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_three_digit_status_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTP

        for code in range(1000):
            raw = b'HTTP/1.1 %03d X\r\n\r\n' % code
            with self.subTest(code=code):
                parsed = HTTP(raw, len(raw))
                self.assertEqual(int(parsed.info.receipt.status), code)
                self.assertEqual(HTTP.from_data(parsed.info).data, raw)

    def test_unassigned_and_unknown_pseudo_members(self) -> None:
        from pcapkit.const.http.status_code import StatusCode

        for value, name in ((999, 'Unknown'), (600, 'Unknown'), (99, 'Unknown'),
                            (0, 'Unknown'), (599, 'Unassigned'), (105, 'Unassigned')):
            with self.subTest(value=value):
                member = StatusCode.get(value)
                self.assertEqual(int(member), value)
                self.assertEqual(member.name, name)
                self.assertEqual(member.message, name)
                self.assertNotIn(name, StatusCode.__members__)

    def test_value_outside_three_digits_still_raises(self) -> None:
        from pcapkit.const.http.status_code import StatusCode

        for value in (-1, 1000):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, r'%d is not a valid StatusCode' % value):
                    StatusCode.get(value)

    def test_make_keeps_the_leading_zero(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTP

        proto = HTTP(status=99, message='X', http_version='1.1')
        self.assertEqual(proto.data, b'HTTP/1.1 099 X\r\n\r\n')
        reparsed = HTTP(proto.data, len(proto.data))
        self.assertEqual(int(reparsed.info.receipt.status), 99)


if __name__ == '__main__':
    unittest.main()
