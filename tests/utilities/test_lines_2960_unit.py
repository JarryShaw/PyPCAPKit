# -*- coding: utf-8 -*-
"""The line reader text protocols share reads lines, replies and blocks on octets alone (#2960).

:mod:`pcapkit.utilities.lines` is exercised here without SMTP: FTP's multi-line
replies (RFC 959, section 4.2) and a POP3 multi-line response (RFC 1939,
section 3), the shapes the protocols after SMTP read with it.

"""

import unittest

#: Test tier (#1958): ``bytes`` edge cases of the shared reader.
__tier__ = 'ALL'


class SplitLinesTests(unittest.TestCase):
    """:func:`~pcapkit.utilities.lines.split_lines` and its inverse."""

    def test_whole_lines(self) -> None:
        from pcapkit.utilities.lines import join_lines, split_lines

        for data, lines in ((b'QUIT\r\n', (b'QUIT',)),
                            (b'\r\n', (b'',)),
                            (b'a\r\n\r\nb\r\n', (b'a', b'', b'b')),
                            (b'a\rb\nc\r\n', (b'a\rb\nc',)),
                            (b'a\r\r\n\nb\r\n', (b'a\r', b'\nb'))):
            with self.subTest(data=data):
                self.assertEqual(split_lines(data), lines)
                self.assertEqual(join_lines(lines), data)

    def test_not_whole_lines(self) -> None:
        from pcapkit.utilities.lines import split_lines

        for data in (b'', b'QUIT', b'QUIT\r', b'a\r\nb', b'a\n'):
            with self.subTest(data=data):
                self.assertIsNone(split_lines(data))


class ClosesReplyTests(unittest.TestCase):
    """:func:`~pcapkit.utilities.lines.closes_reply`, as FTP and SMTP read a reply."""

    def test_free_text_lines(self) -> None:
        """RFC 959, section 4.2: the lines between are free text, which may even open
        with the code and a hyphen, and only ``code SP`` closes."""
        from pcapkit.utilities.lines import closes_reply

        for lines in ((b'123 last',), (b'free text', b'123-not yet', b'123 last'), (b'123 ',)):
            with self.subTest(lines=lines):
                self.assertTrue(closes_reply(b'123', lines, marked=False))
        for lines in ((), (b'123',), (b'free text',), (b'123 early', b'123 last'),
                      (b'free\ntext', b'123 last'), ('123 last',)):
            with self.subTest(lines=lines):
                self.assertFalse(closes_reply(b'123', lines, marked=False))

    def test_marked_lines(self) -> None:
        """RFC 5321, section 4.2.1: every line repeats the code, and the closing line
        may be the code alone."""
        from pcapkit.utilities.lines import closes_reply

        for lines in ((b'250 last',), (b'250-a', b'250-', b'250 last'), (b'250-a', b'250')):
            with self.subTest(lines=lines):
                self.assertTrue(closes_reply(b'250', lines, marked=True))
        for lines in ((), (b'250-a',), (b'free text', b'250 last'), (b'250-a', b'251 last'),
                      (b'250 early', b'250 last'), (b'250-a\n', b'250 last')):
            with self.subTest(lines=lines):
                self.assertFalse(closes_reply(b'250', lines, marked=True))


class BlockTests(unittest.TestCase):
    """:func:`~pcapkit.utilities.lines.block_end`, :func:`~pcapkit.utilities.lines.stuff`
    and :func:`~pcapkit.utilities.lines.unstuff`."""

    def test_pop3_multi_line_response(self) -> None:
        """RFC 1939, section 3: a status line, then byte-stuffed lines, then a lone
        period."""
        from pcapkit.utilities.lines import block_end, split_lines, unstuff

        lines = split_lines(b'+OK 120 octets\r\nSubject: hi\r\n\r\n..hidden\r\n.\r\n')
        assert lines is not None
        end = block_end(lines[1:])

        self.assertEqual(end, 3)
        self.assertEqual(tuple(map(unstuff, lines[1:1 + end])), (b'Subject: hi', b'', b'.hidden'))

    def test_block_end(self) -> None:
        from pcapkit.utilities.lines import block_end

        for lines, end in (((b'.',), 0), ((b'a', b'.', b'b', b'.'), 1), ((), None),
                           ((b'..', b'. ', b' .'), None)):
            with self.subTest(lines=lines):
                self.assertEqual(block_end(lines), end)

    def test_stuffing(self) -> None:
        """RFC 5321, section 4.5.2, both ways; stuffing then unstuffing gives back any line."""
        from pcapkit.utilities.lines import stuff, unstuff

        for line, sent in ((b'', b''), (b'text', b'text'), (b'.', b'..'), (b'.text', b'..text'),
                           (b'..', b'...')):
            with self.subTest(line=line):
                self.assertEqual(stuff(line), sent)
                self.assertEqual(unstuff(sent), line)

    def test_unstuff_a_line_sent_unstuffed(self) -> None:
        """A period opening a line that holds more is dropped, whether or not the
        sender stuffed it, and a lone period is the end of the block, kept as is."""
        from pcapkit.utilities.lines import unstuff

        self.assertEqual(unstuff(b'.text'), b'text')
        self.assertEqual(unstuff(b'.'), b'.')


class DecodeTextTests(unittest.TestCase):
    """:func:`~pcapkit.utilities.lines.decode_text` keeps the octets for a rebuild."""

    def test_round_trip(self) -> None:
        from pcapkit.utilities.lines import decode_text

        # NOTE: the octets after the UTF-8 ones are detected as charsets that decode them
        # back, fail to decode them, or decode them to text that does not encode back.
        for text in (b'', b'ascii text', 'café'.encode(), b'\xe9t\xe9', b'\xff\xfe\x00broken',
                     b'\xa1\xa1\xa1', b'\x1b$B', b'\x81'):
            with self.subTest(text=text):
                value, charset = decode_text(text)
                self.assertEqual(value.encode(charset or 'utf-8'), text)

    def test_utf8_needs_no_charset(self) -> None:
        from pcapkit.utilities.lines import decode_text

        self.assertEqual(decode_text('café'.encode()), ('café', None))
        self.assertEqual(decode_text(b'plain'), ('plain', None))


if __name__ == '__main__':
    unittest.main()
