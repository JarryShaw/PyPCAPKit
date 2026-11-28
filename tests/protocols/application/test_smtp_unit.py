# -*- coding: utf-8 -*-
"""SMTP over TCP ports 25 and 587 (#2960).

A segment reads as a command (RFC 5321, section 4.1.1), a reply (section 4.2), or
mail data ending with its end of mail data indication (section 4.1.1.4), and
rebuilds byte for byte; port 587 is Message Submission (RFC 6409, section 3.1).

"""
from __future__ import annotations

import struct
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: Pipelined commands (RFC 2920), which one segment reads as no command.
PIPELINED = (b'MAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\n', b'RSET\r\nQUIT\r\n')
#: Several replies in one segment, which reads as no reply.
REPLIES = (b'250 a\r\n251 b\r\n', b'250 a\r\n250 b\r\n', b'250-a\r\n250 b\r\n250 c\r\n')


class SMTPTestCase(unittest.TestCase):
    """Shared assertions."""

    def assertRoundTrip(self, raw: 'bytes') -> 'Any':  # pylint: disable=invalid-name
        """Parse ``raw``, check it rebuilds from its data model, and return the layer."""
        from pcapkit.protocols.application.smtp.protocol import SMTP

        smtp = SMTP(raw)
        self.assertEqual(SMTP.from_data(smtp.info).data, raw)
        self.assertEqual(SMTP.from_data(smtp.info.to_dict()).data, raw)
        return smtp

    def assertMakes(self, raw: 'bytes', **fields: 'Any') -> 'None':  # pylint: disable=invalid-name
        """Check ``fields`` make ``raw``, which parses and rebuilds as made."""
        from pcapkit.protocols.application.smtp.protocol import SMTP

        self.assertEqual(SMTP.from_fields(**fields).data, raw)
        self.assertRoundTrip(raw)


class SMTPCommandTests(SMTPTestCase):
    """A command line, a verb and its argument clause (RFC 5321, section 4.1.1)."""

    def test_commands(self) -> None:
        from pcapkit.const.smtp.command import Command
        from pcapkit.protocols.application.smtp.protocol import Type

        for raw, cmmd, args in ((b'EHLO client.example\r\n', Command.EHLO, 'client.example'),
                                (b'mail FROM:<a@b.example> SIZE=10\r\n', Command.MAIL, 'FROM:<a@b.example> SIZE=10'),
                                (b'DATA\r\n', Command.DATA, None),
                                (b'NOOP \r\n', Command.NOOP, ''),
                                (b'RSET  \r\n', Command.RSET, ' ')):
            with self.subTest(raw=raw):
                info = self.assertRoundTrip(raw).info
                self.assertEqual((info.type, info.cmmd, info.args, info.charset), (Type.COMMAND, cmmd, args, None))
                self.assertEqual(info.raw_cmmd, raw.split(b'\r\n')[0].split(b' ')[0])

    def test_a_verb_an_extension_adds(self) -> None:
        """STARTTLS is RFC 3207's, so it resolves to no member but keeps its case."""
        from pcapkit.const.smtp.command import Command

        info = self.assertRoundTrip(b'StartTLS\r\n').info
        self.assertEqual((info.cmmd.name, str(info.cmmd)), ('STARTTLS', 'StartTLS'))
        self.assertNotIn('STARTTLS', Command.__members__)

    def test_octets_that_are_not_utf8(self) -> None:
        info = self.assertRoundTrip(b'HELO \xe9t\xe9\r\n').info
        self.assertIsNotNone(info.charset)

    def test_make(self) -> None:
        from pcapkit.const.smtp.command import Command

        self.assertMakes(b'QUIT\r\n', cmmd=Command.QUIT)
        self.assertMakes(b'rcpt TO:<b@c.example>\r\n', cmmd='RCPT', raw_cmmd=b'rcpt', args='TO:<b@c.example>')
        self.assertMakes(b'VRFY \xe9\r\n', cmmd='VRFY', args='é', charset='latin-1')
        self.assertMakes(b'EXPN \xff\r\n', cmmd='EXPN', args=b'\xff')
        # A raw verb that is not the verb in another case is ignored.
        self.assertMakes(b'HELP\r\n', cmmd='HELP', raw_cmmd=b'QUIT')

    def test_make_refuses_what_would_not_read_back(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP
        from pcapkit.utilities.exceptions import ProtocolError

        for fields in ({'cmmd': 42}, {'cmmd': ''}, {'cmmd': 'MAIL FROM'}, {'cmmd': 'X-1'},
                       {'cmmd': 'HELO', 'args': 'a\r\nQUIT'}, {'cmmd': 'HELO', 'args': 42},
                       {'cmmd': 'HELO', 'args': 'é', 'charset': 'ascii'},
                       {'cmmd': 'HELO', 'args': 'x', 'charset': 'no-such-charset'}):
            with self.subTest(fields=fields), self.assertRaises(ProtocolError):
                SMTP.from_fields(**fields)


class SMTPReplyTests(SMTPTestCase):
    """A reply, its code on every line (RFC 5321, section 4.2)."""

    def test_replies(self) -> None:
        from pcapkit.const.smtp.reply_code import ReplyCode
        from pcapkit.protocols.application.smtp.protocol import Type

        for raw, code, text, more in (
                (b'220 mx.example ESMTP ready\r\n', ReplyCode.CODE_220, ('mx.example ESMTP ready',), False),
                (b'250-mx.example\r\n250-PIPELINING\r\n250 SIZE 1000\r\n', ReplyCode.CODE_250,
                 ('mx.example', 'PIPELINING', 'SIZE 1000'), False),
                (b'250-a\r\n250-\r\n250 \r\n', ReplyCode.CODE_250, ('a', '', ''), False),
                (b'250\r\n', ReplyCode.CODE_250, (None,), False),
                (b'250-a\r\n250\r\n', ReplyCode.CODE_250, ('a', None), False),
                (b'354 Start mail input; end with <CRLF>.<CRLF>\r\n', ReplyCode.CODE_354,
                 ('Start mail input; end with <CRLF>.<CRLF>',), False),
                (b'530 5.7.0 Authentication required\r\n', ReplyCode.CODE_530,
                 ('5.7.0 Authentication required',), False),
                (b'250-a\r\n250-b\r\n', ReplyCode.CODE_250, ('a', 'b'), True)):
            with self.subTest(raw=raw):
                info = self.assertRoundTrip(raw).info
                self.assertEqual((info.type, info.code, info.text, info.more, info.charset),
                                 (Type.REPLY, code, text, more, None))

    def test_an_unlisted_code(self) -> None:
        """RFC 5321, section 4.2.1: a client must take a code it does not know."""
        info = self.assertRoundTrip(b'259 later\r\n').info
        self.assertEqual((int(info.code), info.code.name), (259, 'Unassigned'))

    def test_text_that_is_not_utf8(self) -> None:
        # NOTE: the last is read as a charset whose byte order mark each line would repeat.
        for raw in (b'250-\xe9t\xe9\r\n250 ok\r\n', b'250-\xff\xfe\x00\r\n250 \xa1\r\n',
                    b'250-\xef\xbb\xbfabc\r\n250 def\r\n'):
            with self.subTest(raw=raw):
                self.assertIsNotNone(self.assertRoundTrip(raw).info.charset)

    def test_make(self) -> None:
        from pcapkit.const.smtp.reply_code import ReplyCode

        self.assertMakes(b'221 bye\r\n', code=ReplyCode.CODE_221, text='bye')
        self.assertMakes(b'250\r\n', code=250)
        self.assertMakes(b'250 \r\n', code=250, text='')
        self.assertMakes(b'250-a\r\n250 b\r\n', code=250, text=['a', b'b'])
        self.assertMakes(b'250-a\r\n250\r\n', code=250, text=('a', None))
        self.assertMakes(b'250-a\r\n', code=250, text='a', more=True)
        self.assertMakes(b'550 \xe9\r\n', code=550, text='é', charset='latin-1')

    def test_make_refuses_what_would_not_read_back(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP
        from pcapkit.utilities.exceptions import ProtocolError

        for fields in ({'code': True}, {'code': '250'}, {'code': 199}, {'code': 260}, {'code': 2500},
                       {'code': 250, 'text': []}, {'code': 250, 'text': [None, 'a']},
                       {'code': 250, 'text': None, 'more': True}, {'code': 250, 'text': 'a\nb'},
                       {'code': 250, 'text': [42]}, {'code': 250, 'text': ['a', 3.5]},
                       {'code': 250, 'text': 5}):
            with self.subTest(fields=fields), self.assertRaises(ProtocolError):
                SMTP.from_fields(**fields)


class SMTPMailDataTests(SMTPTestCase):
    """Mail data, which only its end of mail data indication marks (RFC 5321, section 4.1.1.4)."""

    def test_mail_data(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import Type

        for raw, lines, text in ((b'Subject: hi\r\n\r\n..dot\r\nbody\r\n.\r\n',
                                  (b'Subject: hi', b'', b'..dot', b'body'), (b'Subject: hi', b'', b'.dot', b'body')),
                                 (b'.\r\n', (), ()),
                                 # RFC 5321, section 4.5.2: the receiver drops a period a sender failed to double.
                                 (b'.unstuffed\r\n.\r\n', (b'.unstuffed',), (b'unstuffed',)),
                                 (b'250 apples\r\n.\r\n', (b'250 apples',), (b'250 apples',))):
            with self.subTest(raw=raw):
                info = self.assertRoundTrip(raw).info
                self.assertEqual((info.type, info.lines, info.text), (Type.MAIL_DATA, lines, text))

    def test_make(self) -> None:
        self.assertMakes(b'a\r\n..b\r\n.\r\n', lines=[b'a', bytearray(b'..b')])
        self.assertMakes(b'.\r\n', lines=())
        self.assertMakes(b'a\rb\n\r\n.\r\n', lines=[b'a\rb\n'])

    def test_make_refuses_what_would_not_read_back(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP
        from pcapkit.utilities.exceptions import ProtocolError

        for fields in ({'lines': [b'.']}, {'lines': [b'a\r\nb']}, {'lines': ['text']},
                       {'lines': [b'a'], 'charset': 'utf-8'}):
            with self.subTest(fields=fields), self.assertRaises(ProtocolError):
                SMTP.from_fields(**fields)


class SMTPRefusalTests(SMTPTestCase):
    """What no command, reply or mail data reads as."""

    def test_refused(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP
        from pcapkit.utilities.exceptions import ProtocolError

        for raw in (b'EHLO client', b'dXNlcm5hbWU=\r\n', b'Hello there\r\nHow are you\r\n',
                    b'250-a\r\n251 b\r\n', b'199 old\r\n', b'260 x\r\n', b'a\r\n.\r\nQUIT\r\n',
                    b'250-a\rb\r\n250 c\r\n', *PIPELINED, *REPLIES):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                SMTP(raw)

    def test_make_takes_one_kind(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP
        from pcapkit.utilities.exceptions import ProtocolError

        for fields in ({}, {'cmmd': 'QUIT', 'code': 221}, {'cmmd': 'QUIT', 'text': 'x'},
                       {'cmmd': 'QUIT', 'more': True}, {'code': 221, 'args': 'x'},
                       {'code': 221, 'lines': []}, {'lines': [], 'more': True}):
            with self.subTest(fields=fields), self.assertRaises(ProtocolError):
                SMTP.from_fields(**fields)

    def test_from_data_without_a_type(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            SMTP.from_data({'args': 'x'})


class SMTPDispatchTests(SMTPTestCase):
    """TCP ports 25 and 587 (RFC 6409, section 3.1) dispatch to SMTP."""

    @staticmethod
    def _segment(payload: 'bytes', dport: 'int') -> 'bytes':
        return struct.pack('!HHIIBBHHH', 40000, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + payload

    def test_ports(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for port in (25, 587):
            for payload, chain in ((b'EHLO client.example\r\n', 'TCP:SMTP'),
                                   (b'250-mx\r\n250 AUTH PLAIN\r\n', 'TCP:SMTP'),
                                   (b'From: a\r\n\r\nhi\r\n.\r\n', 'TCP:SMTP'),
                                   (b'\x16\x03\x01\x00\x05hello', 'TCP:Raw')):
                with self.subTest(port=port, payload=payload):
                    tcp = TCP(self._segment(payload, port))
                    self.assertEqual(str(tcp.protochain), chain)
                    self.assertEqual(TCP.from_data(tcp.info).data, self._segment(payload, port))

    def test_refused_segment_keeps_the_error(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for payload in (b'Hello\r\nthere\r\n', *PIPELINED, *REPLIES):
            with self.subTest(payload=payload):
                tcp = TCP(self._segment(payload, 25))
                self.assertEqual(str(tcp.protochain), 'TCP:Raw')
                self.assertIn('SMTP', str(tcp.payload.info.error))


class SMTPProtocolTests(unittest.TestCase):
    """The class's own members, and its enumerations."""

    def test_members(self) -> None:
        from pcapkit.protocols.application.smtp.protocol import SMTP, Type
        from pcapkit.utilities.exceptions import UnsupportedCall

        smtp = SMTP(b'QUIT\r\n')
        self.assertEqual((smtp.name, smtp.layer, SMTP.id(), SMTP.__index__()),
                         ('Simple Mail Transfer Protocol', 'Application', ('SMTP',), 25))
        with self.assertRaises(UnsupportedCall):
            _ = smtp.length
        self.assertEqual([(member.name, member.value) for member in Type],
                         [('COMMAND', 'command'), ('REPLY', 'reply'), ('MAIL_DATA', 'mail_data')])

    def test_command_lookup_ignores_case(self) -> None:
        """RFC 5321, section 2.4: command verbs are not case-sensitive."""
        from pcapkit.const.smtp.command import Command
        from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError

        self.assertIs(Command.get('ehlo'), Command.EHLO)
        self.assertIs(Command('Quit'), Command.QUIT)
        self.assertIs(Command.get(b'x', 'DATA'), Command.DATA)
        with self.assertRaises(EnumKeyError):
            Command.get('starttls')
        with self.assertRaises(EnumValueError):
            Command.get(1)
        with self.assertRaises(ValueError):
            Command(1)
        self.assertIsNone(Command._validate_value('NOOP'))  # pylint: disable=protected-access

    def test_reply_code_grammar(self) -> None:
        """RFC 5321, section 4.2: a first digit of 2 to 5 and a second of 0 to 5."""
        from pcapkit.const.smtp.reply_code import ReplyCode
        from pcapkit.utilities.exceptions import EnumValueError

        self.assertIs(ReplyCode.get(250), ReplyCode.CODE_250)
        self.assertEqual(ReplyCode(559).name, 'Unassigned')
        for value in (199, 260, 600, '250'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ReplyCode(value)
        with self.assertRaises(EnumValueError):
            ReplyCode.get(199)


if __name__ == '__main__':
    unittest.main()
