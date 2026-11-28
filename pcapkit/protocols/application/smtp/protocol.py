# -*- coding: utf-8 -*-
"""SMTP - Simple Mail Transfer Protocol
==========================================

.. module:: pcapkit.protocols.application.smtp.protocol

:mod:`pcapkit.protocols.application.smtp.protocol` holds
:class:`~pcapkit.protocols.application.smtp.protocol.SMTP`, the extractor for the
Simple Mail Transfer Protocol (SMTP) [:rfc:`5321`] at TCP port 25, and for
Message Submission [:rfc:`6409`], the same protocol at TCP port 587
(:rfc:`6409#section-3.1`).

.. versionadded:: 1.10.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.smtp.command import Command as Enum_Command
from pcapkit.const.smtp.reply_code import ReplyCode as Enum_ReplyCode
from pcapkit.corekit.enum import EnumLookup
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.application.smtp.const import SMTP_COMMAND, SMTP_REPLY
from pcapkit.protocols.application.smtp.data import SMTP as Data_SMTP
from pcapkit.protocols.application.smtp.data import Command as Data_Command
from pcapkit.protocols.application.smtp.data import MailData as Data_MailData
from pcapkit.protocols.application.smtp.data import Reply as Data_Reply
from pcapkit.protocols.application.smtp.schema import SMTP as Schema_SMTP
from pcapkit.utilities.compat import StrEnum, auto
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.lines import (block_end, closes_reply, decode_text, join_lines, split_lines,
                                     unstuff)

if TYPE_CHECKING:
    from typing import Any, Iterable, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.const.reg.apptype.tcp import TCP as AppType_TCP

__all__ = ['SMTP']

#: The TCP port registry :meth:`SMTP.__index__` reads its port from, resolved
#: there rather than imported, as ``import pcapkit`` leaves it unloaded
#: (:issue:`1538`), so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_TCP: 'ModuleDescriptor[AppType_TCP]' = ModuleDescriptor('pcapkit.const.reg.apptype.tcp', 'TCP')


class Type(EnumLookup, StrEnum):
    """SMTP packet type.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup`, the lookup contract
    shared by every non-registry enumeration (:issue:`877`).

    """

    #: Command packet.
    COMMAND = auto()
    #: Reply packet.
    REPLY = auto()
    #: Mail data packet.
    MAIL_DATA = auto()


class SMTP(Application[Data_SMTP, Schema_SMTP],
           data=Data_SMTP, schema=Schema_SMTP):
    """This class implements Simple Mail Transfer Protocol.

    What a client sends after a ``354`` reply is mail data, but one segment
    carries no session state to tell it from commands. So a segment reads as
    the first of these that it is, whole:

    * a command, one line of a verb and its argument clause
      (:rfc:`5321#section-4.1.1`);
    * a reply, lines sharing one code, each before the last followed by a
      hyphen (:rfc:`5321#section-4.2`); if the last is too, the reply goes on
      in a later segment;
    * mail data, lines whose last, and only the last, holds a single period:
      the end of mail data indication (:rfc:`5321#section-4.1.1.4`), the one
      mark in the octets that they follow a ``354``.

    Mail data in the segments before the one that ends it is therefore refused,
    as are octets that are not whole lines, and a line of it alone in a segment
    reads as a command if it can. Pipelined commands (:rfc:`2920`) and several
    replies in one segment are refused too, so on a TCP port each such segment
    is kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

    Text is decoded with the charset `chardet`_ detects, which can misread a
    short run of non-ASCII octets; the octets still rebuild exactly, as FTP's do.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Simple Mail Transfer Protocol"]':
        """Name of current protocol."""
        return 'Simple Mail Transfer Protocol'

    @property
    def length(self) -> 'NoReturn':
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_SMTP':  # pylint: disable=unused-argument
        """Read Simple Mail Transfer Protocol (SMTP).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is no command, reply or mail data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        lines = split_lines(schema.data)
        if lines is None:
            raise ProtocolError('SMTP: invalid packet format: not whole lines')
        smtp = self._read_command(lines)  # type: Optional[Data_SMTP]
        if smtp is None:
            smtp = self._read_reply(lines)
        if smtp is None:
            smtp = self._read_mail_data(lines)
        if smtp is None:
            raise ProtocolError('SMTP: invalid packet format: no command, reply or mail data')
        return smtp

    def make(self, *,
             cmmd: 'Optional[Enum_Command | str]' = None,
             args: 'Optional[str | bytes | bytearray]' = None,
             raw_cmmd: 'Optional[bytes]' = None,
             code: 'Optional[Enum_ReplyCode | int]' = None,
             text: 'Optional[str | bytes | bytearray | Iterable[Optional[str | bytes | bytearray]]]' = None,
             more: 'bool' = False,
             lines: 'Optional[Iterable[bytes | bytearray]]' = None,
             charset: 'Optional[str]' = None,
             **kwargs: 'Any') -> 'Schema_SMTP':
        """Make (construct) packet data.

        A command takes ``cmmd``, ``args`` and ``raw_cmmd``, a reply ``code``,
        ``text`` and ``more``, both ``charset``, and mail data ``lines`` alone.
        Each line is terminated with CRLF, and each is checked to read back as
        made.

        Args:
            cmmd: Command verb, a :class:`str` (a
                :class:`~pcapkit.const.smtp.command.Command` member is one).
            args: Argument clause, written after a single SP; :obj:`None`
                writes neither.
            raw_cmmd: Verb as received, written in place of ``cmmd`` when the
                two differ only in case (:rfc:`5321#section-2.4`).
            code: Reply code, an :class:`int` (a
                :class:`~pcapkit.const.smtp.reply_code.ReplyCode` member is one).
            text: Text of a one-line reply, or of each line in order. A
                :obj:`None` last line is the code alone, with no SP.
            more: Whether the last line carries a hyphen, so the reply goes on
                in a later segment.
            lines: Lines of mail data as sent, dot-stuffed (see
                :func:`~pcapkit.utilities.lines.stuff`); the line ending the
                mail data is written after them.
            charset: Encoding for :obj:`str` arguments and text, **UTF-8** if not
                given; :class:`bytes` are written verbatim.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If not exactly one of ``cmmd``, ``code`` and ``lines``
                is given, or with another's keywords, or if the octets made
                would not read back as made.

        """
        if cmmd is not None and code is None and lines is None and text is None and not more:
            data = self._make_command(cmmd, args, raw_cmmd, charset)
        elif code is not None and cmmd is None and lines is None and args is None and raw_cmmd is None:
            data = self._make_reply(code, text, more, charset)
        elif lines is not None and cmmd is None and code is None and args is None and raw_cmmd is None \
                and text is None and not more and charset is None:
            data = self._make_mail_data(lines)
        else:
            raise ProtocolError('SMTP: invalid packet type: give one of cmmd, code and lines, '
                                'with its own keywords alone')
        return Schema_SMTP(data=data)

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: TCP port 25, the port of
            :attr:`TCP.smtp <pcapkit.const.reg.apptype.tcp.TCP.smtp>` as an
            :class:`int`, which
            :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>`
            dispatches here, as it does port 587
            (:ref:`registry-protocol-index`).

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        """
        return int(_TCP.klass.smtp)  # type: ignore[call-overload]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_SMTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        kind = getattr(data, 'type', None)
        if kind == Type.COMMAND:
            return {
                'cmmd': getattr(data, 'cmmd', None),
                'args': getattr(data, 'args', None),
                'raw_cmmd': getattr(data, 'raw_cmmd', None),
                'charset': getattr(data, 'charset', None),
            }
        if kind == Type.REPLY:
            return {
                'code': getattr(data, 'code', None),
                'text': getattr(data, 'text', None),
                'more': getattr(data, 'more', False),
                'charset': getattr(data, 'charset', None),
            }
        return {
            'lines': getattr(data, 'lines', None),
        }

    def _read_command(self, lines: 'tuple[bytes, ...]') -> 'Optional[Data_Command]':
        """Read ``lines`` as a command, one line of a verb and its argument clause.

        Args:
            lines: Lines of the segment, CRLF excluded.

        Returns:
            The command, or :obj:`None` if ``lines`` are no command.

        """
        if len(lines) != 1 or (match := SMTP_COMMAND.match(lines[0])) is None:
            return None
        raw_cmmd = match.group('cmmd')
        args = match.group('args')
        args_val, charset = (None, None) if args is None else decode_text(args)
        return Data_Command(
            type=Type.COMMAND,
            cmmd=Enum_Command(raw_cmmd.decode()),
            args=args_val,
            charset=charset,
            raw_cmmd=raw_cmmd,
        )

    def _make_command(self, cmmd: 'Enum_Command | str', args: 'Optional[str | bytes | bytearray]',
                      raw_cmmd: 'Optional[bytes]', charset: 'Optional[str]') -> 'bytes':
        """Make a command line.

        Args:
            cmmd: Command verb.
            args: Argument clause, :obj:`None` for none.
            raw_cmmd: Verb as received.
            charset: Encoding for a :obj:`str` ``args``.

        Returns:
            The command line, CRLF included.

        Raises:
            ProtocolError: If ``cmmd`` is not a :class:`str` of letters, or the
                line would not read back as made.

        """
        if not isinstance(cmmd, str):
            raise ProtocolError(f'SMTP: invalid command: must be a str, not {cmmd!r}')
        verb = cmmd.encode('utf-8', 'replace')
        if isinstance(raw_cmmd, bytes) and raw_cmmd.upper() == verb.upper():
            verb = raw_cmmd

        line = verb if args is None else verb + b' ' + self._make_text(args, charset)
        if (match := SMTP_COMMAND.match(line)) is None or match.group('cmmd') != verb:
            raise ProtocolError(f'SMTP: invalid command line: {line!r}')
        return join_lines((line,))

    def _read_reply(self, lines: 'tuple[bytes, ...]') -> 'Optional[Data_Reply]':
        """Read ``lines`` as a reply, or the start of one that goes on.

        Args:
            lines: Lines of the segment, CRLF excluded.

        Returns:
            The reply, or :obj:`None` if ``lines`` are no reply.

        """
        matches = tuple(SMTP_REPLY.match(line) for line in lines)
        if not all(matches):
            return None
        code = matches[0].group('code')  # type: ignore[union-attr]
        if any(match.group('code') != code for match in matches):  # type: ignore[union-attr]
            return None

        more = all(match.group('sep') == b'-' for match in matches)  # type: ignore[union-attr]
        if not (more or len(lines) == 1 or matches[0].group('sep') == b'-'  # type: ignore[union-attr]
                and closes_reply(code, lines[1:], marked=True)):
            return None

        texts = tuple(match.group('text') for match in matches)  # type: ignore[union-attr]
        closing = () if texts[-1] is not None else (None,)
        values, charset = self._decode_lines(texts[:len(texts) - len(closing)])
        return Data_Reply(
            type=Type.REPLY,
            code=Enum_ReplyCode(int(code)),
            text=values + closing,
            more=more,
            charset=charset,
        )

    def _make_reply(self, code: 'Enum_ReplyCode | int',
                    text: 'Optional[str | bytes | bytearray | Iterable[Optional[str | bytes | bytearray]]]',
                    more: 'bool', charset: 'Optional[str]') -> 'bytes':
        """Make the lines of a reply.

        Args:
            code: Reply code.
            text: Text of the line, or of each line.
            more: Whether the last line carries a hyphen.
            charset: Encoding for :obj:`str` text.

        Returns:
            The reply lines, each with its CRLF.

        Raises:
            ProtocolError: If ``code`` is not an :class:`int`, a :obj:`bool`
                included, if ``text`` is neither text nor an iterable of it, if
                there is no line or a :obj:`None` line other than a closing last
                one, or if a line would not read back as made.

        """
        if isinstance(code, bool) or not isinstance(code, int):
            raise ProtocolError(f'SMTP: invalid reply code: must be an int, not {code!r}')
        if text is None or isinstance(text, (str, bytes, bytearray)):
            items = (text,)  # type: tuple[Optional[str | bytes | bytearray], ...]
        else:
            try:
                items = tuple(text)
            except TypeError as error:
                raise ProtocolError(f'SMTP: invalid reply text: must be a str, bytes, bytearray '
                                    f'or an iterable of them, not {text!r}') from error
        if not items or None in items[:-1] or (more and items[-1] is None):
            raise ProtocolError(f'SMTP: invalid reply text: {text!r}')

        digits = b'%d' % code
        reply = []  # type: list[bytes]
        for index, item in enumerate(items, start=1):
            if item is None:
                line = digits
            else:
                line = digits + (b'-' if more or index < len(items) else b' ') + self._make_text(item, charset)
            if (match := SMTP_REPLY.match(line)) is None or match.group('code') != digits:
                raise ProtocolError(f'SMTP: invalid reply line: {line!r}')
            reply.append(line)
        return join_lines(reply)

    def _read_mail_data(self, lines: 'tuple[bytes, ...]') -> 'Optional[Data_MailData]':
        """Read ``lines`` as mail data ending with its end of mail data indication.

        Args:
            lines: Lines of the segment, CRLF excluded.

        Returns:
            The mail data, or :obj:`None` unless the last line, and only the
            last, holds a single period.

        """
        if block_end(lines) != len(lines) - 1:
            return None
        sent = lines[:-1]
        return Data_MailData(
            type=Type.MAIL_DATA,
            lines=sent,
            text=tuple(unstuff(line) for line in sent),
        )

    def _make_mail_data(self, lines: 'Iterable[bytes | bytearray]') -> 'bytes':
        """Make mail data and the line ending it.

        Args:
            lines: Lines of mail data as sent.

        Returns:
            The lines and the line ending them, each with its CRLF.

        Raises:
            ProtocolError: If a line is not :class:`bytes` or :class:`bytearray`,
                holds a CRLF, or holds a single period, which would end the mail
                data early.

        """
        sent = tuple(bytes(line) if isinstance(line, (bytes, bytearray)) else line for line in lines)
        if not all(isinstance(line, bytes) and b'\r\n' not in line for line in sent) \
                or block_end(sent) is not None:
            raise ProtocolError(f'SMTP: invalid mail data lines: {sent!r}')
        return join_lines(sent + (b'.',))

    @staticmethod
    def _make_text(text: 'str | bytes | bytearray', charset: 'Optional[str]') -> 'bytes':
        """Encode the text of a line; :class:`bytes` and a :class:`bytearray` are written verbatim.

        Args:
            text: Text to encode.
            charset: Encoding for a :obj:`str`, **UTF-8** if not given.

        Returns:
            The octets of the text.

        Raises:
            ProtocolError: If ``text`` is of another type, or ``charset``
                cannot encode it.

        """
        if isinstance(text, (bytes, bytearray)):
            return bytes(text)
        if not isinstance(text, str):
            raise ProtocolError(f'SMTP: invalid text: must be a str, bytes or bytearray, not {text!r}')
        try:
            return text.encode(charset or 'utf-8')
        except (LookupError, UnicodeError) as error:
            raise ProtocolError(f'SMTP: cannot encode {text!r} as {charset!r}') from error

    @staticmethod
    def _decode_lines(texts: 'tuple[bytes, ...]') -> 'tuple[tuple[str, ...], Optional[str]]':
        """Decode the text of several lines with one charset.

        The lines are decoded together, through
        :func:`~pcapkit.utilities.lines.decode_text`, and as ``'latin-1'``
        where that charset does not encode each back as it was.

        Args:
            texts: Text of each line, none holding a CR or LF.

        Returns:
            The decoded text of each line and the charset to encode them with,
            the latter :obj:`None` for UTF-8.

        """
        if not texts:
            return (), None
        value, charset = decode_text(b'\n'.join(texts))
        values = tuple(value.split('\n'))
        if len(values) == len(texts) and all(item.encode(charset or 'utf-8') == raw
                                             for item, raw in zip(values, texts)):
            return values, charset
        return tuple(raw.decode('latin-1') for raw in texts), 'latin-1'
