# -*- coding: utf-8 -*-
"""data models for SMTP protocol

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.const.smtp.command import Command as Enum_Command
    from pcapkit.const.smtp.reply_code import ReplyCode
    from pcapkit.protocols.application.smtp.protocol import Type as SMTP_Type

__all__ = [
    'SMTP',
    'Command', 'Reply', 'MailData',
]


class SMTP(Protocol):
    """Data model for SMTP protocol."""

    #: Type.
    type: 'SMTP_Type'


@info_final
class Command(SMTP):
    """Data model for an SMTP command (:rfc:`5321#section-4.1.1`)."""

    #: Type.
    type: 'Literal[SMTP_Type.COMMAND]'
    #: Command verb.
    cmmd: 'Enum_Command'
    #: Argument clause, :obj:`None` if the command carries none.
    args: 'Optional[str]'
    #: Charset to encode :attr:`args` with, :obj:`None` for UTF-8.
    charset: 'Optional[str]'
    #: Verb as received, in its original case; :attr:`cmmd` is the
    #: case-insensitive lookup of it.
    raw_cmmd: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal[SMTP_Type.COMMAND]', cmmd: 'Enum_Command', args: 'Optional[str]', charset: 'Optional[str]', raw_cmmd: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Reply(SMTP):
    """Data model for an SMTP reply (:rfc:`5321#section-4.2`)."""

    #: Type.
    type: 'Literal[SMTP_Type.REPLY]'
    #: Reply code, the same on every line.
    code: 'ReplyCode'
    #: Text of each line, in order; the last is :obj:`None` where that line
    #: closes the reply with its code alone, with no SP.
    text: 'tuple[Optional[str], ...]'
    #: Whether the last line carries a hyphen, so the reply goes on in a later
    #: segment.
    more: 'bool'
    #: Charset to encode :attr:`text` with, :obj:`None` for UTF-8.
    charset: 'Optional[str]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal[SMTP_Type.REPLY]', code: 'ReplyCode', text: 'tuple[Optional[str], ...]', more: 'bool', charset: 'Optional[str]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MailData(SMTP):
    """Data model for the mail data a ``DATA`` command sends, up to and
    including the end of mail data indication (:rfc:`5321#section-4.1.1.4`)."""

    #: Type.
    type: 'Literal[SMTP_Type.MAIL_DATA]'
    #: Lines as sent, dot-stuffed, without their CRLF or the line ending the
    #: mail data.
    lines: 'tuple[bytes, ...]'
    #: The same lines with the dot-stuffing undone (:rfc:`5321#section-4.5.2`).
    text: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal[SMTP_Type.MAIL_DATA]', lines: 'tuple[bytes, ...]', text: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
