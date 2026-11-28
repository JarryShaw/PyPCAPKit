# -*- coding: utf-8 -*-
"""Text Protocol Lines
=========================

.. module:: pcapkit.utilities.lines

:mod:`pcapkit.utilities.lines` reads and writes what the line-based text
protocols exchange: octets cut into CRLF-terminated lines, a reply that runs
over several lines, a block of lines ended by a line holding a single period,
and the text a line carries. It works on octets alone, so FTP, SMTP and any
other such protocol share it.

.. versionadded:: 1.10.0

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.chardet import detect

if TYPE_CHECKING:
    from typing import Iterable, Optional, Sequence

__all__ = [
    'split_lines', 'join_lines',
    'closes_reply',
    'block_end', 'stuff', 'unstuff',
    'decode_text',
]

#: The line terminator.
_CRLF = b'\r\n'
#: The line that ends a block, and the octet a stuffed line opens with.
_DOT = b'.'


def split_lines(data: 'bytes') -> 'Optional[tuple[bytes, ...]]':
    """Cut ``data`` into its CRLF-terminated lines.

    Only a CRLF ends a line, so a CR or LF outside one stays in the line holding
    it (:rfc:`5321#section-2.3.8`), for the caller to accept or refuse.

    Args:
        data: Octets to cut.

    Returns:
        Each line without its CRLF, or :obj:`None` unless ``data`` is one or
        more whole lines, i.e. ends with CRLF.

    """
    if not data.endswith(_CRLF):
        return None
    return tuple(data[:-len(_CRLF)].split(_CRLF))


def join_lines(lines: 'Iterable[bytes]') -> 'bytes':
    """Write each of ``lines`` followed by its CRLF, as :func:`split_lines` reads them.

    Args:
        lines: Lines without their CRLF.

    Returns:
        The lines, each terminated with CRLF.

    """
    return b''.join(line + _CRLF for line in lines)


def closes_reply(code: 'bytes', lines: 'Sequence[bytes]', *, marked: 'bool') -> 'bool':
    """Whether ``lines`` end a multi-line reply that opened with ``code``.

    A multi-line reply opens with ``code`` and a hyphen, and ends at the first
    line opening with ``code`` and SP (:rfc:`959#section-4.2`). With ``marked``,
    as in SMTP, every line before that one opens with ``code`` and a hyphen too,
    and the closing line may be ``code`` alone, which a client must accept
    (:rfc:`5321#section-4.2.1`). Without it, as in FTP, those lines are free
    text, which may open with ``code`` and a hyphen as well.

    Args:
        code: Reply code of the opening line.
        lines: Lines after the opening one, CRLF excluded.
        marked: Whether every line opens with ``code``.

    Returns:
        Whether each line is :class:`bytes` holding no LF, and the last line,
        and only the last, closes the reply.

    """
    if not lines or not all(isinstance(line, bytes) and b'\n' not in line for line in lines):
        return False
    *body, last = lines
    closing = code + b' '
    if marked:
        continued = code + b'-'
        return (last == code or last.startswith(closing)) and all(line.startswith(continued) for line in body)
    return last.startswith(closing) and not any(line.startswith(closing) for line in body)


def block_end(lines: 'Sequence[bytes]') -> 'Optional[int]':
    """Index of the line that ends a block of ``lines``.

    A block ends at a line holding a single period, as SMTP's mail data does
    (:rfc:`5321#section-4.1.1.4`), and a line of the block opening with a
    period is sent with one more (:func:`stuff`), so none holds one alone.

    Args:
        lines: Lines without their CRLF.

    Returns:
        Index of the first line holding a single period, or :obj:`None` if no
        line does.

    """
    for index, line in enumerate(lines):
        if line == _DOT:
            return index
    return None


def stuff(line: 'bytes') -> 'bytes':
    """Dot-stuff ``line``, a line of a block, for sending.

    A line opening with a period is sent with one more (:rfc:`5321#section-4.5.2`).

    Args:
        line: Line of text, CRLF excluded.

    Returns:
        The line as sent.

    """
    return _DOT + line if line.startswith(_DOT) else line


def unstuff(line: 'bytes') -> 'bytes':
    """Undo the dot-stuffing of ``line``, a line of a block as sent.

    A line opening with a period and holding more loses that period
    (:rfc:`5321#section-4.5.2`), so :func:`stuff` and then this give back any
    line. A line holding a single period ends the block (:func:`block_end`), so
    it comes back as is.

    Args:
        line: Line as sent, CRLF excluded.

    Returns:
        The line of text.

    """
    return line[len(_DOT):] if line.startswith(_DOT) and line != _DOT else line


def decode_text(text: 'bytes') -> 'tuple[str, Optional[str]]':
    """Decode the text a line carries, recording how to encode it back.

    The text is decoded with the charset `chardet`_ detects, or as
    ``'unicode_escape'`` with errors replaced if that fails. Where the result
    does not encode back to ``text`` as UTF-8, the detected charset is returned
    with it, or ``'latin-1'``, decoding again, if that does not reproduce
    ``text`` either, so the octets survive a rebuild.

    Args:
        text: Octets of the text.

    Returns:
        The decoded text and the charset to encode it with, the latter
        :obj:`None` for UTF-8.

    """
    charset = detect(text)
    try:
        value = text.decode(charset)
    except UnicodeError:
        value = text.decode('unicode_escape', errors='replace')
    for encoding in (None, charset):
        try:
            if value.encode(encoding or 'utf-8') == text:
                return value, encoding
        except (LookupError, UnicodeError):
            pass
    return text.decode('latin-1'), 'latin-1'
