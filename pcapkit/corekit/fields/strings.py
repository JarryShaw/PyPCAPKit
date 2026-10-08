# -*- coding: utf-8 -*-
"""text field class"""

import urllib.parse as urllib_parse
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from pcapkit.corekit.fields.field import NO_VALUE, Field
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.compat import Dict
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    '_TextField',
    'StringField',
    'DecodedString',
    'BitField',
    'PaddingField',
]

if TYPE_CHECKING:
    from typing import Callable, Optional, Tuple

    from typing_extensions import Literal, Self

    from pcapkit.corekit.fields.field import NoValueType

    NamespaceEntry = Tuple[int, int]

_T = TypeVar('_T', 'str', 'bytes', 'dict[str, Any]')


class _TextField(Field[_T], Generic[_T]):
    """Internal text value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: '_T | NoValueType' = NO_VALUE,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, default, callback)  # type: ignore[arg-type]

        self._template = f'{self._length}s' if self._length >= 0 else '1024s'  # reasonable default

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            New instance of :class:`_TextField`.

        This method will return a new instance of :class:`_TextField` instead of
        updating the current instance.

        """
        new_self = super().__call__(packet)
        new_self._template = f'{new_self._length}s'
        return new_self


class BytesField(_TextField[bytes]):
    """Bytes value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    def pre_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if self._length < 0:
            self._length = len(value)
            self._template = f'{self._length}s'
        return value


class StringField(_TextField[str]):
    r"""String value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        encoding: The encoding with which to decode the :obj:`bytes`, and with which
            a :obj:`str` is encoded when packing. If not provided, :mod:`pcapkit`
            will first try detecting its encoding using |chardet|_. The fallback
            encoding is **UTF-8**.
        errors: The error handling scheme to use for the handling of decoding errors.
            The default is ``'strict'``. Should decoding fail under it, the field
            retries with ``'replace'`` rather than raising, so an octet the charset
            cannot decode reads as U+FFFD -- the octets themselves are not lost,
            see below. A codec that supports no error handler at all still raises:
            ``idna`` reports ``Unsupported error handling: replace``, measured.
            Other possible values are ``'ignore'`` and ``'replace'`` as well as any
            other name registered with :func:`codecs.register_error` that can handle
            :exc:`UnicodeDecodeError`.
        unquote: Whether to unquote the decoded string as a URL. Should decoding fail,
            the method will try again replacing ``'%'`` with ``'\x'`` then decoding the
            ``url`` as ``'utf-8'`` with ``'replace'`` for error handling.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Unpacking is lossless. Where re-encoding the decoded :obj:`str` would not
    reproduce the octets it came from -- a detected charset other than UTF-8, an
    octet the charset cannot decode, a lossy ``errors`` scheme, or a URL quoting
    that differs from the original -- the field returns a :class:`DecodedString`,
    which remembers those octets and packs back as exactly them. The decoded
    *text* is whatever it has always been, U+FFFD and all: a consumer that only
    reads the text, such as a dumper writing it back out as UTF-8, sees no
    change. A length of ``-1`` is resolved to the number of *encoded* octets.

    .. |chardet| replace:: ``chardet``
    .. _chardet: https://chardet.readthedocs.io

    """

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: 'str | NoValueType' = NO_VALUE, encoding: 'Optional[str]' = None,
                 errors: 'Literal["strict", "ignore", "replace"]' = 'strict',
                 unquote: 'bool' = False,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, default, callback)

        self._encoding = encoding
        self._errors = errors
        self._unquote = unquote

    def _encode(self, value: 'str') -> 'bytes':
        """Encode a :obj:`str` value the way :meth:`pre_process` packs it.

        Arguments:
            value: Field value.

        Returns:
            Encoded field value.

        """
        if self._unquote:
            value = urllib_parse.quote(value, encoding=self._encoding or 'utf-8', errors=self._errors)
        return value.encode(self._encoding or 'utf-8', self._errors)

    def pre_process(self, value: 'str', packet: 'dict[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        # NOTE: The octets a DecodedString was decoded from are used verbatim,
        # since re-encoding its text is exactly what would not reproduce them.
        buffer = value.raw if isinstance(value, DecodedString) else self._encode(value)

        # NOTE: A negative length is resolved from the *encoded* octets, not from
        # the character count -- the ``Ns`` template counts octets, so counting
        # characters truncated any text that does not encode one octet per
        # character.
        if self._length < 0:
            self._length = len(buffer)
            self._template = f'{self._length}s'
        return buffer

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'str':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacked).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value; a :class:`DecodedString` carrying ``value``
            where :meth:`pre_process` would not otherwise reproduce it.

        """
        if self._unquote:
            try:
                ret = urllib_parse.unquote(value, encoding=self._encoding or 'utf-8', errors=self._errors)
            except UnicodeError:
                ret = urllib_parse.unquote(value.replace(b'%', rb'\x'), encoding='utf-8', errors='replace')
        else:
            charset = self._encoding or detect(value)
            try:
                ret = value.decode(charset, self._errors)
            except UnicodeError:
                ret = value.decode(charset, 'replace')

        # NOTE: Encoding may itself fail -- ``errors='strict'`` over text that
        # decoded under a lone-surrogate scheme, for one -- which is as much a
        # failure to reproduce the octets as a mismatch is.
        try:
            lossless = self._encode(ret) == value
        except UnicodeError:
            lossless = False
        if lossless:
            return ret
        return DecodedString(ret, value)


class DecodedString(str):
    """Decoded :class:`StringField` value that remembers its octets.

    :class:`StringField` returns one where encoding the decoded text would not
    reproduce the octets it was decoded from, so that the field packs it back as
    exactly those octets. It is otherwise an ordinary :obj:`str`, and deliberately
    so: it compares and hashes as its text, since the text is the value and
    :attr:`raw` is provenance. Two of them with the same text and different octets
    therefore compare equal -- the alternative, mixing :attr:`raw` into
    :meth:`~object.__eq__`, would make ``info.comment == 'café'`` false against a
    plain :obj:`str` literal, which is the comparison callers actually write.

    Any string operation on one returns a plain :obj:`str`, which a field then
    packs with its own encoding; that is intended, as an edited value is no longer
    the text those octets held.

    Args:
        value: Decoded text.
        raw: Octets ``value`` was decoded from.

    """

    #: Octets the string was decoded from.
    raw: 'bytes'

    def __new__(cls, value: 'str', raw: 'bytes') -> 'Self':
        self = super().__new__(cls, value)
        self.raw = raw
        return self

    def __getnewargs__(self) -> 'tuple[str, bytes]':  # type: ignore[override]
        return str(self), self.raw


class BitField(_TextField[Dict[str, Any]]):
    """Bit value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        namespace: Field namespace (a dict mapping field name to a tuple of start index,
            and length of the subfield).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    def __init__(self, length: 'int',
                 default: 'dict[str, Any] | NoValueType' = NO_VALUE,
                 namespace: 'Optional[dict[str, NamespaceEntry]]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, default, callback)

        self._namespace = namespace or {}

        # NOTE: A subfield reaching past the end of the field is a mistake in the
        # schema that declares it, not something a packet can cause, so it is
        # rejected here rather than at packing time -- where it would instead grow
        # the buffer, and surface much later as an opaque ``OverflowError`` from
        # :meth:`int.to_bytes`.
        width = self.length * 8
        for name, (start, size) in self._namespace.items():
            if start < 0 or size < 1 or start + size > width:
                raise FieldValueError(
                    f'{type(self).__name__}: subfield {name!r} spans bits '
                    f'{start}-{start + size - 1} of a {width}-bit field'
                )

    def pre_process(self, value: 'dict[str, Any]', packet: 'dict[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If a subfield value does not fit the bits it was
                declared to occupy.

        """
        # NOTE: The buffer holds one ASCII digit per bit, so it must be seeded with
        # ``b'0'`` rather than with NUL bytes -- a zero bit written by the loop below
        # is the *character* ``b'0'``, which is itself non-zero, so a truthiness test
        # over the buffer cannot tell a cleared bit from a set one and would report
        # every named bit as set.
        buffer = bytearray(b'0' * (self.length * 8))
        for name, (start, size) in self._namespace.items():
            bits = f'{value[name]:0{size}b}'
            if len(bits) > size:
                raise FieldValueError(
                    f'{type(self).__name__}: subfield {name!r} value {value[name]!r} '
                    f'needs {len(bits)} bits, but was declared with {size}'
                )
            buffer[start:start + size] = bits.encode()
        return int(buffer, 2).to_bytes(self.length, 'big')

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'dict[str, Any]':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacked).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        buffer = {}
        binary = ''.join(f'{byte:08b}' for byte in value)
        for name, (start, len) in self._namespace.items():
            end = start + len
            buffer[name] = int(binary[start:end], 2)
        return buffer


class PaddingField(BytesField):
    """Bytes value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Padding packs back as the octets it was given, so a schema unpacked from
    non-zero padding rebuilds byte for byte. An absent or empty value packs as
    zeros -- the default for a freshly built packet -- and a value of another
    width is truncated or zero-filled to the field's, as :mod:`struct`'s ``s``
    format does.

    """

    def pack(self, value: 'Optional[bytes]', packet: 'dict[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value, i.e. the padding octets as captured.
            packet: Packet data.

        Returns:
            Packed field value: ``value`` truncated or zero-filled to the
            field's width, or that many zero octets if ``value`` is absent or
            empty.

        """
        length = self.length
        if isinstance(value, (bytes, bytearray)) and value:
            return bytes(value[:length]).ljust(length, b'\x00')
        return bytes(length)
