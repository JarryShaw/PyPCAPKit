# -*- coding: utf-8 -*-
"""text field class"""

import urllib.parse as urllib_parse
from typing import TYPE_CHECKING

import chardet

from pcapkit.corekit.fields.field import Field
from pcapkit.corekit.infoclass import Info

__all__ = [
    'BytesField',
    'StringField',
    'BitField',
]

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    from typing_extensions import Literal

    ConverterFunc = Callable[[int], Any]
    ReverserFunc = Callable[[Any], int]
    NamespaceEntry = tuple[int, Optional[int], Optional[ConverterFunc], Optional[ReverserFunc]]


class BytesField(Field):
    """Bytes value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.

    """

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._length

    def __init__(self, name: 'str', length: 'int', default: 'Any' = None) -> 'None':
        super().__init__(name, length, default)

        self._template = f'{length}s'


class StringField(BytesField):
    r"""String value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        encoding: The encoding with which to decode the :obj:`bytes`.
            If not provided, :mod:`pcapkit` will first try detecting its encoding
            using |chardet|_. The fallback encoding would is **UTF-8**.
        errors: The error handling scheme to use for the handling of decoding errors.
            The default is ``'strict'`` meaning that decoding errors raise a
            :exc:`UnicodeDecodeError`. Other possible values are ``'ignore'`` and ``'replace'``
            as well as any other name registered with :func:`codecs.register_error` that
            can handle :exc:`UnicodeDecodeError`.
        unquote: Whether to unquote the decoded string as a URL. Should decoding failed ,
            the method will try again replacing ``'%'`` with ``'\x'`` then decoding the
            ``url`` as ``'utf-8'`` with ``'replace'`` for error handling.

    .. |chardet| replace:: ``chardet``
    .. _chardet: https://chardet.readthedocs.io

    """

    def __init__(self, name: 'str', length: 'int',
                 default: 'Any' = None, encoding: 'Optional[str]' = None,
                 errors: 'Literal["strict", "ignore", "replace"]' = 'strict',
                 unquote: 'bool' = False) -> 'None':
        super().__init__(name, length, default)

        self._encoding = encoding
        self._errors = errors
        self._unquote = unquote

    def pre_process(self, value: 'str') -> 'bytes':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        if self._unquote:
            value = urllib_parse.quote(value, encoding=self._encoding or 'utf-8', errors=self._errors)
        return value.encode(self._encoding or 'utf-8', self._errors)

    def post_process(self, value: 'bytes') -> 'bytes | str':
        """Process field value after parsing (unpacked).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        if self._unquote:
            try:
                ret = urllib_parse.unquote(value, encoding=self._encoding or 'utf-8', errors=self._errors)
            except UnicodeError:
                ret = urllib_parse.unquote(value.replace(b'%', rb'\x'), encoding='utf-8', errors='replace')
        else:
            charset = self._encoding or chardet.detect(value)['encoding'] or 'utf-8'
            try:
                ret = value.decode(charset, self._errors)
            except UnicodeError:
                ret = value.decode(charset, 'replace')
        return ret


class BitField(BytesField):
    """Bit value for protocol fields.

    Args:
        name: field name.
        length: field size (in bytes).
        default: field default value, if any.
        length: field size (in bytes).
        namespace: field namespace (a dict mapping field name to a tuple of start index,
            end index, converter function, which takes the flag value :obj:`int` as
            its only argument, and reverser function, which takes the converted flag value
            and returns the original :obj:`int` value).

    """

    def __init__(self, name: 'str', length: 'int', default: 'Any' = None,
                 namespace: 'Optional[dict[str, NamespaceEntry]]' = None) -> 'None':  # pylint: disable=line-too-long
        super().__init__(name, length, default)

        self._namespace = namespace or {}

    def pre_process(self, value: 'dict[str, Any]') -> 'bytes':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        buffer = bytearray(self.length * 8)
        for name, (start, end, _, reverser) in self._namespace.items():
            end = end or start
            if reverser is None:
                buffer[start:end] = f'{value[name]:0{end - start}b}'.encode()
            else:
                buffer[start:end] = f'{reverser(value[name]):0{end - start}b}'.encode()
        return int(b''.join(map(lambda x: b'1' if x else b'0', buffer)), 2).to_bytes(self.length, 'big')

    def post_process(self, value: 'bytes') -> 'Info':
        """Process field value after parsing (unpacked).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        buffer = {}
        binary = ''.join(f'{byte:08b}' for byte in value)
        for name, (start, end, converter, _) in self._namespace.items():
            if converter is None:
                buffer[name] = int(binary[start:end], 2)
            else:
                buffer[name] = converter(int(binary[start:end], 2))
        return Info.from_dict(buffer)
