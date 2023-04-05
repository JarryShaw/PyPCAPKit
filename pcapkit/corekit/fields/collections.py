# -*- coding: utf-8 -*-
"""container field class"""

import copy
import io
from typing import TYPE_CHECKING, TypeVar, cast

from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.fields.field import _Field
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'ListField', 'OptionField',
]

if TYPE_CHECKING:
    from collections import defaultdict
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, Callable, Optional, Type

    from aenum import IntEnum as AenumEnum

    from pcapkit.protocols.schema.schema import Schema

_TL = TypeVar('_TL', 'Schema', '_Field', 'bytes')


class ListField(_Field[list[_TL]]):
    """Field list for protocol fields.

    Args:
        length: field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        item_type: field type of the contained items.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    This field is used to represent a list of fields, as in the case of lists of
    constrant-length-field items in a protocol.

    """

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    def __init__(self, length: 'int | Callable[[dict[str, Any]], Optional[int]]' = lambda _: None,
                 item_type: 'Optional[_Field]' = None,
                 callback: 'Callable[[ListField, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        self._name = '<list>'
        self._callback = callback
        self._item_type = item_type

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = '0s'

    def __call__(self, packet: 'dict[str, Any]') -> 'ListField':
        """Update field attributes.

        Args:
            packet: packet data.

        Notes:
            This method will return a new instance of :class:`ListField`
            instead of updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._callback(self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)  # type: ignore[assignment]
        return new_self

    def pack(self, value: 'Optional[list[_TL]]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: field value.
            packet: packet data.

        Returns:
            Packed field value.

        """
        if value is None:
            return b''

        from pcapkit.protocols.schema.schema import \
            Schema  # pylint: disable=import-outside-top-level

        temp = []  # type: list[bytes]
        for item in value:
            if isinstance(item, bytes):
                temp.append(item)
            elif isinstance(item, Schema):
                temp.append(item.pack())
            elif self._item_type is not None:
                temp.append(self._item_type.pack(item, packet))
            else:
                raise FieldValueError(f'Field {self.name} has invalid value.')
        return b''.join(temp)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> 'bytes | list[_TL]':  # type: ignore[override]
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.

        Returns:
            Unpacked field value.

        """
        length = self.length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        if self._item_type is not None:
            from pcapkit.corekit.fields.misc import SchemaField
            is_schema = isinstance(self._item_type, SchemaField)

            temp = []  # type: list[_TL]
            while length:
                field = self._item_type(packet)

                if is_schema:
                    data = cast('Schema', self._item_type).unpack(file, None, packet)  # type: ignore[call-arg,misc]

                    length -= len(data)
                    if length < 0:
                        raise FieldValueError(f'Field {self.name} has invalid length.')
                else:
                    length -= field.length
                    if length < 0:
                        raise FieldValueError(f'Field {self.name} has invalid length.')

                    buffer = file.read(field.length)
                    data = field.unpack(buffer, packet)

                temp.append(data)  # type: ignore[arg-type]
            return temp
        return file.read(length)


class OptionField(ListField):
    """Field list for protocol options.

    Args:
        length: field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        base_schema: base schema for option fields.
        type_name: name of the option type field.
        registry: option registry, as in a mapping from option types (enumeration
            values) to option schemas, with the default value being the unknown
            option schema.
        callback: callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field._Field.__call__>`.

    This field is used to represent a list of fields, as in the case of lists of
    options and/or parameters in a protocol.

    """

    @property
    def base_schema(self) -> 'Type[Schema]':
        """Base schema."""
        return self._base_schema

    @property
    def type_name(self) -> 'str':
        """Type name."""
        return self._type_name

    @property
    def registry(self) -> 'dict[int, Type[Schema]]':
        """Option registry."""
        return self._registry

    def __init__(self, length: 'int | Callable[[dict[str, Any]], Optional[int]]' = lambda _: None,
                 base_schema: 'Optional[Type[Schema]]' = None,
                 type_name: 'str' = 'type',
                 registry: 'Optional[defaultdict[int | StdlibEnum | AenumEnum, Type[Schema]]]' = None,
                 callback: 'Callable[[ListField, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, None, callback)
        self._name = '<option>'

        if base_schema is None:
            raise FieldValueError('Field <option> has no base schema.')
        self._base_schema = base_schema

        if not hasattr(self._base_schema, type_name):
            raise FieldValueError(f'Field <option> has no type field "{type_name}".')
        self._type_name = type_name

        if registry is None:
            raise FieldValueError('Field <option> has no registry.')
        self._registry = registry

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> 'list[Schema]':  # type: ignore[override]
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: field buffer.
            packet: packet data.

        Returns:
            Unpacked field value.

        """
        length = self.length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        # make a copy of the ``packet`` dict so that we can include
        # parsed option schema in the ``packet`` dict
        new_packet = packet.copy()
        new_packet[self.name] = OrderedMultiDict()

        temp = []  # type: list[Schema]
        while length:
            # unpack option type using base schema
            meta = self._base_schema.unpack(file, length, packet)  # type: ignore[call-arg,misc]
            code = cast('int', meta[self._type_name])
            schema = self._registry[code]

            # rewind to the beginning of the option
            file.seek(-len(meta), io.SEEK_CUR)

            # unpack option using option schema
            data = schema.unpack(file, length, packet)  # type: ignore[call-arg,misc]
            new_packet[self.name].add(code, data)
            temp.append(data)

            # update length
            length -= len(data)
        return temp
