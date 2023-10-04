# -*- coding: utf-8 -*-
"""container field class"""

import copy
import io
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import FieldBase
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.utilities.compat import List
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'ListField', 'OptionField',
]

if TYPE_CHECKING:
    from collections import defaultdict
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, Callable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Self

    from pcapkit.protocols.schema.schema import Schema

_TL = TypeVar('_TL', 'Schema', 'FieldBase', 'bytes')
_TS = TypeVar('_TS', bound='Schema')


class ListField(FieldBase[List[_TL]], Generic[_TL]):
    """Field list for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        item_type: Field type of the contained items.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    This field is used to represent a list of fields, as in the case of lists of
    constrant-length-field items in a protocol.

    """

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 item_type: 'Optional[FieldBase]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<list>'
        self._callback = callback
        self._item_type = item_type

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = '0s'

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`ListField`
        instead of updating the current instance.

        """
        new_self = copy.copy(self)
        new_self._callback(self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
            new_self._template = f'{new_self._length}s'
        return new_self

    def pack(self, value: 'Optional[list[_TL]]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

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
                temp.append(item.pack(packet))
            elif self._item_type is not None:
                temp.append(self._item_type.pack(item, packet))
            else:
                raise FieldValueError(f'Field {self.name} has invalid value.')
        return b''.join(temp)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> 'bytes | list[_TL]':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        length = self._length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        if self._item_type is None:
            return file.read(length)

        from pcapkit.corekit.fields.misc import SchemaField
        is_schema = isinstance(self._item_type, SchemaField)

        temp = []  # type: list[_TL]
        while length > 0:
            field = self._item_type(packet)

            if is_schema:
                data = cast('SchemaField', self._item_type).unpack(file, packet)

                length -= len(data)
                if length < 0:
                    raise FieldValueError(f'Field {self.name} has invalid length.')
            else:
                length -= field.length
                if length < 0:
                    raise FieldValueError(f'Field {self.name} has invalid length.')

                buffer = file.read(field.length)
                data = field.unpack(buffer, packet)

            temp.append(data)
        return temp


class OptionField(ListField, Generic[_TS]):
    """Field list for protocol options.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        base_schema: Base schema for option fields.
        type_name: Name of the option type field.
        registry: Option registry, as in a mapping from option types (enumeration
            values) to option schemas, with the default value being the unknown
            option schema.
        eool: Enumeration of the EOOL (end-of-option-list, or equivalent) option
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    This field is used to represent a list of fields, as in the case of lists of
    options and/or parameters in a protocol.

    """

    @property
    def base_schema(self) -> 'Type[_TS]':
        """Base schema."""
        return self._base_schema

    @property
    def type_name(self) -> 'str':
        """Type name."""
        return self._type_name

    @property
    def registry(self) -> 'defaultdict[int | StdlibEnum | AenumEnum, Type[_TS]]':
        """Option registry."""
        return self._registry

    @property
    def eool(self) -> 'int | StdlibEnum | AenumEnum':
        """EOOL option."""
        return self._eool

    @property
    def option_padding(self) -> 'int':
        """Length option padding data."""
        return self._option_padding

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 base_schema: 'Optional[Type[_TS]]' = None,
                 type_name: 'str' = 'type',
                 registry: 'Optional[defaultdict[int | StdlibEnum | AenumEnum, Type[_TS]]]' = None,
                 eool: 'Optional[int | StdlibEnum | AenumEnum]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, None, callback)
        #self._name = '<option>'
        self._eool = eool
        self._option_padding = 0

        if base_schema is None:
            raise FieldValueError('Field <option> has no base schema.')
        self._base_schema = base_schema

        if not hasattr(self._base_schema, type_name):
            raise FieldValueError(f'Field <option> has no type field "{type_name}".')
        self._type_name = type_name

        if registry is None:
            raise FieldValueError('Field <option> has no registry.')
        self._registry = registry

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> 'list[_TS]':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        Important:
            If the option list ended before the specified size limit,
            set :attr:`self.option_padding <OptionField.option_padding>`
            as the remaining length to the ``packet`` argument such that
            the next fields can be aware of such informations.

        """
        length = self._length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        # make a copy of the ``packet`` dict so that we can include
        # parsed option schema in the ``packet`` dict
        new_packet = packet.copy()
        new_packet[self.name] = OrderedMultiDict()

        temp = []  # type: list[_TS]
        while length > 0:
            # unpack option type using base schema
            meta = self._base_schema.unpack(file, length, packet)  # type: ignore[call-arg,misc,var-annotated]
            code = cast('int', meta[self._type_name])
            schema = self._registry[code]

            # rewind to the beginning of the option
            file.seek(-len(meta), io.SEEK_CUR)

            # unpack option using option schema
            data = schema.unpack(file, length, packet)  # type: ignore[call-arg,misc,var-annotated]
            new_packet[self.name].add(code, data)
            temp.append(data)

            # update length
            length -= len(data)

            # check for EOOL
            if code == self._eool:
                break

        self._option_padding = length
        return temp
