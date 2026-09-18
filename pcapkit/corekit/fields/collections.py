# -*- coding: utf-8 -*-
"""container field class"""

import copy
import io
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import FieldBase
from pcapkit.corekit.fields.numbers import NumberField
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

        Raises:
            FieldValueError: If the items overrun the field, or if a schema item
                consumes nothing from ``buffer`` -- see the note below.

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

        # NOTE: The item-typed branch below sizes each item by ``field.length``,
        # which is what it read, but the schema branch sizes it by ``len(data)``,
        # which is only what the schema *recorded*. A schema reading a stream that
        # has already run out records nothing, so ``length -= len(data)`` makes no
        # progress and the loop spins forever. Reachable from a TCP segment: a
        # ``SACK`` option declaring more octets than the option area holds leaves
        # ``sack``'s ``ListField`` reading ``SACKBlock`` off an exhausted stream.
        # Remembering where the previous item ended is what bounds the iteration
        # count, since it does not depend on what the schema reports. C.f. #431,
        # which is the same defect in the ``OptionField`` subclass.
        #
        # ``start`` is where the field itself begins. The comparison needs stream
        # positions, but the diagnostic wants an offset into the field, and the two
        # only coincide when the field happens to be reading from the front of its
        # stream -- which it does when handed a :obj:`bytes` buffer and does not
        # when handed a live file.
        start = offset = file.tell()

        temp = []  # type: list[_TL]
        while length > 0:
            field = self._item_type(packet)

            if is_schema:
                data = cast('SchemaField', field).unpack(file, packet)

                end = file.tell()
                if end <= offset:
                    # NOTE: ``len(temp)`` counts the items already parsed, so it
                    # names the failing one as a count rather than as an ordinal --
                    # "after 2 item(s)" rather than "item 2", which would read as
                    # the second item when it is the third. The ``OptionField``
                    # message below names the option code in this slot and so has
                    # no index to be read either way.
                    raise FieldValueError(
                        f'Field {self.name} has an item that consumed no data: '
                        f'after {len(temp)} item(s), at offset {offset - start} of '
                        f'{self._length}, with {length} octet(s) of the field '
                        f'left to parse'
                    )
                offset = end

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

    Note:
        :meth:`self.unpack <unpack>` selects an option's schema by reading the
        ``type_name`` field of ``base_schema`` **alone** off the front of the
        option, instead of unpacking the whole base schema and keeping only that
        one value. That is only the same read when three things hold of the type
        field:

        1. it is the base schema's **first** field, so that it is what sits at the
           front of the option;
        2. it is a :class:`~pcapkit.corekit.fields.numbers.NumberField`, so that
           :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`
           reads it through its ordinary per-field branch;
        3. its length is a fixed integer rather than a callable, so that its width
           does not depend on packet data the shortcut has not read.

        All of that is true of every ``OptionField`` declared in this package. A
        base schema registered from outside it -- c.f.
        :mod:`pcapkit.foundation.registry` -- need not satisfy it, and is **not**
        rejected: such a base schema is unpacked in full, exactly as it was before
        the shortcut existed. It parses correctly and pays the cost of the second
        parse. Only the shortcut is withheld, so a base schema whose type field
        comes second cannot be silently misread.

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

        # NOTE: Decided once, here, rather than per option in ``unpack``. See the
        # docstring above for what the fast path requires and why a base schema
        # that does not meet it is accommodated rather than rejected.
        #
        # The three conditions are exactly what makes reading the type field alone
        # the same read that ``Schema.unpack`` performs for it: it must sit at the
        # front of the option, ``Schema.unpack`` must handle it through its generic
        # branch rather than one of the special ones (a ``NumberField`` is never
        # ``PayloadField``, ``PaddingField``, ``ConditionalField``,
        # ``ForwardMatchField``, ``SwitchField`` or ``OptionField``), and its width
        # must not depend on packet state that the full unpack would have
        # established first.
        #
        # Every test is written so that an unexpected base schema selects the full
        # unpack instead of raising, so this cannot turn a registration that works
        # today into an import-time failure.
        fields = getattr(self._base_schema, '__fields__', {})
        type_field = fields.get(type_name)

        #: Optional[FieldBase]: Base schema's type field, when reading it on its own
        #: is equivalent to unpacking the whole base schema to obtain it; otherwise
        #: :data:`None`, and :meth:`self.unpack <unpack>` unpacks the base schema.
        self._type_field = type_field if (
            isinstance(type_field, NumberField)
            and list(fields)[:1] == [type_name]
            and type_field._length_callback is None  # pylint: disable=protected-access
        ) else None

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

        Raises:
            FieldValueError: If an option consumes nothing from ``buffer``, since
                the loop below has then no way to get past it.

        """
        length = self._length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        # NOTE: The loop below sizes each option by ``len(data)`` -- the size of
        # the schema the option reported -- and that is not always the number of
        # octets the option took from ``file``. The two part company for a schema
        # whose ``post_process`` returns a *nested* schema, since ``len(data)``
        # then measures the nested schema rather than what the outer one read. So
        # ``len(data)`` cannot be the loop's progress measure: an option that
        # over-reads leaves ``length`` above zero with ``file`` already exhausted,
        # every field of the next option reads ``b''``, and an option that read
        # nothing reports ``len(data) == 0`` and leaves ``length`` untouched --
        # which spins forever, with no exception and no diagnostic. C.f. #431.
        #
        # Remembering where the previous option ended gives the loop a measure of
        # progress that does not depend on what a schema reports, and one octet of
        # it per iteration is what bounds the iteration count. ``length`` is still
        # decremented by ``len(data)``, so that an option area which parses today
        # parses identically.
        #
        # ``start`` is where the option area itself begins. The comparison needs
        # stream positions, but the diagnostic wants an offset into the area, and
        # the two only coincide when the field happens to be reading from the front
        # of its stream -- which it does when handed a :obj:`bytes` buffer and does
        # not when handed a live file.
        start = offset = file.tell()

        # make a copy of the ``packet`` dict so that we can include
        # parsed option schema in the ``packet`` dict
        new_packet = packet.copy()
        new_packet[self.name] = OrderedMultiDict()

        # NOTE: Where it can, this reads the base schema's type field alone rather
        # than the whole base schema. The option schema below re-reads the same
        # octets from the rewound stream, and the base schema's result is used for
        # nothing but the type code, so unpacking it in full parsed every option
        # twice -- 2274 schema unpacks for 1137 options of
        # ``examples/captures/profile.pcapng``.
        #
        # Reading the type field alone deliberately mirrors what
        # :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`
        # does for one field -- ``field(packet)``, read ``field.length`` octets,
        # then ``field.unpack(byte, packet.copy())`` -- rather than reaching for
        # :func:`struct.unpack`. That keeps ``code``'s enumeration type, which both
        # the ``self._eool`` comparison and the ``OrderedMultiDict`` key depend on,
        # and it is what makes the two spellings equivalent rather than merely
        # similar.
        #
        # ``self._type_field`` is :data:`None` for a base schema that the shortcut
        # does not fit -- see the class docstring -- and the full unpack is used
        # for it instead. Whichever way the code was read, ``consumed`` is the
        # number of octets to rewind to get back to the front of the option.
        type_field = self._type_field

        temp = []  # type: list[_TS]
        while length > 0:
            if type_field is None:
                # unpack option type using base schema
                meta = self._base_schema.unpack(file, length, packet)  # type: ignore[call-arg,misc,var-annotated]
                code = cast('int', meta[self._type_name])
                consumed = len(meta)
            else:
                # unpack option type using the base schema's type field. No cast
                # is needed here, unlike the branch above: the type field is known
                # to be a ``NumberField``, so ``unpack`` is already typed ``int``.
                field = type_field(packet)
                byte = file.read(field.length)
                code = field.unpack(byte, packet.copy())
                consumed = len(byte)
            schema = self._registry[code]

            # rewind to the beginning of the option
            file.seek(-consumed, io.SEEK_CUR)

            # unpack option using option schema
            data = schema.unpack(file, length, packet)  # type: ignore[call-arg,misc,var-annotated]
            new_packet[self.name].add(code, data)
            temp.append(data)

            # update length
            length -= len(data)

            # check for EOOL
            if code == self._eool:
                break

            # NOTE: The progress check comes *after* the end-of-option-list break,
            # and that order is not incidental. An area declared longer than the
            # octets behind it -- an over-long ``ihl``, or a capture cut short by
            # the snapshot length -- exhausts ``file`` early, and the exhausted
            # read then decodes the type field as 0. For the IPv4, TCP and PCAP-NG
            # registries 0 *is* the end-of-option-list code, so the break above has
            # always absorbed that case and reported the rest of the area as
            # padding. Checking progress first turned all of those into errors:
            # measured on ``IPv4(bytes.fromhex('4a00001800010000400600000a0000010a000002'))``,
            # 20 octets of options declared with none present, and on a TCP segment
            # with a data offset of 10 and four option octets, both of which parse
            # on ``main``.
            #
            # The registries that spin are the ones where 0 is *not* the
            # end-of-option-list code, so they never reach the break: HOPOPT,
            # IPv6-Opts and MH read 0 as ``Pad1``, HIP as an unassigned parameter,
            # SCTP as a DATA chunk. Those are what this guards, and one octet of
            # measured progress per surviving iteration is what bounds the loop.
            end = file.tell()
            if end <= offset:
                raise FieldValueError(
                    f'Field {self.name} has an option that consumed no data: '
                    f'{code!r} at offset {offset - start} of {self._length}, with '
                    f'{length} octet(s) of the option area left to parse'
                )
            offset = end

        self._option_padding = length
        return temp
