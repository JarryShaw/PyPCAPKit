# -*- coding: utf-8 -*-
"""container field class"""

import io
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import FieldBase, _give_back_fill, _zero_filled_items
from pcapkit.corekit.fields.misc import SchemaField
from pcapkit.corekit.fields.numbers import NumberField
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.utilities.compat import List
from pcapkit.utilities.exceptions import FieldValueError, ProtocolError

__all__ = [
    'ListField', 'OptionField',
]

if TYPE_CHECKING:
    from collections import defaultdict
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, Callable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Self

    from pcapkit.protocols.schema import Schema

_TL = TypeVar('_TL', 'Schema', 'FieldBase', 'bytes')
_TS = TypeVar('_TS', bound='Schema')


class _ShortReadTracker:
    """Stream proxy recording whether a read came back short.

    Args:
        file: Stream to read from.

    Only the ``read``, ``seek`` and ``tell`` calls that
    :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>` and
    :meth:`OptionField.unpack` make are delegated.

    """

    __slots__ = ('_file', 'short')

    def __init__(self, file: 'IO[bytes]') -> 'None':
        self._file = file
        #: bool: Whether a read since the last reset returned fewer octets than
        #: it asked for.
        self.short = False

    def read(self, size: 'Optional[int]' = -1) -> 'bytes':
        """Read ``size`` octets, noting a short read."""
        if size is None:
            size = -1
        data = self._file.read(size)
        if 0 <= size and len(data) < size:
            self.short = True
        return data

    def seek(self, offset: 'int', whence: 'int' = io.SEEK_SET) -> 'int':
        """Seek the underlying stream."""
        return self._file.seek(offset, whence)

    def tell(self) -> 'int':
        """Tell the underlying stream's position."""
        return self._file.tell()


class ListField(FieldBase[List[_TL]], Generic[_TL]):
    """Field list for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        item_type: Field type of the contained items.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.
        count: Number of items a field before this one counts, for a list
            running to the end of the data; if a callable is given, it should
            return an integer value and accept the current packet as its only
            argument. A negative value, the default, counts none.

    This field is used to represent a list of fields, as in the case of lists of
    constant-length-field items in a protocol.

    A list whose octets hold fewer items than ``count`` ended with the data
    before the rest, and reports them as :attr:`shortfall`, so that
    :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
    records the cut; the items absent are not made up. A schema item it counts
    is read with ``__data_end__`` in its packet, since its octets end where the
    data does, so an item the data ends inside records the cut as its short
    read rather than warn that its fields run past the length it was given.

    .. versionchanged:: 1.6.0

       Takes ``count`` (:issue:`2711`), and reads a schema item it counts as
       ending with the data (:issue:`2749`).

    """

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def count(self) -> 'int':
        """Number of items counted; negative where none are."""
        return self._count

    @property
    def shortfall(self) -> 'int':
        """Number of the items counted that the octets last unpacked did not hold."""
        return self._shortfall

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 item_type: 'Optional[FieldBase]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None,
                 count: 'int | Callable[[dict[str, Any]], int]' = -1) -> 'None':
        #self._name = '<list>'
        if not hasattr(self, '_name'):
            self._name = f'<{type(self).__name__[:-5].lower()}>'

        self._callback = callback
        self._item_type = item_type

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = '0s'

        self._count_callback = None
        if not isinstance(count, int):
            self._count_callback, count = count, -1
        self._count = count
        self._shortfall = 0

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`ListField`
        instead of updating the current instance.

        """
        new_self = self.__copy__()
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
            new_self._template = f'{new_self._length}s'
        if new_self._count_callback is not None:
            new_self._count = new_self._count_callback(packet)
        return new_self

    def pack(self, value: 'Optional[list[_TL]]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        Without an ``item_type``, :meth:`unpack` returns the field's octets as
        a single :obj:`bytes`, so such a value is written as-is rather than
        iterated item by item.

        """
        if value is None:
            return b''
        if self._item_type is None and isinstance(value, bytes):
            return value

        from pcapkit.protocols.schema import Schema  # pylint: disable=import-outside-toplevel

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
            FieldValueError: If the items overrun the field, if a schema item
                consumes nothing from ``buffer``, or if schema items short of the
                field's length cannot be zero-filled.

        When ``buffer`` falls short of the field's length, the item it ends
        inside is read as though its missing octets were zeros, as
        :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`
        reads any other field, and the list ends with that item: none is read
        from past the data, which holds no octet of it. A ``__data_present__``
        key in ``packet`` says that ``buffer`` holds the data that many octets
        in, and past them the zeros an enclosing list of schema items was
        filled out with, as :meth:`Schema.unpack
        <pcapkit.protocols.schema.Schema.unpack>` tells the fields of the item
        the data ends inside; the list then ends with the data there.

        A ``__zero_tail__`` key in ``packet``, true, says instead that the
        octets past ``buffer`` are zeros of the data, as radiotap.org reads the
        octets a producer leaves off a TLV item (:issue:`2655`), so the list
        reads its items on through them to its length.

        .. versionchanged:: 1.6.0

           A list the data ends inside ends with the data, the item it ends
           inside read with its missing octets as zeros, where a schema item
           past the data was refused as consuming nothing and a plain value
           past it was read as zeros, and so does a list in an item the data
           ends inside (:issue:`2686`, :issue:`2756`, :issue:`2760`).

        """
        length = self._length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        if self._item_type is None:
            return file.read(length)

        # NOTE: ``SchemaField`` is imported at module level: a re-executed ``misc`` (as the #439 tests
        # force) would mint a second class this ``isinstance`` misses, mis-sizing items (#525).
        is_schema = isinstance(self._item_type, SchemaField)
        if length > 0:
            start = file.tell()
            octets = file.seek(0, io.SEEK_END) - start
            file.seek(start, io.SEEK_SET)
            # NOTE: Past ``__data_present__`` octets the buffer holds an enclosing fill (#2760).
            held = cast('int', packet.get('__data_present__', -1))
            present = held if 0 <= held < octets else octets
            # NOTE: Octets past the data that are zeros of it are read as items too (#2655, #2760).
            stop = -1 if packet.get('__zero_tail__') else present
            if present < length and is_schema:
                with _zero_filled_items(self.name, length, file.read(), present) as filled:
                    return self._unpack_items(filled, packet, is_schema, stop)
            if present < length and stop >= 0:
                # NOTE: A plain value the data ends inside zero-fills itself, as any field does.
                items = self._unpack_items(file, packet, is_schema, present)
                _give_back_fill(octets - (file.tell() - start))
                return items
        return self._unpack_items(file, packet, is_schema)

    def _unpack_items(self, file: 'IO[bytes]', packet: 'dict[str, Any]', is_schema: 'bool',
                      present: 'int' = -1) -> 'list[_TL]':
        """Unpack the field's items from ``file``.

        Args:
            file: Stream the items are read from.
            packet: Packet data.
            is_schema: Whether the items are schemas.
            present: Octets of ``file`` the data holds, past which ``file``
                ends or holds zeros a fill made up; negative where it holds the
                data to the field's length.

        Returns:
            Unpacked items.

        Raises:
            FieldValueError: If the items overrun the field, or if a schema item
                consumes nothing from ``file`` -- see the note below.

        """
        length = self._length
        item_type = cast('FieldBase', self._item_type)

        # NOTE: A schema item that reads nothing records ``len(data) == 0`` and would spin forever, so
        # progress is measured by stream position (#431); ``start`` turns positions into field offsets.
        start = offset = file.tell()

        temp = []  # type: list[_TL]
        while length > 0:
            # NOTE: An item starting past the octets present would be made of the zero-fill alone,
            # or of nothing, one the capture never held, so the list ends with the data (#2756, #2760).
            if 0 <= present <= offset - start:
                # NOTE: A length no whole number of plain values fills is refused, as it is whole.
                if not is_schema and length % item_type(packet).length:
                    raise FieldValueError(f'Field {self.name} has invalid length.')
                break
            field = item_type(packet)

            if is_schema:
                # NOTE: A counted list runs to the end of the data, so an item it counts
                # running past the octets left is cut, not overrunning a length (#2749).
                context = dict(packet, __data_end__=True) if len(temp) < self._count else packet
                # NOTE: The item the data ends inside reads the fill past it, which the lists in it
                # are told of, so they end with the data too (#2760).
                if present >= 0:
                    context = dict(context, __data_present__=present - (offset - start))
                data = cast('SchemaField', field).unpack(file, context)

                end = file.tell()
                if end <= offset:
                    # NOTE: ``len(temp)`` counts items already parsed, so it reads "after N item(s)",
                    # not an ordinal that would be off by one.
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
                offset = file.tell()

            temp.append(data)

        # NOTE: Items are read to the end of the octets, so those counted past them are
        # not there to read: the data ended first, and the field reads short (#2711).
        if self._count >= 0:
            self._shortfall = max(self._count - len(temp), 0)
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
        one value. That is only the same read when the following hold of the type
        field:

        1. it is the base schema's **first** field, so that it is what sits at the
           front of the option;
        2. it is a :class:`~pcapkit.corekit.fields.numbers.NumberField`, so that
           :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
           reads it through its ordinary per-field branch;
        3. its length is a fixed integer rather than a callable, so that its width
           does not depend on packet data the shortcut has not read.

        All of that is true of every :class:`~pcapkit.corekit.fields.collections.OptionField`
        declared in this package. A base schema registered from outside it -- cf.
        :mod:`pcapkit.foundation.registry` -- need not satisfy it, and is **not**
        rejected: such a base schema is unpacked in full. It parses correctly and
        pays the cost of the second parse. Only the shortcut is withheld, so a base schema whose type field
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
        """Length of option padding data."""
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

        # NOTE: Decided once here (see the docstring); each test falls back to the full unpack rather than
        # raising, so an unexpected base schema cannot turn a registration into an import-time failure.
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
            :attr:`self.option_padding <OptionField.option_padding>` is set
            to the remaining length, which :meth:`Schema.unpack
            <pcapkit.protocols.schema.Schema.unpack>` records in
            ``packet`` as ``__option_padding__`` so that the next fields can
            be aware of it.

            A ``__capture_cut__`` key in ``packet``, false, says that the data
            ends at the length the enclosing layer declares for it, so that an
            area the data ends inside runs past that length rather than being
            cut short by the capture, as
            :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` tells the extension
            headers it walks (:issue:`2694`). Absent, the data may end at a cut.

        Raises:
            FieldValueError: If an option consumes nothing from ``buffer``, since
                the loop below has then no way to get past it.
            ProtocolError: If an option that begins with octets present reads
                past the end of the data, unless the data ends inside the area,
                the option's fields fit it and :meth:`_accepts_cut` keeps it, or
                :meth:`_accepts_short_read` accepts it. Or if the area runs past
                the end of the data where ``packet`` gives ``__capture_cut__``
                as false, the data ending at the length the enclosing layer
                declares rather than at a cut.

        .. versionchanged:: 1.5.0

           An option that begins with octets present and reads past the end of
           the data raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
           where it was parsed from zero-filled octets (:issue:`1325`).

        .. versionchanged:: 1.6.0

           Where the data ends inside the area, as a capture cut short leaves
           it, the list ends with the data, and an option it ends inside is
           kept if its fields fit the area, so :meth:`Schema.unpack
           <pcapkit.protocols.schema.Schema.unpack>` records the cut as
           a short read rather than either error being raised
           (:issue:`2694`). See :meth:`_accepts_cut`, and ``__capture_cut__``
           above.

        """
        length = self._length
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        # NOTE: ``len(data)`` measures the reported schema, not the octets read, so an option reading
        # nothing would spin forever; stream position bounds the loop (#431), ``start`` maps it to offsets.
        start = offset = file.tell()

        # make a copy of the ``packet`` dict so that we can include
        # parsed option schema in the ``packet`` dict
        new_packet = packet.copy()
        new_packet[self.name] = OrderedMultiDict()

        # NOTE: Reads only the type field, as ``Schema.unpack`` reads it, so no option is parsed twice and
        # ``code`` keeps its enum type; a None ``_type_field`` falls back to the full unpack.
        type_field = self._type_field

        # NOTE: An option reading short past its octets would rebuild zeros as values, so it is rejected
        # (#1325) unless a capture cut ends the data inside the area, read as a short read (#2694).
        if isinstance(buffer, bytes):
            present = len(buffer)
        else:
            try:
                present = file.seek(0, io.SEEK_END) - start
                file.seek(start, io.SEEK_SET)
            except (OSError, ValueError):  # a stream that cannot seek to its end counts as whole
                present = self._length
        short = present < self._length
        cut = short and packet.get('__capture_cut__', True)
        tracker = file = _ShortReadTracker(file)  # type: ignore[assignment]

        temp = []  # type: list[_TS]
        while length > 0:
            tracker.short = False
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

            # NOTE: A cut where this option would begin ends the list, the rest left as ``option_padding``
            # (#2694); with no cut the area runs past the data, and a 0 end-of-list code stops below.
            if not consumed and short and code != self._eool:
                if cut:
                    break
                raise ProtocolError(
                    f'Field {self.name} has an option area that runs past the end of '
                    f'the data: {self._length} octet(s) declared, with {present} present'
                )
            schema = self._registry[code]

            # rewind to the beginning of the option
            file.seek(-consumed, io.SEEK_CUR)

            # unpack option using option schema
            data = schema.unpack(file, length, packet)  # type: ignore[call-arg,misc,var-annotated]

            # NOTE: An option the cut lands inside stands if its fields fit the area (``__length__`` >= 0)
            # and it read octets there (#2694); one reaching past the area runs past both (#1325).
            stands = (cut and packet['__length__'] >= 0 and file.tell() > offset
                      and self._accepts_cut(data))
            if tracker.short and consumed > 0 and not stands and not self._accepts_short_read(data):
                raise ProtocolError(
                    f'Field {self.name} has an option that runs past the end of '
                    f'the data: {code!r} at offset {offset - start} of '
                    f'{self._length}, with only {file.tell() - offset} octet(s) '
                    f'of it present'
                )
            new_packet[self.name].add(code, data)
            temp.append(data)

            # update length
            length -= len(data)

            # check for EOOL
            if code == self._eool:
                break

            # NOTE: Checked after the end-of-list break, where an exhausted read decoding as a 0 end code ends
            # as padding; registries whose 0 is not that code (e.g. HOPOPT ``Pad1``) would otherwise spin.
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

    def _accepts_short_read(self, option: '_TS') -> 'bool':  # pylint: disable=unused-argument
        """Whether an option that read past the end of the data may stand.

        Args:
            option: Option just unpacked, which read short and ran past its area
                or past the data at the end of the area.

        Returns:
            :data:`False`, so that :meth:`unpack` refuses the option
            (:issue:`1325`): padding cut short may be content the option's own
            length declares, as a ``PadN`` option's is. A list whose items'
            lengths leave out their trailing padding may override this, as
            :class:`~pcapkit.protocols.transport.sctp.schema.PaddedOptionField`
            does; :meth:`Schema.pack <pcapkit.protocols.schema.Schema.pack>`
            then writes back only the octets read.

        """
        return False

    def _accepts_cut(self, option: '_TS') -> 'bool':  # pylint: disable=unused-argument
        """Whether an option the data ends inside, inside its area, may stand.

        Args:
            option: Option just unpacked, which read short where the data ends
                short of the area declared, and whose fields fit the area.

        Returns:
            :data:`True`, so that :meth:`unpack` keeps the option, as the short
            read :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
            records (:issue:`2694`). A list that keeps such an area as the octets
            captured instead may override this, as
            :class:`~pcapkit.protocols.misc.pcapng.schema.OptionAreaField` does.

        """
        return True
