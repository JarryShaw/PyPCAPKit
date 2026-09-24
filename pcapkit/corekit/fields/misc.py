# -*- coding: utf-8 -*-
"""miscellaneous field class"""

import io
from typing import TYPE_CHECKING, TypeVar, cast

from pcapkit.corekit.fields.field import FieldBase, NoValue
from pcapkit.utilities.exceptions import FieldError, NoDefaultValue

__all__ = [
    'ConditionalField', 'PayloadField',
    'SwitchField', 'ForwardMatchField',
    'NoValueField',
]

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Optional, Type

    from typing_extensions import Self

    from pcapkit.corekit.fields.field import NoValueType
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

_TC = TypeVar('_TC')
_TS = TypeVar('_TS', bound='Schema')
_TP = TypeVar('_TP', bound='Protocol')
_TN = TypeVar('_TN', bound='NoValueType')


class NoValueField(FieldBase[_TN]):
    """Schema field for no value type (or :obj:`None`)."""

    _default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return '0s'

    @property
    def length(self) -> 'int':
        """Field size."""
        return 0

    def pack(self, value: 'Optional[_TN]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        return b''

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TN':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        return None  # type: ignore[return-value]


class ConditionalField(FieldBase[_TC]):
    """Conditional value for protocol fields.

    Args:
        field: Field instance.
        condition: Field condition function (this function should return a bool
            value and accept the current packet :class:`pcapkit.corekit.infoclass.Info`
            as its only argument).

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._field.name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._field.name = value

    @property
    def default(self) -> '_TC | NoValueType':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC | NoValueType') -> 'None':
        """Set field default value."""
        self._field.default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._field.default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def field(self) -> 'FieldBase[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'FieldBase[_TC]',  # pylint: disable=super-init-not-called
                 condition: 'Callable[[dict[str, Any]], bool]') -> 'None':
        self._field = field  # type: FieldBase[_TC]
        self._condition = condition

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Arguments:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`ConditionalField`
        instead of updating the current instance.

        """
        new_self = self.__copy__()
        if new_self._condition(packet):
            new_self._field = new_self._field(packet)
        return new_self

    def pre_process(self, value: '_TC', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return self._field.pre_process(value, packet)

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        if not self._condition(packet):
            return b''
        return self._field.pack(value, packet)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_TC':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return self._field.post_process(value, packet)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        if not self._condition(packet):
            return self._field.default  # type: ignore[return-value]
        return self._field.unpack(buffer, packet)

    def test(self, packet: 'dict[str, Any]') -> 'bool':
        """Test field condition.

        Arguments:
            packet: Current packet.

        Returns:
            bool: Test result.

        """
        return self._condition(packet)


class PayloadField(FieldBase[_TP]):
    """Payload value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value.
        protocol: Payload protocol.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def protocol(self) -> 'Type[_TP]':
        """Payload protocol."""
        if self._protocol is None:
            from pcapkit.protocols.misc.raw import Raw  # type: ignore[unreachable] # pylint: disable=import-outside-top-level # isort:skip
            return Raw
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: 'Type[_TP] | str') -> 'None':
        """Set payload protocol.

        Arguments:
            protocol: Payload protocol.

        """
        if isinstance(protocol, str):
            from pcapkit.protocols import __proto__  # pylint: disable=import-outside-top-level
            protocol = cast('Type[_TP]', __proto__.get(protocol))
        self._protocol = protocol

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 default: '_TP | NoValueType | bytes' = NoValue,
                 protocol: 'Optional[Type[_TP]]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<payload>'
        self._default = default  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]
        self._callback = callback

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = f'{self._length}s' if self._length >= 0 else '1024s'  # use a reasonable default

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`PayloadField`
        instead of updating the current instance.

        """
        new_self = self.__copy__()
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
            new_self._template = f'{new_self._length}s'
        return new_self

    def pack(self, value: 'Optional[_TP | Schema | bytes]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        if value is None:
            if self._default is NoValue:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = cast('_TP', self._default)

        from pcapkit.protocols.schema.schema import \
            Schema  # pylint: disable=import-outside-top-level
        if isinstance(value, bytes):
            return value
        if isinstance(value, Schema):
            return value.pack()
        return value.data  # type: ignore[union-attr]

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TP':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        if self._protocol is None:
            if isinstance(buffer, bytes):  # type: ignore[unreachable]
                return cast('_TP', buffer)
            return cast('_TP', buffer.read())

        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        length = self._length if self._length > 0 else None
        return self._protocol(file, length)  # type: ignore[abstract]


class SwitchField(FieldBase[_TC]):
    """Conditional type-switching field for protocol schema.

    Args:
        selector: Callable function to select field type, which should accept
            the current packet as its only argument and return a field instance.

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._field.name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._field.name = value

    @property
    def default(self) -> '_TC | NoValueType':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC | NoValueType') -> 'None':
        """Set field default value."""
        self._field.default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._field.default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def field(self) -> 'FieldBase[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, selector: 'Callable[[dict[str, Any]], FieldBase[_TC]]' = lambda _: NoValueField()) -> 'None':  # type: ignore[assignment,return-value]
        #self._name = '<switch>'
        self._field = cast('FieldBase[_TC]', NoValueField())
        self._selector = selector

    def __call__(self, packet: 'dict[str, Any]') -> 'SwitchField[_TC]':
        """Call field.

        Args:
            packet: Packet data.

        Returns:
            New field instance.

        This method will return a new instance of :class:`SwitchField`
        instead of updating the current instance.

        """
        new_self = self.__copy__()
        new_self._field = new_self._selector(packet)(packet)
        new_self._field.name = self.name
        return new_self

    def pre_process(self, value: '_TC', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if self._field is None:
            return NoValue  # type: ignore[unreachable]
        return self._field.pre_process(value, packet)

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        if self._field is None:
            return b''  # type: ignore[unreachable]
        return self._field.pack(value, packet)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_TC':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if self._field is None:
            return NoValue  # type: ignore[unreachable]
        return self._field.post_process(value, packet)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        if self._field is None:
            return None  # type: ignore[unreachable]
        return self._field.unpack(buffer, packet)


def nested_packet_context(packet: 'dict[str, Any]') -> 'dict[str, Any]':
    """Build the packet context handed to a nested schema's field callbacks.

    Args:
        packet: The enclosing schema's own packet data.

    Returns:
        A plain :class:`dict` holding a shallow copy of ``packet``'s own names,
        plus the reserved ``__packet__`` key bound to ``packet`` itself.

    Notes:
        A nested schema's field callbacks are written exactly like a top-level
        schema's -- ``length=lambda pkt: pkt['length']`` -- so a name the
        nested schema does not itself declare has to resolve to the enclosing
        schema's value rather than raise :exc:`KeyError`. Copying the
        enclosing names in is what gives that, with no lookup protocol to
        implement: every mapping operation is :class:`dict`'s own, so
        ``pkt[key]``, ``key in pkt``, :meth:`~dict.get`,
        :meth:`~dict.setdefault`, :meth:`~dict.pop`, ``==``, iteration and
        ``dict(**pkt)`` all behave exactly as a caller reading the code would
        expect, and none of them needs an override.

        The enclosing schema is also reachable *unconditionally* under the
        reserved ``__packet__`` key, for a callback that needs to name the
        outer schema specifically rather than whichever schema happens to
        declare a given field -- see
        :func:`pcapkit.protocols.schema.misc.pcapng.packet_byteorder` and
        :meth:`~pcapkit.protocols.schema.misc.pcapng.BlockType.post_process`
        for why that distinction matters, and note that both already
        hand-roll this exact fallback and so are unaffected by (and do not
        need to route through) this function.

        Nothing written through the returned mapping reaches ``packet``,
        because the returned mapping *is* a copy: a nested schema can set --
        or shadow -- a name also declared by the enclosing schema without the
        write ever touching the enclosing schema's own data, and without the
        write silently disappearing either. That matters concretely rather
        than hypothetically:
        :class:`~pcapkit.protocols.schema.internet.mh.CGAExtension` declares
        its own ``length`` while the option enclosing it declares ``length``
        too, so handing a nested schema the enclosing mapping itself would let
        the inner ``length`` overwrite the outer one mid-pack.

        Two consequences of it being a copy rather than a live view, both
        deliberate and neither reached by any current call site. A name
        deleted from the returned mapping is simply gone, rather than
        reverting to the enclosing schema's value. And the copy is taken when
        this function is called, so a later mutation of ``packet`` is not
        observed through it -- ``__packet__`` remains bound to the live
        enclosing mapping for any callback that needs the current value.

        No dedicated class and no :class:`~collections.ChainMap`. Earlier
        versions of this function returned each in turn: a
        :class:`~collections.ChainMap` first, then a hand-written
        :class:`dict` subclass adopted when the ``ChainMap`` was suspected of
        corrupting the shared :class:`~abc.ABCMeta` cache every
        :class:`Schema <pcapkit.protocols.schema.schema.Schema>` subclass used
        to share on CPython <= 3.10 (issue #439), and then a
        :class:`~collections.ChainMap` again once that suspicion was doubted.
        A plain :class:`dict` ends the question: it satisfies every
        ``packet: 'dict[str, Any]'`` annotation on the rest of the field
        classes natively, so no :func:`~typing.cast` is needed at the call
        site, and it cannot interact with :class:`~abc.ABCMeta` at all because
        :class:`dict` is not an :class:`~abc.ABCMeta`-based class.

        On the #439 suspicion itself, for the record, since it drove two
        rewrites: it is *probably* wrong and no longer decidable. What is
        directly measured is that the cache keys on the **exact type
        queried**, so asking about a :class:`~collections.ChainMap` instance
        caches lookups for :class:`~collections.ChainMap` and not for
        :class:`dict`, and that the poisoning observed in #439 came from
        ordinary code asking :func:`isinstance` about a plain :class:`dict` --
        :func:`~pcapkit.corekit.infoclass.Info.__update__` does exactly that.
        Against that, swapping the ``ChainMap`` for a plain literal was, at
        the time and on a real CPython 3.10 venv, enough to move
        ``test_pcapng_remaining_constructor_branches_and_custom_dispatch``
        between passing and failing, toggled both ways. The likeliest
        reconciliation -- that the ``ChainMap`` was never causal but changed
        which concrete types flowed through unrelated :func:`isinstance` calls
        in the same run, and so changed *when* the pre-existing corruption
        fired -- is plausible rather than demonstrated, and cannot now be
        tested: #439 has been fixed directly, every :class:`Schema` subclass
        gets its own ``_abc_impl``, and the original conditions no longer
        exist. It does not affect correctness either way.

    """
    return {**packet, '__packet__': packet}


class SchemaField(FieldBase[_TS]):
    """Schema field for protocol schema.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        schema: Field schema.
        default: Default value for field.
        packet: Optional packet data for unpacking and/or packing purposes.
        callback: Callback function to process field value, which should accept
            the current field and the current packet as its arguments.

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
    def schema(self) -> 'Type[_TS]':
        """Field schema."""
        return self._schema

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]' = lambda _: -1,
                 schema: 'Optional[Type[_TS]]' = None,
                 default: '_TS | NoValueType | bytes' = NoValue,
                 packet: 'Optional[dict[str, Any]]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<schema>'
        self._callback = callback

        if packet is None:
            packet = {}
        self._packet = packet

        if schema is None:
            raise FieldError('Schema field must have a schema.')
        self._schema = schema

        if isinstance(default, bytes):
            default = cast('_TS', schema.unpack(default))  # type: ignore[call-arg,misc]
        self._default = default

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length
        self._template = f'{self._length}s' if self._length >= 0 else '1024s'  # use a reasonable default

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            New field instance.

        This method will return a new instance of :class:`SchemaField`
        instead of updating the current instance.

        """
        new_self = self.__copy__()
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
            new_self._template = f'{new_self._length}s' if self._length >= 0 else '1024s'  # use a reasonable default
        return new_self

    def pack(self, value: 'Optional[_TS | bytes]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        Notes:
            ``packet`` is reachable from the nested schema's own field
            callbacks both under a ``__packet__`` key and, for a name the
            nested schema does not itself declare, directly -- see
            :func:`~pcapkit.corekit.fields.misc.nested_packet_context`.

        """
        if value is None:
            if self._default is NoValue:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = cast('_TS', self._default)

        if isinstance(value, bytes):
            return value

        packet.update(self._packet)
        return value.pack(nested_packet_context(packet))

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TS':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        Notes:
            ``packet`` is reachable from the nested schema's own field
            callbacks both under a ``__packet__`` key and, for a name the
            nested schema does not itself declare, directly -- see
            :func:`~pcapkit.corekit.fields.misc.nested_packet_context`.

        """
        if isinstance(buffer, bytes):
            file = io.BytesIO(buffer)  # type: IO[bytes]
        else:
            file = buffer

        packet.update(self._packet)
        return cast('_TS', self._schema.unpack(file, self.length,  # type: ignore[call-arg,misc]
                                                nested_packet_context(packet)))


class ForwardMatchField(FieldBase[_TC]):
    """Schema field for non-capturing forward matching.

    Args:
        field: Field to forward match.

    """

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._field.name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._field.name = value

    @property
    def default(self) -> '_TC | NoValueType':
        """Field default value."""
        return self._field.default

    @default.setter
    def default(self, value: '_TC | NoValueType') -> 'None':
        """Set field default value."""
        self._field.default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._field.default = NoValue

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._field.template

    @property
    def length(self) -> 'int':
        """Field size."""
        return self._field.length

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return True

    @property
    def field(self) -> 'FieldBase[_TC]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'FieldBase[_TC]') -> 'None':
        #self._name = '<forward_match>'
        self._field = field

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Arguments:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`ConditionalField`
        instead of updating the current instance.

        """
        new_self = self.__copy__()
        new_self._field = new_self._field(packet)
        return new_self

    def pack(self, value: 'Optional[_TC]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        return b''

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_TC':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        """
        return self._field.unpack(buffer, packet)
