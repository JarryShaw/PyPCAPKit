# -*- coding: utf-8 -*-
"""numerical field class"""

import enum
import functools
import math
from typing import TYPE_CHECKING, Generic, TypeVar, Union, cast

import aenum

from pcapkit.corekit.fields.field import Field, NoValue
from pcapkit.utilities.exceptions import BaseError, FieldValueError, IntError, ProtocolError

__all__ = [
    'NumberField',
    'Int32Field', 'UInt32Field',
    'Int16Field', 'UInt16Field',
    'Int64Field', 'UInt64Field',
    'Int8Field', 'UInt8Field',
    'EnumField',
]

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Callable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal, Self

    from pcapkit.corekit.fields.field import NoValueType

_T = TypeVar('_T', bound='int')


class NumberField(Field[int], Generic[_T]):
    """Numerical value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        signed: Whether the field is signed; :data:`None` defers to the
            class-level ``__signed__``, which this class leaves unset and so
            means unsigned.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        IntError: If no ``length`` is given and ``__length__`` fixes none either.
        FieldValueError: If ``signed`` contradicts a sign already fixed by
            ``__signed__`` -- never from this class, which fixes none.

    Notes:
        A subclass such as :class:`UInt32Field` fixes the sign through
        ``__signed__``, so ``signed`` there is at best redundant. It used to be
        discarded outright, in both directions, which meant
        ``UInt32Field(signed=True)`` handed back an unsigned field whose values
        only looked wrong once the high bit was set -- see GitHub issue #545. A
        contradicting value is now rejected instead; omitting it, or passing the
        sign the class already fixes, stays legal.

    """

    __length__ = None  # type: Optional[int]
    __template__ = None  # type: Optional[str]
    __signed__ = None  # type: Optional[bool]

    @property
    def bit_length(self) -> 'int':
        """Field bit length."""
        return self._bit_length

    def __init__(self, length: 'Optional[int | Callable[[dict[str, Any]], int]]' = None,
                 default: 'int | NoValueType' = NoValue, signed: 'Optional[bool]' = None,
                 byteorder: 'Literal["little", "big"]' = 'big',
                 bit_length: 'Optional[int]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        if length is None:
            if self.__length__ is None:
                raise IntError(f'Field has no length.')
            length = self.__length__
        super().__init__(length, default, callback)

        if bit_length is not None:
            self._bit_length = bit_length
            self._bit_mask = (1 << bit_length) - 1
        else:
            self._bit_length, self._bit_mask = -1, -1

        # NOTE: ``__signed__`` fixes the sign for a subclass such as
        # :class:`UInt32Field`, and used to *discard* the ``signed`` argument to
        # do it -- in both directions, so ``UInt32Field(signed=True)`` returned
        # an unsigned field and ``Int8Field(signed=False)`` a signed one, both
        # without a word. ``None`` is what "not given" looks like, which is what
        # lets a contradicting value be told apart from the default and rejected
        # while leaving an agreeing one alone. See #545.
        if self.__signed__ is None:
            self._signed = False if signed is None else bool(signed)
        elif signed is None or bool(signed) == self.__signed__:
            self._signed = self.__signed__
        else:
            raise FieldValueError(
                f'{type(self).__name__}: field is fixed as '
                f'{"signed" if self.__signed__ else "unsigned"}, '
                f'but signed={signed!r} was given'
            )
        self._byteorder = byteorder
        self._need_process = False

        endian = '>' if byteorder == 'big' else '<'
        if self.__template__ is not None:
            struct_fmt = self.__template__
        else:
            # NOTE: ``self._signed``, not the ``signed`` argument. A subclass
            # that fixes ``__signed__`` without also fixing ``__template__``
            # would otherwise build its template from the argument and parse
            # with the opposite sign to the one it declared.
            struct_fmt = self.build_template(self._length, self._signed)
        self._template = f'{endian}{struct_fmt}'

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            New instance of :class:`NumberField`.

        This method will return a new instance of :class:`NumberField` instead of
        updating the current instance.

        Raises:
            ProtocolError: If the resolved ``length`` is negative and
                ``bit_length`` was not supplied -- e.g. a ``length`` callback
                such as ``lambda pkt: pkt['len'] - 4`` resolving below zero
                once the wire value it reads is smaller than the subtrahend.
                Left alone, ``1 << (length * 8)`` raises a bare, uncatchable
                :exc:`ValueError` (``negative shift count``) here, before
                :attr:`~pcapkit.corekit.fields.field.FieldBase.length` (see
                its own :exc:`ProtocolError` guard, #805/#811/#827) or
                :meth:`build_template` ever sees the value: this method sets
                ``self._bit_length`` from the resolved length eagerly, as a
                cache, and shifts by it immediately, so the crash happens on
                *this* line rather than on the later, already-guarded ones.
                See GitHub issue #828. A resolved length of exactly ``0`` is a
                legitimate empty field (e.g. ``len=4`` above resolving to
                ``0``) and is left alone.

        Notes:
            Rebuilding the template here is what applies a callable ``length``,
            and :meth:`build_template` recomputes ``self._need_process`` as it
            goes, so the flag and the template always describe the same width.
            They did not always: see GitHub issue #591.

        """
        new_self = super().__call__(packet)

        if new_self._bit_length < 0:
            if new_self._length < 0:
                raise ProtocolError(
                    f'Field {new_self.name} resolved to a negative length; '
                    f'length={new_self._length!r}'
                )
            new_self._bit_length = new_self._length * 8
            new_self._bit_mask = (1 << new_self._bit_length) - 1

        endian = '>' if new_self._byteorder == 'big' else '<'
        struct_fmt = new_self.build_template(new_self._length, new_self._signed)

        new_self._template = f'{endian}{struct_fmt}'
        return new_self

    def build_template(self, length: 'int', signed: 'bool') -> 'str':
        """Build template for field.

        Arguments:
            length: Field size (in bytes)
            signed: Whether the field is signed

        Returns:
            Template for field.

        Notes:
            ``self._need_process`` is **assigned** here rather than only ever
            raised, so that it always describes the ``length`` this template
            was built for. It used to be
            set :data:`True` in the fall-through branch and never put back,
            which made it a latch: a callable ``length`` is a placeholder of
            ``-1`` at construction, ``-1`` takes the fall-through branch, and
            the flag then survived the rebuild in :meth:`__call__` that
            resolved the real width. :meth:`pre_process` consequently handed
            :obj:`bytes` to a template that had become ``>Q`` -- or ``>I``,
            ``>H``, ``>B`` -- and :func:`struct.pack` refused it. See GitHub
            issue #591.

            Assigning it is what tells a placeholder apart from a width that
            genuinely needs byte packing, without having to remember that a
            placeholder was ever in play: the answer for ``-1`` is
            :data:`True`, the answer for ``8`` is :data:`False`, and whichever
            width is in force now is the one that decides. A callable
            resolving to, say, ``3`` still takes the fall-through branch and
            still gets :data:`True`, because for ``3`` that is the correct
            answer rather than a leftover one.

        """
        if length == 8:       # unpack to 8-byte integer (long long)
            struct_fmt, need_process = 'q' if signed else 'Q', False
        elif length == 4:     # unpack to 4-byte integer (int / long)
            struct_fmt, need_process = 'i' if signed else 'I', False
        elif length == 2:     # unpack to 2-byte integer (short)
            struct_fmt, need_process = 'h' if signed else 'H', False
        elif length == 1:     # unpack to 1-byte integer (char)
            struct_fmt, need_process = 'b' if signed else 'B', False
        else:                 # do not unpack
            struct_fmt, need_process = f'{length}s', True
        self._need_process = need_process
        return struct_fmt

    def pre_process(self, value: 'int', packet: 'dict[str, Any]') -> 'int | bytes':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Notes:
            Masking against :attr:`self._bit_mask <NumberField.bit_length>`
            truncates the value to the field's bit length, but it also turns a
            negative value into its unsigned two's-complement pattern, which
            neither :func:`struct.pack` nor :meth:`int.to_bytes` accepts for a
            signed field. A signed field therefore maps the pattern back into
            its signed range afterwards, so that e.g. a PCAP-NG section length
            of ``-1`` (section length not specified) can be written out.

            A field packed without having been resolved -- so with ``_length``
            still negative -- has its width derived from the value instead, and
            that rebuild can land on a width :func:`struct` has a native
            integer code for. The flag is therefore consulted **after** the
            rebuild rather than before it, since deciding first and rebuilding
            second is how the template and the value being returned came to
            disagree in the first place. C.f. #591.

            That width is a **ceiling** of the bit length over eight, and it is
            written as one. It used to read
            ``math.ceil(value.bit_length() // 8)``, which is not a ceiling at
            all: :func:`math.ceil` of an :obj:`int` is that :obj:`int`, so the
            ``//`` had already floored the quotient and the outer call did
            nothing. Every value whose bit length is not an exact multiple of
            eight was therefore sized one octet short -- ``256`` at one octet,
            ``65536`` at two, and ``1`` itself at *zero* -- which
            :meth:`int.to_bytes` and :func:`struct.pack` both refuse. See GitHub
            issue #599.

        """
        value = value & self._bit_mask
        if self._signed and value > self._bit_mask >> 1:
            value -= self._bit_mask + 1

        if self._need_process and self._length < 0:
            self._length = math.ceil(value.bit_length() / 8)

            endian = '>' if self._byteorder == 'big' else '<'
            struct_fmt = self.build_template(self._length, self._signed)

            self._template = f'{endian}{struct_fmt}'

        if not self._need_process:
            return value

        return value.to_bytes(
            self._length, self._byteorder, signed=self._signed
        )

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'int':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if not self._need_process:
            return cast('int', value) & self._bit_mask
        return int.from_bytes(
            cast('bytes', value), self._byteorder, signed=self._signed
        ) & self._bit_mask


class Int32Field(NumberField):
    """Integer value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`True` here, so a
            contradicting :data:`False` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`False`, contradicting
            the sign this class fixes.

    """

    __length__ = 4
    __template__ = 'i'
    __signed__ = True


class UInt32Field(NumberField):
    """Unsigned integer value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`False` here, so a
            contradicting :data:`True` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`True`, contradicting
            the sign this class fixes.

    """

    __length__ = 4
    __template__ = 'I'
    __signed__ = False


class Int16Field(NumberField):
    """Short integer value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`True` here, so a
            contradicting :data:`False` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`False`, contradicting
            the sign this class fixes.

    """

    __length__ = 2
    __template__ = 'h'
    __signed__ = True


class UInt16Field(NumberField):
    """Unsigned short integer value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`False` here, so a
            contradicting :data:`True` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`True`, contradicting
            the sign this class fixes.

    """

    __length__ = 2
    __template__ = 'H'
    __signed__ = False


class Int64Field(NumberField):
    """Long integer value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`True` here, so a
            contradicting :data:`False` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`False`, contradicting
            the sign this class fixes.

    """

    __length__ = 8
    __template__ = 'q'
    __signed__ = True


class UInt64Field(NumberField):
    """Unsigned long integer value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`False` here, so a
            contradicting :data:`True` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`True`, contradicting
            the sign this class fixes.

    """

    __length__ = 8
    __template__ = 'Q'
    __signed__ = False


class Int8Field(NumberField):
    """Byte value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`True` here, so a
            contradicting :data:`False` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`False`, contradicting
            the sign this class fixes.

    """

    __length__ = 1
    __template__ = 'b'
    __signed__ = True


class UInt8Field(NumberField):
    """Unsigned byte value for protocol fields.

    Args:
        length: Field size (in bytes).
        default: Field default value, if any.
        signed: Whether the field is signed; fixed as :data:`False` here, so a
            contradicting :data:`True` is rejected rather than ignored.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Raises:
        FieldValueError: If ``signed`` is given as :data:`True`, contradicting
            the sign this class fixes.

    """

    __length__ = 1
    __template__ = 'B'
    __signed__ = False


class EnumField(NumberField[Union[enum.IntEnum, aenum.IntEnum]]):
    """Enumerated value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        signed: Whether the field is signed; :data:`None` defers to the
            class-level ``__signed__``, which this class leaves unset and so
            means unsigned.
        byteorder: Field byte order.
        bit_length: Field bit length.
        namespace: Field namespace (a :class:`enum.IntEnum` class).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Notes:
        A wire value the ``namespace`` registry has no member for resolves to a
        nameless pseudo-member rather than failing the parse -- see
        :meth:`post_process`.

    """

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: 'StdlibEnum | AenumEnum | NoValueType' = NoValue,
                 signed: 'Optional[bool]' = None,
                 byteorder: 'Literal["little", "big"]' = 'big',
                 bit_length: 'Optional[int]' = None,
                 namespace: 'Optional[Type[StdlibEnum] | Type[AenumEnum]]' = None,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, default, signed, byteorder, bit_length, callback)

        self._namespace = namespace

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'StdlibEnum | AenumEnum':
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value -- the registry member declared for the value,
            or a nameless pseudo-member carrying the value itself when the
            registry declares none.

        Raises:
            BaseError: Whatever in-library error the registry raised for the
                value, re-raised untouched.

        Notes:
            The registry is consulted through its constructor, which raises for
            a value no member and no ``_missing_`` rule accounts for. That raise
            used to propagate, and it is :mod:`aenum`'s own bare
            :exc:`ValueError`: not one of :mod:`pcapkit.utilities.exceptions`,
            so a caller cannot tell it from a bug of its own, and not an
            :exc:`EOFError`, so :meth:`Extractor.record_frames
            <pcapkit.foundation.extraction.Extractor.record_frames>` does not
            catch it. One unassigned code therefore cost the whole extraction.

            It also made the "unknown" reader the formats require unreachable
            for any genuinely unassigned code -- PCAP-NG's
            :class:`~pcapkit.protocols.schema.misc.pcapng.UnknownBlock`, and the
            ``unassigned`` option readers of IPv4, TCP, HOPOPT, MH and HIP --
            because the lookup failed several frames before the dispatch that
            would have selected it. PCAP-NG repeats a block's total length at
            both ends precisely so that a reader can skip a block type it does
            not recognise; that skip is what this fallback restores. See GitHub
            issue #701.

            The fallback is the same nameless pseudo-member this method already
            builds for a field carrying no registry at all, so it is a value
            shape the package already produces and the dump layer already
            renders -- as ``<unknown>::<unassigned> [28]``, through
            :func:`~pcapkit.dumpkit.common.render_enum`, not through the
            ``name is None`` branch #648 added, which a member named
            ``<unassigned>`` never takes -- and one an :class:`int`-keyed
            dispatch registry looks up by value like any declared member. It is
            built per value rather than grafted onto
            the registry with :func:`aenum.extend_enum`, for two reasons: a
            capture carrying many distinct unassigned codes would otherwise grow
            a process-global registry without bound, which is the growth
            :meth:`ProtocolBase._lookup_registry
            <pcapkit.protocols.protocol.ProtocolBase._lookup_registry>` exists
            to avoid; and a stdlib :class:`enum.IntEnum` registry is then
            handled exactly like an :class:`aenum.IntEnum` one.

            Only a *foreign* rejection is absorbed. A registry rejecting a value
            with one of :mod:`pcapkit.utilities.exceptions` has made a
            deliberate decision that this layer -- which sees only that the value
            arrived in a field of some width -- is in no position to overrule, so
            an in-library error propagates unchanged and it is only :mod:`aenum`'s
            and :mod:`enum`'s "no member has this value" that becomes a
            pseudo-member. That is what keeps the fallback from being an
            unconditional ``except ValueError: pass``.

            No registry under :mod:`pcapkit.const` raises an in-library error
            from its guard today, and deliberately so: a generated guard raises a
            bare, unlogged :exc:`ValueError` precisely because the generated
            ``get()``'s ``except ValueError`` fallback has to keep catching it
            (GitHub issues #584 and #647). The registries that *do* bound
            themselves to a width and reject outside it are the bit-flag ones --
            :class:`pcapkit.const.tcp.flags.Flags` among them -- and none of
            those is named as the namespace of a plain :class:`EnumField`
            anywhere in the package, so no in-library guard loses its force
            through this method. The distinction is therefore for a registry
            registered from outside :mod:`pcapkit.const`, which has no such
            obligation to stay quiet.

        """
        value = super().post_process(value, packet)
        if self._namespace is not None:
            try:
                return self._namespace(value)
            except ValueError as error:
                # NOTE: An in-library rejection is pcapkit's own decision about
                # the value, rather than the enumeration library reporting that
                # no member carries it, so it is not this layer's to absorb.
                if isinstance(error, BaseError):
                    raise
        return self._pseudo_member(value)

    def _pseudo_member(self, value: 'int') -> 'StdlibEnum | AenumEnum':
        """Build the bounded nameless pseudo-member this method falls back to
        when ``value`` is a foreign miss rather than an in-library rejection.

        Returns:
            A single-member, throwaway :class:`enum.IntEnum` instance, built
            fresh per call rather than :func:`~aenum.extend_enum`-ed onto
            ``self._namespace``, per this method's own docstring above.

        """
        unknown = enum.IntEnum('<unknown>', {
            '<unassigned>': value,
        }, module='pcapkit.const', qualname='pcapkit.const.<unknown>')
        return getattr(unknown, '<unassigned>')

    @staticmethod
    def _unregistered_member(namespace: 'Type[StdlibEnum] | Type[AenumEnum]',
                             value: 'Any', name: 'str' = '<unassigned>',
                             **attrs: 'Any') -> 'Any':
        """Build a member of ``namespace``, absent from every one of its own
        lookup tables, for a value a *parse* -- rather than a direct call to
        the registry's own ``get()`` -- resolved without anyone asking for a
        name.

        GitHub issue #575: the owner's ruling is that an unassigned wire value
        should resolve to a real member of the registry the field names --
        ``isinstance`` against it and every ancestor holds, and it renders and
        dispatches exactly like a declared one -- provided building it never
        grows the registry, which is the whole reason the field stopped
        calling ``get()`` unconditionally in the first place. This is what
        gets there: it calls ``namespace``'s own storage base's ``__new__``
        directly -- :class:`str` or :class:`int`, whichever ``namespace``
        derives from -- which skips ``namespace``'s *own* ``__new__``
        entirely, and with it the ``cls.__registry__.add(...)`` /
        ``cls.__members_ns__[...] = ...`` line every registry in this package
        uses to record a member it mints. No entry is added to
        ``_member_map_`` or ``_value2member_map_`` either, since those are
        only ever touched by the metaclass machinery :func:`aenum.extend_enum`
        drives, which this bypasses completely.

        Note:
            Building a member this way, rather than as some other type
            altogether, is why :meth:`~pcapkit.protocols.schema.transport.tcp.PortEnumField.post_process`
            and its siblings need this rather than :meth:`_pseudo_member`:
            the result answers ``isinstance(result, AppType)`` truthfully,
            which matters to at least seven ``isinstance`` sites elsewhere in
            :mod:`pcapkit.protocols` (see ``test_a_member_is_still_an_apptype``
            in ``tests/const/test_const_apptype_split_unit.py``), and a value
            that fails all of them would be a second defect standing in for
            the one this fix removes.

            The member this returns is absent from ``_value2member_map_``, so
            a *value*-keyed lookup on it -- ``self._namespace(value)`` --
            still raises exactly as it did before this existed. Nothing on the
            parse or reconstruction path does that to a value it just resolved
            this way, which is what keeps this safe to return from
            ``post_process``. A direct call to
            :meth:`~pcapkit.const.reg.apptype.AppType.get` for the same port
            is a different matter and deliberately unchanged: asking the
            registry for a name is an explicit request for a named member, so
            it still mints one -- measured on this tree,
            ``AppType.get(54321, proto=tcp)`` returns ``PORT_54321_tcp`` and
            takes ``TCP.__members__`` from 6147 to 6148, and a second call
            with the same port returns that member rather than raising. Two
            unregistered members for the same value also compare equal
            without being identical, since
            :class:`~pcapkit.const.reg.apptype.AppType` and
            :class:`~pcapkit.const.pcapng.option_type.OptionType` both define
            ``__eq__``/``__hash__`` off an attribute (``.port`` /
            ``.opt_value``) rather than object identity -- harmless for every
            reader in this package, since none compares one with ``is`` or
            keys a mapping on it expecting identity, but worth knowing before
            reusing this elsewhere.

            :mod:`pickle` and :func:`copy.copy`/:func:`copy.deepcopy` all
            reduce an :class:`~enum.Enum` member through
            ``Enum.__reduce_ex__``, which returns ``(cls, (value,))`` -- the
            one lookup this member is deliberately absent from. Left alone
            that is a genuine regression rather than a pre-existing
            limitation, because the call sites used to *mint*, so the member
            was registered and a round-trip worked. Measured on CPython
            3.14.7, resolving port 53406 through
            :class:`~pcapkit.protocols.schema.transport.tcp.PortEnumField`:
            on ``83b58ebda`` ``pickle.loads(pickle.dumps(member))`` returned
            the member, and with the mint removed and nothing in its place it
            raised ``ValueError: 'unknown [53406 - tcp]' is not a valid TCP``
            -- while ``pickle.dumps`` still succeeded, so the failure
            surfaced only on read-back rather than where it was caused.

            So ``__reduce_ex__`` is set on the member itself, reducing it to
            :func:`_rebuild_unregistered_member` instead of to a value lookup.
            Both :mod:`pickle` and :mod:`copy` fetch that attribute with
            :func:`getattr` on the object rather than on its type, so a
            per-instance override is honoured: verified against the C
            :mod:`pickle` accelerator on every protocol from 0 to 5, against
            the pure-Python ``pickle._Pickler``, and against
            :func:`copy.copy`/:func:`copy.deepcopy` both as they are on 3.11+
            and with CPython's ``Enum.__copy__``/``__deepcopy__`` deleted to
            emulate 3.10, where those two do not exist. Rebuilding re-enters
            this method rather than ``namespace.__new__``, so an unpickled
            member is unregistered exactly as the original was and the
            registry does not grow -- ``TCP.__members__`` measured at 6147
            before and after. On 3.11+ ``copy``/``deepcopy`` still return the
            member itself, since ``Enum.__copy__`` short-circuits ahead of
            any reduction; on 3.10 they return an equal rebuilt one, which is
            the same answer for an immutable value.

        Args:
            namespace: The concrete registry class to build the member as an
                instance of. ``isinstance`` holds against it and every
                ancestor; it never gains an entry in any of its own tables.
            value: The value ``namespace``'s own constructor would have
                wrapped -- e.g. the crafted string
                :meth:`~pcapkit.const.reg.apptype.AppType.__new__` builds from
                a name, a port and a transport, or
                :meth:`~pcapkit.const.pcapng.option_type.OptionType.__new__`'s
                equivalent -- kept the same shape here so a rendered or
                re-keyed member reads the same either way.
            name: The member's own ``.name``; ``'<unassigned>'`` matches every
                other nameless value this package produces.
            **attrs: Extra attributes to set on the returned member, matching
                the shape the caller's registry gives its real members --
                :class:`~pcapkit.const.reg.apptype.AppType`'s ``.port``,
                ``.svc`` and ``.proto``, or
                :class:`~pcapkit.const.pcapng.option_type.OptionType`'s
                ``.opt_name`` and ``.opt_value``.

        Returns:
            The unregistered member.

        Raises:
            TypeError: If ``namespace`` derives from neither :class:`str` nor
                :class:`int` -- every registry this package builds does one or
                the other, and guessing wrong for some future one would ship
                a member silently missing whatever its storage base provides,
                rather than saying plainly that this needs extending first.

        """
        obj: 'Any'
        if issubclass(namespace, str):
            obj = str.__new__(namespace, value)
        elif issubclass(namespace, int):
            obj = int.__new__(namespace, value)
        else:
            raise TypeError(
                f'{namespace!r} derives from neither str nor int; '
                '_unregistered_member does not know how to build one of its members')
        # NOTE: setting the enum protocol's own name/value attributes
        # directly, rather than through namespace's own __new__, is what
        # skips the registration that __new__ would otherwise have done.
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        for attr_name, attr_value in attrs.items():
            setattr(obj, attr_name, attr_value)
        # NOTE: ``Enum.__reduce_ex__`` reduces a member to ``(cls, (value,))``,
        # i.e. to the one lookup this member is deliberately absent from, so
        # pickle and copy would both raise on it without this. Overriding it
        # per instance -- which pickle and copy both honour, since both fetch
        # it with getattr on the object rather than on its type -- rebuilds an
        # equivalent unregistered member instead. functools.partial rather
        # than a closure keeps this off obj itself, so the member does not
        # become part of a reference cycle merely by being reducible.
        obj.__reduce_ex__ = functools.partial(
            _reduce_unregistered_member, namespace, value, name, attrs)
        return obj


def _rebuild_unregistered_member(namespace: 'Type[StdlibEnum] | Type[AenumEnum]',
                                 value: 'Any', name: 'str',
                                 attrs: 'dict[str, Any]') -> 'Any':
    """Rebuild the member :meth:`EnumField._unregistered_member` returned.

    This is what :mod:`pickle` and :mod:`copy` reconstruct through, in place of
    the value lookup ``Enum.__reduce_ex__`` would otherwise have reduced the
    member to. It is a module-level function rather than a method so that every
    :mod:`pickle` protocol can name it: protocols below 4 cannot reference a
    callable nested inside a class.

    Args:
        namespace: The registry class to rebuild the member as an instance of.
        value: The member's ``_value_``.
        name: The member's ``_name_``.
        attrs: The extra attributes the member carried.

    Returns:
        A member equal to the original and, like it, absent from every one of
        ``namespace``'s lookup tables -- rebuilding goes back through
        :meth:`EnumField._unregistered_member` and never through
        ``namespace.__new__``, so it cannot register anything either.

    """
    return EnumField._unregistered_member(  # pylint: disable=protected-access
        namespace, value, name, **attrs)


def _reduce_unregistered_member(  # pylint: disable=unused-argument
        namespace: 'Type[StdlibEnum] | Type[AenumEnum]',
        value: 'Any', name: 'str', attrs: 'dict[str, Any]',
        protocol: 'int') -> 'tuple[Callable[..., Any], tuple[Any, ...]]':
    """The ``__reduce_ex__`` :meth:`EnumField._unregistered_member` installs.

    Bound to its first four arguments with :func:`functools.partial`, so that
    the reducer holds the ingredients of the member rather than the member
    itself.

    Args:
        namespace: The registry class the member is an instance of.
        value: The member's ``_value_``.
        name: The member's ``_name_``.
        attrs: The extra attributes the member carries.
        protocol: The :mod:`pickle` protocol version, ignored -- the reduction
            is the same for all of them, and :mod:`copy` passes 4 here.

    Returns:
        A two-tuple of :func:`_rebuild_unregistered_member` and its arguments.

    """
    return (_rebuild_unregistered_member, (namespace, value, name, attrs))
