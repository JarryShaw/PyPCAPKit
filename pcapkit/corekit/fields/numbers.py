# -*- coding: utf-8 -*-
"""numerical field class"""

import enum
import math
from typing import TYPE_CHECKING, Generic, TypeVar, Union, cast

import aenum

from pcapkit.corekit.fields.field import Field, NoValue
from pcapkit.utilities.exceptions import BaseError, FieldValueError, IntError

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

        Notes:
            Rebuilding the template here is what applies a callable ``length``,
            and :meth:`build_template` recomputes ``self._need_process`` as it
            goes, so the flag and the template always describe the same width.
            They did not always: see GitHub issue #591.

        """
        new_self = super().__call__(packet)

        if new_self._bit_length < 0:
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
        unknown = enum.IntEnum('<unknown>', {
            '<unassigned>': value,
        }, module='pcapkit.const', qualname='pcapkit.const.<unknown>')
        return getattr(unknown, '<unassigned>')
