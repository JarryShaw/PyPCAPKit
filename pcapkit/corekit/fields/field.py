# -*- coding: utf-8 -*-
"""Base Fields
================

.. module:: pcapkit.corekit.fields.field

:mod:`pcapkit.corekit.fields.field` contains the base field classes.

.. versionremoved:: 1.3.0

   ``pcapkit.corekit.fields.field._Field``, renamed
   :class:`~pcapkit.corekit.fields.field.FieldBase` with no alias left behind.

.. versionremoved:: 1.5.0

   ``pcapkit.corekit.fields.field.NoValueType``, now
   :class:`pcapkit.corekit.sentinels.NoValueType` (:issue:`911`,
   :issue:`1744`), and ``pcapkit.corekit.fields.field.NoValue``, now
   :data:`pcapkit.corekit.sentinels.NO_VALUE` (:issue:`937`).

"""

import abc
import contextlib
import contextvars
import re
import struct
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.sentinels import NO_VALUE
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import FieldValueError, NoDefaultValue, ProtocolError

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Iterator, Optional

    from typing_extensions import Self

    from pcapkit.corekit.sentinels import NoValueType
    from pcapkit.protocols.schema.schema import Schema

_T = TypeVar('_T')

#: ContextVar[Optional[list[int]]]: Running ``[octets supplied, octets
#: synthesised]`` ledger for :meth:`FieldBase.unpack`, against which
#: :data:`~pcapkit.utilities.config.ZERO_PAD_BUDGET_RATIO` is enforced.
#:
#: A :class:`~contextvars.ContextVar` rather than a plain module global so that
#: a thread parsing one capture cannot spend the budget of a thread parsing
#: another: a new thread runs in an empty :class:`~contextvars.Context`, so it
#: reads the default and installs a ledger of its own. The default is
#: :data:`None` rather than a list precisely because ``ContextVar.get()`` hands
#: back the *same* default object to every context, so a mutable default would
#: be the shared global this is meant to avoid.
#:
#: Measured, because the two cases differ and the difference is easy to state
#: wrongly: a thread gets its own ledger, but an :mod:`asyncio` task does *not*
#: -- :func:`asyncio.create_task` copies the current context, and a copied
#: context carries the same list object, so a task started after a ledger exists
#: shares and mutates it. :func:`_zero_pad_budget` is how such a task gets a
#: budget of its own.
#:
#: The ledger is cumulative and is not reset on its own. That is deliberate:
#: real parsing supplies real octets, so the allowance grows with the work
#: actually done and a long-lived process does not drift into refusing valid
#: captures.
#:
#: Be precise about what that means in practice, because nothing in this package
#: calls :func:`_zero_pad_budget` -- so the bound as shipped is over everything a
#: context has ever parsed, not over one :class:`~pcapkit.foundation.extraction.Extractor` run. It is still a bound,
#: and still proportionate: total padding past
#: :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL` stays within
#: ``MAX_ZERO_PAD_LENGTH + ZERO_PAD_BUDGET_RATIO`` times the octets that
#: context has genuinely been given, so a long-running service that has read a
#: great deal has earned proportionately more, rather than banking an unlimited
#: allowance. Scoping it per file would make the bound tighter and is a one-line
#: change at whichever layer owns a run; :func:`_zero_pad_budget` exists so that
#: layer has something to call.
#:
#: Cumulative state is what makes an answer depend on history, so note what is
#: *not* weighed against it: a shortfall within :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL`
#: neither consults this ledger nor is charged to it, which is what keeps every
#: legitimate short read answering the same however much preceded it. Only the
#: 32-bit band above reads and writes ``[1]``.
_zero_pad_ledger = contextvars.ContextVar(
    'pcapkit.corekit.fields.field._zero_pad_ledger',
    default=cast('Optional[list[int]]', None),
)  # type: contextvars.ContextVar[Optional[list[int]]]


@contextlib.contextmanager
def _zero_pad_budget() -> 'Iterator[list[int]]':
    """Give the parse in this block a padding budget of its own.

    :data:`_zero_pad_ledger` is cumulative across a context, so by default the
    bound :meth:`FieldBase.unpack` enforces is over everything that context has
    parsed. Entering this scope starts a fresh ledger and restores the previous
    one afterwards, which is what makes the bound *per parse* -- per
    :class:`~pcapkit.foundation.extraction.Extractor` run, per file, per frame -- for a caller that wants it that
    way, and what makes it reproducible for a test.

    Note that nothing in this package calls it: the layer that knows where
    one parse ends is the layer that should, and that is not this one.

    Yields:
        The ledger installed for the block, as ``[octets supplied, octets
        synthesised]``. It is live: reading it inside the block reports what the
        parse has done so far.

    """
    ledger = [0, 0]
    token = _zero_pad_ledger.set(ledger)
    try:
        yield ledger
    finally:
        _zero_pad_ledger.reset(token)


#: Pattern[str]: Matches a leading, optionally byte-order-prefixed negative
#: count in a :attr:`FieldBase.template`, e.g. the ``-1`` in ``'-1s'`` or in
#: ``'>-1s'``.
#:
#: Every template this package builds from a resolved field length is
#: ``f'{length}s'`` (see :mod:`pcapkit.corekit.fields.strings`,
#: :mod:`~pcapkit.corekit.fields.misc`, :mod:`~pcapkit.corekit.fields.collections`
#: and, before it gets byte-order-prefixed, :mod:`~pcapkit.corekit.fields.numbers`
#: --
#: :meth:`NumberField.build_template <pcapkit.corekit.fields.numbers.NumberField.build_template>`'s
#: ``else`` arm), so a negative resolved length
#: always leaves that literal ``-`` immediately before the digits. What
#: :class:`~pcapkit.corekit.fields.numbers.NumberField` adds is a byte-order
#: prefix -- one of ``'@=<>!'`` -- *in front of* that whole template
#: (``f'{endian}{struct_fmt}'``), which is what a plain ``^-\d+`` misses: the
#: prefix, not the minus sign, is what starts the string. The optional
#: character class here accounts for exactly that one prefix position, so a
#: negative count is recognised whether or not it was byte-order-prefixed, while
#: still refusing anything else -- a bare byte-order character with no minus
#: sign after it (``'>Xs'``), or any other malformed template -- which is what
#: makes checking for it a reliable way to tell those cases apart from each
#: other *before* :func:`struct.calcsize` is asked to size either one. See
#: :issue:`825`.
_RE_NEGATIVE_LENGTH_TEMPLATE = re.compile(r'^[@=<>!]?-\d+')


class FieldMeta(abc.ABCMeta, Generic[_T]):
    """Meta class to add dynamic support to :class:`FieldBase`.

    It defines nothing of its own, so a field class is built exactly as by
    :class:`abc.ABCMeta`.

    """


class FieldBase(Generic[_T], metaclass=FieldMeta):
    """Internal base class for protocol fields.

    Important:
        A negative value of :attr:`~FieldBase.length` indicates that the field
        is variable-length (i.e., length unspecified) and thus
        :meth:`~FieldBase.pack` should be considerate of the template format
        and the actual value provided for packing.

    Args:
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    """

    if TYPE_CHECKING:
        _name: 'str'
        _template: 'str'
        _callback: 'Callable[[Self, dict[str, Any]], None]'

    # NOTE: Declared on the class, not only assigned in :meth:`__init__`, so that
    # :attr:`default` is answerable for every field. A field class is free to
    # replace :meth:`__init__` without chaining to this one -- as
    # :class:`~pcapkit.corekit.fields.collections.ListField` does, since a list of
    # fields takes no default value of its own -- and reading :attr:`default` off
    # one of those would otherwise raise :exc:`AttributeError` for a private
    # attribute rather than report that the field declares no default. See #422.
    _default: '_T | NoValueType' = NO_VALUE

    @property
    def name(self) -> 'str':
        """Field name."""
        return self._name

    @name.setter
    def name(self, value: 'str') -> 'None':
        """Set field name."""
        self._name = value

    @property
    def default(self) -> '_T | NoValueType':
        """Field default value."""
        return self._default

    @default.setter
    def default(self, value: '_T | NoValueType') -> 'None':
        """Set field default value."""
        self._default = value

    @default.deleter
    def default(self) -> 'None':
        """Delete field default value."""
        self._default = NO_VALUE

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    @property
    def length(self) -> 'int':
        """Field size.

        Raises:
            ProtocolError: If :attr:`template` resolves to a negative count
                (e.g. ``'-5s'``, from a ``length`` callback such as
                ``lambda pkt: pkt['__length__']`` resolving below zero once
                the buffer ran short of what the schema declared).
                :func:`struct.calcsize` cannot size such a template and raises
                a bare :exc:`struct.error`, uncatchable as a pcapkit-specific
                error; this re-raises it as the negative-length message below.
                See :issue:`805`.
            ProtocolError: If :attr:`template` is otherwise malformed --
                anything else :func:`struct.calcsize` cannot size, such as a
                typo'd format character -- rather than the negative-length
                message above, which would misreport the actual cause.
                :func:`struct.calcsize` raises the identical bare
                :exc:`struct.error` for both cases (measured:
                ``calcsize('-1s')`` and ``calcsize('Xs')`` both raise ``bad
                char in struct format``), so the two are told apart by
                :data:`_RE_NEGATIVE_LENGTH_TEMPLATE` against :attr:`template`
                itself -- which is known already, without needing anything
                :func:`struct.calcsize`'s own error says -- rather than by the
                error message. See :issue:`825`.

        .. versionchanged:: 1.5.0

           Raises :exc:`~pcapkit.utilities.exceptions.ProtocolError` where
           :func:`struct.calcsize` raised a bare :exc:`struct.error`
           (:issue:`805`, :issue:`825`).

        """
        try:
            return struct.calcsize(self.template)
        except struct.error as error:
            if _RE_NEGATIVE_LENGTH_TEMPLATE.match(self.template) is not None:
                raise ProtocolError(
                    f'Field {self.name} resolved to a negative length; '
                    f'template={self.template!r}'
                ) from error
            raise ProtocolError(
                f'Field {self.name} has a malformed template; '
                f'template={self.template!r}'
            ) from error

    @property
    def optional(self) -> 'bool':
        """Field is optional."""
        return False

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Arguments:
            packet: Packet data.

        Returns:
            Updated field instance.

        This method will return a new instance of :class:`FieldBase` instead of
        updating the current instance.

        """
        new_self = self.__copy__()
        new_self._callback(new_self, packet)
        return new_self

    # NOTE: This method is created as a placeholder for the necessary attributes.
    def __init__(self, *args: 'Any', **kwargs: 'Any') -> 'None':
        if not hasattr(self, '_name'):
            self._name = f'<{type(self).__name__[:-5].lower()}>'

        self._default = NO_VALUE
        self._template = '0s'
        self._callback = lambda *_: None

    def __copy__(self) -> 'Self':
        """Return a shallow copy of the field.

        Every field of every protocol is copied once per packet by
        :meth:`__call__`, which makes the generic :func:`copy.copy` path -- via
        :meth:`object.__reduce_ex__` and :func:`copy._reconstruct` -- one of the
        costlier things an extraction would do. This does what that path would
        do, and only that: a new instance of the same class, its
        :attr:`~object.__dict__` shallow-updated from this one.

        Note:
            Every ``__call__`` in :mod:`pcapkit.corekit.fields` copies through
            ``self.__copy__()`` -- directly, or by way of ``super().__call__`` --
            rather than :func:`copy.copy(self) <copy.copy>`.
            :func:`copy.copy` still has to *find* this method before it can call
            it -- ``getattr(cls, '__copy__', None)`` -- and that lookup alone
            was profiled at 55,846 calls (~1.7% of an
            :func:`~pcapkit.interface.core.extract` run) on
            ``examples/captures/http.pcap``, one per field
            per packet, all from this exact path. Calling ``__copy__``
            directly is exactly what :func:`copy.copy` would have done once it
            found it, so a field is copied at the same points and to the same
            contents either way -- only the redundant dispatch is skipped.
            See GitHub issue :issue:`730`.

        Returns:
            A new field instance sharing this one's attribute values.

        """
        new_self = self.__class__.__new__(self.__class__)
        new_self.__dict__.update(self.__dict__)
        return new_self

    def __repr__(self) -> 'str':
        if not self.name.isidentifier():
            return f'<{self.__class__.__name__}>'
        return f'<{self.__class__.__name__} {self.name}>'

    def __set_name__(self, owner: 'Schema', name: 'str') -> 'None':
        """Set field name and update field list (if applicable).

        This method is to be called by the metaclass during class creation.
        It is used to set the field name and update the field list, i.e.,
        :attr:`Schema.__fields__ <pcapkit.protocols.schema.schema.Schema.__fields__>`
        mapping dictionary.

        """
        # Update field list (if applicable)
        if hasattr(owner, '__fields__'):
            owner.__fields__[name] = self

        # Set field name
        self.name = name

    def pre_process(self, value: '_T', packet: 'dict[str, Any]') -> 'Any':  # pylint: disable=unused-argument
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return cast('Any', value)

    def pack(self, value: 'Optional[_T]', packet: 'dict[str, Any]') -> 'bytes':
        """Pack field value into :obj:`bytes`.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Packed field value.

        """
        if value is None:
            if self._default is NO_VALUE:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = cast('_T', self._default)

        pre_processed = self.pre_process(value, packet)

        # NOTE: CPython's ``s`` and ``p`` formats take a bytearray, PyPy's take
        # bytes alone (``TypeError: expected bytes, got bytearray object``), so a
        # bytearray is handed over as bytes, packing identically on both (#2004).
        # The ``c`` format is converted too: CPython's refuses a bytearray and
        # GraalPy's takes one, so converting it packs alike everywhere (#2015).
        # A memoryview is left to the engine, which CPython refuses for all three.
        if isinstance(pre_processed, bytearray) and self.template[-1:] in ('s', 'p', 'c'):
            pre_processed = bytes(pre_processed)
        return struct.pack(self.template, pre_processed)

    def post_process(self, value: 'Any', packet: 'dict[str, Any]') -> '_T':  # pylint: disable=unused-argument
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        return cast('_T', value)

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> '_T':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value.

        Raises:
            FieldValueError: If ``buffer`` holds fewer octets than :attr:`length`
                declares, and either ``length`` is past
                :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH`, or the shortfall is past
                :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL` and takes this parse's total of
                such shortfalls past what :data:`~pcapkit.utilities.config.ZERO_PAD_BUDGET_RATIO` allows
                for the octets it has actually been given. A shortfall within
                :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL` is always padded and never
                raises.

        .. versionchanged:: 1.5.0

           A short read is zero-filled on the tail, where its missing octets
           are, rather than on the head (:issue:`604`).

        """
        # NOTE: ``length`` recomputes struct.calcsize() on every read, so it is
        # read once here.
        length = self.length

        if not isinstance(buffer, bytes):
            buffer = buffer.read(length)

        # NOTE: ``length`` is frequently wire-derived -- resolved by a
        # ``_length_callback`` against the very packet being parsed, per
        # :meth:`Field.__call__` below, or by a schema's own selector building a
        # field from a value it just read off the wire (e.g. ``DecryptionSecretsBlock``'s
        # ``secrets_data: BytesField(length=lambda pkt: pkt['__length__'])``) --
        # and is thus attacker-controlled: a corrupt or hostile capture can
        # declare an arbitrarily large one. Past :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH`, a
        # length that ``buffer`` falls short of is provably bogus: the padding
        # cannot recover data that was never in the buffer, only zero-fill for
        # it, and no field this large is legitimate to begin with. Honouring it
        # would allocate and zero-fill up to ``length`` octets on nothing but
        # the packet's own say-so. Cf. #554.
        ceiling = config.MAX_ZERO_PAD_LENGTH
        if ceiling != -1 and length > ceiling and len(buffer) < length:
            raise FieldValueError(
                f'Field {self.name} declares a length of {length} octet(s), '
                f'but only {len(buffer)} octet(s) are available.'
            )

        # NOTE: The ceiling above bounds one field; this bounds their sum. A
        # declared length just under :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH` passes it every
        # time it is declared, so 200 of them amplify 4,800 wire octets into
        # 50.0 MiB of retained zeros with the ceiling doing exactly what it was
        # written to do. Cf. #573.
        #
        # ``max(length, 0)`` is defensive rather than a case anything is known to
        # reach. :attr:`length` here resolves through :func:`struct.calcsize`, so
        # it cannot be negative; the classes that instead answer it straight out
        # of ``self._length``, which *is* negative for a variable-length field --
        # :class:`~pcapkit.corekit.fields.misc.PayloadField` and
        # :class:`~pcapkit.corekit.fields.misc.SchemaField` -- each replace this
        # method outright and so never arrive here. The clamp costs one
        # comparison and stops a negative width ever *granting* padding allowance
        # for reading nothing, which is the one way this bookkeeping could be
        # turned against itself.
        width = max(length, 0)
        supplied = len(buffer) if len(buffer) < width else width
        padding = width - supplied

        # ``supplied`` is what earns allowance, so it is tallied on every read,
        # padded or not: a parse made of small, honest reads is exactly the parse
        # that should be able to afford the one large shortfall a capture
        # truncated at EOF ends on.
        #
        # It counts octets as each field saw them, which is not the same as
        # octets consumed from the file. A nested schema re-reads its enclosing
        # field's span, and :meth:`OptionField.unpack <pcapkit.corekit.fields.
        # collections.OptionField.unpack>` peeks an option's type field and then
        # rewinds and parses the same span again, so a span can be credited more
        # than once -- measured at 28 credited octets for a 24-octet IPv4 header
        # carrying four one-octet ``NOP`` options. The over-count is bounded by
        # nesting depth, so it makes the allowance somewhat more generous than the
        # ratio alone suggests; it cannot grow without limit, which is what would
        # actually matter.
        ledger = _zero_pad_ledger.get()
        if ledger is None:
            ledger = [0, 0]
            _zero_pad_ledger.set(ledger)
        ledger[0] += supplied

        # A shortfall no larger than :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL` is padded
        # without consulting the budget, and is not charged to it either. That is
        # load-bearing rather than a concession: it is
        # what keeps the answer a function of *this* read rather than of
        # everything read before it. No shortfall a 16-bit wire length can produce
        # -- which is every shortfall a snapshot-truncated capture, a truncated
        # option area or an over-long ``ihl`` can produce (#431, #554) -- is ever
        # refused, on the first frame or the ten-thousandth.
        #
        # Nor may those small shortfalls *spend* the budget, which is why they are
        # not tallied against it. A snapshot-truncated capture of offload-sized
        # frames pads some 935 octets for every octet it reads, all of it in this
        # band; charging that to the same ledger would exhaust it within a few
        # frames and refuse the next large shortfall -- making the answer depend on
        # history, which is exactly what the band exists to prevent.
        shortfall, ratio = config.MAX_ZERO_PAD_SHORTFALL, config.ZERO_PAD_BUDGET_RATIO
        if shortfall != -1 and padding > shortfall:
            # NOTE: ``-1`` for either term of the allowance lifts the budget.
            unbounded = ceiling == -1 or ratio == -1
            allowance = 0 if unbounded else ceiling + ratio * ledger[0]
            if not unbounded and ledger[1] + padding > allowance:
                raise FieldValueError(
                    f'Field {self.name} would zero-pad {padding} octet(s), '
                    f'taking this parse to {ledger[1] + padding} octet(s) of '
                    f'padding past {shortfall} octet(s) against '
                    f'{ledger[0]} octet(s) actually read, past the {allowance} '
                    f'octet(s) allowed.'
                )
            ledger[1] += padding

        # NOTE: ``ljust()``, not ``rjust()``. A short read has lost the *trailing*
        # octets of the field -- the buffer ran out, so what is missing is
        # whatever came after what was read -- so the zeros belong at the end,
        # where the unread octets were. ``rjust()`` would put them at the
        # front, which asserts that the octets never read were the *leading*
        # ones, and that is wrong for every byte order rather than only for
        # little-endian ones. Under ``rjust()``, one octet of a four-octet
        # little-endian 120 (``0x78``) reads as 2,013,265,920, and three octets
        # of a four-octet big-endian ``0x01020304`` read as ``0x10203``.
        # ``ljust()`` answers 120 and ``0x1020300``. The big-endian error is the
        # more dangerous of the two -- it scales the value *down*, so it passes a
        # sanity check far more easily than the inflated little-endian one. See
        # #604.
        #
        # The choice decides what a truncated field *reports*, not *whether* a
        # truncated capture parses, which must not change: the
        # accommodation itself is deliberate (#431) and the budget above is built
        # around preserving it. An entirely empty buffer pads to all zeros either
        # way, so the end-of-option-list and ``Pad1`` reads the option and list
        # loops depend on are unaffected.
        value = struct.unpack(self.template, buffer[:length].ljust(length, b'\x00'))[0]
        return self.post_process(value, packet)


class Field(FieldBase[_T], Generic[_T]):
    """Base class for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    if TYPE_CHECKING:
        _template: 'str'

    @property
    def template(self) -> 'str':
        """Field template."""
        return self._template

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: '_T | NoValueType' = NO_VALUE,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        #self._name = '<unknown>'
        if not hasattr(self, '_name'):
            self._name = f'<{type(self).__name__[:-5].lower()}>'

        self._default = default
        self._callback = callback

        self._length_callback = None
        if not isinstance(length, int):
            self._length_callback, length = length, -1
        self._length = length

    def __call__(self, packet: 'dict[str, Any]') -> 'Self':
        """Update field attributes.

        Args:
            packet: Packet data.

        Returns:
            New instance of :class:`Field`.

        This method will return a new instance of :class:`Field` instead of
        updating the current instance.

        """
        new_self = self.__copy__()
        new_self._callback(new_self, packet)
        if new_self._length_callback is not None:
            new_self._length = new_self._length_callback(packet)
        return new_self
