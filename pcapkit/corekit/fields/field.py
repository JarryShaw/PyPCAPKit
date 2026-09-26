# -*- coding: utf-8 -*-
"""base field class"""

import abc
import contextlib
import contextvars
import re
import struct
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.utilities.compat import final
from pcapkit.utilities.exceptions import FieldValueError, NoDefaultValue, ProtocolError

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Iterator, Optional

    from typing_extensions import Literal, Self

    from pcapkit.protocols.schema.schema import Schema

_T = TypeVar('_T')


@final
class NoValueType:
    """Default value for fields."""

    def __bool__(self) -> 'Literal[False]':
        """Return :obj:`False`."""
        return False


#: NoValueType: Default value for :attr:`FieldBase.default`.
NoValue = NoValueType()

#: int: Ceiling on the zero-padding :meth:`FieldBase.unpack` will still perform
#: for a field whose declared length outruns its buffer.
#:
#: This is libpcap's own ``MAXIMUM_SNAPLEN`` -- the point past which libpcap
#: itself treats a capture's declared snapshot length as corrupt or
#: byte-order-swapped rather than real -- and it is the same figure this
#: package's own PCAP writer defaults ``snaplen`` to
#: (:meth:`pcapkit.protocols.misc.pcap.header.Header.make`). No single field
#: within one captured packet is legitimately larger than the largest packet
#: libpcap itself is willing to believe, so nothing this library parses
#: should ever declare a length past it.
#:
#: The bound is deliberately *not* "any declared length beyond what the
#: buffer holds": :meth:`ListField.unpack <pcapkit.corekit.fields.collections.
#: ListField.unpack>` and :meth:`OptionField.unpack <pcapkit.corekit.fields.
#: collections.OptionField.unpack>` depend on reading a short, sometimes
#: empty, tail past a truncated area and having it decode as zero -- that is
#: how an over-long ``ihl``, or a capture cut short by the snapshot length,
#: reads as end-of-option-list or ``Pad1`` instead of wedging or raising (see
#: #431). Every such read is of a fixed-width, few-octet field, always far
#: under this ceiling, so it is untouched; only a length past it -- which no
#: fixed-width field ever legitimately is -- gets refused.
#:
#: A ceiling on one field says nothing about how many fields a parse may pad,
#: which is what :data:`_MAX_ZERO_PAD_SHORTFALL` and
#: :data:`_ZERO_PAD_BUDGET_RATIO` below are for. See #573.
_MAX_ZERO_PAD_LENGTH = 0x40_000

#: int: Shortfall :meth:`FieldBase.unpack` will always zero-pad for, whatever
#: else a parse has already padded.
#:
#: :data:`_MAX_ZERO_PAD_LENGTH` bounds each field on its own, and a packet holds
#: many fields, so the *sum* was unbounded: a declared length just under the
#: ceiling is honoured however often it is declared. Measured on this tree, 200
#: minimal PCAP-NG Decryption Secrets Blocks -- 4,800 wire octets, each block
#: declaring ``secrets_length`` of 262,142 against two supplied octets through
#: ``UnknownSecrets.data`` (``pcapkit/protocols/schema/misc/pcapng.py``) --
#: retained 50.0 MiB, an amplification of 10,922x per block. Every individual
#: field was under the ceiling, so nothing refused any of them (#573).
#:
#: The sum therefore wants a budget, and this is the figure that makes one
#: *safe*. A budget on its own is not: a capture cut short by its snapshot length
#: pads legitimately and must keep parsing (#431, and the reasoning that declined
#: #571), and it pads far more than it reads, so any running budget tight enough
#: to matter starts refusing real captures. Worse, it refuses them *sometimes* --
#: measured on this tree with a running budget alone, the same legitimate
#: 54-octet frame parsed to one result on 37 of 40 calls and to another on calls
#: 26, 33 and 39, because whether it fit depended on what had been parsed before
#: it. A guard whose answer moves with history is not a guard.
#:
#: 65,536 is what removes that. It is the whole span of a 16-bit wire length
#: field -- which is how an IP header, an IPv6 payload, a TCP or IPv4 option and
#: a PCAP-NG option all declare their size -- so no shortfall that one of those
#: can produce is subject to the budget at all, and every one of them is padded
#: unconditionally, exactly as before. Measured: the largest legitimate single
#: shortfall found anywhere was 65,495 octets, from a snapshot-truncated
#: offload-sized frame (100 frames at ``incl_len`` 54 declaring an IPv4 total
#: length of 65,535, padding 6,549,500 octets from 7,024 read), and 64,750 from a
#: truncated PCAP-NG option. Both sit under this figure, and so does anything
#: else a 16-bit field can ask for.
#:
#: What is left above it is the band a *32-bit* wire length reaches --
#: PCAP-NG's own block and secrets lengths, which is where #573's amplification
#: lives -- and legitimately that is a once-per-file event, since only the last
#: block of a truncated capture is cut short. So the band gets the running budget
#: below, whose one-off term already covers any single such event outright.
_MAX_ZERO_PAD_SHORTFALL = 0x10_000

#: int: Zero padding *past* :data:`_MAX_ZERO_PAD_SHORTFALL` that
#: :meth:`FieldBase.unpack` will synthesise in total for every octet a parse has
#: actually been given, over and above the one-off
#: :data:`_MAX_ZERO_PAD_LENGTH` allowance.
#:
#: A shortfall in this band -- past 65,536 octets and so past anything a 16-bit
#: wire length can declare, but within :data:`_MAX_ZERO_PAD_LENGTH` -- is a
#: PCAP-NG block or secrets length, a 32-bit figure. One of those, on its own, is
#: legitimate: it is what the final block of a capture truncated at EOF looks
#: like, and the ``_MAX_ZERO_PAD_LENGTH`` term of the allowance covers it whole,
#: from a cold start, because such a shortfall cannot exceed that ceiling and
#: still be padded at all.
#:
#: *Repeating* one is not legitimate, and that is what 16 is chosen to catch.
#: Truncation cuts the end of a file, so a capture has one short block, not two
#: hundred; #573's shape has two hundred because they are declared rather than
#: cut. 16 octets of further allowance per octet genuinely read leaves any real
#: file an allowance orders of magnitude past the one event it can want, while
#: bounding the sum for a file whose blocks all lie.
_ZERO_PAD_BUDGET_RATIO = 0x10

#: ContextVar[Optional[list[int]]]: Running ``[octets supplied, octets
#: synthesised]`` ledger for :meth:`FieldBase.unpack`, against which
#: :data:`_ZERO_PAD_BUDGET_RATIO` is enforced.
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
#: context has ever parsed, not over one ``Extractor`` run. It is still a bound,
#: and still proportionate: total padding past
#: :data:`_MAX_ZERO_PAD_SHORTFALL` stays within
#: ``_MAX_ZERO_PAD_LENGTH + _ZERO_PAD_BUDGET_RATIO`` times the octets that
#: context has genuinely been given, so a long-running service that has read a
#: great deal has earned proportionately more, rather than banking an unlimited
#: allowance. Scoping it per file would make the bound tighter and is a one-line
#: change at whichever layer owns a run; :func:`_zero_pad_budget` exists so that
#: layer has something to call.
#:
#: Cumulative state is what makes an answer depend on history, so note what is
#: *not* weighed against it: a shortfall within :data:`_MAX_ZERO_PAD_SHORTFALL`
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
    ``Extractor`` run, per file, per frame -- for a caller that wants it that
    way, and what makes it reproducible for a test.

    Note that nothing in this package calls it yet: the layer that knows where
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
#: -- :meth:`NumberField.build_template <pcapkit.corekit.fields.numbers.
#: NumberField.build_template>`'s ``else`` arm), so a negative resolved length
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
#: #825, #827.
_RE_NEGATIVE_LENGTH_TEMPLATE = re.compile(r'^[@=<>!]?-\d+')


class FieldMeta(abc.ABCMeta, Generic[_T]):
    """Meta class to add dynamic support to :class:`FieldBase`.

    This meta class is used to generate necessary attributes for the
    :class:`FieldBase` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

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
    # one of those raised :exc:`AttributeError` for a private attribute rather
    # than reporting that the field declares no default. See #422.
    _default: '_T | NoValueType' = NoValue

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
        self._default = NoValue

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
                See #805.
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
                error message. See #825.

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

        self._default = NoValue
        self._template = '0s'
        self._callback = lambda *_: None

    def __copy__(self) -> 'Self':
        """Return a shallow copy of the field.

        Every field of every protocol is copied once per packet by
        :meth:`__call__`, which made the generic :func:`copy.copy` path -- via
        :meth:`object.__reduce_ex__` and :func:`copy._reconstruct` -- one of the
        costlier things an extraction did. This does what that path would have
        done, and only that: a new instance of the same class, its
        :attr:`~object.__dict__` shallow-updated from this one.

        Note:
            Every ``__call__`` override in this module calls ``self.__copy__()``
            directly rather than :func:`copy.copy(self) <copy.copy>`.
            :func:`copy.copy` still has to *find* this method before it can call
            it -- ``getattr(cls, '__copy__', None)`` -- and that lookup alone
            was profiled at 55,846 calls (~1.7% of an :func:`~pcapkit.interface.
            core.extract` run) on ``examples/captures/http.pcap``, one per field
            per packet, all from this exact path. Calling ``__copy__``
            directly is exactly what :func:`copy.copy` would have done once it
            found it, so this changes nothing about *when* a field is copied or
            what the copy contains -- only the redundant dispatch is removed.
            See GitHub issue #730.

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
            if self._default is NoValue:
                raise NoDefaultValue(f'Field {self.name} has no default value.')
            value = cast('_T', self._default)

        pre_processed = self.pre_process(value, packet)
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
                :data:`_MAX_ZERO_PAD_LENGTH`, or the shortfall is past
                :data:`_MAX_ZERO_PAD_SHORTFALL` and takes this parse's total of
                such shortfalls past what :data:`_ZERO_PAD_BUDGET_RATIO` allows
                for the octets it has actually been given. A shortfall within
                :data:`_MAX_ZERO_PAD_SHORTFALL` is always padded and never
                raises.

        """
        # NOTE: ``length`` recomputes struct.calcsize() on every read, so the
        # three reads this method used to make were three calcsize() calls for
        # one value.
        length = self.length

        if not isinstance(buffer, bytes):
            buffer = buffer.read(length)

        # NOTE: ``length`` is frequently wire-derived -- resolved by a
        # ``_length_callback`` against the very packet being parsed, per
        # :meth:`Field.__call__` below, or by a schema's own selector building a
        # field from a value it just read off the wire (e.g. ``DecryptionSecretsBlock``'s
        # ``secrets_data: BytesField(length=lambda pkt: pkt['__length__'])``) --
        # and is thus attacker-controlled: a corrupt or hostile capture can
        # declare an arbitrarily large one. Past :data:`_MAX_ZERO_PAD_LENGTH`, a
        # length short of what ``buffer`` holds is provably bogus: the padding
        # cannot recover data that was never in the buffer, only zero-fill for
        # it, and no field this large is legitimate to begin with. Honouring it
        # would allocate and zero-fill up to ``length`` octets on nothing but
        # the packet's own say-so. C.f. #554.
        if length > _MAX_ZERO_PAD_LENGTH and len(buffer) < length:
            raise FieldValueError(
                f'Field {self.name} declares a length of {length} octet(s), '
                f'but only {len(buffer)} octet(s) are available.'
            )

        # NOTE: The ceiling above bounds one field; this bounds their sum. A
        # declared length just under :data:`_MAX_ZERO_PAD_LENGTH` passes it every
        # time it is declared, so 200 of them amplified 4,800 wire octets into
        # 50.0 MiB of retained zeros with the ceiling doing exactly what it was
        # written to do -- the sum was never bounded at all. C.f. #573.
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

        # A shortfall no larger than :data:`_MAX_ZERO_PAD_SHORTFALL` is padded
        # without consulting the budget, and is not charged to it either. That is
        # the load-bearing half of this fix rather than a concession in it: it is
        # what keeps the answer a function of *this* read rather than of
        # everything read before it. No shortfall a 16-bit wire length can produce
        # -- which is every shortfall a snapshot-truncated capture, a truncated
        # option area or an over-long ``ihl`` can produce (#431, #571) -- is ever
        # refused, on the first frame or the ten-thousandth.
        #
        # Nor may those small shortfalls *spend* the budget, which is why they are
        # not tallied against it. A snapshot-truncated capture of offload-sized
        # frames pads some 935 octets for every octet it reads, all of it in this
        # band; charging that to the same ledger would exhaust it within a few
        # frames and refuse the next large shortfall -- reintroducing exactly the
        # history-dependence the band exists to remove.
        if padding > _MAX_ZERO_PAD_SHORTFALL:
            allowance = _MAX_ZERO_PAD_LENGTH + _ZERO_PAD_BUDGET_RATIO * ledger[0]
            if ledger[1] + padding > allowance:
                raise FieldValueError(
                    f'Field {self.name} would zero-pad {padding} octet(s), '
                    f'taking this parse to {ledger[1] + padding} octet(s) of '
                    f'padding past {_MAX_ZERO_PAD_SHORTFALL} octet(s) against '
                    f'{ledger[0]} octet(s) actually read, past the {allowance} '
                    f'octet(s) allowed.'
                )
            ledger[1] += padding

        # NOTE: ``ljust()``, not ``rjust()``. A short read has lost the *trailing*
        # octets of the field -- the buffer ran out, so what is missing is
        # whatever came after what was read -- so the zeros belong at the end,
        # where the unread octets were. ``rjust()`` instead put them at the
        # front, which asserts that the octets never read were the *leading*
        # ones, and that is wrong for every byte order rather than only for
        # little-endian ones. Measured on the tree that padded with ``rjust()``:
        # one octet of a four-octet little-endian 120 (``0x78``) read as
        # 2,013,265,920, and three octets of a four-octet big-endian
        # ``0x01020304`` read as ``0x10203``. ``ljust()`` answers 120 and
        # ``0x1020300``. The big-endian error is the more dangerous of the two --
        # it scales the value *down*, so it passes a sanity check far more easily
        # than the inflated little-endian one, which is why the defect went
        # unnoticed there. See #604.
        #
        # This changes what a truncated field *reports*, which is the point, and
        # not *whether* a truncated capture parses, which must not change: the
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
                 default: '_T | NoValueType' = NoValue,
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
