# -*- coding: utf-8 -*-
"""Configuration
=================

.. module:: pcapkit.utilities.config

:mod:`pcapkit.utilities.config` holds every tunable limit of :mod:`pcapkit`
(:issue:`1726`), and its checksum flags (:issue:`2471`). Each is read from a
``PCAPKIT_*`` environment variable once, when this module is imported, and
validated there; a flag as :func:`read_flag` describes, and a limit as follows:

* A value that is not an integer, or is below the variable's minimum, is
  reported with a :exc:`~pcapkit.utilities.warnings.ConfigWarning`, and the
  default is used instead.
* A limit takes ``-1`` to mean no limit at all. That, or any value above the
  default, is accepted and reported with a
  :exc:`~pcapkit.utilities.warnings.ConfigWarning` naming the risk.

Each message names the variable and the value it was given. The warning is
reported through :func:`~pcapkit.utilities.warnings.warn`, so it obeys the
warning filters: under :option:`-W error <-W>` or ``PYTHONWARNINGS=error``, an
out-of-range value makes ``import pcapkit`` raise
:exc:`~pcapkit.utilities.warnings.ConfigWarning`.

Every reader looks the value up here at call time, as ``config.<NAME>``, so
patching one name in this module reaches every engine and every protocol that
reads it.

:func:`read_limit` and :func:`read_flag` read and validate the variables, and
are public so that a module keeping variables of its own validates them the same
way: :mod:`pcapkit.vendor.default` reads the crawlers' variables with them, and
documents those variables itself.

Besides the standard library, this module imports
:mod:`pcapkit.utilities.warnings` and nothing else from :mod:`pcapkit`, which is
what lets :mod:`pcapkit.utilities.logging` load before it. The flags that
:mod:`pcapkit.utilities.logging` needs while it is loading,
:envvar:`PCAPKIT_DEVMODE`, :envvar:`PCAPKIT_VERBOSE` and
:envvar:`PCAPKIT_SPHINX`, are therefore read there instead.

.. versionadded:: 1.5.0

"""
import os
from typing import TYPE_CHECKING

from pcapkit.utilities.warnings import ConfigWarning, _importer_stacklevel, warn

if TYPE_CHECKING:
    from typing import Optional

__all__ = [
    # limits
    'FRAME_LAYER_LIMIT', 'EXTENSION_HEADER_LIMIT', 'IPV6_TCP_WARNED_LIMIT',
    'TCP_GAP_LIMIT', 'FALLBACK_LIMIT', 'DETECT_CACHE_SIZE', 'READ_CHUNK',
    'MAX_ZERO_PAD_LENGTH', 'MAX_ZERO_PAD_SHORTFALL', 'ZERO_PAD_BUDGET_RATIO',
    # flags
    'CHECKSUM_VERIFY', 'CHECKSUM_COMPUTE',
    # readers
    'read_limit', 'read_flag',
]

#: Strings a boolean variable may take, case-insensitively.
_BOOLEAN_STATES = {'1': True, '0': False,
                   'yes': True, 'no': False,
                   'true': True, 'false': False,
                   'on': True, 'off': False}

#: What a recursion-bound limit risks once lifted, cf. :issue:`1610`.
_RECURSION_RISK = ("each layer is dissected from inside the parse of the one before it, so a deep "
                   "frame may hit Python's recursion limit and raise RecursionError (#1610)")


def read_limit(name: 'str', default: 'int', *, minimum: 'int' = 0,
               risk: 'Optional[str]' = None) -> 'int':
    """Read the integer environment variable ``PCAPKIT_<name>``.

    A value that is not an integer, or is below ``minimum``, is reported with a
    :exc:`~pcapkit.utilities.warnings.ConfigWarning` naming the variable and the
    value, and ``default`` is used instead.

    Args:
        name: Variable name, without the ``PCAPKIT_`` prefix.
        default: Value used when the variable is unset or invalid.
        minimum: Smallest value accepted, besides ``-1`` where ``risk`` is set.
        risk: What lifting the limit risks. If set, ``-1`` means no limit, and
            ``-1`` or any value above ``default`` is reported with it. If
            :data:`None`, ``-1`` is not accepted and nothing is reported.

    Returns:
        The value of the variable, or ``default``.

    .. versionadded:: 1.5.0

    """
    variable = f'PCAPKIT_{name}'
    text = os.environ.get(variable)
    if text is None:
        return default

    accepted = f'an integer of at least {minimum}' + (', or -1 for no limit' if risk is not None else '')
    try:
        value = int(text)
    except ValueError:
        value = None
    if value is None or (value < minimum and not (risk is not None and value == -1)):
        warn(f'{variable}={text!r} is not {accepted}; using the default, {default}',
             ConfigWarning, stacklevel=_importer_stacklevel())
        return default

    if risk is not None and (value == -1 or value > default):
        lifted = 'lifts the limit' if value == -1 else f'is above the default of {default}'
        warn(f'{variable}={text!r} {lifted}: {risk}', ConfigWarning,
             stacklevel=_importer_stacklevel())
    return value


def read_flag(name: 'str', default: 'bool' = False) -> 'bool':
    """Read the boolean environment variable ``PCAPKIT_<name>``.

    The value is read with surrounding whitespace stripped and
    case-insensitively, and is one of ``1``, ``yes``, ``true`` or ``on``, or of
    ``0``, ``no``, ``false`` or ``off``. Any other value is reported with a
    :exc:`~pcapkit.utilities.warnings.ConfigWarning` naming the variable and the
    value, and ``default`` is used instead.

    Args:
        name: Variable name, without the ``PCAPKIT_`` prefix.
        default: Value used when the variable is unset or invalid.

    Returns:
        The value of the variable, or ``default``.

    .. versionadded:: 1.5.0

    """
    variable = f'PCAPKIT_{name}'
    text = os.environ.get(variable)
    if text is None:
        return default
    try:
        return _BOOLEAN_STATES[text.strip().casefold()]
    except KeyError:
        warn(f'{variable}={text!r} is not one of {", ".join(_BOOLEAN_STATES)}; '
             f'using the default, {default}', ConfigWarning, stacklevel=_importer_stacklevel())
        return default


###############################################################################
# Limits
###############################################################################

#: int: Most layers dissected in one frame (:issue:`1610`),
#: :envvar:`PCAPKIT_FRAME_LAYER_LIMIT`.
#:
#: A layer is one entry of the frame's protocol chain, counted from the first
#: layer the frame record carries, usually its link layer; a protocol
#: constructed from its own octets is not counted itself, so the count starts at
#: the first layer it dissects. IPv6 extension headers are layers like any
#: other, whether :class:`~pcapkit.protocols.internet.ipv6.IPv6` walks them or
#: each dissects the next. What follows the last layer is kept as
#: :class:`~pcapkit.protocols.misc.raw.Raw`, with one
#: :exc:`~pcapkit.utilities.warnings.ProtocolWarning`, unless it would have been
#: left raw anyway or there is nothing left.
#:
#: Each layer dissects the next from inside its own parse, so without the bound
#: a deep enough frame, such as IP in IP or stacked 802.1Q tags, stops wherever
#: Python's recursion limit falls, which depends on the interpreter and on how
#: deep the caller's own stack is. A tunnel does not restart the count, and nor
#: does the end of a chain of extension headers, which
#: :data:`EXTENSION_HEADER_LIMIT` bounds on its own.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`` (:issue:`1726`).
FRAME_LAYER_LIMIT = read_limit('FRAME_LAYER_LIMIT', 64, risk=_RECURSION_RISK)

#: int: Most IPv6 extension headers dissected in one chain, i.e. one after
#: another with no other layer between them (:issue:`1604`),
#: :envvar:`PCAPKIT_EXTENSION_HEADER_LIMIT`.
#:
#: The walk stops there, and what follows the last of them is kept as
#: :class:`~pcapkit.protocols.misc.raw.Raw`, with one
#: :exc:`~pcapkit.utilities.warnings.ProtocolWarning`. That holds whether the
#: chain follows IPv6, which walks it in a loop
#: (:meth:`IPv6._decode_next_layer
#: <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`), or another
#: layer such as IPv4, where each header dissects the next one itself
#: (:meth:`Internet._import_next_layer
#: <pcapkit.protocols.internet.internet.Internet._import_next_layer>`). Behind
#: IPv4, the ``scapy`` toolkit steps over at most this many in the octets to find
#: TCP; the third-party engines are otherwise best effort here (:issue:`1687`).
#:
#: :rfc:`8200#section-4.1` allows each extension header at most once, and the
#: Destination Options header at most twice, so no compliant chain gets close.
#: Without the bound, a chain dissected header by header stops wherever
#: Python's recursion limit falls, which depends on the interpreter. Each
#: header is a layer, so :data:`FRAME_LAYER_LIMIT` applies as well.
#:
#: Rebuilding a frame with :meth:`~pcapkit.protocols.protocol.Protocol.from_data`
#: stops where parsing it did, and warns once too (:issue:`1619`), cf.
#: :meth:`Internet._make_payload
#: <pcapkit.protocols.internet.internet.Internet._make_payload>`.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`` (:issue:`1726`).
EXTENSION_HEADER_LIMIT = read_limit('EXTENSION_HEADER_LIMIT', 32, risk=_RECURSION_RISK)

#: int: How many captures the ``pypcapfile`` engine remembers having warned
#: about for TCP over IPv6, :envvar:`PCAPKIT_IPV6_TCP_WARNED_LIMIT`.
#:
#: Each one pins a packet of its own in memory, so the memory is bounded and the
#: oldest is forgotten first. Up to this many captures read at the same time
#: warn exactly once each.
#:
#: .. versionadded:: 1.5.0
IPV6_TCP_WARNED_LIMIT = read_limit('IPV6_TCP_WARNED_LIMIT', 32, risk=(
    'each capture remembered pins one of its packets in memory'))

#: int: Widest gap, in octets, that
#: :meth:`TCP.reassembly <pcapkit.foundation.reassembly.tcp.TCP.reassembly>`
#: zero-fills to merge a segment into the payload buffer it is read against,
#: :envvar:`PCAPKIT_TCP_GAP_LIMIT`; ``-1`` always merges.
#:
#: This is a safety limit, not a reassembly rule: no RFC calls for one
#: (:issue:`2546`). A segment can only legitimately open a gap as wide as the
#: data in flight, which the receive window bounds. :rfc:`7323` allows windows
#: up to ``2 ** 30``, but zero-filling a gap that wide costs 1 GiB, and real
#: windows are far smaller -- Linux's default ``net.ipv4.tcp_rmem`` ceiling is
#: 6 MiB -- so the default of 16 MiB clears them with room to spare. Past it,
#: the stream is split rather than padded, as :meth:`TCP.reassembly
#: <pcapkit.foundation.reassembly.tcp.TCP.reassembly>` describes.
#:
#: At ``-1`` only the sequence space bounds the gap: a sequence number is read
#: within ``2 ** 31`` of the data buffered (:rfc:`9293#section-3.4`), so one
#: segment can have up to 2 GiB zero-filled.
#:
#: .. versionadded:: 1.6.0
#:
#:    Moved from ``pcapkit.foundation.reassembly.tcp.TCP.__window__`` (:issue:`2546`).
TCP_GAP_LIMIT = read_limit('TCP_GAP_LIMIT', 1 << 24, risk=(
    'merging a segment that far from the data buffered zero-fills the gap in memory, '
    'up to 2 GiB per segment at -1'))

#: int: Most objects the ``_append_fallback`` method of a dumper
#: :func:`~pcapkit.dumpkit.common.make_dumper` builds
#: expands for one top-level object, counting an object once per time it is met,
#: :envvar:`PCAPKIT_FALLBACK_LIMIT`; ``-1`` expands without bound.
#:
#: Measured over the ``foundation``, ``dumpkit`` and ``interface`` test legs, no
#: fallback object expands into more than 7, so the default leaves three orders
#: of magnitude of room.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.dumpkit.common.FALLBACK_LIMIT`` (:issue:`1726`).
FALLBACK_LIMIT = read_limit('FALLBACK_LIMIT', 10_000, risk=(
    'an object that expands into a large or endless object graph is written out '
    'in full, which takes memory and time without bound'))

#: int: How many distinct bytestrings :func:`~pcapkit.utilities.chardet.detect`
#: remembers, :envvar:`PCAPKIT_DETECT_CACHE_SIZE`; ``-1`` leaves the cache
#: unbounded.
#:
#: Unlike the other limits, this one is read once, when
#: :mod:`pcapkit.utilities.chardet` is imported, as the size of its
#: :func:`functools.lru_cache`.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.utilities.chardet.DETECT_CACHE_SIZE`` (:issue:`1726`).
DETECT_CACHE_SIZE = read_limit('DETECT_CACHE_SIZE', 1024, risk=(
    'the cache keeps every bytestring it was asked about, so a capture full of '
    'never-repeating text is retained in memory'))

#: int: Most octets :class:`~pcapkit.corekit.io.SeekableReader` asks of its
#: stream in one read, :envvar:`PCAPKIT_READ_CHUNK`; ``-1`` asks for the whole
#: read at once.
#:
#: A read allocates what it asks for up front, so a record's bogus length is read
#: in pieces.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.corekit.io._READ_CHUNK`` (:issue:`1726`).
READ_CHUNK = read_limit('READ_CHUNK', 1 << 20, minimum=1, risk=(
    'a bogus record length allocates up to that many octets in one read'))

#: int: Ceiling on the zero-padding
#: :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`
#: will still perform for a field whose declared length outruns its buffer.
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
#: buffer holds":
#: :meth:`ListField.unpack <pcapkit.corekit.fields.collections.ListField.unpack>`
#: and
#: :meth:`OptionField.unpack <pcapkit.corekit.fields.collections.OptionField.unpack>`
#: depend on reading a short, sometimes
#: empty, tail past a truncated area and having it decode as zero -- that is
#: how an over-long ``ihl``, or a capture cut short by the snapshot length,
#: reads as end-of-option-list or ``Pad1`` instead of wedging or raising (see
#: :issue:`431`). Every such read is of a fixed-width, few-octet field, always
#: far under this ceiling, so it is untouched; only a length past it -- which
#: no fixed-width field ever legitimately is -- gets refused.
#:
#: A ceiling on one field says nothing about how many fields a parse may pad,
#: which is what :data:`MAX_ZERO_PAD_SHORTFALL` and
#: :data:`ZERO_PAD_BUDGET_RATIO` below are for. See :issue:`573`.
#:
#: Set with :envvar:`PCAPKIT_MAX_ZERO_PAD_LENGTH`. ``-1`` lifts the ceiling, and
#: lifts the running budget of :data:`ZERO_PAD_BUDGET_RATIO` with it, since the
#: ceiling is the one-off term of that budget's allowance.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH`` (:issue:`1726`).
MAX_ZERO_PAD_LENGTH = read_limit('MAX_ZERO_PAD_LENGTH', 0x40_000, risk=(
    'a hostile capture can declare a field that long and have it zero-filled in memory'))

#: int: Shortfall
#: :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`
#: will always zero-pad for, whatever else a parse has already padded.
#:
#: :data:`MAX_ZERO_PAD_LENGTH` bounds each field on its own, and a packet holds
#: many fields, so it leaves the *sum* unbounded: a declared length just under the
#: ceiling is honoured however often it is declared. Measured for :issue:`573`, 200
#: minimal PCAP-NG Decryption Secrets Blocks -- 4,800 wire octets, each block
#: declaring ``secrets_length`` of 262,142 against two supplied octets through
#: :attr:`UnknownSecrets.data <pcapkit.protocols.schema.misc.pcapng.UnknownSecrets.data>`
#: (``pcapkit/protocols/schema/misc/pcapng.py``) -- retained 50.0 MiB, an amplification of 10,922x
#: per block. Every individual field was under the ceiling, so nothing refused any of them.
#:
#: The sum therefore wants a budget, and this is the figure that makes one
#: *safe*. A budget on its own is not: a capture cut short by its snapshot length
#: pads legitimately and must keep parsing (:issue:`431`, and the reasoning that
#: declined :issue:`554`), and it pads far more than it reads, so any running
#: budget tight enough to matter starts refusing real captures. Worse, it refuses
#: them *sometimes* -- measured with a running budget alone, the
#: same legitimate 54-octet frame parsed to one result on 37 of 40 calls and to
#: another on calls 26, 33 and 39, because whether it fit depended on what had
#: been parsed before it. A guard whose answer moves with history is not a guard.
#:
#: 65,536 is what removes that. It is the whole span of a 16-bit wire length
#: field -- which is how an IPv4 datagram, an IPv6 payload and a PCAP-NG option
#: all declare their size, and a TCP or IPv4 option's 8-bit length declares less
#: -- so no shortfall that one of those can produce is subject to the budget at
#: all, and every one of them is padded unconditionally. Measured: the largest legitimate single
#: shortfall found anywhere was 65,495 octets, from a snapshot-truncated
#: offload-sized frame (100 frames at ``incl_len`` 54 declaring an IPv4 total
#: length of 65,535, padding 6,549,500 octets from 7,024 read), and 64,750 from a
#: truncated PCAP-NG option. Both sit under this figure, and so does anything
#: else a 16-bit field can ask for.
#:
#: What is left above it is the band a *32-bit* wire length reaches --
#: PCAP-NG's own block and secrets lengths, which is where :issue:`573`'s
#: amplification lives -- and legitimately that is a once-per-file event, since
#: only the last block of a truncated capture is cut short. So the band gets the
#: running budget below, whose one-off term already covers any single such event
#: outright.
#:
#: Set with :envvar:`PCAPKIT_MAX_ZERO_PAD_SHORTFALL`. ``-1`` disables the running
#: budget: every shortfall within :data:`MAX_ZERO_PAD_LENGTH` is then padded
#: without being charged to it.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.corekit.fields.field._MAX_ZERO_PAD_SHORTFALL`` (:issue:`1726`).
MAX_ZERO_PAD_SHORTFALL = read_limit('MAX_ZERO_PAD_SHORTFALL', 0x10_000, risk=(
    'shortfalls up to that size are zero-filled without being charged to the running budget, '
    'so a capture of many lying lengths can amplify into that much memory each'))

#: int: Zero padding *past* :data:`MAX_ZERO_PAD_SHORTFALL` that
#: :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`
#: will synthesise in total for every octet a parse has actually been given, over
#: and above the one-off :data:`MAX_ZERO_PAD_LENGTH` allowance.
#:
#: A shortfall in this band -- past 65,536 octets and so past anything a 16-bit
#: wire length can declare, but within :data:`MAX_ZERO_PAD_LENGTH` -- is a
#: PCAP-NG block or secrets length, a 32-bit figure. One of those, on its own, is
#: legitimate: it is what the final block of a capture truncated at EOF looks
#: like, and the ``MAX_ZERO_PAD_LENGTH`` term of the allowance covers it whole,
#: from a cold start, because such a shortfall cannot exceed that ceiling and
#: still be padded at all.
#:
#: *Repeating* one is not legitimate, and that is what 16 is chosen to catch.
#: Truncation cuts the end of a file, so a capture has one short block, not two
#: hundred; :issue:`573`'s shape has two hundred because they are declared
#: rather than cut. 16 octets of further allowance per octet genuinely read
#: leaves any real file an allowance orders of magnitude past the one event it
#: can want, while bounding the sum for a file whose blocks all lie.
#:
#: Set with :envvar:`PCAPKIT_ZERO_PAD_BUDGET_RATIO`. ``-1`` lifts the running
#: budget; :data:`MAX_ZERO_PAD_LENGTH` still bounds each field.
#:
#: .. versionadded:: 1.5.0
#:
#:    Moved from ``pcapkit.corekit.fields.field._ZERO_PAD_BUDGET_RATIO`` (:issue:`1726`).
ZERO_PAD_BUDGET_RATIO = read_limit('ZERO_PAD_BUDGET_RATIO', 0x10, risk=(
    'a capture whose blocks all lie about their lengths can amplify each octet read '
    'into that many zero octets in memory'))

###############################################################################
# Flags
###############################################################################

#: bool: Whether parsing verifies the one's-complement checksums, of the IPv4
#: header, TCP, UDP, ICMP, ICMPv6 and OSPF, :envvar:`PCAPKIT_CHECKSUM_VERIFY`.
#:
#: Off by default, since checksumming every packet costs time on a large
#: capture (:issue:`2471`). When on, each records a
#: :class:`~pcapkit.protocols.misc.checksum.checksum.ChecksumStatus` as
#: ``checksum_status`` in its info, and a wrong checksum warns with a
#: :exc:`~pcapkit.utilities.warnings.ChecksumWarning` rather than raising.
#:
#: .. versionadded:: 1.6.0
CHECKSUM_VERIFY = read_flag('CHECKSUM_VERIFY', False)

#: bool: Whether construction computes a checksum the caller leaves out, for
#: the protocols :data:`CHECKSUM_VERIFY` names, :envvar:`PCAPKIT_CHECKSUM_COMPUTE`.
#:
#: On by default (:issue:`2471`). A checksum given explicitly, as
#: :meth:`~pcapkit.protocols.protocol.Protocol.from_data` gives the parsed one,
#: is written as given either way. Off, a checksum left out is zero.
#:
#: .. versionadded:: 1.6.0
CHECKSUM_COMPUTE = read_flag('CHECKSUM_COMPUTE', True)
