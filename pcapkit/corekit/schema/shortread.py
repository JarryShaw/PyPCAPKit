# -*- coding: utf-8 -*-
"""Short-Read Replay
=======================

.. module:: pcapkit.corekit.schema.shortread

:mod:`pcapkit.corekit.schema.shortread` carries a header cut short by the end of the
capture through to the protocol's info, by which a protocol rebuilt from that info
is cut back to the octets its header had (:issue:`1458`), for the layer base classes
and the PCAP global header alike, and tells a protocol's checks of a header parsed on
its own where the cut fell (:issue:`2880`). It names the protocol and schema classes
for type checking only, since those import it. It is one of the :mod:`pcapkit.corekit.schema`
helpers shared across the schema layer, not part of the header schema framework in
:mod:`pcapkit.protocols.schema`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.schema`` (:issue:`2674`).

"""

import collections.abc
import io
from typing import TYPE_CHECKING, cast

from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.utilities.contextvars import frame_depth, frame_length

if TYPE_CHECKING:
    from typing import Any, Iterable, Optional, TypeVar

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

    _PB = TypeVar('_PB', bound=ProtocolBase)

__all__ = ['keep_short_read', 'replay_short_read', 'hoist_short_read', 'cut_on_its_own', 'fill_short_options',
           'ends_inside_option']


def keep_short_read(protocol: 'ProtocolBase', length: 'Optional[int]' = None) -> 'None':
    """Carry a parsed header's short read into the protocol's info.

    Args:
        protocol: Protocol instance, just parsed.
        length: Length of data the parse was given, :data:`None` for the octets
            it holds.

    Called by the layer base classes, and by the PCAP global
    :class:`~pcapkit.protocols.misc.pcap.header.protocol.Header`, once a parse is done.
    When the data ended inside one of the header's fields, ``info`` gains the ``__short_read__``
    record :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
    made, so that :meth:`Protocol.from_data
    <pcapkit.protocols.protocol.Protocol.from_data>` hands it to the rebuild,
    whose :meth:`Protocol.pack <pcapkit.protocols.protocol.Protocol.pack>` cuts
    the header back to what was captured before it is read (:issue:`1458`,
    :issue:`2703`). Beside it, ``__short_width__`` records the length the parse
    read the header at, which the rebuild is read at in turn, so that it holds
    the values its parse read (:issue:`2761`). Both keys are listed
    in :attr:`Data.__included__ <pcapkit.protocols.data.Data.__included__>`,
    so :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` carries them
    and ``from_data(info.to_dict())`` cuts its rebuild back too; they are absent
    for a header that was captured whole.

    Where the capture cut the frame short, as
    :data:`~pcapkit.utilities.contextvars.frame_length` gives its lengths, a
    layer whose message runs to the end of the frame records the cut too, on the
    field it runs to the end in, through :meth:`Schema._note_short_read
    <pcapkit.protocols.schema.Schema._note_short_read>`, so its rebuild
    reads as cut, as the layer did inside the frame (:issue:`2711`). A layer
    whose own header declares where its message ends records none, whether the
    cut falls at that end or past it; see :meth:`Schema._frame_end_field
    <pcapkit.protocols.schema.Schema._frame_end_field>`.

    """
    header = cast('Optional[Schema]', getattr(protocol, '__header__', None))
    if header is None:
        return
    lengths = frame_length.get()
    if lengths is not None and lengths[1] > lengths[0]:
        name = header._frame_end_field()  # pylint: disable=protected-access
        if name is not None:
            octets = header.__buffer__[name]
            header._note_short_read(name, len(octets) + lengths[1] - lengths[0], octets)  # pylint: disable=protected-access
    record = header.__dict__.get('__short_read__')
    if record is not None:
        width = len(protocol._data) if length is None else length  # pylint: disable=protected-access
        protocol._info.__update__({'__short_read__': record, '__short_width__': width})  # pylint: disable=protected-access


def replay_short_read(protocol: '_PB', data: 'Any') -> '_PB':
    """Hold a protocol rebuilt by ``from_data`` to the octets its header had.

    Args:
        protocol: Protocol instance, just built by ``from_data``.
        data: The info it was built from.

    Returns:
        ``protocol`` itself.

    The layer base classes and the PCAP global
    :class:`~pcapkit.protocols.misc.pcap.header.protocol.Header` call it on what
    :meth:`Protocol.from_data <pcapkit.protocols.protocol.Protocol.from_data>`
    returns, which is cut back before it gets here: ``from_data`` hands the
    construction the ``__short_read__`` record that :func:`keep_short_read`
    left in ``data``, :meth:`Protocol.pack
    <pcapkit.protocols.protocol.Protocol.pack>` cuts the header it makes back
    to the octets captured through :meth:`Schema._cut_short_read
    <pcapkit.protocols.schema.Schema._cut_short_read>`, and
    :meth:`Protocol.__post_init__
    <pcapkit.protocols.protocol.Protocol.__post_init__>` has
    :meth:`~pcapkit.protocols.protocol.Protocol.read` parse those octets at the
    width ``__short_width__`` records, the one its parse read them at, so the
    rebuild is read and verified as its capture was (:issue:`2703`,
    :issue:`2761`).

    The record names the field the capture ended inside and how much of it
    there was. Everything in the rebuild from that point on is dropped, which
    on a rebuild cut back as above is nothing, and the header and the info
    keep the record (:issue:`1458`). A header cut short has no payload past
    it, so that point ends the rebuilt data, and what the protocol writes
    ahead of the header is kept: the HTTP/2 connection preface ``HTTP.pack``
    writes (:issue:`2665`). This holds while ``pack`` writes nothing after the
    header schema, as no protocol rebuilt here does; a trailer would keep as
    many of the cut octets.

    """
    record = data.get('__short_read__') if isinstance(data, collections.abc.Mapping) else None
    header = cast('Optional[Schema]', getattr(protocol, '__header__', None))
    if record is None or header is None:
        return protocol

    name, count = record
    # NOTE: Where the header starts, past what is written ahead of it (#2665); the
    # width is summed from the buffers, as ``Schema.unpack`` sums it, not repacked.
    offset = len(protocol._data) - sum(map(len, header.__buffer__.values()))  # pylint: disable=protected-access
    for key in header.__fields__:
        if key == name:
            offset += min(count, len(header.__buffer__[key]))
            break
        offset += len(header.__buffer__[key])
    else:
        return protocol

    header.__dict__['__short_read__'] = record
    header._cut_short_read()  # pylint: disable=protected-access

    # pylint: disable=protected-access
    protocol._data = protocol._data[:offset]
    protocol._file = io.BytesIO(protocol._data)
    protocol.__cached__.pop('__len__', None)
    protocol._info.__update__({'__short_read__': record})
    return protocol


def hoist_short_read(schema: 'Schema', name: 'str', parts: 'Iterable[Optional[Schema]]') -> 'None':
    """Record on ``schema`` a short read only the schemas in its field ``name`` recorded.

    Args:
        schema: The header just parsed.
        name: Its field holding ``parts``.
        parts: The schemas read in that field, :data:`None` for one absent.

    Each of ``parts`` must read to the end of the data, so a field there that reads
    short has reached it, and the record names ``name`` with every octet of it
    read. Elsewhere a nested record need not mean that: hoisting one in
    :func:`keep_short_read` marks a complete TCP segment with a malformed MPTCP DSS
    option as cut (:issue:`2660`). IGMPv3 and ICMPv6 hoist the record of a message
    body counting records the data ends before.

    .. versionadded:: 1.7.0

    """
    if '__short_read__' not in schema.__dict__ and any(
            part is not None and '__short_read__' in part.__dict__ for part in parts):
        schema.__dict__['__short_read__'] = (name, len(schema.__buffer__[name]))


def cut_on_its_own(header: 'Schema', name: 'Optional[str]' = None, end: 'Optional[int]' = None) -> 'bool':
    """Tell a check of a header parsed on its own whether the data ended before what it reads.

    Args:
        header: The header just parsed.
        name: Its field the check reads; :data:`None` for the whole header.
        end: How many octets of ``name``, from its start, the check reads;
            :data:`None` for all of them.

    Returns:
        Whether ``header`` was parsed with no layer before it, as
        :data:`~pcapkit.utilities.contextvars.frame_depth` tells, and the short
        read it records ends the data before those octets of ``name``, or
        anywhere in it without a ``name``.

    On its own the end of the data is a cut (:issue:`2880`), so a value past it is a
    zero the cut left, not one read. A check that would refuse such a value leaves it
    to the short read, as a field callback does (:issue:`2727`), and so does one refusing
    a header length the data ends inside, refused on :issue:`1404` because the rebuild
    filled the zeros in, which the short read now cuts back. Inside a frame its lengths
    say where the message ends, so such a check refuses as before.

    .. versionadded:: 1.7.0

    """
    record = header.__dict__.get('__short_read__')
    if record is None or frame_depth.get():
        return False
    if name is None:
        return True
    cut, count = record
    for key in header.__fields__:
        if key == cut:
            return key != name or end is None or count < end
        if key == name:
            return False
    return False


def fill_short_options(data: 'Any', options: 'Any', size: 'int', zero: 'tuple[Any, Any]',
                       padding: 'Optional[bytes]' = None) -> 'tuple[Any, Optional[bytes]]':
    """Fill out an options area a short read ended inside, so a rebuild writes its length.

    Args:
        data: The data model a protocol is rebuilt from.
        options: Its options, keyed by code, as the protocol's ``read`` gives them, or
            :data:`None` for none.
        size: Octets its header length gives the options area.
        zero: The code and data model of the one-octet option a zero octet reads as.
        padding: Octets it records after an End of Option List, or :data:`None` where
            the protocol records none.

    Returns:
        ``options`` and ``padding`` to ``size`` octets where ``data`` records a short
        read: past ``size``, trailing ``zero`` options dropped; short of it, filled out
        with zero octets, after ``padding`` where the options end with ``zero``, else
        as that many ``zero`` options.

    A header length the data ends before is read as parsed on its own
    (:func:`cut_on_its_own`), but ``make`` writes the length of the options it is
    given, which past the cut are a cut option's whole length and the end of the
    list its zeros read as. Whatever is filled or dropped lies past the cut, so the
    rebuild's cut back leaves the octets and the header length its parse read
    (:issue:`2880`).

    .. versionadded:: 1.7.0

    """
    if options is None or data.get('__short_read__') is None:
        return options, padding
    items = list(options.items(multi=True))
    fill = size - sum(option.length for _, option in items) - len(padding or b'')
    if fill < 0:
        while fill < 0 and items and items[-1][0] == zero[0]:
            fill += items.pop()[1].length
        options = OrderedMultiDict(items)
    if fill <= 0:
        return options, padding
    if padding is not None and items and items[-1][0] == zero[0]:
        return options, padding + bytes(fill)
    return OrderedMultiDict([*items, *[zero] * fill]), padding


def ends_inside_option(options: 'Any', count: 'int') -> 'bool':
    """Tell whether the first ``count`` octets of an options area end inside one of its options.

    Args:
        options: The options read from the area, keyed by code, each with the
            ``length`` it declares.
        count: Octets of the area the data holds.

    Returns:
        Whether an option starts before ``count`` octets and declares more than them.

    Such an option rebuilds by the values it holds rather than by the length it
    declares, so neither its own length nor the header length before it would
    rebuild as parsed: a header the data ends inside an option of stays refused
    on its own too (:issue:`1404`, :issue:`2880`).

    .. versionadded:: 1.7.0

    """
    offset = 0
    for _, option in options.items(multi=True):
        if offset >= count:
            return False
        offset += option.length
        if offset > count:
            return True
    return False
