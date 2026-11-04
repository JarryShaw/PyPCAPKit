# -*- coding: utf-8 -*-
"""Short-Read Replay
=======================

.. module:: pcapkit.corekit.schema.shortread

:mod:`pcapkit.corekit.schema.shortread` carries a header cut short by the end of the
capture through to the protocol's info, by which a protocol rebuilt from that info
is cut back to the octets its header had (:issue:`1458`), for the layer base classes
and the PCAP global header alike. It names the protocol and schema classes for type
checking only, since those import it. It is one of the :mod:`pcapkit.corekit.schema`
helpers shared across the schema layer, not part of the header schema framework in
:mod:`pcapkit.protocols.schema`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.schema`` (:issue:`2674`).

"""

import collections.abc
import io
from typing import TYPE_CHECKING, cast

from pcapkit.utilities.contextvars import frame_length

if TYPE_CHECKING:
    from typing import Any, Optional, TypeVar

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

    _PB = TypeVar('_PB', bound=ProtocolBase)

__all__ = ['keep_short_read', 'replay_short_read']


def keep_short_read(protocol: 'ProtocolBase') -> 'None':
    """Carry a parsed header's short read into the protocol's info.

    Args:
        protocol: Protocol instance, just parsed.

    Called by the layer base classes, and by the PCAP global
    :class:`~pcapkit.protocols.misc.pcap.header.protocol.Header`, once a parse is done.
    When the data ended inside one of the header's fields, ``info`` gains the ``__short_read__``
    record :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
    made, so that :meth:`Protocol.from_data
    <pcapkit.protocols.protocol.Protocol.from_data>` hands it to the rebuild,
    whose :meth:`Protocol.pack <pcapkit.protocols.protocol.Protocol.pack>` cuts
    the header back to what was captured before it is read (:issue:`1458`,
    :issue:`2703`). The key is listed
    in :attr:`Data.__included__ <pcapkit.protocols.data.Data.__included__>`,
    so :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` carries it
    and ``from_data(info.to_dict())`` cuts its rebuild back too; it is absent for
    a header that was captured whole.

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
        protocol._info.__update__({'__short_read__': record})  # pylint: disable=protected-access


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
    width the header declares, so the rebuild is read and verified as its
    capture was (:issue:`2703`).

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
