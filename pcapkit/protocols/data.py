# -*- coding: utf-8 -*-
"""base class for data models"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

__all__ = [
    'Data', 'Packet'
]

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.protocols.protocol import ProtocolBase


class Data(Info):
    """Base class for data models.

    The ``__next_name__``, ``__next_type__``, ``__short_read__`` and
    ``__short_width__`` keys are metadata, listed in
    :attr:`~pcapkit.corekit.infoclass.Info.__included__` and
    :attr:`~pcapkit.corekit.infoclass.Info.__excluded__`.
    :meth:`Protocol.from_data <pcapkit.protocols.protocol.Protocol.from_data>`
    dispatches the payload on the first two alone, cuts a short read back on
    the third, and reads it at the width the fourth records.

    :meth:`to_dict` carries them, so ``from_data(info.to_dict())`` rebuilds as
    ``from_data(info)`` does; the dumpers and ``repr`` leave them out. A
    hand-written :obj:`dict` needs them too, and for IPv6 the extension header
    chain under ``__exthdr__``: without the first two no payload layer is
    dispatched, and without ``__exthdr__`` no IPv6 extension header is rebuilt
    (:issue:`2003`).

    """

    #: Metadata keys that :meth:`to_dict` carries, for a rebuild to read.
    __included__ = ['__next_name__', '__next_type__', '__short_read__', '__short_width__']
    #: Metadata keys that ``repr``, ``str`` and the dumps leave out.
    __excluded__ = ['__next_name__', '__next_type__', '__short_read__', '__short_width__']

    if TYPE_CHECKING:
        #: Next field name, i.e., the name of the payload field.
        __next_name__: 'str'
        #: Next field type, i.e., the type of the payload field.
        __next_type__: 'Type[ProtocolBase]'
        #: Name of the header field the data ended inside, and how many of its
        #: octets were there; present only then. See
        #: :func:`~pcapkit.corekit.schema.shortread.keep_short_read`.
        __short_read__: 'tuple[str, int]'
        #: Length of data the parse read the header at, where it recorded
        #: ``__short_read__``; present only then. ``from_data`` reads the
        #: rebuild at it, so it holds the values its parse read (:issue:`2761`).
        __short_width__: 'int'


class Protocol(Data):
    """Root protocol."""

    if TYPE_CHECKING:
        #: Packet payload.
        packet: 'bytes'


@info_final
class Packet(Data):
    """Header and payload data."""

    #: packet header
    header: 'bytes'
    #: packet payload
    payload: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, header: 'bytes', payload: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
