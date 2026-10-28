# -*- coding: utf-8 -*-
"""base class for data models"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

__all__ = ['Data']

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.protocols.protocol import ProtocolBase


class Data(Info):
    """Base class for data models.

    The ``__next_name__``, ``__next_type__`` and ``__short_read__`` keys are
    metadata, listed in :attr:`~pcapkit.corekit.infoclass.Info.__included__`
    and :attr:`~pcapkit.corekit.infoclass.Info.__excluded__`:
    :meth:`ProtocolBase.from_data <pcapkit.protocols.protocol.ProtocolBase.from_data>`
    dispatches the payload on the first two and on nothing else, and cuts a
    short read back on the third. :meth:`to_dict` carries them, so that
    ``from_data(info.to_dict())`` rebuilds as ``from_data(info)`` does, while
    the dumpers and ``repr`` leave them out. A hand-written :obj:`dict` must
    carry them as well -- and, for IPv6, the extension header chain under
    ``__exthdr__`` -- to be rebuilt the same way: without the first two, no
    payload layer is dispatched, as for a protocol with no next layer, and
    without ``__exthdr__`` no IPv6 extension header is rebuilt
    (:issue:`2003`).

    """

    #: Metadata keys that :meth:`to_dict` carries, for a rebuild to read.
    __included__ = ['__next_name__', '__next_type__', '__short_read__']
    #: Metadata keys that ``repr``, ``str`` and the dumps leave out.
    __excluded__ = ['__next_name__', '__next_type__', '__short_read__']

    if TYPE_CHECKING:
        #: Next field name, i.e., the name of the payload field.
        __next_name__: 'str'
        #: Next field type, i.e., the type of the payload field.
        __next_type__: 'Type[ProtocolBase]'
        #: Name of the header field the data ended inside, and how many of its
        #: octets were there; present only then. :meth:`to_dict` carries it,
        #: so that ``from_data(info.to_dict())`` cuts the rebuild back as
        #: ``from_data(info)`` does. See
        #: :func:`~pcapkit.protocols.schema.schema.keep_short_read`.
        __short_read__: 'tuple[str, int]'
