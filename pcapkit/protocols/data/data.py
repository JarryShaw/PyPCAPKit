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

    The ``__next_name__`` and ``__next_type__`` keys are metadata: they name
    the payload, and :meth:`Protocol.from_data
    <pcapkit.protocols.protocol.ProtocolBase.from_data>` dispatches the payload
    on them and on nothing else. :meth:`to_dict` carries them, so that
    ``from_data(info.to_dict())`` rebuilds as ``from_data(info)`` does, while
    the dumpers and ``repr`` leave out every such dunder key. A hand-written
    :obj:`dict` must carry them as well -- and, for IPv6, the extension
    headers under ``extension_headers`` -- for the payload to be rebuilt:
    without them, no payload layer is dispatched, as for a protocol with no
    next layer (:issue:`2003`).

    """

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
