# -*- coding: utf-8 -*-
"""Shared Context Variables
==============================

.. module:: pcapkit.utilities.contextvars

:mod:`pcapkit.utilities.contextvars` holds the :class:`~contextvars.ContextVar`
objects that more than one :mod:`pcapkit` module sets or reads, so that no module
imports another's private state (:issue:`2616`). A context variable that only its
own module uses stays there. This module imports nothing from :mod:`pcapkit`, so
a module at any layer may import it; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

"""
import contextvars
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['beholding', 'frame_depth', 'frame_length', 'rebuilding']

#: contextvars.ContextVar[bool]: Whether a layer that raises is discarded by its
#: caller, as :func:`~pcapkit.corekit.decorators.beholder` replaces it and
#: :func:`~pcapkit.toolkit.pypcapfile._default_extension_header` drops it, so
#: that :meth:`Protocol._parse_next_layer
#: <pcapkit.protocols.protocol.Protocol._parse_next_layer>` drops its warnings
#: with it (:issue:`2308`).
beholding = contextvars.ContextVar('pcapkit.utilities.contextvars.beholding', default=False)

#: contextvars.ContextVar[int]: How many layers of the frame being dissected
#: come before the next one :meth:`Protocol._parse_next_layer
#: <pcapkit.protocols.protocol.Protocol._parse_next_layer>` parses; see
#: :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.
frame_depth = contextvars.ContextVar('pcapkit.utilities.contextvars.frame_depth', default=0)

#: contextvars.ContextVar[tuple[int, int] | None]: The captured and the original
#: length of the frame being dissected, in octets, as its PCAP record or PCAP-NG
#: packet block states them; :data:`None` outside a frame, and inside the payload
#: of an :class:`~pcapkit.protocols.internet.internet.Internet` layer that
#: bounds it, which neither an IPv4 Total Length of 0 nor
#: :class:`~pcapkit.protocols.internet.ah.AH` does (:issue:`2689`). A frame
#: the capture cut short holds fewer octets than were on the wire, which a layer
#: stating no length of its own, as :class:`~pcapkit.protocols.link.gre.GRE`,
#: cannot tell from the octets it is handed (:issue:`2653`).
frame_length = contextvars.ContextVar(
    'pcapkit.utilities.contextvars.frame_length', default=None,
)  # type: contextvars.ContextVar[Optional[tuple[int, int]]]

#: contextvars.ContextVar[bool]: Whether a payload is being rebuilt by
#: :meth:`Protocol._make_payload
#: <pcapkit.protocols.protocol.Protocol._make_payload>`, so that the layer
#: it is rebuilt for parses the same octets again; see
#: :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.
rebuilding = contextvars.ContextVar('pcapkit.utilities.contextvars.rebuilding', default=False)
