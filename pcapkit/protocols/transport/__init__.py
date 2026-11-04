# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Transport Layer Protocols
===============================

.. module:: pcapkit.protocols.transport

:mod:`pcapkit.protocols.transport` is a collection of all protocols in
the transport layer, with detailed implementation and methods.

Each protocol class, and the base class
:class:`~pcapkit.protocols.transport.transport.Transport`, is imported the first
time it is reached rather than with this package, through
:func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
# TODO: Implement RSVP.

from typing import TYPE_CHECKING

# Transport Layer Protocol Numbers
from pcapkit.const.reg.transtype import TransType as TRANSTYPE
from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    # Base Class for Transport Layer
    from pcapkit.protocols.transport.transport import Transport

    # Transport Layer Protocols
    from pcapkit.protocols.transport.dccp import DCCP
    from pcapkit.protocols.transport.sctp import SCTP
    from pcapkit.protocols.transport.tcp import TCP
    from pcapkit.protocols.transport.udp import UDP

__all__ = [
    'TRANSTYPE',   # Protocol Numbers
    'DCCP', 'TCP', 'UDP', 'SCTP',  # Transport Layer Protocols
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Transport': ('transport', 'Transport'),
    'DCCP': ('dccp', 'DCCP'),
    'SCTP': ('sctp', 'SCTP'),
    'TCP': ('tcp', 'TCP'),
    'UDP': ('udp', 'UDP'),
})
