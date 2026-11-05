# -*- coding: utf-8 -*-
"""data models for no-payload packet"""

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

__all__ = ['NoPayload']


@info_final
class NoPayload(Protocol):
    """No-payload packet is an empty packet."""

    # NOTE: So the class takes no arguments, where ``Info`` would generate an ``__init__``
    # taking any mapping and keywords for a class with no annotations.
    def __init__(self) -> 'None':  # pylint: disable=super-init-not-called
        pass
