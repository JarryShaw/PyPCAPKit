# -*- coding: utf-8 -*-
"""data modules for no-payload packet"""

from pcapkit.protocols.data.data import Data

__all__ = ['NoPayload']


class NoPayload(Data):
    """No-payload packet is an empty packet."""

    # NOTE: We add this method for both type annotation and to mark that this
    # class accepts no arguments at runtime, since :class:`Info` explicitly
    # skipped those whose :attr:`__annotations__` is empty :obj:`dict`.
    def __init__(self) -> 'None':  # pylint: disable=super-init-not-called
        pass
