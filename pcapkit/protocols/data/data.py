# -*- coding: utf-8 -*-
"""base class for data models"""

from pcapkit.corekit.infoclass import Info

__all__ = ['Data']


class Data(Info):
    """Base class for data models."""

    __excluded__ = ['__next_name__', '__next_type__']
