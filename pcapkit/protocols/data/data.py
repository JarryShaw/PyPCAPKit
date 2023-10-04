# -*- coding: utf-8 -*-
"""base class for data models"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

__all__ = ['Data']

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.protocols.protocol import ProtocolBase as Protocol


class Data(Info):
    """Base class for data models."""

    __excluded__ = ['__next_name__', '__next_type__']

    if TYPE_CHECKING:
        #: Next field name, i.e., the name of the payload field.
        __next_name__: 'str'
        #: Next field type, i.e., the type of the payload field.
        __next_type__: 'Type[Protocol]'
