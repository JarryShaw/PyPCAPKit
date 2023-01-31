# -*- coding: utf-8 -*-
"""base field class"""

import abc
import struct
from typing import TYPE_CHECKING

__all__ = ['Field']

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.infoclass import Info


class Field(abc.ABC):
    """Base class for protocol fields.

    Args:
        condition: field condition function (this function should return a bool
            value and accept the current packet :class:`pcapkit.corekit.infoclass.Info`
            as its only argument).

    """

    @property
    def endian(self) -> 'Literal["little", "big"]':
        """Field byte order."""
        return 'big'

    @abc.abstractmethod
    @property
    def template(self) -> 'str':
        """Field template."""

    @property
    def length(self) -> 'int':
        """Field size."""
        return struct.calcsize(self.template)

    def __init__(self, condition: 'Optional[Callable[[Info], bool]]' = None) -> 'None':
        self._condition = condition

    def test(self, packet: 'Info') -> 'bool':
        """Test field condition.

        Arguments:
            packet: current packet

        Returns:
            bool: test result

        """
        if self._condition is None:
            return True
        return self._condition(packet)

    def pre_process(self, value: 'Any') -> 'Any':
        """Process field value before construction (packing).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        return value

    def post_process(self, value: 'Any') -> 'Any':
        """Process field value after parsing (unpacked).

        Arguments:
            value: field value

        Returns:
            Processed field value.

        """
        return value
