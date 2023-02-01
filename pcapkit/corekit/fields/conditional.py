# -*- coding: utf-8 -*-
"""conditional field class"""

from typing import TYPE_CHECKING, TypeVar

from pcapkit.corekit.fields.field import Field

__all__ = ['ConditionalField']

if TYPE_CHECKING:
    from typing import Any, Callable

_P = TypeVar('_P', 'int', 'bytes')
_T = TypeVar('_T')


class ConditionalField(Field[_P, _T]):
    """Conditional value for protocol fields.

    Args:
        field: field instance.
        condition: field condition function (this function should return a bool
            value and accept the current packet :class:`pcapkit.corekit.infoclass.Info`
            as its only argument).

    """

    @property
    def field(self) -> 'Field[_P, _T]':
        """Field instance."""
        return self._field

    def __init__(self, field: 'Field[_P, _T]',  # pylint: disable=super-init-not-called
                 condition: 'Callable[[dict[str, Any]], bool]') -> 'None':
        self._field = field  # type: Field[_P, _T]
        self._condition = condition

    def test(self, packet: 'dict[str, Any]') -> 'bool':
        """Test field condition.

        Arguments:
            packet: current packet

        Returns:
            bool: test result

        """
        return self._condition(packet)
