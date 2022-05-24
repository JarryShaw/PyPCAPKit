# -*- coding: utf-8 -*-
"""root transport layer protocol

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.transport.udp.UDP`.

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.protocols.protocol import PT, Protocol
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['Transport']


class Transport(Protocol[PT], Generic[PT]):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Transport'  # type: Literal['Transport']

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self) -> 'Literal["Transport"]':
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'int', module: str, class_: str) -> 'None':
        """Register a new protocol class.

        Important:
            This method must be called from a non-abstract class, as the
            protocol map should be associated directly with specific
            transport layer protocol type.

        Arguments:
            code: port number
            module: module name
            class_: class name

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        """
        if cls is Transport:
            raise UnsupportedCall(f'{cls.__name__} is an abstract class')

        cls.__proto__[code] = (module, class_)
