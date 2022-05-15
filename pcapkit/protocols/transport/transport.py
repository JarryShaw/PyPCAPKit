# -*- coding: utf-8 -*-
"""root transport layer protocol

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.transport.udp.UDP`.

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.decorators import beholder, beholder_ng
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import NoReturn, Optional, Type

    from typing_extensions import Literal

__all__ = ['Transport']


class Transport(Protocol):  # pylint: disable=abstract-method
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
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @beholder
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None) -> 'Protocol':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length

        Returns:
            Instance of next layer.

        """
        if TYPE_CHECKING:
            protocol: 'Type[Protocol]'

        if length is not None and length == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
        else:
            from pcapkit.foundation.analysis import analyse as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
            protocol = beholder_ng(protocol)

        next_ = protocol(self._file, length, layer=self._exlayer, protocol=self._exproto)  # type: ignore[abstract]
        return next_
