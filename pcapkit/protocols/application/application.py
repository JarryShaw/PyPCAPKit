# -*- coding: utf-8 -*-
"""Base Protocol
===================

.. module:: pcapkit.protocols.application.application

:mod:`pcapkit.protocols.application.application` contains only
:class:`~pcapkit.protocols.application.application.Application`,
which is a base class for application layer protocols, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.application.httpv1>`,
:class:`HTTP/2 <pcapkit.protocols.application.application.httpv2>`
and etc.

"""
from typing import TYPE_CHECKING, Generic, overload

from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.protocols.protocol import ProtocolBase as Protocol
from pcapkit.utilities.exceptions import IntError, UnsupportedCall

if TYPE_CHECKING:
    from typing import IO, Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['Application']


class Application(Protocol[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Application'  # type: Literal['Application']

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self) -> 'Literal["Application"]':
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction arguments, please refer to
            :meth:`self.make <pcapkit.protocols.protocol.Protocol.make>`.

        """
        # call super post-init
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

        #: pcapkit.protocols.null.NoPayload: Payload of current instance.
        self._next = NoPayload()
        #: pcapkit.corekit.protochain.ProtoChain: Protocol chain of current instance.
        self._protos = ProtoChain(self.__class__, self.alias)

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            IntError: This protocol doesn't support :meth:`__index__`.

        """
        raise IntError(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_: '_PT', proto: 'Optional[int]' = None, length: 'Optional[int]' = None, *,
                           packet: 'Optional[dict[str, Any]]' = None) -> 'NoReturn':
        """Decode next layer protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_decode_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[override]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'NoReturn':
        """Import next layer extractor.

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_import_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")
