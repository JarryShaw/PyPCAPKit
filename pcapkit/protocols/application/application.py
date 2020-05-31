# -*- coding: utf-8 -*-
"""root application layer protocol

:mod:`pcapkit.protocols.application.application` contains only
:class:`~pcapkit.protocols.application.application.Application`,
which is a base class for application layer protocols, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.application.httpv1>`,
:class:`HTTP/2 <pcapkit.protocols.application.application.httpv2>`
and etc.

"""
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.null import NoPayload
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import IntError, UnsupportedCall

__all__ = ['Application']


class Application(Protocol):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Application'

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self):
        """Protocol layer.

        :rtype: Literal['Application']
        """
        return self.__layer__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file=None, length=None, **kwargs):
        """Post initialisation hook.

        Args:
            file (Optional[io.BytesIO]): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        # call super post-init
        super().__post_init__(file, length, **kwargs)

        #: pcapkit.protocols.null.NoPayload: Payload of current instance.
        self._next = NoPayload()
        #: pcapkit.corekit.protochain.ProtoChain: Protocol chain of current instance.
        self._protos = ProtoChain(self.__class__, self.alias)

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            IntError: This protocol doesn't support :meth:`__index__`.

        """
        raise IntError(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Decode next layer protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_decode_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, proto, length=None):
        """Import next layer extractor.

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_import_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")
