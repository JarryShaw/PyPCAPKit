# -*- coding: utf-8 -*-
"""hypertext transfer protocol

:mod:`pcapkit.protocols.application.http` contains
:class:`~pcapkit.protocols.application.http.HTTP`
only, which is a base class for Hypertext Transfer
Protocol (HTTP) [*]_ family, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.application.httpv1>`
and :class:`HTTP/2 <pcapkit.protocols.application.application.httpv2>`.

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol

"""
import abc

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.null import NoPayload
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['HTTP']


class HTTP(Application):  # pylint: disable=abstract-method
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [:rfc:`7230`]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [:rfc:`7540`]

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Hypertext Transfer Protocol']
        """
        return 'Hypertext Transfer Protocol'

    @property
    def length(self):
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    ##########################################################################
    # Methods.
    ##########################################################################

    @abc.abstractmethod
    def read_http(self, length):
        """Read Hypertext Transfer Protocol (HTTP).

        Args:
            length (int): packet length

        Returns:
            dict: Parsed packet data.

        """

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
            Tuple[Literal['HTTPv1'], Literal['HTTPv2']]: Index ID of the protocol.

        """
        return ('HTTPv1', 'HTTPv2')

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        """
        self._file = _file
        self._info = Info(self.read_http(length))

        self._next = NoPayload()
        self._protos = ProtoChain(self.__class__, self.alias)
