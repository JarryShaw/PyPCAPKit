# -*- coding: utf-8 -*-
# pylint: disable=bad-whitespace
"""root transport layer protocol

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.transport.udp.UDP`.

"""
from pcapkit.const.reg.transtype import TransType as TP_PROTO
from pcapkit.protocols.null import NoPayload
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.decorators import beholder_ng

###############################################################################
# from pcapkit.fundation.analysis import analyse
###############################################################################

__all__ = ['Transport', 'TP_PROTO']


class Transport(Protocol):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Transport'

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self):
        """Protocol layer.

        :rtype: Literal['Transport']
        """
        return self.__layer__

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _import_next_layer(self, proto, length=None):
        """Import next layer extractor.

        Arguments:
            proto (str): next layer protocol name
            length (int): valid (*non-padding*) length

        Returns:
            pcapkit.protocols.protocol.Protocol: instance of next layer

        """
        if self._exproto == 'null' and self._exlayer == 'None':
            from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel
        else:
            from pcapkit.foundation.analysis import analyse as protocol  # pylint: disable=import-outside-toplevel

        if length == 0:
            next_ = NoPayload()
        elif self._onerror:
            next_ = beholder_ng(protocol)(self._file, length, termination=self._sigterm)
        else:
            next_ = protocol(self._file, length, termination=self._sigterm)
        return next_
