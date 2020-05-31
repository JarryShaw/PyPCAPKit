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
from pcapkit.protocols.application.application import Application
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

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
            Tuple[Literal['HTTPv1'], Literal['HTTPv2']]: Index ID of the protocol.

        """
        return ('HTTPv1', 'HTTPv2')
