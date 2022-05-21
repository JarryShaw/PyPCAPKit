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
import contextlib
from typing import TYPE_CHECKING

from pcapkit.protocols.application.application import Application
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.infoclass import Info
    from pcapkit.protocols.protocol import Protocol

__all__ = ['HTTP']


class HTTP(Application):
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [:rfc:`7230`]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [:rfc:`7540`]

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Hypertext Transfer Protocol"]':
        """Name of current protocol."""
        return 'Hypertext Transfer Protocol'

    @property
    def length(self) -> 'NoReturn':
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    @property
    def version(self) -> 'Literal["0.9", "1.0", "1.1", "2"]':
        """Version of current protocol."""
        return self._version

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["HTTPv1"], Literal["HTTPv2"]]':
        """Index ID of the protocol."""
        return ('HTTPv1', 'HTTPv2')

    def read(self, length: 'Optional[int]' = None, *, version: 'Optional[Literal[1, 2]]' = None,
             **kwargs: 'Any') -> 'Info':
        """Read (parse) packet data.

        Args:
            length: Length of packet data.

        Keyword Args:
            version: Version of HTTP.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if TYPE_CHECKING:
            protocol: 'Type[Protocol]'

        if length is None:
            length = len(self)

        if version is None:
            http = self._guess_version(length, **kwargs)
        elif version == 1:
            from pcapkit.protocols.application.httpv1 import HTTPv1 as protocol  # type: ignore[no-redef] # isort: skip
        elif version == 2:
            from pcapkit.protocols.application.httpv2 import HTTPv2 as protocol  # type: ignore[no-redef] # isort: skip
        else:
            raise ProtocolError(f"invalid HTTP version: {version}")

        http = protocol(self._file, length, **kwargs)  # type: ignore[abstract]
        self._version = http.version  # type: ignore[attr-defined]
        return http.info

    def make(self, *, version: 'Literal[1, 2]', **kwargs: 'Any') -> 'bytes':  # type: ignore[override]
        """Make (construct) packet data.

        Keyword Args:
            version: Version of HTTP.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        if TYPE_CHECKING:
            protocol: 'Type[Protocol]'

        if version == 1:
            from pcapkit.protocols.application.httpv1 import HTTPv1 as protocol  # type: ignore[no-redef] # isort: skip
        elif version == 2:
            from pcapkit.protocols.application.httpv2 import HTTPv2 as protocol  # type: ignore[no-redef] # isort: skip
        else:
            raise ProtocolError(f"invalid HTTP version: {version}")

        http = protocol(**kwargs)  # type: ignore[abstract]
        self._version = http.version  # type: ignore[attr-defined]
        return http.data

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _guess_version(self, length: 'int', **kwargs: 'Any') -> 'Protocol':
        """Guess HTTP version.

        Args:
            length: Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        from pcapkit.protocols.application.httpv1 import HTTPv1
        with contextlib.suppress(ProtocolError):
            return HTTPv1(self._file, length, **kwargs)

        from pcapkit.protocols.application.httpv2 import HTTPv2
        with contextlib.suppress(ProtocolError):
            return HTTPv2(self._file, length, **kwargs)

        raise ProtocolError(f"unknown HTTP version: {length}")
