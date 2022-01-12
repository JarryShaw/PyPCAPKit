# -*- coding: utf-8 -*-
"""no-payload packet

:mod:`pcapkit.protocols.null` contains
:class:`~pcapkit.protocols.null.NoPayload` only, which
implements a :class:`~pcapkit.protocols.protocol.Protocol` like
object whose payload is recursively
:class:`~pcapkit.protocols.null.NoPayload` itself.

"""
import io
from typing import TYPE_CHECKING, overload

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.data.misc.null import NoPayload as DataType_NoPayload
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, BinaryIO, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['NoPayload']


class NoPayload(Protocol):
    """This class implements no-payload protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    def name(self) -> 'Literal["Null"]':
        """Name of current protocol."""
        return 'Null'

    # header length of current protocol
    @property
    def length(self) -> 'NoReturn':
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    # name of next layer protocol
    @property
    def protocol(self) -> 'NoReturn':
        """Name of next layer protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`protocol`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_NoPayload':  # pylint: disable=unused-argument
        """Read (parse) packet data.

        Args:
            length: Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        return DataType_NoPayload()

    def make(self, **kwargs: 'Any') -> 'bytes':
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        return b''

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[BinaryIO]' = None, length: 'Optional[int]' = None, **kwargs: 'Any') -> None:  # pylint: disable=unused-argument
        """Post initialisation hook.

        Args:
            file (Optional[io.BytesIO]): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        """
        #: bytes: Raw packet data.
        self._data = bytes()
        #: io.BytesIO: Source data stream.
        self._file = io.BytesIO()
        #: pcapkit.corekit.infoclass.Info: Info dict of current instance.
        self._info = Info()

        #: pcapkit.protocols.null.NoPayload: Payload of current instance.
        self._next = self
        #: pcapkit.corekit.protochain.ProtoChain: Protocol chain of current instance.
        self._protos = None  # type: ignore[assignment]

    @classmethod
    def __index__(cls) -> 'NoReturn':
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, *args: 'Any', **kwargs: 'Any') -> 'NoReturn':  # pylint: disable=signature-differs
        """Decode next layer protocol.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_decode_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, *args: 'Any', **kwargs: 'Any') -> 'NoReturn':  # pylint: disable=signature-differs
        """Import next layer extractor.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_import_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")