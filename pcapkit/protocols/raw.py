# -*- coding: utf-8 -*-
"""raw packet data

:mod:`pcapkit.protocols.raw` contains
:class:`~pcapkit.protocols.raw.Raw` only, which implements
extractor for unknown protocol, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

"""
import io

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.null import NoPayload
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['Raw']


class Raw(Protocol):
    """This class implements universal unknown protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Unknown']
        """
        return 'Unknown'

    # header length of current protocol
    @property
    def length(self):
        """Header length of current protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`length`.

        """
        raise UnsupportedCall(f"{self.__class__.__name__!r} object has no attribute 'length'")

    # name of next layer protocol
    @property
    def protocol(self):
        """Name of next layer protocol.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`protocol`.

        """
        raise UnsupportedCall(f"{self.__class__.__name__!r} object has no attribute 'protocol'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, *, error=None, **kwargs):  # pylint: disable=arguments-differ,unused-argument
        """Read raw packet data.

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            error (Optional[str]): Parsing errors if any.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_Raw: The parsed packet data.

        """
        if length is None:
            length = len(self)

        raw = dict(
            packet=self._read_fileng(length),
            error=error or None,
        )

        return raw

    def make(self, **kwargs):
        """Make raw packet data.

        Keyword Args:
            packet (bytes): Raw packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        return bytes(kwargs.get('packet'))

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file, length=None, *, error=None, **kwargs):  # pylint: disable=arguments-differ
        """Post initialisation hook.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            error (Optional[str]): Parsing errors if any (for parsing).
            **kwargs: Arbitrary keyword arguments.

        Would :mod:`pcapkit` encounter malformed packets, the original parsing
        error message will be provided as in ``error``.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        if file is None:
            _data = self.make(**kwargs)
        else:
            _data = file.read(length)

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = Info(self.read(length, error=error, **kwargs))

        #: pcapkit.protocols.null.NoPayload: Next layer (no payload).
        self._next = NoPayload()
        #: pcapkit.corekit.protochain.ProtoChain: Protocol chain from current layer.
        self._protos = ProtoChain(self.__class__, self.alias)

    @classmethod
    def __index__(cls):
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')
