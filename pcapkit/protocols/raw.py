# -*- coding: utf-8 -*-
"""raw packet data

:mod:`pcapkit.protocols.raw` contains
:class:`~pcapkit.protocols.raw.Raw` only, which implements
extractor for unknown protocol, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

"""
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
        """Name of current protocol."""
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

    def read_raw(self, length, *, error=None):
        """Read raw packet data.

        Args:
            length (int): Length of packet data.

        Keyword Args:
            error (Optional[str]): Parsing errors if any.

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

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, length=None, *, error=None, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            error: Parsing errors if any.
            **kwargs: Arbitrary keyword arguments.

        Would :mod:`pcapkit` encounter malformed packets, the original parsing
        error message will be provided as in ``error``.

        """
        #: io.BytesIO: Source packet stream.
        self._file = file
        #: Info: Parsed packet data.
        self._info = Info(self.read_raw(length, error=error))

        #: NoPayload: Next layer (no payload).
        self._next = NoPayload()
        #: ProtoChain: Protocol chain from current layer.
        self._protos = ProtoChain(self.__class__, self.alias)

    def __length_hint__(self):
        """Return an estimated length for the object."""
