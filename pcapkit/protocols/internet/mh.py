# -*- coding: utf-8 -*-
# pylint: disable=fixme
"""mobility header

:mod:`pcapkit.protocols.internet.mh` contains
:class:`~pcapkit.protocols.internet.mh.MH` only,
which implements extractor for Mobility Header
(MH) [*]_, whose structure is described as below:

======= ========= ================== ===============================
Octets      Bits        Name                    Description
======= ========= ================== ===============================
  0           0   ``mh.next``                 Next Header
  1           8   ``mh.length``               Header Length
  2          16   ``mh.type``                 Mobility Header Type
  3          24                               Reserved
  4          32   ``mh.chksum``               Checksum
  6          48   ``mh.data``                 Message Data
======= ========= ================== ===============================

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6

"""
# TODO: Implements extractor for message data of all MH types.

from typing import TYPE_CHECKING, overload

from pcapkit.const.mh.packet import Packet as RegType_Packet
from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.protocols.data.internet.mh import MH as DataType_MH
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, BinaryIO, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import Protocol

__all__ = ['MH']


class MH(Internet[DataType_MH]):
    """This class implements Mobility Header."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Mobility Header"]':
        """Name of current protocol."""
        return 'Mobility Header'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return super().payload

    @property
    def protocol(self) -> 'Optional[str] | NoReturn':
        """Name of next layer protocol (if any).

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")
        return super().protocol

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, version: 'Literal[4, 6]' = 4,  # pylint: disable=arguments-differ,unused-argument
             extension: bool = False, **kwargs: 'Any') -> 'DataType_MH':  # pylint: disable=unused-argument
        """Read Mobility Header.

        Structure of MH header [:rfc:`6275`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Checksum            |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
           |                                                               |
           .                                                               .
           .                       Message Data                            .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_unpack(1)
        _temp = self._read_fileng(1)
        _csum = self._read_fileng(2)
        _data = self._read_fileng((_hlen+1)*8)

        mh = DataType_MH(
            next=_next,
            length=(_hlen + 1) * 8,
            type=RegType_Packet.get(_type),
            chksum=_csum,
            data=_data,
        )

        if extension:
            return mh
        return self._decode_next_layer(mh, _next, length - mh.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = ..., extension: 'bool' = ...,
                      **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[BinaryIO]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = 4, extension: 'bool' = False,  # pylint: disable=unused-argument
                      **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[6]':
        """Return an estimated length for the object."""
        return 6

    @classmethod
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.Mobility_Header  # type: ignore[return-value]
