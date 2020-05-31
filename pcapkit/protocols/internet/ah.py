# -*- coding: utf-8 -*-
"""authentication header

:mod:`pcapkit.protocols.internet.ah` contains
:class:`~pcapkit.protocols.internet.AH` only,
which implements extractor for Authentication
Header (AH) [*]_, whose structure is described
as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``ah.next``               Next Header
  1           8   ``ah.length``             Payload Length
  2          16                             Reserved (must be zero)
  4          32   ``sah.spi``               Security Parameters Index (SPI)
  8          64   ``sah.seq``               Sequence Number Field
  12         96   ``sah.icv``               Integrity Check Value (ICV)
======= ========= ======================= ===================================

.. [*] https://en.wikipedia.org/wiki/IPsec

"""
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.internet.ipsec import IPsec
from pcapkit.utilities.exceptions import (ProtocolError, UnsupportedCall,
                                          VersionError)

__all__ = ['AH']


class AH(IPsec):
    """This class implements Authentication Header."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol.

        :rtype: Literal['Authentication Header']
        """
        return 'Authentication Header'

    @property
    def length(self):
        """Info dict of current instance.

        :rtype: int
        """
        return self._info.length  # pylint: disable=E1101

    @property
    def payload(self):
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.transtype.TransType
        """
        return self._info.next  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, *, version=4, extension=False, **kwargs):  # pylint: disable=arguments-differ,unused-argument
        """Read Authentication Header.

        Structure of AH header [:rfc:`4302`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Next Header   |  Payload Len  |          RESERVED             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Security Parameters Index (SPI)               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                    Sequence Number Field                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            +                Integrity Check Value-ICV (variable)           |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            version (Literal[4, 6]): IP protocol version.
            extension (bool): If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_AH: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _plen = self._read_unpack(1)
        _resv = self._read_fileng(2)
        _scpi = self._read_unpack(4)
        _dsnf = self._read_unpack(4)

        # ICV length & value
        _tlen = _plen * 4 - 2
        _vlen = _tlen - 12
        _chkv = self._read_fileng(_vlen)

        ah = dict(
            next=_next,
            length=_tlen,
            spi=_scpi,
            seq=_dsnf,
            icv=_chkv,
        )

        if version == 6:
            _plen = 8 - (_tlen % 8)
        elif version == 4:
            _plen = 4 - (_tlen % 4)
        else:
            raise VersionError(f'Unknown IP version {version}')

        if _plen:   # explicit padding in need
            padding = self._read_binary(_plen)
            if any((int(bit, base=2) for bit in padding)):
                raise ProtocolError(f'{self.alias}: invalid format')

        length -= ah['length']
        ah['packet'] = self._read_packet(header=ah['length'], payload=length)

        if extension:
            self._protos = None
            return ah
        return self._decode_next_layer(ah, _next, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
           Literal['AH']: Index ID of the protocol.

        """
        return cls.__name__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file, length=None, *, version=4, extension=False, **kwargs):  # pylint: disable=arguments-differ
        """Post initialisation hook.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            version (Literal[4, 6]): IP protocol version.
            extension (bool): If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, version=version, extension=extension, **kwargs)

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[20]
        """
        return 20

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(51)
