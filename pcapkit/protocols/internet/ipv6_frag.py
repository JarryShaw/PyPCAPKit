# -*- coding: utf-8 -*-
"""fragment header for IPv6

:mod:`pcapkit.protocols.internet.ipv6_frag` contains
:class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`
only, which implements extractor for Fragment Header for
IPv6 (IPv6-Frag) [*]_, whose structure is described as
below:

======= ========= ==================== =======================
Octets      Bits        Name                    Description
======= ========= ==================== =======================
  0           0   ``frag.next``               Next Header
  1           8                               Reserved
  2          16   ``frag.offset``             Fragment Offset
  3          29                               Reserved
  3          31   ``frag.mf``                 More Flag
  4          32   ``frag.id``                 Identification
======= ========= ==================== =======================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Fragment

"""
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['IPv6_Frag']


class IPv6_Frag(Internet):
    """This class implements Fragment Header for IPv6."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Fragment Header for IPv6']
        """
        return 'Fragment Header for IPv6'

    @property
    def alias(self):
        """Acronym of corresponding protocol.

        :rtype: Literal['IPv6-Frag']
        """
        return 'IPv6-Frag'

    @property
    def length(self):
        """Header length of current protocol.

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

    def read(self, length=None, *, extension=False, **kwargs):  # pylint: disable=arguments-differ,unused-argument
        """Read Fragment Header for IPv6.

        Structure of IPv6-Frag header [:rfc:`8200`]::

            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                         Identification                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_IPv6_Frag: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _temp = self._read_fileng(1)
        _offm = self._read_binary(2)
        _ipid = self._read_unpack(4)

        ipv6_frag = dict(
            next=_next,
            length=8,
            offset=int(_offm[:13], base=2),
            mf=bool(int(_offm[15], base=2)),
            id=_ipid,
        )

        length -= ipv6_frag['length']
        ipv6_frag['packet'] = self._read_packet(header=8, payload=length)

        if extension:
            self._protos = None
            return ipv6_frag
        return self._decode_next_layer(ipv6_frag, _next, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file, length=None, *, extension=False, **kwargs):  # pylint: disable=arguments-differ
        """Post initialisation hook.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[8]
        """
        return 8

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(44)
