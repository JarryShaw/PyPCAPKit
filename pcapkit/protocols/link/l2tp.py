# -*- coding: utf-8 -*-
"""layer two tunnelling protocol

:mod:`pcapkit.protocols.link.l2tp` contains
:class:`~pcapkit.protocols.link.l2tp.L2TP` only,
which implements extractor for Layer Two Tunnelling
Protocol (L2TP) [*]_, whose structure is described
as below:

+========+=======+=======================+============================================+
| Octets | Bits  | Name                  | Description                                |
+========+=======+=======================+============================================+
| 0      |     0 | ``l2tp.flags``        | Flags and Version Info                     |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     0 | ``l2tp.flags.type``   | Type (control / data)                      |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     1 | ``l2tp.flags.len``    | Length                                     |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     2 |                       | Reserved (must be zero ``\\x00``)          |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     4 | ``l2tp.flags.seq``    | Sequence                                   |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     5 |                       | Reserved (must be zero ``\\x00``)          |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     6 | ``l2tp.flags.offset`` | Offset                                     |
+--------+-------+-----------------------+--------------------------------------------+
| 0      |     7 | ``l2tp.flags.prio``   | Priority                                   |
+--------+-------+-----------------------+--------------------------------------------+
| 1      |     8 |                       | Reserved (must be zero ``\\x00``)          |
+--------+-------+-----------------------+--------------------------------------------+
| 1      |    12 | ``l2tp.ver``          | Version (``2``)                            |
+--------+-------+-----------------------+--------------------------------------------+
| 2      |    16 | ``l2tp.length``       | Length (optional by ``len``)               |
+--------+-------+-----------------------+--------------------------------------------+
| 4      |    32 | ``l2tp.tunnelid``     | Tunnel ID                                  |
+--------+-------+-----------------------+--------------------------------------------+
| 6      |    48 | ``l2tp.sessionid``    | Session ID                                 |
+--------+-------+-----------------------+--------------------------------------------+
| 8      |    64 | ``l2tp.ns``           | Sequence Number (optional by ``seq``)      |
+--------+-------+-----------------------+--------------------------------------------+
| 10     |    80 | ``l2tp.nr``           | Next Sequence Number (optional by ``seq``) |
+--------+-------+-----------------------+--------------------------------------------+
| 12     |    96 | ``l2tp.offset``       | Offset Size (optional by ``offset``)       |
+========+=======+=======================+============================================+

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol

"""
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['L2TP']


class L2TP(Link):
    """This class implements Layer Two Tunnelling Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Layer 2 Tunnelling Protocol']
        """
        return 'Layer 2 Tunnelling Protocol'

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: int
        """
        return self._info.hdr_len  # pylint: disable=E1101

    @property
    def type(self):
        """L2TP type.

        :rtype: Literal['Control', 'Data']
        """
        return self._info.flags.type  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Layer Two Tunnelling Protocol.

        Structure of L2TP header [:rfc:`2661`]::

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Tunnel ID           |           Session ID          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Ns (opt)          |             Nr (opt)          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Offset Size (opt)        |    Offset pad... (opt)
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_L2TP: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _flag = self._read_binary(1)
        _vers = self._read_fileng(1).hex()[1]
        _hlen = self._read_unpack(2) if int(_flag[1]) else None
        _tnnl = self._read_unpack(2)
        _sssn = self._read_unpack(2)
        _nseq = self._read_unpack(2) if int(_flag[4]) else None
        _nrec = self._read_unpack(2) if int(_flag[4]) else None
        _size = self._read_unpack(2) if int(_flag[6]) else 0

        l2tp = dict(
            flags=dict(
                type='Control' if int(_flag[0]) else 'Data',
                len=bool(int(_flag[1])),
                seq=bool(int(_flag[4])),
                offset=bool(int(_flag[6])),
                prio=bool(int(_flag[7])),
            ),
            ver=int(_vers, base=16),
            length=_hlen,
            tunnelid=_tnnl,
            sessionid=_sssn,
            ns=_nseq,
            nr=_nrec,
            offset=8*_size or None,
        )

        hdr_len = _hlen or (6 + 2*(int(_flag[1]) + 2*int(_flag[4]) + int(_flag[6])))
        l2tp['hdr_len'] = hdr_len + _size * 8
        # if _size:
        #     l2tp['padding'] = self._read_fileng(_size * 8)

        length -= l2tp['hdr_len']
        l2tp['packet'] = self._read_packet(header=l2tp['hdr_len'], payload=length)

        return self._decode_next_layer(l2tp, length)

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

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[16]
        """
        return 16

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')
