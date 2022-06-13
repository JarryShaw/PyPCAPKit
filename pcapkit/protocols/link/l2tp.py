# -*- coding: utf-8 -*-
"""L2TP - Layer Two Tunnelling Protocol
==========================================

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
| 1      |    12 | ``l2tp.version``      | Version (``2``)                            |
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
from typing import TYPE_CHECKING

from pcapkit.const.l2tp.type import Type as RegType_Type
from pcapkit.protocols.data.link.l2tp import L2TP as DataType_L2TP
from pcapkit.protocols.data.link.l2tp import Flags as DataType_Flags
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['L2TP']


class L2TP(Link[DataType_L2TP]):
    """This class implements Layer Two Tunnelling Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Layer 2 Tunnelling Protocol"]':
        """Name of current protocol."""
        return 'Layer 2 Tunnelling Protocol'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.hdr_len

    @property
    def type(self) -> 'Literal["control", "data"]':
        """L2TP type."""
        return self._info.flags.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_L2TP':  # pylint: disable=unused-argument
        """Read Layer Two Tunnelling Protocol.

        Structure of L2TP header [:rfc:`2661`]:

        .. code-block:: text

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
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        _flag = self._read_binary(1)

        flags = DataType_Flags(
            type=RegType_Type(int(_flag[0])),
            len=bool(int(_flag[1])),
            seq=bool(int(_flag[4])),
            offset=bool(int(_flag[6])),
            prio=bool(int(_flag[7])),
        )

        _vers = self._read_fileng(1).hex()[1]
        _hlen = self._read_unpack(2) if flags.len else None
        _tnnl = self._read_unpack(2)
        _sssn = self._read_unpack(2)
        _nseq = self._read_unpack(2) if flags.seq else None
        _nrec = self._read_unpack(2) if flags.seq else None
        _size = self._read_unpack(2) if flags.offset else 0

        l2tp = DataType_L2TP(
            flags=flags,
            version=int(_vers, base=16),
            length=_hlen,
            tunnelid=_tnnl,
            sessionid=_sssn,
            ns=_nseq,
            nr=_nrec,
            offset=8*_size or None,
        )

        hdr_len = _hlen or (6 + 2*(int(_flag[1]) + 2*int(_flag[4]) + int(_flag[6])))
        l2tp.__update__([
            ('hdr_len', hdr_len + _size * 8),
        ])
        # if _size:
        #     l2tp['padding'] = self._read_fileng(_size * 8)

        return self._decode_next_layer(l2tp, length - l2tp.hdr_len)

    def make(self, **kwargs: 'Any') -> 'NoReturn':  # pylint: disable=unused-argument
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return 16

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')
