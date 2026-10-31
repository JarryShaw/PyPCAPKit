# -*- coding: utf-8 -*-
"""Netlink - Linux Netlink Socket Framing
============================================

.. module:: pcapkit.protocols.link.netlink

:mod:`pcapkit.protocols.link.netlink` contains
:class:`~pcapkit.protocols.link.netlink.Netlink` only, which implements the
extractor for the ``struct nlmsghdr`` framing [*]_ of Linux's own kernel/user
IPC transport, as seen on a ``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2``
capture whose ``arphrd_type`` is ``ARPHRD_NETLINK`` (an ``nlmon`` interface)
-- :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` dispatches here
instead of falling back to :class:`~pcapkit.protocols.misc.raw.Raw` for that
one case; see :data:`~pcapkit.protocols.link.linux_sll._ARPHRD_NOT_ETHERTYPE`.
Netlink is the kernel's own IPC mechanism (routing table dumps, interface
notifications and the like), not a "next protocol over this link" the way
every other ``arphrd_type`` exception is -- there is no next-layer dispatch
table here at all, every message's payload is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`.

.. table::

   ====== ==== ======================= ================================
   Octets Bits Name                    Description
   ====== ==== ======================= ================================
   0      0    ``netlink.nlmsg_len``   Message Length (header included)
   4      32   ``netlink.nlmsg_type``  Message Type
   6      48   ``netlink.nlmsg_flags`` Message Flags
   8      64   ``netlink.nlmsg_seq``   Sequence Number
   12     96   ``netlink.nlmsg_pid``   Sender Port ID
   ====== ==== ======================= ================================

Scope
-----

Only the fixed 16-octet ``nlmsghdr`` framing is dissected -- ``nlmsg_len``,
``nlmsg_type``, ``nlmsg_flags``, ``nlmsg_seq`` and ``nlmsg_pid``. Two things a
complete Netlink dissector would eventually need are deliberately left out of
this first cut:

* **Per-family message payloads.** What a given ``nlmsg_type`` means, and how
  its payload is laid out, is defined independently by each Netlink family
  (``NETLINK_ROUTE``, ``NETLINK_GENERIC``, ...) and is a large surface of its
  own -- routing table entries, link attributes (``rtattr``/``nlattr`` TLV
  chains), and so on. The payload is kept as
  :class:`~pcapkit.protocols.misc.raw.Raw`, unconditionally.
* **Multiple messages packed into one read.** The kernel's own netlink(7)
  page documents that a single read from a netlink socket, and so a single
  captured frame, commonly carries more than one ``nlmsghdr`` message back to
  back (:rfc:`3549#section-2.3.2` numbers the header fields; it does not
  itself restate the "one read, several messages" framing convention, which
  is :manpage:`netlink(7)`'s). This class dissects only the *first* message's
  header; everything after it -- that message's own payload, and any sibling
  messages the frame may carry -- is kept together as the undissected
  :class:`~pcapkit.protocols.misc.raw.Raw` payload, exactly as if it were one
  larger opaque blob. Splitting the frame on every ``nlmsg_len`` boundary is
  future work, tracked on :issue:`2460`.

Byte Order
----------

Netlink is a kernel/userspace IPC mechanism, not a protocol with octets
specified for the wire -- its messages are written in the *capturing host's*
native byte order, and neither :manpage:`netlink(7)`, :rfc:`3549` nor
tcpdump.org's `LINKTYPE_NETLINK`_ page record a marker for which order that
was. :func:`nlmsg_byteorder` resolves it with the same heuristic Wireshark's
own netlink dissector uses (``packet-netlink.c``, ``dissect_netlink()``,
comment: *"We do not know the endianness of the capture host, we have to
guess."*): decode ``nlmsg_len`` both ways and keep whichever reading comes
closer to the number of octets actually available, since a genuine message
length is normally well under the size either misreading would imply. See
:func:`~pcapkit.protocols.link.loopback.family_byteorder` for the same
problem solved the same way for ``LINKTYPE_NULL``.

.. [*] :manpage:`netlink(7)`; :rfc:`3549#section-2.3.2`

.. _LINKTYPE_NETLINK: https://www.tcpdump.org/linktypes/LINKTYPE_NETLINK.html

.. versionadded:: 1.6.0

"""
import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.link.netlink import Netlink as Data_Netlink
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.netlink import Netlink as Schema_Netlink
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, DefaultDict, NoReturn, Optional, Type

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['Netlink', 'nlmsg_byteorder']


def nlmsg_byteorder(nlmsg_len: 'bytes', length: 'int') -> "Literal['big', 'little']":
    """Guess the byte order a Netlink message header was written in.

    Args:
        nlmsg_len: The 4 raw octets of ``nlmsg_len``.
        length: Octets available from the start of this header to the end of
            the frame -- ``nlmsg_len`` counts the header itself
            (:rfc:`3549#section-2.3.2`: *"the length of the message in
            bytes, including the header"*), so this is the quantity to
            compare against, not the payload alone.

    Returns:
        ``'big'`` or ``'little'``, whichever reading of ``nlmsg_len`` comes
        closer to ``length``; ties favour ``'little'``, the overwhelmingly
        common case (x86/ARM hosts).

    Note:
        This is the heuristic Wireshark's own netlink dissector uses
        (``packet-netlink.c``, ``dissect_netlink()``): a genuine message
        length is normally well under the size either misreading of 4
        arbitrary octets would imply, so the reading closer to the octets
        actually on hand is overwhelmingly likely to be the real one.

    """
    len_be = int.from_bytes(nlmsg_len, 'big')
    len_le = int.from_bytes(nlmsg_len, 'little')
    if abs(len_be - length) < abs(len_le - length):
        return 'big'
    return 'little'


class Netlink(Link[Data_Netlink, Schema_Netlink],
              schema=Schema_Netlink, data=Data_Netlink):
    """This class implements Linux Netlink socket framing.

    Every message's payload is kept as
    :class:`~pcapkit.protocols.misc.raw.Raw`, unconditionally -- see the
    module docstring's *Scope* section for why. :attr:`self.__proto__
    <pcapkit.protocols.link.netlink.Netlink.__proto__>` is kept, as an empty
    registry, only so :meth:`register` works the same way every other
    :class:`~pcapkit.protocols.link.link.Link` subclass's does.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer. Deliberately empty --
    #: see the class docstring -- so every key, including the ``nlmsg_type``
    #: this class dispatches with, resolves through the
    #: :class:`~collections.defaultdict` fallback to
    #: :class:`~pcapkit.protocols.misc.raw.Raw`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Netlink"]':
        """Name of current protocol."""
        return 'Netlink'

    @property
    def alias(self) -> 'Literal["Netlink"]':
        """Acronym of corresponding protocol."""
        return 'Netlink'

    @property
    def length(self) -> 'Literal[16]':
        """Header length of current protocol."""
        return 16

    @property
    def protocol(self) -> 'int':  # type: ignore[override]
        """Message type of the dissected ``nlmsghdr``."""
        return self._info.nlmsg_type

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["Netlink"]]':
        """Index ID of the protocol."""
        return ('Netlink',)

    def read(self, length: 'Optional[int]' = None, *,
             byteorder: "Optional[Literal['big', 'little']]" = None,
             **kwargs: 'Any') -> 'Data_Netlink':  # pylint: disable=unused-argument
        """Read Linux Netlink socket framing.

        Structure of the ``nlmsghdr`` this class dissects, the first message
        in the frame:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            nlmsg_len                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |            nlmsg_type         |          nlmsg_flags          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            nlmsg_seq                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            nlmsg_pid                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            byteorder: Byte order to read the header in, ahead of guessing it
                from :func:`nlmsg_byteorder`. :meth:`make` is handed the one
                :attr:`~pcapkit.protocols.protocol.Protocol.info` holds by
                :meth:`from_data <pcapkit.protocols.link.link.Link.from_data>`,
                and it reaches here too, so a rebuild reads the header as it
                was parsed rather than guessing again.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If ``byteorder`` is neither ``'big'`` nor
                ``'little'``.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        if byteorder is None:
            _byte = nlmsg_byteorder(schema.nlmsg_len, length)
        elif byteorder in ('big', 'little'):
            _byte = byteorder
        else:
            raise ProtocolError(f'{self.alias}: invalid byte order: {byteorder!r}')

        netlink = Data_Netlink(
            nlmsg_len=int.from_bytes(schema.nlmsg_len, _byte),
            nlmsg_type=int.from_bytes(schema.nlmsg_type, _byte),
            nlmsg_flags=int.from_bytes(schema.nlmsg_flags, _byte),
            nlmsg_seq=int.from_bytes(schema.nlmsg_seq, _byte),
            nlmsg_pid=int.from_bytes(schema.nlmsg_pid, _byte),
            byteorder=_byte,
        )
        return self._decode_next_layer(netlink, netlink.nlmsg_type, length - self.length)

    def make(self,
             nlmsg_type: 'int' = 0,
             nlmsg_flags: 'int' = 0,
             nlmsg_seq: 'int' = 0,
             nlmsg_pid: 'int' = 0,
             nlmsg_len: 'Optional[int]' = None,
             byteorder: "Literal['big', 'little']" = sys.byteorder,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_Netlink':
        """Make (construct) packet data.

        Args:
            nlmsg_type: Message type.
            nlmsg_flags: Message flags.
            nlmsg_seq: Sequence number.
            nlmsg_pid: Sender port ID.
            nlmsg_len: Message length, header included; computed from the
                header and ``payload`` when omitted.
            byteorder: Byte order to write the header in, by default this
                host's, as a genuine capture is written in the capturing
                host's own order.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``byteorder`` is neither ``'big'`` nor
                ``'little'``; if ``nlmsg_type`` or ``nlmsg_flags`` is not an
                :class:`int` (a :class:`bool` included) or does not fit in 16
                bits; if ``nlmsg_seq`` or ``nlmsg_pid`` is not an :class:`int`
                (a :class:`bool` included) or does not fit in 32 bits; or if
                ``nlmsg_len`` is given and does not fit in 32 bits.

        """
        if byteorder not in ('big', 'little'):
            raise ProtocolError(f'{self.alias}: invalid byte order: {byteorder!r}')
        for name, value in (('nlmsg_type', nlmsg_type), ('nlmsg_flags', nlmsg_flags)):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF:
                raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')
        for name, value in (('nlmsg_seq', nlmsg_seq), ('nlmsg_pid', nlmsg_pid)):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF_FFFF:
                raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')

        if nlmsg_len is None:
            nlmsg_len = 16 + len(payload)
        elif (not isinstance(nlmsg_len, int) or isinstance(nlmsg_len, bool)
              or not 0 <= nlmsg_len <= 0xFFFF_FFFF):
            raise ProtocolError(f'{self.alias}: invalid nlmsg_len: {nlmsg_len!r}')

        return Schema_Netlink(
            nlmsg_len=nlmsg_len.to_bytes(4, byteorder),
            nlmsg_type=nlmsg_type.to_bytes(2, byteorder),
            nlmsg_flags=nlmsg_flags.to_bytes(2, byteorder),
            nlmsg_seq=nlmsg_seq.to_bytes(4, byteorder),
            nlmsg_pid=nlmsg_pid.to_bytes(4, byteorder),
            payload=payload,
        )

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
            UnsupportedCall: This protocol is reached only through
                :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`'s
                ``arphrd_type`` dispatch, not through a link-layer header
                type of its own.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Netlink') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'nlmsg_type': data.nlmsg_type,
            'nlmsg_flags': data.nlmsg_flags,
            'nlmsg_seq': data.nlmsg_seq,
            'nlmsg_pid': data.nlmsg_pid,
            'nlmsg_len': data.nlmsg_len,
            'byteorder': data.byteorder,
            'payload': cls._make_payload(data),
        }
