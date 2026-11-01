# -*- coding: utf-8 -*-
"""data models for Linux Netlink socket framing"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['Netlink']


@info_final
class Netlink(Protocol):
    """Data model for Linux Netlink socket framing (``nlmsghdr``)."""

    #: Message length, in octets, including this 16-octet header -- as
    #: written, in whichever byte order :attr:`byteorder` records.
    nlmsg_len: 'int'
    #: Message type; ``1``-``4`` are the generic control values
    #: (``NLMSG_NOOP``/``NLMSG_ERROR``/``NLMSG_DONE``/``NLMSG_OVERRUN``)
    #: shared by every Netlink family, ``16`` and above are family-specific
    #: and not interpreted by this class.
    nlmsg_type: 'int'
    #: Message flags; their bit meanings depend on ``nlmsg_type`` and on
    #: whether the message is a request, so they are not decoded further.
    nlmsg_flags: 'int'
    #: Sequence number.
    nlmsg_seq: 'int'
    #: Sender port ID; ``0`` when sent by the kernel.
    nlmsg_pid: 'int'
    #: Byte order the header was written in.
    byteorder: "Literal['big', 'little']"

    if TYPE_CHECKING:
        def __init__(self, nlmsg_len: 'int', nlmsg_type: 'int', nlmsg_flags: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     nlmsg_seq: 'int', nlmsg_pid: 'int',  # pylint: disable=unused-argument
                     byteorder: "Literal['big', 'little']") -> 'None': ...  # pylint: disable=unused-argument
