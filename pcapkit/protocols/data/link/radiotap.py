# -*- coding: utf-8 -*-
"""data models for IEEE 802.11 radiotap headers"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    pass

__all__ = ['Radiotap']


@info_final
class Radiotap(Protocol):
    """Data model for an IEEE 802.11 radiotap header.

    Only the fixed 8-octet start is decoded field by field; the rest is kept
    whole, see :attr:`present` and :attr:`fields` and the module docstring's
    *Scope* section on :mod:`pcapkit.protocols.link.radiotap`.

    """

    #: Header revision; ``0`` is the only version radiotap.org defines, and
    #: the only one this package decodes.
    it_version: 'int'
    #: Padding octet, kept for alignment; not interpreted.
    it_pad: 'int'
    #: Total length of the radiotap header -- the fixed 8-octet start,
    #: every extended present-flags word, and the optional-field region
    #: they select -- in octets; the 802.11 MAC frame starts here. Kept
    #: exactly as captured, even where it disagrees with :attr:`present`
    #: and :attr:`fields`.
    it_len: 'int'
    #: Every present-flags word in the chain that was actually read, in
    #: order; index ``0`` is the mandatory first word (radiotap.org's own
    #: ``it_present``). Bit 31 of a word signals that another word
    #: follows; it is clear on the last word read, unless the capture ran
    #: out before a word it claimed would follow.
    present: 'tuple[int, ...]'
    #: The optional-field region :attr:`present` selects, kept whole and
    #: undissected.
    fields: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, it_version: 'int', it_pad: 'int', it_len: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     present: 'tuple[int, ...]', fields: 'bytes') -> 'None': ...  # pylint: disable=unused-argument
