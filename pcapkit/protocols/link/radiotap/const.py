# -*- coding: utf-8 -*-
"""constants for IEEE 802.11 radiotap headers

.. versionadded:: 1.7.0

"""

__all__ = []  # type: list[str]

#: Bit 31 of an ``it_present`` word -- set, another present-flags word
#: follows; clear, the field-data region starts right after this word.
_IT_PRESENT_EXTENDED = 1 << 31

#: Octets of the fixed start every radiotap header has, before any extended
#: present-flags word or field data.
_FIXED_HEADER_LEN = 8

#: Octets of one present-flags word, extended or not.
_PRESENT_WORD_LEN = 4

#: Bits of one present-flags word.
_PRESENT_WORD_BITS = 8 * _PRESENT_WORD_LEN

#: Why an :class:`~pcapkit.protocols.link.radiotap.data.Unknown` entry ended
#: the walk, as its ``reason`` says.
_REASON_NO_LAYOUT, _REASON_PAST_REGION = ('no layout is defined for the field type',
                                          'the field runs past the field-data region')
