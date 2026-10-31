# -*- coding: utf-8 -*-
"""data models for Generic Routing Encapsulation (GRE) frames"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.reg.ethertype import EtherType

__all__ = ['GRE']


@info_final
class GRE(Protocol):
    """Data model for a Generic Routing Encapsulation (GRE) frame."""

    #: Checksum Present bit (``C``), :rfc:`2784`.
    checksum_present: 'bool'
    #: Key Present bit (``K``), :rfc:`2890`.
    key_present: 'bool'
    #: Sequence Number Present bit (``S``), :rfc:`2890`.
    sequence_present: 'bool'
    #: Reserved bits of the flags word outside ``C``/``K``/``S``/``Ver``, in
    #: their on-wire positions (i.e. masked by ``0x4FF8``). :rfc:`2784` calls
    #: the whole 12-bit span (before :rfc:`2890` carved ``K``/``S`` out of it)
    #: ``Reserved0`` and requires it sent as zero; carried verbatim so a
    #: rebuild reproduces the word as it arrived.
    reserved: 'int'
    #: Version Number; :rfc:`2784` requires this to be ``0``.
    version: 'int'
    #: Protocol Type: the EtherType of the encapsulated payload.
    protocol_type: 'EtherType'
    #: Checksum, present only when :attr:`checksum_present` is set.
    checksum: 'Optional[int]'
    #: Reserved1, present only when :attr:`checksum_present` is set;
    #: :rfc:`2784` requires it sent as zero, carried verbatim.
    reserved1: 'Optional[int]'
    #: Key, present only when :attr:`key_present` is set, :rfc:`2890`.
    key: 'Optional[int]'
    #: Sequence Number, present only when :attr:`sequence_present` is set,
    #: :rfc:`2890`.
    sequence_number: 'Optional[int]'
    #: Header length, in octets -- ``4``, plus ``4`` more for each of
    #: :attr:`checksum_present`, :attr:`key_present` and
    #: :attr:`sequence_present` that is set.
    len: 'int'

    if TYPE_CHECKING:
        def __init__(self, checksum_present: 'bool', key_present: 'bool',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     sequence_present: 'bool', reserved: 'int', version: 'int',  # pylint: disable=unused-argument
                     protocol_type: 'EtherType', checksum: 'Optional[int]',  # pylint: disable=unused-argument
                     reserved1: 'Optional[int]', key: 'Optional[int]',  # pylint: disable=unused-argument
                     sequence_number: 'Optional[int]', len: 'int') -> 'None': ...  # pylint: disable=unused-argument,redefined-builtin
