# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IEEE 802.11 radiotap headers"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field, UInt32Field
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Radiotap']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class Radiotap(Schema):
    """Header schema for an IEEE 802.11 radiotap header.

    Only the fixed 8-octet start -- ``it_version``, ``it_pad``, ``it_len``
    and the first ``it_present`` word -- is given its own field, all
    little-endian per radiotap.org. Everything that follows -- any extended
    present-flags words, the optional-field region they select, and the
    802.11 MAC frame behind it -- is captured together as :attr:`payload`,
    since where one ends and the next begins is only known once the
    present-flags chain itself has been walked; see :meth:`Radiotap.read
    <pcapkit.protocols.link.radiotap.Radiotap.read>`.

    """

    #: Header revision.
    it_version: 'int' = UInt8Field()
    #: Padding octet.
    it_pad: 'int' = UInt8Field()
    #: Total header length, including this fixed start.
    it_len: 'int' = UInt16Field(byteorder='little')
    #: First present-flags word.
    it_present: 'int' = UInt32Field(byteorder='little')
    #: Everything after the fixed start -- see the class docstring.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, it_version: 'int', it_pad: 'int', it_len: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     it_present: 'int',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument
