# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for generically-parsed IPv6 extension headers"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['IPv6_GenericExt']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class IPv6_GenericExt(Schema):
    """Header schema for a generically-parsed IPv6 extension header.

    Only the two octets :rfc:`6564#section-4` guarantees are parsed at this
    layer -- ``next`` and the raw ``Hdr Ext Len`` octet. Combining them into
    an actual skip distance is per protocol (a constant for ``IPv6-Frag``,
    4-octet units for ``AH``, 8-octet units for the rest), so that part is
    done in :meth:`pcapkit.protocols.internet.ipv6_generic_ext.IPv6_GenericExt.read`,
    which knows which protocol this instance stands in for; this schema does
    not.

    """

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Raw ``Hdr Ext Len`` octet -- see the class docstring for why its
    #: interpretation is not fixed here.
    len: 'int' = UInt8Field()
    #: Everything after the two fixed octets; opaque at this layer.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType | int', len: 'int',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
