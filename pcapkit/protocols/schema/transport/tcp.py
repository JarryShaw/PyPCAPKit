# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for transmission control protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = [
    'TCP',

    'Option',
]

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import Protocol


class TCP(Schema):
    """Header schema for TCP packet."""


class Option(Schema):
    """Header schema for TCP options."""


class MPTCP(Option):
    """Header schema for Multipath TCP options."""
