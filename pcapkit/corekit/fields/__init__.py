# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""Protocol Fields
=====================

:mod:`pcapkit.protocols.fields` is collection of protocol fields,
descriptive of the structure of protocol headers.

"""

from pcapkit.corekit.fields.field import Field

from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import (Int8Field, EnumField, Int32Field, Int64Field, NumberField,
                                            Int16Field, UInt8Field, UInt32Field, UInt64Field,
                                            UInt16Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, StringField

__all__ = [
    'NumberField',
    'Int32Field', 'UInt32Field',
    'Int16Field', 'UInt16Field',
    'Int64Field', 'UInt64Field',
    'Int8Field', 'UInt8Field',
    'EnumField',

    'BytesField',
    'StringField',
    'BitField',

    'ConditionalField', 'PayloadField',
]
