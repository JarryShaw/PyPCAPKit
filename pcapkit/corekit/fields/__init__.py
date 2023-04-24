# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""Protocol Fields
=====================

.. module:: pcapkit.corekit.fields

:mod:`pcapkit.corekit.fields` is collection of protocol fields,
descriptive of the structure of protocol headers.

"""

from pcapkit.corekit.fields.field import Field

from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import (IPv4AddressField, IPv4InterfaceField,
                                              IPv6AddressField, IPv6InterfaceField)
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, NoValueField,
                                         PayloadField, SchemaField)
from pcapkit.corekit.fields.numbers import (EnumField, Int8Field, Int16Field, Int32Field,
                                            Int64Field, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field, UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField, StringField

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
    'PaddingField',

    'ConditionalField', 'PayloadField', 'SchemaField',
    'ForwardMatchField', 'NoValueField',

    'ListField', 'OptionField',

    'IPv4AddressField', 'IPv6AddressField',
    'IPv4InterfaceField', 'IPv6InterfaceField',
]
