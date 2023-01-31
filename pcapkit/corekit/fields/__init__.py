# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""Protocol Fields
=====================

:mod:`pcapkit.protocols.fields` is collection of protocol fields,
descriptive of the structure of protocol headers.

"""

from pcapkit.corekit.fields.field import Field

from pcapkit.corekit.fields.numbers import NumberField, EnumField
from pcapkit.corekit.fields.strings import BytesField, StringField, BitField

__all__ = [
    'NumberField',
    'EnumField',

    'BytesField',
    'StringField',
    'BitField',
]
