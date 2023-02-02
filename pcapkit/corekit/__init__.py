# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import
"""Core Utilities
====================

:mod:`pcapkit.corekit` is the collection of core utilities
for :mod:`pcapkit` implementation, including :obj:`dict` like
class :class:`~pcapkit.corekit.infoclass.Info`,
:obj:`tuple` like class :class:`~pcapkit.corekit.version.VersionInfo`,
protocol collection class :class:`~pcapkit.corekit.protochain.ProtoChain`,
and :class:`~pcapkit.corekit.multidict.MultiDict` family inspired from
:mod:`Werkzeug` for multientry :obj:`dict` data mapping, as well as
the :class:`~pcapkit.corekit.fields.field.Field` family for data parsing.

"""
from pcapkit.corekit.fields import *
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.version import VersionInfo

__all__ = [
    'Info',

    'ProtoChain',

    'VersionInfo',

    'MultiDict', 'OrderedMultiDict',

    'NumberField',
    'IntField', 'UIntField',
    'ShortField', 'UShortField',
    'LongField', 'ULongField',
    'ByteField', 'UByteField',
    'EnumField',

    'BytesField',
    'StringField',
    'BitField',

    'ConditionalField', 'PayloadField',
]
