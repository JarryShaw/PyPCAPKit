# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import
"""Core Utilities
====================

.. module:: pcapkit.corekit

:mod:`pcapkit.corekit` is the collection of core utilities
for :mod:`pcapkit` implementation, including :obj:`dict` like
class :class:`~pcapkit.corekit.infoclass.Info`,
:obj:`tuple` like class :class:`~pcapkit.corekit.version.VersionInfo`,
protocol collection class :class:`~pcapkit.corekit.protochain.ProtoChain`,
and :class:`~pcapkit.corekit.multidict.MultiDict` family inspired from
:mod:`Werkzeug` for multientry :obj:`dict` data mapping, the
:class:`~pcapkit.corekit.fields.field.Field` family for data parsing,
etc.

"""
from pcapkit.corekit.io import SeekableReader
from pcapkit.corekit.fields import *
from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.version import VersionInfo

__all__ = [
    'Info', 'info_final',

    'ProtoChain',

    'VersionInfo',

    'MultiDict', 'OrderedMultiDict',

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

    'SeekableReader',

    'ModuleDescriptor',
]
