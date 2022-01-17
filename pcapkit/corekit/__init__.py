# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""core utilities

:mod:`pcapkit.corekit` is the collection of core utilities
for :mod:`pcapkit` implementation, including :obj:`dict` like
class :class:`~pcapkit.corekit.infoclass.Info`,
:obj:`tuple` like class :class:`~pcapkit.corekit.version.VersionInfo`,
and protocol collection class :class:`~pcapkit.corekit.protochain.ProtoChain`.

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.version import VersionInfo

__all__ = ['Info', 'ProtoChain', 'VersionInfo',
           'MultiDict', 'OrderedMultiDict']
