# -*- coding: utf-8 -*-
"""core utilities

`pcapkit.corekit` is the collection of core utilities for
`pcapkit` implementation, including dict-like class `Info`,
tuple-like class `VersionInfo`, and protocol collection
class `ProtoChain`.

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.version import VersionInfo

__all__ = ['Info', 'ProtoChain', 'VersionInfo']
