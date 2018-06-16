# -*- coding: utf-8 -*-
"""core utilities

`jspcap.corekit` is the collection of core utilities for
`jspcap` implementation, including dict-like class `Info`,
tuple-like class `VersionInfo`, and protocol collection
class `ProtoChain`.

"""
from jspcap.corekit.infoclass import Info
from jspcap.corekit.protochain import ProtoChain
from jspcap.corekit.version import VersionInfo


__all__ = ['Info', 'ProtoChain', 'VersionInfo']
