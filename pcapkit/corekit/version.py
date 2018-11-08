# -*- coding: utf-8 -*-
"""version info

`pcapkit.corekit.version` contains tuple-like class
`VersionInfo`, which is originally designed alike
`sys.version_info`.

"""
import collections

__all__ = ['VersionInfo']

VersionInfo = collections.namedtuple('VersionInfo', ['major', 'minor'])
VersionInfo.__doc__ = """VersionInfo is alike `sys.version_info`."""
