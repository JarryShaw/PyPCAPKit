# -*- coding: utf-8 -*-
"""version info

:mod:`pcapkit.corekit.version` contains :obj:`tuple`
like class :class:`~pcapkit.corekit.version.VersionInfo`,
which is originally designed alike :class:`sys.version_info`.

"""
import collections

__all__ = ['VersionInfo']

VersionInfo = collections.namedtuple('VersionInfo', ['major', 'minor'])
VersionInfo.__doc__ = """VersionInfo is alike :class:`sys.version_info`."""
