# -*- coding: utf-8 -*-
"""Version Info
==================

.. module:: pcapkit.corekit.version

:mod:`pcapkit.corekit.version` contains :obj:`tuple`
like class :class:`~pcapkit.corekit.version.VersionInfo`,
which is originally designed alike :class:`sys.version_info`.

"""
import collections

__all__ = ['VersionInfo']


class VersionInfo(collections.namedtuple('VersionInfo', ['major', 'minor'])):
    """VersionInfo is alike :class:`sys.version_info`."""

    __slots__ = ()

    #: Major version.
    major: int
    #: Minor version.
    minor: int

    @property
    def version(self) -> 'str':
        """Return version string."""
        return f'{self.major}.{self.minor}'

    def __str__(self) -> 'str':
        return f'{self.major}.{self.minor}'
