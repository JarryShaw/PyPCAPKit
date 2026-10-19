# -*- coding: utf-8 -*-
"""Version Info
==================

.. module:: pcapkit.corekit.version

:mod:`pcapkit.corekit.version` contains :obj:`tuple`
like class :class:`~pcapkit.corekit.version.VersionInfo`,
modelled on :data:`sys.version_info`.

"""
import collections

__all__ = ['VersionInfo']


class VersionInfo(collections.namedtuple('VersionInfo', ['major', 'minor'])):
    """VersionInfo is modelled on :data:`sys.version_info`.

    .. versionchanged:: 1.3.0

       :class:`str` gives ``'major.minor'`` rather than the tuple's
       :func:`repr`.

    """

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
