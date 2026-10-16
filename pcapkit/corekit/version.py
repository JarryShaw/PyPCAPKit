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


# The generated base carries a name of its own, so that the class's ``Bases:``
# line in the docs does not link the class to itself (#1843).
class VersionInfo(collections.namedtuple('_VersionInfo', ['major', 'minor'])):
    """VersionInfo is alike :class:`sys.version_info`.

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
