# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Checksum Pseudo-Headers
=============================

.. module:: pcapkit.protocols.misc.checksum

:mod:`pcapkit.protocols.misc.checksum` contains the pseudo-header that
upper-layer checksums cover,
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`. The checksum
itself is in :mod:`pcapkit.corekit.checksum`.

The pseudo-header is imported the first time it is reached rather than with this
package, through :func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

__all__ = ['IP_Pseudo']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'IP_Pseudo': ('ip_pseudo', 'IP_Pseudo'),
})
