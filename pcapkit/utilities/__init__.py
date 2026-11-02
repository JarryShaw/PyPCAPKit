# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""Module Utilities
======================

.. module:: pcapkit.utilities

:mod:`pcapkit.utilities` holds the cross-cutting services
:mod:`pcapkit` is built with: user-refined exceptions and
warnings, logging, the tunable limits of
:mod:`~pcapkit.utilities.config`, a compatibility layer,
timestamp conversion, the context variables its modules
share, and wrappers around third-party
libraries. It imports nothing from :mod:`pcapkit`
outside itself (:issue:`1712`).

.. versionremoved:: 1.5.0

   ``pcapkit.utilities.decorators``, and the ``seekset``, ``beholder`` and
   ``prepare`` it bound on :mod:`pcapkit.utilities`, with no re-export; import
   them from :mod:`pcapkit.corekit.decorators` (:issue:`1735`).

"""
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.logging import configure, ensure_output, get_logger, logger, reset
from pcapkit.utilities.warnings import warn

__all__ = ['logger', 'get_logger', 'configure', 'reset', 'ensure_output',
           'warn', 'stacklevel', 'detect']
