# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""Module Utilities
======================

.. module:: pcapkit.utilities

:mod:`pcapkit.utilities` holds the cross-cutting services :mod:`pcapkit`
is built with, and imports nothing from :mod:`pcapkit` outside itself
(:issue:`1712`):

============================================ ================================================
Module                                       Service
============================================ ================================================
:mod:`~pcapkit.utilities.exceptions`         user-refined exceptions
:mod:`~pcapkit.utilities.warnings`           user-refined warnings
:mod:`~pcapkit.utilities.logging`            logging
:mod:`~pcapkit.utilities.config`             tunable limits and flags
:mod:`~pcapkit.utilities.compat`             compatibility layer
:mod:`~pcapkit.utilities.datetime`           timestamp conversion
:mod:`~pcapkit.utilities.pickle`             shared pickle reductions
:mod:`~pcapkit.utilities.contextvars`        context variables shared across modules
:mod:`~pcapkit.utilities.importlib`          lazy imports of a package's exports
:mod:`~pcapkit.utilities.inspect`            abstract-class check
:mod:`~pcapkit.utilities.chardet`            `chardet`_ wrapper
============================================ ================================================

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
