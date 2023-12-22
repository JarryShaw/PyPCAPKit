# -*- coding: utf-8 -*-
"""Logging System
====================

.. module:: pcapkit.utilities.logging

:mod:`pcapkit.utilities.logging` contains naïve integration
of the Python logging system, i.e. a :class:`logging.Logger`
instance as :data:`~pcapkit.utilities.logging.logger`.

"""
import logging
import os
import sys

__all__ = ['logger']

###############################################################################
# Dev Mode
###############################################################################

# boolean mappings
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}

#: bool: Development mode flag.
DEVMODE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_DEVMODE', 'false').casefold(), False)
#: bool: Verbose output flag.
VERBOSE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_VERBOSE', 'false').casefold(), False)

###############################################################################
# Sphinx Mode
###############################################################################

#: bool: This is a workaround for :data:`typing.TYPE_CHECKING` in Sphinx.
SPHINX_TYPE_CHECKING = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_SPHINX', 'false').casefold(), False)

###############################################################################
# Logger Setup
###############################################################################

#: logging.Logger: :class:`~logging.Logger` instance named after ``pcapkit``.
logger = logging.getLogger('pcapkit')

formatter = logging.Formatter(fmt='[%(levelname)s] %(asctime)s - %(message)s',
                              datefmt='%m/%d/%Y %I:%M:%S %p')
handler = logging.StreamHandler(sys.stderr)
if DEVMODE:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)
