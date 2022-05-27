# -*- coding: utf-8 -*-
"""logging system

:mod:`pcapkit.utilities.logging` contains naïve integration
of the Python logging system, i.e. a :class:`logging.Logger`
instance as :data:`~pcapkit.utilities.logging.logger`.

"""
import os
import logging
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

#: Development mode (``DEVMODE``) flag.
DEVMODE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_DEVMODE', 'false').casefold(), False)

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
