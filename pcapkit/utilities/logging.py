# -*- coding: utf-8 -*-
"""logging system

:mod:`pcapkit.utilities.logging` contains naïve integration
of the Python logging system, i.e. a :class:`logging.Logger`
instance as :data:`~pcapkit.utilities.logging.logger`.

"""
import logging

from pcapkit.utilities.exceptions import DEVMODE

__all__ = ['logger']

#: logging.Logger: :class:`~logging.Logger` instance named after ``pcapkit``.
logger = logging.getLogger('pcapkit')

if DEVMODE:
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
logger.addHandler(logging.NullHandler())
