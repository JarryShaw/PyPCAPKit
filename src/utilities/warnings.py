# -*- coding: utf-8 -*-
"""user defined warnings

"""
import warnings
import sys


__all__ = [
    'BaseWarning',                                                  # Warning
    'FormatWarning', 'EngineWarning',                               # ImportWarning
    'FileWarning', 'LayerWarning', 'ProtocolWarning',               # RuntimeWarning
]


##############################################################################
# BaseWarning (abc of warnings) session.
##############################################################################


class BaseWarning(Warning):
    """Base warning class of all kinds."""
    def __init__(self, *args, **kwargs):
        sys.tracebacklimit = 0
        warnings.simplefilter('default')
        super().__init__(*args, **kwargs)


##############################################################################
# ImportWarning session.
##############################################################################


class FormatWarning(BaseWarning, ImportWarning):
    """Warning on unknown format(s)."""
    pass


class EngineWarning(BaseWarning, ImportWarning):
    """Unsupported extraction engine."""
    pass


##############################################################################
# RuntimeWarning session.
##############################################################################


class FileWarning(BaseWarning, RuntimeWarning):
    """Warning on file(s)."""
    pass


class LayerWarning(BaseWarning, RuntimeWarning):
    """Unrecognised layer."""
    pass


class ProtocolWarning(BaseWarning, RuntimeWarning):
    """Unrecognised protocol."""
    pass
