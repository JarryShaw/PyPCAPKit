# -*- coding: utf-8 -*-
"""user defined warnings

"""
##############################################################################
# import warnings
##############################################################################


__all__ = [
    'BaseWarning',                                                  # Warning
    'FormatWarning', 'EngineWarning',                               # ImportWarning
    'FileWarning', 'LayerWarning', 'ProtocolWarning', 'AttributeWarning',
                                                                    # RuntimeWarning
    'DPKTWarning', 'ScapyWarning', 'PySharkWarning'                 # ResourceWarning
]


##############################################################################
# BaseWarning (abc of warnings) session.
##############################################################################


class BaseWarning(Warning):
    """Base warning class of all kinds."""
    def __init__(self, *args, **kwargs):
        # warnings.simplefilter('default')
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


class AttributeWarning(BaseWarning, RuntimeWarning):
    """Unsupported attribute."""
    pass


##############################################################################
# ResourceWarning session.
##############################################################################


class DPKTWarning(BaseWarning, ResourceWarning):
    """Warnings on DPKT usage."""
    pass


class ScapyWarning(BaseWarning, ResourceWarning):
    """Warnings on Scapy usage."""
    pass


class PySharkWarning(BaseWarning, ResourceWarning):
    """Warnings on PyShark usage."""
    pass
