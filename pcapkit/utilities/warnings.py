# -*- coding: utf-8 -*-
"""user defined warnings

:mod:`pcapkit.warnings` refined built-in warnings.

"""

__all__ = [
    # UserWarning
    'BaseWarning',
    # ImportWarning
    'FormatWarning', 'EngineWarning', 'InvalidVendorWarning',
    # RuntimeWarning
    'FileWarning', 'LayerWarning', 'ProtocolWarning', 'AttributeWarning',
    'DevModeWarning', 'VendorRequestWarning', 'VendorRuntimeWarning',
    # ResourceWarning
    'DPKTWarning', 'ScapyWarning', 'PySharkWarning'
]

##############################################################################
# BaseWarning (abc of warnings) session.
##############################################################################


class BaseWarning(UserWarning):
    """Base warning class of all kinds."""

    def __init__(self, *args, **kwargs):  # pylint: disable=useless-super-delegation
        # warnings.simplefilter('default')
        super().__init__(*args, **kwargs)


##############################################################################
# ImportWarning session.
##############################################################################


class FormatWarning(BaseWarning, ImportWarning):
    """Warning on unknown format(s)."""


class EngineWarning(BaseWarning, ImportWarning):
    """Unsupported extraction engine."""


class InvalidVendorWarning(BaseWarning, ImportWarning):
    """Vendor CLI invalid updater."""


##############################################################################
# RuntimeWarning session.
##############################################################################


class FileWarning(BaseWarning, RuntimeWarning):
    """Warning on file(s)."""


class LayerWarning(BaseWarning, RuntimeWarning):
    """Unrecognised layer."""


class ProtocolWarning(BaseWarning, RuntimeWarning):
    """Unrecognised protocol."""


class AttributeWarning(BaseWarning, RuntimeWarning):
    """Unsupported attribute."""


class DevModeWarning(BaseWarning, RuntimeWarning):
    """Run in development mode."""


class VendorRequestWarning(BaseWarning, RuntimeWarning):
    """Vendor request connection failed."""


class VendorRuntimeWarning(BaseWarning, RuntimeWarning):
    """Vendor failed during runtime."""


##############################################################################
# ResourceWarning session.
##############################################################################


class DPKTWarning(BaseWarning, ResourceWarning):
    """Warnings on DPKT usage."""


class ScapyWarning(BaseWarning, ResourceWarning):
    """Warnings on Scapy usage."""


class PySharkWarning(BaseWarning, ResourceWarning):
    """Warnings on PyShark usage."""
