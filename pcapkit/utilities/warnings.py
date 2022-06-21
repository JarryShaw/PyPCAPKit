# -*- coding: utf-8 -*-
"""User Defined Warnings
===========================

:mod:`pcapkit.warnings` refined built-in warnings.

"""
import warnings
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import stacklevel as stacklevel_calculator
from pcapkit.utilities.logging import DEVMODE, logger

if TYPE_CHECKING:
    from typing import Any, Optional, Type, Union

__all__ = [
    'warn',

    # UserWarning
    'BaseWarning',
    # ImportWarning
    'FormatWarning', 'EngineWarning', 'InvalidVendorWarning',
    # RuntimeWarning
    'FileWarning', 'LayerWarning', 'ProtocolWarning', 'AttributeWarning',
    'DevModeWarning', 'VendorRequestWarning', 'VendorRuntimeWarning',
    # ResourceWarning
    'DPKTWarning', 'ScapyWarning', 'PySharkWarning', 'EmojiWarning',
    'VendorWarning',
]


def warn(message: 'Union[str, Warning]', category: 'Type[Warning]',
         stacklevel: 'Optional[int]' = None) -> 'None':
    """Wrapper function of :func:`warnings.warn`.

    Args:
        message: Warning message.
        category: Warning category.
        stacklevel: Warning stack level.

    """
    if stacklevel is None:
        stacklevel = stacklevel_calculator()
    warnings.warn(message, category, stacklevel)


##############################################################################
# BaseWarning (abc of warnings) session.
##############################################################################


class BaseWarning(UserWarning):
    """Base warning class of all kinds."""

    def __init__(self, *args: 'Any', **kwargs: 'Any') -> 'None':  # pylint: disable=useless-super-delegation
        # log warning
        if DEVMODE:
            logger.warning(str(self), exc_info=self)
        else:
            logger.warning(str(self))

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


class EmojiWarning(BaseWarning, ResourceWarning):
    """Warnings on Emoji usage."""


class VendorWarning(BaseWarning, ResourceWarning):
    """Warnings on vendor usage."""
