# -*- coding: utf-8 -*-
"""User Defined Warnings
===========================

.. module:: pcapkit.utilities.warnings

:mod:`pcapkit.warnings` refined built-in warnings.

"""
import warnings
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import stacklevel as stacklevel_calculator
from pcapkit.utilities.logging import DEVMODE, VERBOSE, logger

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
    'UnknownFieldWarning', 'RegistryWarning', 'SchemaWarning', 'InfoWarning',
    'SeekWarning', 'ExtractionWarning',
    # ResourceWarning
    'DPKTWarning', 'ScapyWarning', 'PySharkWarning', 'EmojiWarning',
    'VendorWarning',
    # DeprecationWarning
    'DeprecatedFormatWarning',
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

    logger.warning(message, exc_info=VERBOSE, stack_info=VERBOSE,
                   stacklevel=stacklevel)
    warnings.warn(message, category, stacklevel)


##############################################################################
# BaseWarning (abc of warnings) session.
##############################################################################


class BaseWarning(UserWarning):
    """Base warning class of all kinds."""

    def __init__(self, *args: 'Any', **kwargs: 'Any') -> 'None':  # pylint: disable=useless-super-delegation
        # log warning
        if DEVMODE:
            if VERBOSE:
                logger.warning(str(self), exc_info=self, stack_info=True,
                            stacklevel=stacklevel_calculator())
            else:
                logger.warning(str(self))
        else:
            warnings.simplefilter('ignore', type(self))

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


class UnknownFieldWarning(BaseWarning, RuntimeWarning):
    """Unknown field."""


class RegistryWarning(BaseWarning, RuntimeWarning):
    """Registry warning."""


class SchemaWarning(BaseWarning, RuntimeWarning):
    """Schema warning."""


class InfoWarning(BaseWarning, RuntimeWarning):
    """Info class warning."""


class SeekWarning(BaseWarning, RuntimeWarning):
    """Seek operation warning."""


class ExtractionWarning(BaseWarning, RuntimeWarning):
    """Extraction warning."""


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


##############################################################################
# DeprecationWarning session.
##############################################################################


class DeprecatedFormatWarning(BaseWarning, DeprecationWarning):
    """Warning on deprecated formats."""
