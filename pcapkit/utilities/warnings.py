# -*- coding: utf-8 -*-
"""User Defined Warnings
===========================

.. module:: pcapkit.utilities.warnings

:mod:`pcapkit.warnings` refined built-in warnings.

Every warning :mod:`pcapkit` reports goes through :func:`warn`, which reports it
**exactly once on each of two channels**:

1. the :data:`~pcapkit.utilities.logging.logger` logger, at
   :data:`logging.WARNING` level, unconditionally -- so a consumer watching the
   ``pcapkit`` logger sees every complaint whatever the warning filters say;
2. the standard :mod:`warnings` machinery, via :func:`warnings.warn`, subject to
   the filters -- so :func:`warnings.filterwarnings`,
   :func:`warnings.catch_warnings`, :mod:`pytest`'s ``filterwarnings``,
   :option:`-W` and :envvar:`PYTHONWARNINGS` govern :mod:`pcapkit` warnings
   exactly as they govern any other library's (see below for the one wrinkle in
   naming a category on the command line).

The counts are the same in development mode as outside it;
:data:`~pcapkit.utilities.logging.DEVMODE` and
:data:`~pcapkit.utilities.logging.VERBOSE` change how much detail the log record
carries, never how many records there are. Constructing a warning class is not
an act of reporting one, and has no side effects at all.

To silence :mod:`pcapkit` warnings, filter them like any other category::

    import warnings

    from pcapkit.utilities.warnings import BaseWarning

    warnings.filterwarnings('ignore', category=BaseWarning)

From the command line, name one of the standard categories these are mixed with
-- :exc:`UserWarning` covers all of them, and :exc:`RuntimeWarning`,
:exc:`ImportWarning`, :exc:`ResourceWarning` and :exc:`DeprecationWarning` each
select a family::

    python -W ignore::UserWarning ...

:option:`-W` and :envvar:`PYTHONWARNINGS` cannot name a :mod:`pcapkit` category
directly -- ``-W ignore::pcapkit.utilities.warnings.BaseWarning`` is rejected
with ``Invalid -W option ignored: invalid module name``. CPython imports the
category while parsing the option, which happens before :mod:`site` has added
``site-packages`` to :data:`sys.path`, so no installed package's own category can
be named there; this is not specific to :mod:`pcapkit`.

Note that all of the above governs the :mod:`warnings` channel only. The
``pcapkit`` logger is configured separately, e.g. with
``logging.getLogger('pcapkit').setLevel(logging.ERROR)``.

"""
import warnings
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import stacklevel as stacklevel_calculator
from pcapkit.utilities.logging import VERBOSE, get_logger

if TYPE_CHECKING:
    from typing import Optional, Type, Union

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


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


def warn(message: 'Union[str, Warning]', category: 'Type[Warning]',
         stacklevel: 'Optional[int]' = None) -> 'None':
    """Wrapper function of :func:`warnings.warn`.

    The warning is reported once on the :data:`~pcapkit.utilities.logging.logger`
    logger, then once through :func:`warnings.warn`. The logger call does not
    consult :data:`warnings.filters`, so a log-based consumer sees the complaint
    even when the application has filtered the category out; the
    :func:`warnings.warn` call is filtered normally, so the application keeps
    full control of that channel -- including turning the warning into an error
    with :option:`-W error <-W>`.

    Args:
        message: Warning message.
        category: Warning category.
        stacklevel: Warning stack level.

    See Also:
        :mod:`pcapkit.utilities.warnings` for the emission model in full, and for
        how to silence either channel.

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
    """Base warning class of all kinds.

    Constructing one of these is deliberately free of side effects: it emits
    nothing and mutates no process-global state. Reporting a warning is the job
    of :func:`warn`, which is called once per complaint; a warning object may be
    built without ever being reported, and the two must not be confused.

    Note:
        Up to and including v1.4.1, this constructor called
        ``warnings.simplefilter('ignore', type(self))`` outside development
        mode, which inserted an entry at the front of the process-global
        :data:`warnings.filters` -- overriding whatever the host application,
        :option:`-W` or the test runner had configured, and invalidating every
        module's ``__warningregistry__`` so that unrelated warnings re-fired.
        It also logged the warning a second time under
        :data:`~pcapkit.utilities.logging.DEVMODE`. Both are gone; filtering is
        the application's business, and is done through the standard
        :mod:`warnings` machinery.

    """


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
