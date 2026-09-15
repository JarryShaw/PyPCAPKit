User Defined Warnings
=====================

.. module:: pcapkit.utilities.warnings

:mod:`pcapkit.warnings` refined built-in warnings.

How a Warning Is Reported
-------------------------

Every warning :mod:`pcapkit` reports goes through
:func:`~pcapkit.utilities.warnings.warn`, which reports it **exactly once on each
of two channels**:

1. the :data:`~pcapkit.utilities.logging.logger` logger, at
   :data:`logging.WARNING` level, unconditionally -- so a consumer watching the
   ``pcapkit`` logger sees every complaint whatever the warning filters say;
2. the standard :mod:`warnings` machinery, via :func:`warnings.warn`, subject to
   the filters -- so :func:`warnings.filterwarnings`,
   :func:`warnings.catch_warnings`, :mod:`pytest`'s ``filterwarnings``,
   :option:`-W` and :envvar:`PYTHONWARNINGS` govern :mod:`pcapkit` warnings
   exactly as they govern any other library's (with one wrinkle in naming a
   category on the command line, noted below).

The counts are the same in development mode as outside it:
:envvar:`PCAPKIT_DEVMODE` and :envvar:`PCAPKIT_VERBOSE` change how much detail
the log record carries, never how many records there are. Constructing a warning
class is not an act of reporting one -- it emits nothing and has no side effects.

Silencing pcapkit Warnings
--------------------------

Filter them like any other library's, at the level of granularity you want --
:class:`~pcapkit.utilities.warnings.BaseWarning` for all of them, or a single
category::

   import warnings

   from pcapkit.utilities.warnings import BaseWarning, SchemaWarning

   warnings.filterwarnings('ignore', category=BaseWarning)    # all of them
   warnings.filterwarnings('error', category=SchemaWarning)   # or turn one into an error

From the command line, name one of the standard categories these are mixed with.
:exc:`UserWarning` covers all of them, and :exc:`RuntimeWarning`,
:exc:`ImportWarning`, :exc:`ResourceWarning` and :exc:`DeprecationWarning` each
select a family::

   python -W ignore::UserWarning ...      # every pcapkit warning, and everyone else's
   python -W error::RuntimeWarning ...    # the RuntimeWarning family, as errors

.. note::

   :option:`-W` and :envvar:`PYTHONWARNINGS` cannot name a :mod:`pcapkit`
   category directly: ``-W ignore::pcapkit.utilities.warnings.BaseWarning`` is
   rejected with ``Invalid -W option ignored: invalid module name``. CPython
   imports the category while parsing the option, and that happens before
   :mod:`site` has added ``site-packages`` to :data:`sys.path`, so no installed
   package's own category can be named there -- this is not specific to
   :mod:`pcapkit`. Use a standard category on the command line, or install a
   precise filter in code as above.

All of that governs the :mod:`warnings` channel. The ``pcapkit`` logger is
configured separately, through the :mod:`logging` module::

   import logging

   logging.getLogger('pcapkit').setLevel(logging.ERROR)   # drop WARNING records

.. attention::

   Up to and including v1.4.1, :class:`~pcapkit.utilities.warnings.BaseWarning`
   installed an ``ignore`` filter for its own class as a side effect of being
   constructed, so :mod:`pcapkit` warnings were invisible on the :mod:`warnings`
   channel by default and a caller could not re-enable them. They are now
   delivered, which means a consumer who was relying on that silence will start
   seeing them; the first snippet above restores the old quiet. Since the filter
   was installed at the *front* of the process-global :data:`warnings.filters`,
   it also overrode the host application's own configuration for those
   categories and made unrelated warnings re-fire, so it is not something that
   can be kept.

.. autoexception:: pcapkit.utilities.warnings.BaseWarning
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.

:exc:`ImportWarning` Category
-----------------------------

.. autoexception:: pcapkit.utilities.warnings.FormatWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.EngineWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.InvalidVendorWarning
   :no-members:
   :show-inheritance:

:exc:`RuntimeWarning` Category
------------------------------

.. autoexception:: pcapkit.utilities.warnings.FileWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.LayerWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.ProtocolWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.AttributeWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.DevModeWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.VendorRequestWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.VendorRuntimeWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.UnknownFieldWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.RegistryWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.SchemaWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.InfoWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.SeekWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.ExtractionWarning
   :no-members:
   :show-inheritance:

:exc:`ResourceWarning` Category
-------------------------------

.. autoexception:: pcapkit.utilities.warnings.DPKTWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.ScapyWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.PySharkWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.EmojiWarning
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.warnings.VendorWarning
   :no-members:
   :show-inheritance:

:exc:`DeprecationWarning` Category
----------------------------------

.. autoexception:: pcapkit.utilities.warnings.DeprecatedFormatWarning
   :no-members:
   :show-inheritance:
