User Defined Warnings
=====================

.. module:: pcapkit.utilities.warnings

:mod:`pcapkit.utilities.warnings` holds refined built-in warnings.

.. versionremoved:: 1.5.0

   ``pcapkit.utilities.warnings.DEVMODE``, which 1.4.x imported from
   :mod:`pcapkit.utilities.logging`; read
   :data:`pcapkit.utilities.logging.DEVMODE` instead.

Reporting a Warning
-------------------

Every warning :mod:`pcapkit` reports goes through
:func:`~pcapkit.utilities.warnings.warn`, which reports it **exactly once on each
channel**:

1. the ``pcapkit`` logger (:data:`~pcapkit.utilities.logging.logger`), at
   :data:`logging.WARNING` level, unconditionally -- so a consumer watching the
   ``pcapkit`` logger sees every complaint whatever the warning filters say;
2. the standard :mod:`warnings` machinery, via :func:`warnings.warn`, subject to
   the filters -- so :func:`warnings.filterwarnings`,
   :class:`warnings.catch_warnings`, :mod:`pytest`'s ``filterwarnings``,
   :option:`-W` and :envvar:`PYTHONWARNINGS` govern :mod:`pcapkit` warnings
   exactly as they govern any other library's (with one wrinkle in naming a
   category on the command line, noted below).

The counts are the same in development mode as outside it:
:envvar:`PCAPKIT_DEVMODE` changes where the log records go, and
:envvar:`PCAPKIT_VERBOSE` how much detail they carry, never how many records
there are. Constructing a warning class is not an act of reporting one -- it
emits nothing and has no side effects.

A next layer is parsed on trial, and replaced with
:class:`~pcapkit.protocols.misc.raw.Raw` when its header was not captured or its
parse raises. The trial's warnings are held back by
:class:`~pcapkit.utilities.warnings.hold_warnings`: a replaced layer's are dropped
on each channel, since they describe a layer the result does not have, and a kept
layer's are reported as above when the trial ends (:issue:`1580`, :issue:`2308`,
:issue:`2516`).

.. autofunction:: pcapkit.utilities.warnings.warn

.. autoclass:: pcapkit.utilities.warnings.hold_warnings
   :members: discard, holding

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

.. versionchanged:: 1.5.0

   :mod:`pcapkit` warnings reach the :mod:`warnings` channel by default, and
   the first snippet above restores the 1.4.x quiet. In 1.4.x, constructing a
   :class:`~pcapkit.utilities.warnings.BaseWarning` installed an ``ignore``
   filter for its own class, so a caller could not re-enable them. The filter
   went at the *front* of the process-global ``warnings.filters``, so it
   also overrode the host application's own configuration for those categories
   and made unrelated warnings re-fire (:issue:`364`).

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

.. autoexception:: pcapkit.utilities.warnings.ChecksumWarning
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

.. autoexception:: pcapkit.utilities.warnings.ConfigWarning
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
