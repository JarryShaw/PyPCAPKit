Configuration
=============

.. module:: pcapkit.utilities.config

:mod:`pcapkit.utilities.config` holds every tunable limit of :mod:`pcapkit`, and
the settings of the :mod:`pcapkit.vendor` crawlers (:issue:`1726`). Each limit
is read from a ``PCAPKIT_*`` environment variable once, when the module is
imported:

* A value that is not an integer, or is below the variable's minimum, warns with
  a :exc:`~pcapkit.utilities.warnings.ConfigWarning` and falls back to the
  default.
* A limit takes ``-1`` for no limit. That, or a value above the default, is
  accepted and warns with a :exc:`~pcapkit.utilities.warnings.ConfigWarning`
  naming the risk below.

Each warning names the variable and the value it was given, e.g.
``PCAPKIT_FALLBACK_LIMIT='-7' is not an integer of at least 0, or -1 for no
limit; using the default, 10000``. It obeys the warning filters, so under
:option:`-W error <-W>` or ``PYTHONWARNINGS=error`` an out-of-range value makes
``import pcapkit`` raise :exc:`~pcapkit.utilities.warnings.ConfigWarning`.

Readers look each value up as ``config.<NAME>`` at call time, so patching a name
here reaches every engine and protocol that reads it. The proxy addresses are
read on every call of :func:`~pcapkit.utilities.config.http_proxy` and
:func:`~pcapkit.utilities.config.https_proxy` instead.

:envvar:`PCAPKIT_DEVMODE`, :envvar:`PCAPKIT_VERBOSE` and :envvar:`PCAPKIT_SPHINX`
are read by :mod:`pcapkit.utilities.logging`, which needs them while it loads
and so cannot import this module. A bad value of one falls back to off, and is
reported with a :exc:`~pcapkit.utilities.warnings.ConfigWarning` once
:mod:`pcapkit.utilities.warnings` has loaded.

.. versionadded:: 1.5.0

Limits
------

.. list-table::
   :header-rows: 1

   * - Variable
     - Default
     - Accepted
     - Risk past the default, or at ``-1``
   * - :envvar:`PCAPKIT_FRAME_LAYER_LIMIT`
     - ``64``
     - ``>= 0``, or ``-1``
     - Python's recursion limit: a deep frame may raise :exc:`RecursionError`
       (:issue:`1610`)
   * - :envvar:`PCAPKIT_EXTENSION_HEADER_LIMIT`
     - ``32``
     - ``>= 0``, or ``-1``
     - as above, once :envvar:`PCAPKIT_FRAME_LAYER_LIMIT` is raised too
   * - :envvar:`PCAPKIT_IPV6_TCP_WARNED_LIMIT`
     - ``32``
     - ``>= 0``, or ``-1``
     - each capture remembered pins one packet in memory
   * - :envvar:`PCAPKIT_FALLBACK_LIMIT`
     - ``10000``
     - ``>= 0``, or ``-1``
     - a large or endless object graph is dumped without bound
   * - :envvar:`PCAPKIT_DETECT_CACHE_SIZE`
     - ``1024``
     - ``>= 0``, or ``-1``
     - the cache retains every bytestring it was asked about
   * - :envvar:`PCAPKIT_READ_CHUNK`
     - ``1048576``
     - ``>= 1``, or ``-1``
     - a bogus record length allocates that much in one read
   * - :envvar:`PCAPKIT_MAX_ZERO_PAD_LENGTH`
     - ``262144``
     - ``>= 0``, or ``-1`` to lift the ceiling and the running budget
     - a hostile capture's declared length is zero-filled in memory
       (:issue:`554`)
   * - :envvar:`PCAPKIT_MAX_ZERO_PAD_SHORTFALL`
     - ``65536``
     - ``>= 0``, or ``-1`` to disable the running budget
     - lying lengths amplify into memory without being charged (:issue:`573`)
   * - :envvar:`PCAPKIT_ZERO_PAD_BUDGET_RATIO`
     - ``16``
     - ``>= 0``, or ``-1`` to lift the running budget
     - as above, per octet actually read (:issue:`573`)

.. envvar:: PCAPKIT_FRAME_LAYER_LIMIT

   Sets :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.

.. envvar:: PCAPKIT_EXTENSION_HEADER_LIMIT

   Sets :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`.

.. envvar:: PCAPKIT_IPV6_TCP_WARNED_LIMIT

   Sets :data:`~pcapkit.utilities.config.IPV6_TCP_WARNED_LIMIT`.

.. envvar:: PCAPKIT_FALLBACK_LIMIT

   Sets :data:`~pcapkit.utilities.config.FALLBACK_LIMIT`.

.. envvar:: PCAPKIT_DETECT_CACHE_SIZE

   Sets :data:`~pcapkit.utilities.config.DETECT_CACHE_SIZE`. Read once, when
   :mod:`pcapkit.utilities.chardet` is imported.

.. envvar:: PCAPKIT_READ_CHUNK

   Sets :data:`~pcapkit.utilities.config.READ_CHUNK`.

.. envvar:: PCAPKIT_MAX_ZERO_PAD_LENGTH

   Sets :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH`.

.. envvar:: PCAPKIT_MAX_ZERO_PAD_SHORTFALL

   Sets :data:`~pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL`.

.. envvar:: PCAPKIT_ZERO_PAD_BUDGET_RATIO

   Sets :data:`~pcapkit.utilities.config.ZERO_PAD_BUDGET_RATIO`.

.. autodata:: pcapkit.utilities.config.FRAME_LAYER_LIMIT
.. autodata:: pcapkit.utilities.config.EXTENSION_HEADER_LIMIT
.. autodata:: pcapkit.utilities.config.IPV6_TCP_WARNED_LIMIT
.. autodata:: pcapkit.utilities.config.FALLBACK_LIMIT
.. autodata:: pcapkit.utilities.config.DETECT_CACHE_SIZE
.. autodata:: pcapkit.utilities.config.READ_CHUNK
.. autodata:: pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH
.. autodata:: pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL
.. autodata:: pcapkit.utilities.config.ZERO_PAD_BUDGET_RATIO

Vendor Crawlers
---------------

.. envvar:: PCAPKIT_VENDOR_RETRY

   Sets :data:`~pcapkit.utilities.config.VENDOR_RETRY`: an integer ``>= 1``,
   default ``5``.

.. envvar:: PCAPKIT_CI_MODE

   Sets :data:`~pcapkit.utilities.config.CI_MODE`: ``1``/``yes``/``true``/``on``
   or ``0``/``no``/``false``/``off``, default off.

.. envvar:: PCAPKIT_HTTP_PROXY

   The HTTP proxy address for the :mod:`pcapkit.vendor` crawlers, read by
   :func:`~pcapkit.utilities.config.http_proxy` on every call. Unset by default.

.. envvar:: PCAPKIT_HTTPS_PROXY

   The HTTPS proxy address for the :mod:`pcapkit.vendor` crawlers, read by
   :func:`~pcapkit.utilities.config.https_proxy` on every call. Unset by
   default.

.. autodata:: pcapkit.utilities.config.VENDOR_RETRY
.. autodata:: pcapkit.utilities.config.CI_MODE
.. autofunction:: pcapkit.utilities.config.http_proxy
.. autofunction:: pcapkit.utilities.config.https_proxy
