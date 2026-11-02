Shared Context Variables
========================

.. module:: pcapkit.utilities.contextvars

:mod:`pcapkit.utilities.contextvars` holds the :class:`~contextvars.ContextVar`
objects that more than one :mod:`pcapkit` module sets or reads, so that no module
imports another's private state (:issue:`2616`). A context variable that only its
own module uses stays there. This module imports nothing from :mod:`pcapkit`, so
a module at any layer may import it; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

.. autodata:: pcapkit.utilities.contextvars.beholding
   :no-value:

.. autodata:: pcapkit.utilities.contextvars.frame_depth
   :no-value:

.. autodata:: pcapkit.utilities.contextvars.in_fragment
   :no-value:

.. autodata:: pcapkit.utilities.contextvars.rebuilding
   :no-value:
