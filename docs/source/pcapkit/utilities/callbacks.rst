Running Callbacks
=================

.. module:: pcapkit.utilities.callbacks

:mod:`pcapkit.utilities.callbacks` holds :func:`run_callbacks`, which calls every
registered callback whatever an earlier one raised. Reassembly and flow tracing run
their callbacks through it, so both follow the ruling recorded on
:ref:`reassembly-integration` (:issue:`2881`). It behaves the same on every
interpreter, so it is not in :mod:`~pcapkit.utilities.compat`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.7.0

.. autofunction:: pcapkit.utilities.callbacks.run_callbacks
