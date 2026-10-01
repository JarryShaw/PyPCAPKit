Sentinel Objects
================

.. module:: pcapkit.corekit.sentinels

:mod:`pcapkit.corekit.sentinels` is the single, shared home for every
module-level singleton sentinel this package defines for itself -- a value
whose only job is to be recognised by identity (``value is SENTINEL``), so
that it can never be confused with a value a caller might legitimately pass.

All four are defined here. The three public ones are also re-exported by
:mod:`pcapkit.corekit.module`, :mod:`pcapkit.corekit.fields.field` and
:mod:`pcapkit.corekit.enum` respectively, so ``from <module> import <name>``
resolves from either path.

.. autoclass:: pcapkit.corekit.sentinels.NullType
.. autodata:: pcapkit.corekit.sentinels.NULL

.. autoclass:: pcapkit.corekit.sentinels.NoValueType
.. autodata:: pcapkit.corekit.sentinels.NO_VALUE
   :no-value:

.. autoclass:: pcapkit.corekit.sentinels.NoDefaultType
.. autodata:: pcapkit.corekit.sentinels.NO_DEFAULT

.. note::

   :class:`AbsentType` and :data:`ABSENT` are **private** -- never imported outside
   :mod:`pcapkit.protocols.protocol`, and named in no module's ``__all__``. For
   SCREAMING_SNAKE consistency with the other three sentinels (see
   :ref:`sentinel-convention`), neither carries the leading underscore that would
   otherwise hide it from Sphinx automatically, so both are documented below and
   explicitly marked private. Neither is for use outside this package.

.. autoclass:: pcapkit.corekit.sentinels.AbsentType
.. autodata:: pcapkit.corekit.sentinels.ABSENT
