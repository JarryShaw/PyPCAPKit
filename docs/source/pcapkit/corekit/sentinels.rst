Sentinel Objects
================

.. module:: pcapkit.corekit.sentinels

:mod:`pcapkit.corekit.sentinels` is the shared home of every module-level
singleton sentinel this package defines for itself: a value recognised only by
identity (``value is SENTINEL``), so it cannot be confused with a value a
caller might legitimately pass.

They are all defined here, and this is their only import path: the modules
that use them do not re-export them (:issue:`1744`).

Each behaves like a built-in singleton such as :obj:`None`: calling its type,
copying it and pickling it give back the one instance, it reprs as its own
name, neither it nor its type can be changed, and its type cannot be
subclassed (:issue:`1842`).

.. versionadded:: 1.5.0

   :class:`NoValueType` moves here from :mod:`pcapkit.corekit.fields.field`
   (:issue:`911`), and :data:`NO_VALUE` replaces its ``NoValue`` there
   (:issue:`937`). :class:`Sentinel` is the public base of every sentinel
   type (:issue:`1842`).

.. autoclass:: pcapkit.corekit.sentinels.Sentinel

.. autoclass:: pcapkit.corekit.sentinels.NullType
.. autodata:: pcapkit.corekit.sentinels.NULL

.. autoclass:: pcapkit.corekit.sentinels.NoValueType
.. autodata:: pcapkit.corekit.sentinels.NO_VALUE

.. autoclass:: pcapkit.corekit.sentinels.NoDefaultType
.. autodata:: pcapkit.corekit.sentinels.NO_DEFAULT

.. note::

   :class:`AbsentType` and :data:`ABSENT` are **private** -- never imported outside
   :mod:`pcapkit.protocols.protocol`, and named in no module's ``__all__``. For
   SCREAMING_SNAKE consistency with the other sentinels (see
   :ref:`sentinel-convention`), neither carries the leading underscore that would
   hide it from Sphinx, so both are documented below and marked private.

.. autoclass:: pcapkit.corekit.sentinels.AbsentType
.. autodata:: pcapkit.corekit.sentinels.ABSENT

Internal Definitions
--------------------

.. autoclass:: pcapkit.corekit.sentinels.SentinelMeta
   :no-members:
   :show-inheritance:
