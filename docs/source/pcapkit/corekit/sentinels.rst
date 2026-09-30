Sentinel Objects
================

.. module:: pcapkit.corekit.sentinels

:mod:`pcapkit.corekit.sentinels` is the single, shared home for every
module-level singleton sentinel this package defines for itself -- a value
whose only job is to be recognised by identity (``value is SENTINEL``), so
that it can never be confused with a value a caller might legitimately pass.

Each of the three below used to live beside the one class that consumed it --
:class:`NullType` in :mod:`pcapkit.corekit.module`, :class:`NoValueType` in
:mod:`pcapkit.corekit.fields.field` and :class:`NoDefaultType` in
:mod:`pcapkit.corekit.enum` -- until GitHub issue #911 moved all four
definitions here, the private ``_AbsentType``/``_Absent`` included. Each
original module keeps a re-export, so every existing ``from <module> import
<name>`` keeps working unchanged.

.. autoclass:: pcapkit.corekit.sentinels.NullType
.. autodata:: pcapkit.corekit.sentinels.NULL

.. autoclass:: pcapkit.corekit.sentinels.NoValueType
.. autodata:: pcapkit.corekit.sentinels.NoValue
   :no-value:

.. autoclass:: pcapkit.corekit.sentinels.NoDefaultType
.. autodata:: pcapkit.corekit.sentinels.NO_DEFAULT
