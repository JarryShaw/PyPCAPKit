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
definitions here, the private ``AbsentType``/``ABSENT`` included. Each
original module keeps a re-export, so every existing ``from <module> import
<name>`` keeps working unchanged.

.. autoclass:: pcapkit.corekit.sentinels.NullType
.. autodata:: pcapkit.corekit.sentinels.NULL

.. autoclass:: pcapkit.corekit.sentinels.NoValueType
.. autodata:: pcapkit.corekit.sentinels.NO_VALUE
   :no-value:

.. autoclass:: pcapkit.corekit.sentinels.NoDefaultType
.. autodata:: pcapkit.corekit.sentinels.NO_DEFAULT

.. note::

   :class:`AbsentType` and :data:`ABSENT` are **private** -- never imported outside
   :mod:`pcapkit.protocols.protocol`, and named in no module's ``__all__``. Until
   GitHub issue #937, the leading underscore they carried (``_AbsentType``/
   ``_Absent``) hid them from Sphinx automatically, the way it hides every other
   ``_``-prefixed name; dropping the underscore for SCREAMING_SNAKE consistency with
   the other three sentinels (see :ref:`sentinel-convention`) means Sphinx would
   otherwise document them as though they were public. They are documented below
   instead, explicitly marked private, per the maintainer's ruling on #937: *"we can
   change* ``_ABSENT`` *to* ``ABSENT`` *just document it as private type/class in the
   documentation and not for public use is enough."* Neither is for use outside this
   package.

.. autoclass:: pcapkit.corekit.sentinels.AbsentType
.. autodata:: pcapkit.corekit.sentinels.ABSENT
