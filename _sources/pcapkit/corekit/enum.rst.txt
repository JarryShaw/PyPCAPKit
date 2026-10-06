Enumeration Base
================

.. module:: pcapkit.corekit.enum

:mod:`pcapkit.corekit.enum` contains the two bases every enumeration in this
library inherits from: :class:`EnumLookup`, the *lookup* half shared by open
registries and closed sets alike, and its subclass :class:`EnumRegistry`, which
adds the *mutating* half every registry under :mod:`pcapkit.const` inherits.

.. autoclass:: pcapkit.corekit.enum.EnumLookup
   :members:
   :show-inheritance:

   .. automethod:: _validate_value

.. autoclass:: pcapkit.corekit.enum.EnumRegistry
   :members:
   :show-inheritance:

   .. automethod:: _extend
   .. automethod:: _unregistered_member

Auxiliaries
-----------

.. autoclass:: pcapkit.corekit.enum.NoDefaultType
.. autodata:: pcapkit.corekit.enum.NO_DEFAULT
