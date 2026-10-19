Enumeration Base
================

.. module:: pcapkit.corekit.enum

:mod:`pcapkit.corekit.enum` contains the bases every enumeration in this
library inherits from: :class:`EnumLookup`, the *lookup* half shared by open
registries and closed sets alike, and its subclass :class:`EnumRegistry`, which
adds the *mutating* half every registry under :mod:`pcapkit.const` inherits.

.. versionadded:: 1.5.0

   The ``get`` each :mod:`pcapkit.const` enumeration carried as generated text
   moves onto :class:`EnumLookup`, and :class:`EnumRegistry` adds ``register``,
   which is how a member is minted at runtime: outside
   :class:`~pcapkit.const.mh.cga_type.CGAType`, looking up an unknown value does not mint
   one (:issue:`775`).

.. autoclass:: pcapkit.corekit.enum.EnumLookup
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.enum.EnumRegistry
   :members:
   :show-inheritance:
