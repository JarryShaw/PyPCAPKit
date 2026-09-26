Module Descriptor
=================

.. module:: pcapkit.corekit.module

:mod:`pcapkit.corekit.module` contains :obj:`tuple`
like class :class:`~pcapkit.corekit.module.ModuleDescriptor`,
which is originally designed as :obj:`tuple[str, str] <tuple>`.

.. autoclass:: pcapkit.corekit.module.ModuleDescriptor
   :no-members:
   :show-inheritance:

   .. autoproperty:: klass

   .. property:: module
      :type: str

      Module name.

   .. property:: name
      :type: str | pcapkit.corekit.module.NullType

      Class name, or :data:`NULL` when whatever built this descriptor never
      got one -- see :attr:`klass`.

Auxiliaries
-----------

.. autoclass:: pcapkit.corekit.module.NullType
.. autodata:: pcapkit.corekit.module.NULL

Type Variables
--------------

.. data:: pcapkit.corekit.module._T
   :type: typing.Any
