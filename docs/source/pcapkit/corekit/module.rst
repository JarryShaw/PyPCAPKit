Module Descriptor
=================

.. module:: pcapkit.corekit.module

:mod:`pcapkit.corekit.module` contains the :obj:`tuple`-like class
:class:`~pcapkit.corekit.module.ModuleDescriptor`, which pairs a module name
with a class name.

.. autoclass:: pcapkit.corekit.module.ModuleDescriptor
   :no-members:
   :show-inheritance:

   .. autoproperty:: klass

   .. property:: module
      :type: str

      Module name.

   .. property:: name
      :type: str | pcapkit.corekit.sentinels.NullType

      Class name, or :data:`~pcapkit.corekit.sentinels.NULL` when whatever
      built this descriptor never got one -- see :attr:`klass`.

Type Variables
--------------

.. data:: pcapkit.corekit.module._T
   :type: typing.Any
