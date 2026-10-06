Base Engine
===========

.. module:: pcapkit.foundation.engines.engine

:mod:`pcapkit.foundation.engines.engine` defines the abstract base class of
every extraction engine.

.. autoclass:: pcapkit.foundation.engines.engine.Engine
   :no-members:
   :show-inheritance:

   .. seealso::

      For customisation and extension, see :doc:`../../../ext`.

   .. automethod:: __init_subclass__

.. autoclass:: pcapkit.foundation.engines.engine.EngineBase
   :no-members:
   :show-inheritance:

   .. property:: name
      :type: str

      Engine name.

      .. note::

         Also available as a class variable; set it with the
         :attr:`__engine_name__` class attribute.


   .. property:: module
      :type: str

      Engine module name.

      .. note::

         Also available as a class variable; set it with the
         :attr:`__engine_module__` class attribute.

   .. property:: registry
      :type: python:dict[str, ModuleDescriptor[EngineBase] | typing.Type[EngineBase]]

      Mapping of engine names to engine classes.

      .. note::

         Only available as a class variable, since it is defined on
         :class:`EngineMeta`. It is not a per-class mapping: it reads
         :attr:`~pcapkit.foundation.extraction.Extractor.__engine__`, the
         single table every engine registration lands in.

   .. autoproperty:: extractor

   .. autoattribute:: _extractor

   .. automethod:: unsupported_reason

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. automethod:: __call__

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.engines.engine.EngineMeta
   :no-members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.foundation.engines.engine._T
   :type: typing.Any
