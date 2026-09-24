Base Engine
===========

.. module:: pcapkit.foundation.engines.engine

This is the abstract base class implementation for
all engine support functionality.

.. autoclass:: pcapkit.foundation.engines.engine.Engine
   :no-members:
   :show-inheritance:

   .. seealso::

      For more information on customisation and extension, please
      refer to :doc:`../../../ext`.

   .. property:: name
      :type: str

      Engine name.

      .. note::

         This property is also available as a class variable. Its
         value can be set by :attr:`__engine_name__` class attribute.


   .. property:: module
      :type: str

      Engine module name.

      .. note::

         This property is also available as a class variable. Its
         value can be set by :attr:`__engine_module__` class attribute.

   .. property:: registry
      :type: dict[str, ModuleDescriptor[EngineBase] | typing.Type[EngineBase]]

      Mapping of engine names to engine classes.

      .. note::

         This property is only available as a class variable, since it is
         defined on :class:`EngineMeta`. It reads
         :attr:`~pcapkit.foundation.extraction.Extractor.__engine__`, the
         single table every engine registration lands in, so it is not a
         per-class mapping.

   .. autoproperty:: extractor

   .. autoattribute:: _extractor

   .. automethod:: unsupported_reason

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. automethod:: __call__
   .. automethod:: __init_subclass__

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.engines.engine.EngineBase
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.engines.engine.EngineMeta
   :no-members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.foundation.engines.engine._T
   :type: typing.Any
