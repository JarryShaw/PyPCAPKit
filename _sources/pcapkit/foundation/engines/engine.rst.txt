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

         Also a class variable, set by :attr:`__engine_name__`.

   .. property:: module
      :type: str

      Engine module name.

      .. note::

         Also a class variable, set by :attr:`__engine_module__`.

   .. property:: registry
      :type: dict[str, ModuleDescriptor[EngineBase] | typing.Type[EngineBase]]

      Mapping of engine names to engine classes.

      .. note::

         A class variable only, defined on :class:`EngineMeta`. It is not
         per-class: it reads
         :attr:`~pcapkit.foundation.extraction.Extractor.__engine__`, the one
         table every engine registration lands in.

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

.. data:: _T
   :type: typing.Any

   Frame type the engine reads.
