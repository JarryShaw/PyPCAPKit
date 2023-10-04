Base Class
==========

.. module:: pcapkit.foundation.engines.engine

This is the abstract base class implementation for
all engine support functionality.

.. autoclass:: pcapkit.foundation.engines.engine.Engine
   :members:
   :show-inheritance:

   .. .. autoproperty:: name
   .. .. autoproperty:: module
   .. .. autoproperty:: extractor

   .. .. automethod:: run
   .. .. automethod:: read_frame
   .. .. automethod:: close

   .. .. automethod:: __call__
   .. .. automethod:: __init_subclass__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.engines.engine.EngineBase
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.engines.engine.EngineMeta
   :members:
   :show-inheritance:
