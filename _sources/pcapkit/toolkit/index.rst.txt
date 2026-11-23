Compatibility Tools
===================

.. module:: pcapkit.toolkit

:mod:`pcapkit.toolkit` provides per-engine adapters that convert each engine's
packets into the data :mod:`pcapkit` consumes, chiefly for reassembly and flow
tracing. An engine feeds a reassembler or a flow tracer through the adapter its
:attr:`~pcapkit.foundation.engines.engine.EngineBase.__reassembly__` or
:attr:`~pcapkit.foundation.engines.engine.EngineBase.__traceflow__` names for it.

.. toctree::
   :maxdepth: 2

   builtin
   3rdparty
