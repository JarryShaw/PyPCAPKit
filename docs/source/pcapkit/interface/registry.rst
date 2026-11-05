Registry Helpers
================

.. module:: pcapkit.interface.registry

:mod:`pcapkit.interface.registry` holds the helpers the registrars use to
compare registry entries and to put back the entry a registry shipped with, so
that an override of a built-in can be undone (:issue:`1363`, :issue:`1364`).
They back the registrars of :class:`~pcapkit.foundation.extraction.Extractor` --
:meth:`~pcapkit.foundation.extraction.Extractor.register_engine`,
:meth:`~pcapkit.foundation.extraction.Extractor.register_reassembly`,
:meth:`~pcapkit.foundation.extraction.Extractor.register_traceflow` and
:meth:`~pcapkit.foundation.extraction.Extractor.register_dumper` -- and
:meth:`TraceFlow.register_dumper <pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper>`,
which the functions in :mod:`pcapkit.foundation.registry` call in turn.

A registry entry is a class or a
:class:`~pcapkit.corekit.module.ModuleDescriptor` naming one; an
``__output__`` entry is a ``(dumper, ext)`` pair whose ``dumper``
is such an entry.

What a registrar does with the entry it is handed:

.. mermaid::

   flowchart TD
       CALL["a registrar is<br/>handed an entry"] --> SHIPPED{"same_entry: the entry<br/>the key shipped with?"}
       SHIPPED -->|yes| RESTORE["restore_shipped, or<br/>restore_shipped_dumper"]
       RESTORE --> HELD{"what is registered<br/>under the key?"}
       HELD -->|"the shipped class"| SILENT["silent; for a dumper,<br/>a new ext is stored"]
       HELD -->|"another class"| WARN1["RegistryWarning"]
       HELD -->|nothing| STORE1["store the shipped entry"]
       WARN1 --> STORE1
       SHIPPED -->|no| CHECK{"a class, and a subclass<br/>of the public base?"}
       CHECK -->|no| ERROR["RegistryError"]
       CHECK -->|yes| OTHER{"another class<br/>under the key?"}
       OTHER -->|yes| WARN2["RegistryWarning"]
       OTHER -->|no| STORE2["store the class"]
       WARN2 --> STORE2

       click SHIPPED "registry.html#pcapkit.interface.registry.same_entry"
       click RESTORE "registry.html#pcapkit.interface.registry.restore_shipped"

.. autofunction:: pcapkit.interface.registry.same_entry

.. autofunction:: pcapkit.interface.registry.restore_shipped

.. autofunction:: pcapkit.interface.registry.restore_shipped_dumper
