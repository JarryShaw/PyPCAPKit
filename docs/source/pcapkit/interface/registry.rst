Registry Helpers
================

.. module:: pcapkit.interface.registry

:mod:`pcapkit.interface.registry` contains the helpers the
registrars use to compare registry entries and to put back
the entry a registry shipped with, so that an override of a
built-in can be undone (:issue:`1363`, :issue:`1364`).

They back the registrars of
:class:`~pcapkit.foundation.extraction.Extractor` --
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

.. autofunction:: pcapkit.interface.registry.same_entry

.. autofunction:: pcapkit.interface.registry.restore_shipped

.. autofunction:: pcapkit.interface.registry.restore_shipped_dumper
