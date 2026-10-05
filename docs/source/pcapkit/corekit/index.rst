Core Utilities
==============

.. module:: pcapkit.corekit

:mod:`pcapkit.corekit` holds the core utilities :mod:`pcapkit` is built on:
the :obj:`dict`-like :class:`~pcapkit.corekit.infoclass.Info`, the
:obj:`tuple`-like :class:`~pcapkit.corekit.version.VersionInfo`, the protocol
collection :class:`~pcapkit.corekit.protochain.ProtoChain`, the
:class:`~pcapkit.corekit.multidict.MultiDict` family for multi-entry
mappings, the :class:`~pcapkit.corekit.fields.field.Field` family for data
parsing, the :class:`~pcapkit.corekit.context.ContextRegistry` channel for
caller-supplied information a protocol needs but the wire does not carry, and
the :class:`~pcapkit.corekit.enum.EnumLookup`/
:class:`~pcapkit.corekit.enum.EnumRegistry` bases every constant enumeration
inherits from.

.. toctree::
   :maxdepth: 2

   fields/index
   context
   enum
   infoclass
   io
   module
   multidict
   protochain
   sentinels
   version
