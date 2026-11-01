Core Utilities
==============

.. module:: pcapkit.corekit

:mod:`pcapkit.corekit` holds the core utilities :mod:`pcapkit` is built on:
the :class:`~pcapkit.corekit.fields.field.Field` family for data parsing, the
:mod:`~pcapkit.corekit.checksum` algorithms the protocols compute and verify,
the :class:`~pcapkit.corekit.context.ContextRegistry` channel for caller-supplied
information a protocol needs but the wire does not carry, the
:mod:`~pcapkit.corekit.decorators` that protocols and schemas parse through,
the :class:`~pcapkit.corekit.enum.EnumLookup`/
:class:`~pcapkit.corekit.enum.EnumRegistry` bases every constant enumeration
inherits from, the :obj:`dict`-like :class:`~pcapkit.corekit.infoclass.Info`,
the :class:`~pcapkit.corekit.io.SeekableReader` and stream proxies of
:mod:`~pcapkit.corekit.io`, the
:class:`~pcapkit.corekit.module.ModuleDescriptor` naming a class by module, the
:class:`~pcapkit.corekit.multidict.MultiDict` family for multi-entry mappings,
the :class:`~pcapkit.corekit.packet.DeferredPacket` mixin for a ``packet``
parsed on first read, the protocol collection
:class:`~pcapkit.corekit.protochain.ProtoChain`, the shared
:mod:`~pcapkit.corekit.sentinels`, and the :obj:`tuple`-like
:class:`~pcapkit.corekit.version.VersionInfo`.

.. toctree::
   :maxdepth: 2

   fields/index
   checksum/index
   context
   decorators
   enum
   infoclass
   io
   module
   multidict
   packet
   protochain
   sentinels
   version
