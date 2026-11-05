Core Utilities
==============

.. module:: pcapkit.corekit

:mod:`pcapkit.corekit` holds the core utilities :mod:`pcapkit` is built on:

.. list-table::
   :header-rows: 1

   * - Module
     - Holds
   * - :mod:`~pcapkit.corekit.fields`
     - the :class:`~pcapkit.corekit.fields.field.Field` family for data parsing
   * - :mod:`~pcapkit.corekit.checksum`
     - the checksum algorithms the protocols compute and verify
   * - :mod:`~pcapkit.corekit.context`
     - the :class:`~pcapkit.corekit.context.ContextRegistry` channel for
       caller-supplied information a protocol needs but the wire does not carry
   * - :mod:`~pcapkit.corekit.decorators`
     - the decorators that protocols and schemas parse through
   * - :mod:`~pcapkit.corekit.enum`
     - the :class:`~pcapkit.corekit.enum.EnumLookup` and
       :class:`~pcapkit.corekit.enum.EnumRegistry` bases of every constant
       enumeration
   * - :mod:`~pcapkit.corekit.infoclass`
     - the :obj:`dict`-like :class:`~pcapkit.corekit.infoclass.Info`
   * - :mod:`~pcapkit.corekit.io`
     - :class:`~pcapkit.corekit.io.SeekableReader` and the stream proxies
   * - :mod:`~pcapkit.corekit.module`
     - :class:`~pcapkit.corekit.module.ModuleDescriptor`, naming a class by module
   * - :mod:`~pcapkit.corekit.multidict`
     - the :class:`~pcapkit.corekit.multidict.MultiDict` family for multi-entry
       mappings
   * - :mod:`~pcapkit.corekit.packet`
     - the :class:`~pcapkit.corekit.packet.DeferredPacket` mixin, for a
       ``packet`` parsed on first read
   * - :mod:`~pcapkit.corekit.protochain`
     - the protocol collection :class:`~pcapkit.corekit.protochain.ProtoChain`
   * - :mod:`~pcapkit.corekit.schema`
     - helpers shared across the schema layer
   * - :mod:`~pcapkit.corekit.sentinels`
     - the shared sentinels
   * - :mod:`~pcapkit.corekit.version`
     - the :obj:`tuple`-like :class:`~pcapkit.corekit.version.VersionInfo`

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
   schema/index
   sentinels
   version
