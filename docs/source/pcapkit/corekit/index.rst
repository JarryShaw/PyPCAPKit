Core Utilities
==============

.. module:: pcapkit.corekit

:mod:`pcapkit.corekit` is the collection of core utilities
for :mod:`pcapkit` implementation, including :obj:`dict` like
class :class:`~pcapkit.corekit.infoclass.Info`,
:obj:`tuple` like class :class:`~pcapkit.corekit.version.VersionInfo`,
protocol collection class :class:`~pcapkit.corekit.protochain.ProtoChain`,
and :class:`~pcapkit.corekit.multidict.MultiDict` family inspired from
:mod:`Werkzeug` for multientry :obj:`dict` data mapping, the
:class:`~pcapkit.corekit.fields.field.Field` family for data parsing,
the :class:`~pcapkit.corekit.context.ContextRegistry` channel for caller
supplied information that a protocol needs but the wire does not carry, and
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
   version
