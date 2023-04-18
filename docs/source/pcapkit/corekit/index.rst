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
:class:`~pcapkit.corekit.fields.field.Field` family for data parsing.

.. toctree::
   :maxdepth: 2

   fields
   infoclass
   multidict
   protochain
   version
