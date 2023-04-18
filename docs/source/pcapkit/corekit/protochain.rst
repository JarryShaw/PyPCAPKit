Protocol Chain
==============

.. module:: pcapkit.corekit.protochain

:mod:`pcapkit.corekit.protochain` contains special protocol
collection class :class:`~pcapkit.corekit.protochain.ProtoChain`.

.. autoclass:: pcapkit.corekit.protochain.ProtoChain
   :no-members:
   :show-inheritance:

   :param proto: New protocol class on the top stack.
   :param alias: New protocol alias on the top stack.
   :param basis: Original protocol chain as base stacks.

   .. autoproperty:: protocols
   .. autoproperty:: aliases
   .. autoproperty:: chain

   .. automethod:: from_list
   .. automethod:: index
   .. automethod:: count

   .. automethod:: __str__
   .. automethod:: __repr__

   .. automethod:: __add__
   .. automethod:: __contains__
