Protocol Chain
==============

.. module:: pcapkit.corekit.protochain

:mod:`pcapkit.corekit.protochain` contains special protocol
collection class :class:`~pcapkit.corekit.protochain.ProtoChain`.

.. autoclass:: pcapkit.corekit.protochain.ProtoChain
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: __alias__
      :type: pcapkit.corekit.protochain._AliasList

      Protocol aliases chain.

   .. attribute:: __proto__
      :type: pcapkit.corekit.protochain._ProtoList

      Protocol classes chain.

.. autoclass:: pcapkit.corekit.protochain._AliasList
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: __data__
      :type: List[str]

      Protocol aliases chain data.

.. autoclass:: pcapkit.corekit.protochain._ProtoList
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: __data__
      :type: List[pcapkit.protocols.protocol.Protocol]

      Protocol classes chain data.
