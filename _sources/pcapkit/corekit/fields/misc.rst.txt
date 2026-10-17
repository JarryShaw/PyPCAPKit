Miscellaneous Fields
--------------------

.. module:: pcapkit.corekit.fields.misc

Conditional Fields
~~~~~~~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.misc.SwitchField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.ConditionalField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.ForwardMatchField
   :members:
   :show-inheritance:

Generic Data Fields
~~~~~~~~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.misc.SchemaField
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.corekit.fields.misc.nested_packet_context

.. autoclass:: pcapkit.corekit.fields.misc.PayloadField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.NoValueField
   :members:
   :show-inheritance:

Type Variables
~~~~~~~~~~~~~~

.. data:: _TC
   :type: typing.Any

.. data:: _TS
   :type: pcapkit.protocols.schema.schema.Schema

.. data:: _TP
   :type: pcapkit.protocols.protocol.ProtocolBase

.. data:: _TN
   :type: pcapkit.corekit.sentinels.NoValueType
