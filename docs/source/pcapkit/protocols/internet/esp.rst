ESP - Encapsulating Security Payload
====================================

.. module:: pcapkit.protocols.internet.esp

.. automodule:: pcapkit.protocols.internet.esp
   :no-members:

.. autoclass:: pcapkit.protocols.internet.esp.ESP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data
   .. automethod:: _payload_bytes
   .. automethod:: _read_trailer
   .. automethod:: _make_opaque

   .. automethod:: __post_init__
   .. automethod:: __index__

Security Associations
---------------------

SA context is supplied through the generic, protocol keyed channel of
:mod:`pcapkit.corekit.context`.

.. autoclass:: pcapkit.protocols.internet.esp.SecurityAssociation
   :no-members:
   :show-inheritance:

   .. autoproperty:: encryption_key
   .. autoproperty:: salt
   .. autoproperty:: integrity_key
   .. autoproperty:: icv_length
   .. autoproperty:: authenticated

   .. automethod:: matches
   .. automethod:: unavailable
   .. automethod:: compute_icv
   .. automethod:: decrypt
   .. automethod:: encrypt

   .. automethod:: _split_key
   .. automethod:: __repr__

.. autoclass:: pcapkit.protocols.internet.esp.ESPContext
   :no-members:
   :show-inheritance:

   .. autoproperty:: associations

   .. automethod:: protocol
   .. automethod:: register
   .. automethod:: match
   .. automethod:: __repr__

Algorithm Registries
--------------------

.. autoclass:: pcapkit.protocols.internet.esp.Cipher
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.esp.Integrity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.esp.ESPStatus
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.protocols.internet.esp.load_cryptography

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.esp

.. autoclass:: pcapkit.protocols.schema.internet.esp.ESP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.esp

.. autoclass:: pcapkit.protocols.data.internet.esp.ESP
   :members:
   :show-inheritance:
