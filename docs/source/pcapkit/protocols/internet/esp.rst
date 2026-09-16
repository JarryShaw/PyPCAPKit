ESP - Encapsulating Security Payload
====================================

.. Unlike its sibling pages, this one renders the module docstring through
   ``automodule`` rather than repeating it as prose. That docstring already
   carries its own ``.. module::`` directive -- as every module under
   ``pcapkit`` does -- so there must be no second one here, and ``automodule``
   itself must not register a third: hence ``:no-index:``.

.. automodule:: pcapkit.protocols.internet.esp
   :no-members:
   :no-index:

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

The algorithm enumerations are the IANA IKEv2 transform ID registries,
generated into :mod:`pcapkit.const.esp` and re-exported here for convenience:
:class:`Cipher <pcapkit.const.esp.cipher.Cipher>` is
:class:`pcapkit.const.esp.cipher.Cipher` and :class:`Integrity
<pcapkit.const.esp.integrity.Integrity>` is
:class:`pcapkit.const.esp.integrity.Integrity`.

Algorithm Support
-----------------

A registry enumerates what IANA assigned an ID to, which is far more than
:mod:`pcapkit` implements. The tables below are the authority on what an SA may
actually name, and the two ``get`` methods refuse anything outside them.

.. autoclass:: pcapkit.protocols.internet.esp.CipherSuite
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.esp.IntegritySuite
   :members:
   :undoc-members:
   :show-inheritance:

.. autodata:: pcapkit.protocols.internet.esp.CIPHER_SUITES

.. autodata:: pcapkit.protocols.internet.esp.INTEGRITY_SUITES

.. autofunction:: pcapkit.protocols.internet.esp._resolve

Processing Status
-----------------

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
