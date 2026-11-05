===========================================================================
:class:`~pcapkit.protocols.internet.esp.protocol.ESP` Constant Enumerations
===========================================================================

.. module:: pcapkit.const.esp

.. list-table::

   * - :class:`ESP_Cipher <pcapkit.const.esp.cipher.Cipher>`
     - Encryption Algorithm Transform IDs [*]_
   * - :class:`ESP_Integrity <pcapkit.const.esp.integrity.Integrity>`
     - Integrity Algorithm Transform IDs [*]_

ESP has no algorithm registry of its own: IKEv2 negotiates an SA's algorithms, so
both enumerations are IKEv2 *transform ID* sub-registries. They live here rather
than under an ``ikev2`` package because
:class:`~pcapkit.protocols.internet.esp.protocol.ESP` is their only consumer.

Both list every transform **IANA has registered**, far more than :mod:`pcapkit` can
apply; :data:`~pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.protocol.INTEGRITY_SUITES` list those ESP
implements.

.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7

ESP Encryption Algorithm Transform IDs
======================================

.. module:: pcapkit.const.esp.cipher

IANA's *Transform Type 1 - Encryption Algorithm Transform IDs*, generated from
:class:`pcapkit.vendor.esp.cipher.Cipher`.

.. autoclass:: pcapkit.const.esp.cipher.Cipher
   :members:
   :undoc-members:
   :show-inheritance:

ESP Integrity Algorithm Transform IDs
=====================================

.. module:: pcapkit.const.esp.integrity

IANA's *Transform Type 3 - Integrity Algorithm Transform IDs*, generated from
:class:`pcapkit.vendor.esp.integrity.Integrity`.

.. autoclass:: pcapkit.const.esp.integrity.Integrity
   :members:
   :undoc-members:
   :show-inheritance:
