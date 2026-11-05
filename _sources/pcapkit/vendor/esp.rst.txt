=====================================================================
:class:`~pcapkit.protocols.internet.esp.protocol.ESP` Vendor Crawlers
=====================================================================

.. module:: pcapkit.vendor.esp

.. list-table::

   * - :class:`ESP_Cipher <pcapkit.vendor.esp.cipher.Cipher>`
     - Encryption Algorithm Transform IDs [*]_
   * - :class:`ESP_Integrity <pcapkit.vendor.esp.integrity.Integrity>`
     - Integrity Algorithm Transform IDs [*]_

ESP has no algorithm registry of its own: IKEv2 negotiates an SA's algorithms, so
both crawlers pull IKEv2 *transform ID* sub-registries, each published as its own
CSV file.

.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7

ESP Encryption Algorithm Transform IDs
======================================

.. module:: pcapkit.vendor.esp.cipher

Crawls IANA's *Transform Type 1 - Encryption Algorithm Transform IDs* to generate
:class:`pcapkit.const.esp.cipher.Cipher`.

.. autoclass:: pcapkit.vendor.esp.cipher.Cipher
   :members: FLAG, LINK
   :show-inheritance:

ESP Integrity Algorithm Transform IDs
=====================================

.. module:: pcapkit.vendor.esp.integrity

Crawls IANA's *Transform Type 3 - Integrity Algorithm Transform IDs* to generate
:class:`pcapkit.const.esp.integrity.Integrity`.

.. autoclass:: pcapkit.vendor.esp.integrity.Integrity
   :members: FLAG, LINK
   :show-inheritance:
