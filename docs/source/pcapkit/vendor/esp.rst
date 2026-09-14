============================================================
:class:`~pcapkit.protocols.internet.esp.ESP` Vendor Crawlers
============================================================

.. module:: pcapkit.vendor.esp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.esp.ESP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`ESP_Cipher <pcapkit.vendor.esp.cipher.Cipher>`
     - Encryption Algorithm Transform IDs [*]_
   * - :class:`ESP_Integrity <pcapkit.vendor.esp.integrity.Integrity>`
     - Integrity Algorithm Transform IDs [*]_

ESP has no algorithm registry of its own: an SA's algorithms are negotiated by
IKEv2, so both crawlers pull the corresponding IKEv2 *transform ID*
sub-registries, which are published as separate CSV files from the IKEv2
parameters page.

.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7

ESP Encryption Algorithm Transform IDs
======================================

.. module:: pcapkit.vendor.esp.cipher

This module contains the vendor crawler for **Transform Type 1 - Encryption
Algorithm Transform IDs**, which is automatically generating
:class:`pcapkit.const.esp.cipher.Cipher`.

.. autoclass:: pcapkit.vendor.esp.cipher.Cipher
   :members: FLAG, LINK
   :show-inheritance:

ESP Integrity Algorithm Transform IDs
=====================================

.. module:: pcapkit.vendor.esp.integrity

This module contains the vendor crawler for **Transform Type 3 - Integrity
Algorithm Transform IDs**, which is automatically generating
:class:`pcapkit.const.esp.integrity.Integrity`.

.. autoclass:: pcapkit.vendor.esp.integrity.Integrity
   :members: FLAG, LINK
   :show-inheritance:
