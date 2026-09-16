# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.esp.ESP` Vendor Crawlers
=================================================================

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

"""

from pcapkit.vendor.esp.cipher import Cipher as ESP_Cipher
from pcapkit.vendor.esp.integrity import Integrity as ESP_Integrity

__all__ = ['ESP_Cipher', 'ESP_Integrity']
