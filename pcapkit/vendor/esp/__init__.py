# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.esp.ESP` Vendor Crawlers
=================================================================

.. module:: pcapkit.vendor.esp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.esp.ESP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ESP_Cipher <pcapkit.vendor.esp.cipher.Cipher>`
     - Encryption Algorithm Transform IDs [*]_
   * - :class:`ESP_Integrity <pcapkit.vendor.esp.integrity.Integrity>`
     - Integrity Algorithm Transform IDs [*]_

ESP has no algorithm registry of its own: an SA's algorithms are negotiated by
IKEv2, so both enumerations are the corresponding IKEv2 *transform ID*
sub-registries. They live here rather than under an ``ikev2`` package because
:class:`~pcapkit.protocols.internet.esp.ESP` is the only thing in
:mod:`pcapkit` that consumes them.

.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7

"""

from pcapkit.vendor.esp.cipher import Cipher as ESP_Cipher
from pcapkit.vendor.esp.integrity import Integrity as ESP_Integrity

__all__ = ['ESP_Cipher', 'ESP_Integrity']
