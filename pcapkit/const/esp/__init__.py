# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.esp.ESP` Constant Enumerations
=======================================================================

.. module:: pcapkit.const.esp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.esp.ESP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ESP_Cipher <pcapkit.const.esp.cipher.Cipher>`
     - Encryption Algorithm Transform IDs [*]_
   * - :class:`ESP_Integrity <pcapkit.const.esp.integrity.Integrity>`
     - Integrity Algorithm Transform IDs [*]_

ESP has no algorithm registry of its own: an SA's algorithms are negotiated by
IKEv2, so both enumerations are the corresponding IKEv2 *transform ID*
sub-registries. They live here rather than under an ``ikev2`` package because
:class:`~pcapkit.protocols.internet.esp.ESP` is the only thing in
:mod:`pcapkit` that consumes them.

Both enumerate every transform **IANA has registered**, which is a much larger
set than :mod:`pcapkit` can apply. Which of them ESP actually implements is a
separate question, answered by
:data:`~pcapkit.protocols.internet.esp.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.INTEGRITY_SUITES`.

.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
.. [*] https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7

"""

from pcapkit.const.esp.cipher import Cipher as ESP_Cipher
from pcapkit.const.esp.integrity import Integrity as ESP_Integrity

__all__ = ['ESP_Cipher', 'ESP_Integrity']
