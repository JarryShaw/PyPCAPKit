====================================================================
:class:`~pcapkit.protocols.internet.hip.protocol.HIP` Vendor Crawler
====================================================================

.. module:: pcapkit.vendor.hip

.. list-table::

   * - :class:`HIP_Certificate <pcapkit.vendor.hip.certificate.Certificate>`
     - HIP Certificate Types [*]_
   * - :class:`HIP_Cipher <pcapkit.vendor.hip.cipher.Cipher>`
     - HIP Cipher IDs [*]_
   * - :class:`HIP_DITypes <pcapkit.vendor.hip.di.DITypes>`
     - DI-Types [*]_
   * - :class:`HIP_ECDSACurve <pcapkit.vendor.hip.ecdsa_curve.ECDSACurve>`
     - ECDSA Curve Label [*]_
   * - :class:`HIP_ECDSALowCurve <pcapkit.vendor.hip.ecdsa_low_curve.ECDSALowCurve>`
     - ECDSA_LOW Curve Label [*]_
   * - :class:`HIP_EdDSACurve <pcapkit.vendor.hip.eddsa_curve.EdDSACurve>`
     - EdDSA Curve Label [*]_
   * - :class:`HIP_ESPTransformSuite <pcapkit.vendor.hip.esp_transform_suite.ESPTransformSuite>`
     - ESP Transform Suite IDs [*]_
   * - :class:`HIP_Group <pcapkit.vendor.hip.group.Group>`
     - Group IDs [*]_
   * - :class:`HIP_HIAlgorithm <pcapkit.vendor.hip.hi_algorithm.HIAlgorithm>`
     - HI Algorithm [*]_
   * - :class:`HIP_HITSuite <pcapkit.vendor.hip.hit_suite.HITSuite>`
     - HIT Suite IDs [*]_
   * - :class:`HIP_NATTraversal <pcapkit.vendor.hip.nat_traversal.NATTraversal>`
     - HIP NAT Traversal Modes [*]_
   * - :class:`HIP_NotifyMessage <pcapkit.vendor.hip.notify_message.NotifyMessage>`
     - Notify Message Types [*]_
   * - :class:`HIP_Packet <pcapkit.vendor.hip.packet.Packet>`
     - Packet Types [*]_
   * - :class:`HIP_Parameter <pcapkit.vendor.hip.parameter.Parameter>`
     - Parameter Types [*]_
   * - :class:`HIP_Registration <pcapkit.vendor.hip.registration.Registration>`
     - Registration Types [*]_
   * - :class:`HIP_RegistrationFailure <pcapkit.vendor.hip.registration_failure.RegistrationFailure>`
     - Registration Failure Types [*]_
   * - :class:`HIP_Suite <pcapkit.vendor.hip.suite.Suite>`
     - Suite IDs [*]_
   * - :class:`HIP_Transport <pcapkit.vendor.hip.transport.Transport>`
     - HIP Transport Modes [*]_

HIP Certificate Types
=====================

.. module:: pcapkit.vendor.hip.certificate

Generates :class:`pcapkit.const.hip.certificate.Certificate`.

.. autoclass:: pcapkit.vendor.hip.certificate.Certificate
   :members: FLAG, LINK
   :show-inheritance:

Cipher IDs
==========

.. module:: pcapkit.vendor.hip.cipher

Generates :class:`pcapkit.const.hip.cipher.Cipher`.

.. autoclass:: pcapkit.vendor.hip.cipher.Cipher
   :members: FLAG, LINK
   :show-inheritance:

DI-Types
========

.. module:: pcapkit.vendor.hip.di

Generates :class:`pcapkit.const.hip.di.DITypes`.

.. autoclass:: pcapkit.vendor.hip.di.DITypes
   :members: FLAG, LINK
   :show-inheritance:

ECDSA Curve Label
=================

.. module:: pcapkit.vendor.hip.ecdsa_curve

Generates :class:`pcapkit.const.hip.ecdsa_curve.ECDSACurve`.

.. autoclass:: pcapkit.vendor.hip.ecdsa_curve.ECDSACurve
   :members: FLAG, LINK
   :show-inheritance:

ECDSA_LOW Curve Label
=====================

.. module:: pcapkit.vendor.hip.ecdsa_low_curve

Generates :class:`pcapkit.const.hip.ecdsa_low_curve.ECDSALowCurve`.

.. autoclass:: pcapkit.vendor.hip.ecdsa_low_curve.ECDSALowCurve
   :members: FLAG, LINK
   :show-inheritance:

EdDSA Curve Label
=================

.. module:: pcapkit.vendor.hip.eddsa_curve

Generates :class:`pcapkit.const.hip.eddsa_curve.EdDSACurve`.

.. autoclass:: pcapkit.vendor.hip.eddsa_curve.EdDSACurve
   :members: FLAG, LINK
   :show-inheritance:

ESP Transform Suite IDs
=======================

.. module:: pcapkit.vendor.hip.esp_transform_suite

Generates :class:`pcapkit.const.hip.esp_transform_suite.ESPTransformSuite`.

.. autoclass:: pcapkit.vendor.hip.esp_transform_suite.ESPTransformSuite
   :members: FLAG, LINK
   :show-inheritance:

Group IDs
=========

.. module:: pcapkit.vendor.hip.group

Generates :class:`pcapkit.const.hip.group.Group`.

.. autoclass:: pcapkit.vendor.hip.group.Group
   :members: FLAG, LINK
   :show-inheritance:

HI Algorithm
============

.. module:: pcapkit.vendor.hip.hi_algorithm

Generates :class:`pcapkit.const.hip.hi_algorithm.HIAlgorithm`.

.. autoclass:: pcapkit.vendor.hip.hi_algorithm.HIAlgorithm
   :members: FLAG, LINK
   :show-inheritance:

HIT Suite ID
============

.. module:: pcapkit.vendor.hip.hit_suite

Generates :class:`pcapkit.const.hip.hit_suite.HITSuite`.

.. autoclass:: pcapkit.vendor.hip.hit_suite.HITSuite
   :members: FLAG, LINK
   :show-inheritance:

HIP NAT Traversal Modes
=======================

.. module:: pcapkit.vendor.hip.nat_traversal

Generates :class:`pcapkit.const.hip.nat_traversal.NATTraversal`.

.. autoclass:: pcapkit.vendor.hip.nat_traversal.NATTraversal
   :members: FLAG, LINK
   :show-inheritance:

Notify Message Types
==========================

.. module:: pcapkit.vendor.hip.notify_message

Generates :class:`pcapkit.const.hip.notify_message.NotifyMessage`.

.. autoclass:: pcapkit.vendor.hip.notify_message.NotifyMessage
   :members: FLAG, LINK
   :show-inheritance:

HIP Packet Types
================

.. module:: pcapkit.vendor.hip.packet

Generates :class:`pcapkit.const.hip.packet.Packet`.

.. autoclass:: pcapkit.vendor.hip.packet.Packet
   :members: FLAG, LINK
   :show-inheritance:

HIP Parameter Types
===================

.. module:: pcapkit.vendor.hip.parameter

Generates :class:`pcapkit.const.hip.parameter.Parameter`.

.. autoclass:: pcapkit.vendor.hip.parameter.Parameter
   :members: FLAG, LINK
   :show-inheritance:

Registration Failure Types
==========================

.. module:: pcapkit.vendor.hip.registration_failure

Generates :class:`pcapkit.const.hip.registration_failure.RegistrationFailure`.

.. autoclass:: pcapkit.vendor.hip.registration_failure.RegistrationFailure
   :members: FLAG, LINK
   :show-inheritance:

Registration Types
==================

.. module:: pcapkit.vendor.hip.registration

Generates :class:`pcapkit.const.hip.registration.Registration`.

.. autoclass:: pcapkit.vendor.hip.registration.Registration
   :members: FLAG, LINK
   :show-inheritance:

Suite IDs
=========

.. module:: pcapkit.vendor.hip.suite

Generates :class:`pcapkit.const.hip.suite.Suite`.

.. autoclass:: pcapkit.vendor.hip.suite.Suite
   :members: FLAG, LINK
   :show-inheritance:

HIP Transport Modes
===================

.. module:: pcapkit.vendor.hip.transport

Generates :class:`pcapkit.const.hip.transport.Transport`.

.. autoclass:: pcapkit.vendor.hip.transport.Transport
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#certificate-types
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-cipher-id
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-7
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#ecdsa-curve-label
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#ecdsa-low-curve-label
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#eddsa-curve-label
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#esp-transform-suite-ids
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-5
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hi-algorithm
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hit-suite-id
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#nat-traversal
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-9
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-1
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-4
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-11
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-13
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-6
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#transport-modes
