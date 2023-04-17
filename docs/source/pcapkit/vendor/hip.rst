:class:`~pcapkit.protocols.internet.hip.HIP` Vendor Crawlers
============================================================

.. module:: pcapkit.vendor.hip

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.hip.HIP` implementations. Available
crawlers include:

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

.. automodule:: pcapkit.vendor.hip.certificate
   :no-members:

.. autoclass:: pcapkit.vendor.hip.certificate.Certificate
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.cipher
   :no-members:

.. autoclass:: pcapkit.vendor.hip.cipher.Cipher
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.di
   :no-members:

.. autoclass:: pcapkit.vendor.hip.di.DITypes
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.ecdsa_curve
   :no-members:

.. autoclass:: pcapkit.vendor.hip.ecdsa_curve.ECDSACurve
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.ecdsa_low_curve
   :no-members:

.. autoclass:: pcapkit.vendor.hip.ecdsa_low_curve.ECDSALowCurve
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.esp_transform_suite
   :no-members:

.. autoclass:: pcapkit.vendor.hip.esp_transform_suite.ESPTransformSuite
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.group
   :no-members:

.. autoclass:: pcapkit.vendor.hip.group.Group
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.hi_algorithm
   :no-members:

.. autoclass:: pcapkit.vendor.hip.hi_algorithm.HIAlgorithm
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.hit_suite
   :no-members:

.. autoclass:: pcapkit.vendor.hip.hit_suite.HITSuite
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.nat_traversal
   :no-members:

.. autoclass:: pcapkit.vendor.hip.nat_traversal.NATTraversal
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.notify_message
   :no-members:

.. autoclass:: pcapkit.vendor.hip.notify_message.NotifyMessage
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.packet
   :no-members:

.. autoclass:: pcapkit.vendor.hip.packet.Packet
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.parameter
   :no-members:

.. autoclass:: pcapkit.vendor.hip.parameter.Parameter
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.registration
   :no-members:

.. autoclass:: pcapkit.vendor.hip.registration.Registration
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.registration_failure
   :no-members:

.. autoclass:: pcapkit.vendor.hip.registration_failure.RegistrationFailure
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.suite
   :no-members:

.. autoclass:: pcapkit.vendor.hip.suite.Suite
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.hip.transport
   :no-members:

.. autoclass:: pcapkit.vendor.hip.transport.Transport
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#certificate-types
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-cipher-id
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#hip-parameters-7
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#ecdsa-curve-label
.. [*] https://www.iana.org/assignments/hip-parameters/hip-parameters.xhtml#ecdsa-low-curve-label
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
