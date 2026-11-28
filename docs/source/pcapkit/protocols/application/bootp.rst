BOOTP - Bootstrap Protocol
================================

.. module:: pcapkit.protocols.application.bootp
.. module:: pcapkit.protocols.application.bootp.protocol

:mod:`pcapkit.protocols.application.bootp.protocol` holds
:class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`, the extractor for
Bootstrap Protocol (BOOTP) messages [:rfc:`951`, :rfc:`1542`], laid out as
:mod:`~pcapkit.protocols.application.dhcp.protocol` gives. Its last field,
``vend``, holds the vendor extensions of :rfc:`1497` and :rfc:`2132` sections 3
to 8 where the magic cookie opens it, and is vendor-specific octets otherwise.

.. versionadded:: 1.10.0

.. autoclass:: pcapkit.protocols.application.bootp.protocol.BOOTP
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. rubric:: Utilities

   .. automethod:: _make_data

Data Models
-----------

.. module:: pcapkit.protocols.application.bootp.data

.. autoclass:: pcapkit.protocols.application.bootp.data.BOOTP
   :members:
   :show-inheritance:

Constants
---------

.. module:: pcapkit.protocols.application.bootp.const

.. autodata:: pcapkit.protocols.application.bootp.const.VENDOR_EXTENSIONS
