Raw Packet Data
===============

.. module:: pcapkit.protocols.misc.raw
.. module:: pcapkit.protocols.misc.raw.protocol

:mod:`pcapkit.protocols.misc.raw.protocol` contains
:class:`~pcapkit.protocols.misc.raw.protocol.Raw` only, which implements
an extractor for unknown protocols, and constructs a
:class:`~pcapkit.protocols.protocol.Protocol` like object.

.. autoclass:: pcapkit.protocols.misc.raw.protocol.Raw
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make

   .. rubric:: Data Models

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.misc.raw.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.misc.raw``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.misc.raw.schema.Raw
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.misc.raw.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.misc.raw``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.misc.raw.data.Raw
   :members:
   :show-inheritance:
