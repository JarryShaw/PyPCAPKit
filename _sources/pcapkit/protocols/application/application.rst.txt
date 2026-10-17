Application Layer Base Protocol
===============================

.. module:: pcapkit.protocols.application.application

:mod:`pcapkit.protocols.application.application` contains only
:class:`~pcapkit.protocols.application.application.Application`,
which is a base class for application layer protocols, e.g.
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.HTTP>` and
:class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTP>`.

.. versionchanged:: 1.5.0

   :meth:`~pcapkit.protocols.application.application.Application._decode_next_layer`
   and
   :meth:`~pcapkit.protocols.application.application.Application._import_next_layer`
   accept the ``-1`` sentinel, so an application layer protocol can carry the
   rest of its packet undissected as its payload; every call raised
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` (:issue:`719`).

.. autoclass:: pcapkit.protocols.application.application.Application
   :no-members:
   :show-inheritance:

   .. autoproperty:: layer

   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer

   .. autoattribute:: __layer__
      :no-value:

   .. automethod:: __post_init__
   .. automethod:: __index__
