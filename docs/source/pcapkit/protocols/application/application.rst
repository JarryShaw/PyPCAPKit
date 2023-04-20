Base Protocol
=============

.. module:: pcapkit.protocols.application.application

:mod:`pcapkit.protocols.application.application` contains only
:class:`~pcapkit.protocols.application.application.Application`,
which is a base class for application layer protocols, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.application.httpv1>`,
:class:`HTTP/2 <pcapkit.protocols.application.application.httpv2>`
and etc.

.. autoclass:: pcapkit.protocols.application.application.Application
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: layer

   .. automethod:: _decode_next_layer
   .. automethod:: _import_next_layer

   .. autoattribute:: __layer__

   .. automethod:: __post_init__
   .. automethod:: __index__
