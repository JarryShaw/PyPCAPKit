Application Layer Protocols
===========================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` is collection of all protocols in
application layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 5

   ftp
   http
   httpv1
   httpv2

Base Protocol
-------------

:mod:`pcapkit.protocols.application.application` contains only
:class:`~pcapkit.protocols.application.application.Application`,
which is a base class for application layer protocols, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.application.httpv1>`,
:class:`HTTP/2 <pcapkit.protocols.application.application.httpv2>`
and etc.

.. module:: pcapkit.protocols.application.application

.. autoclass:: pcapkit.protocols.application.application.Application
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. autoattribute:: __layer__
