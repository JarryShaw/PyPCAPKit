HTTP/2 - Hypertext Transfer Protocol
====================================

.. module:: pcapkit.protocols.application.httpv2

:mod:`pcapkit.protocols.application.httpv2` contains
:class:`~pcapkit.protocols.application.httpv2.HTTPv2`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/2) [*]_, whose structure is described as
below:

======= ========= ===================== ==========================
Octets      Bits        Name                    Description
======= ========= ===================== ==========================
  0           0     http.length             Length
  3          24     http.type               Type
  4          32     http.flags              Flags
  5          40     -                       Reserved
  5          41     http.sid                Stream Identifier
  9          72     http.payload            Frame Payload
======= ========= ===================== ==========================

.. raw:: html

   <br />

.. .. autoclass:: pcapkit.protocols.application.httpv2.HTTPv2
..    :members:
..    :undoc-members:
..    :private-members:
..    :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/HTTP/2
