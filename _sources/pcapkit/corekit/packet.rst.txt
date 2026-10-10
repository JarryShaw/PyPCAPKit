Deferred Packet
===============

.. module:: pcapkit.corekit.packet

:mod:`pcapkit.corekit.packet` contains
:class:`~pcapkit.corekit.packet.DeferredPacket`, the mixin that lets an
:class:`~pcapkit.corekit.infoclass.Info` subclass hold its ``packet`` field as
a placeholder and resolve it on first read. It is shared by the reassembled
datagrams of :mod:`pcapkit.foundation.reassembly` and the traced flows of
:mod:`pcapkit.foundation.traceflow`, whose ``packet`` is a second parse of the
payload and a reassembly of the stream respectively.

A subclass is declared ``class X(DeferredPacket, Info)``, lists ``packet`` in
its ``__additional__``, and names its placeholder class in
:attr:`~pcapkit.corekit.packet.DeferredPacket.__deferred__`;
:meth:`~pcapkit.corekit.packet.DeferredPacket.__init_subclass__` refuses one
that does not. Listing ``packet`` in ``__additional__`` is what makes the field
lazy: :class:`~pcapkit.corekit.infoclass.Info` then stores it under a mangled
key, so reading it reaches ``__getattr__``, while ``dict(x)``,
:meth:`~pcapkit.corekit.packet.DeferredPacket.to_dict` and iteration still
report it as ``packet``.

Resolution happens **at most once**: the placeholder is called with no
arguments, and its result replaces it, so every later read returns that same
object.

.. autoclass:: pcapkit.corekit.packet.DeferredPacket
   :no-members:
   :show-inheritance:

   .. attribute:: __deferred__

      Placeholder class the ``packet`` field may hold, set by each subclass. A
      value of this class is resolved by calling it with no arguments; an
      instance of any other class, :data:`None` included, is not.

   .. automethod:: __init_subclass__
   .. automethod:: __analyse__
   .. automethod:: to_dict
