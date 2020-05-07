Internet Layer Protocols
========================

.. module:: pcapkit.protocols.internet

:mod:`pcapkit.protocols.internet` is collection of all protocols in
internet layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 4

   ah
   hip
   hopopt

Base Protocol
-------------

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, eg. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, :class:`~pcapkit.protocols.internet.ipx.IPX`, and etc.

.. module:: pcapkit.protocols.internet.internet

.. autoclass:: pcapkit.protocols.internet.internet.Internet
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. autoattribute:: __layer__

   .. attribute:: __proto__
      :type: DefaultDict[int, Tuple[str, str]]

      Protocol index mapping for decoding next layer,
      c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
      & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
      The values should be a tuple representing the module name and class name.

      .. list-table::
         :header-rows: 1

         * - Code
           - Module
           - Class
         * - 0
           - :mod:`pcapkit.protocols.internet.hopopt`
           - :class:`~pcapkit.protocols.internet.hopopt.HOPOPT`
         * - 4
           - :mod:`pcapkit.protocols.internet.ipv4`
           - :class:`~pcapkit.protocols.internet.ipv4.IPv4`
         * - 6
           - :mod:`pcapkit.protocols.transport.tcp`
           - :class:`~pcapkit.protocols.transport.tcp.TCP`
         * - 17
           - :mod:`pcapkit.protocols.transport.udp`
           - :class:`~pcapkit.protocols.transport.udp.UDP`
         * - 41
           - :mod:`pcapkit.protocols.internet.ipv6`
           - :class:`~pcapkit.protocols.internet.ipv6.IPv6`
         * - 43
           - :mod:`pcapkit.protocols.internet.ipv6_route`
           - :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`
         * - 44
           - :mod:`pcapkit.protocols.internet.ipv6_frag`
           - :class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`
         * - 51
           - :mod:`pcapkit.protocols.internet.ah`
           - :class:`~pcapkit.protocols.internet.ah.AH`
         * - 60
           - :mod:`pcapkit.protocols.internet.ipv6_opts`
           - :class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`
         * - 135
           - :mod:`pcapkit.protocols.internet.mh`
           - :class:`~pcapkit.protocols.internet.mh.MH`
         * - 139
           - :mod:`pcapkit.protocols.internet.hip`
           - :class:`~pcapkit.protocols.internet.hip.HIP`
