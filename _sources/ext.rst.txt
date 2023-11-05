Customisation & Extensions
==========================

:mod:`pcapkit` is designed with extensive ability in customisation and
extension. It is easy to add new protocols, layers, fields, and even new file
formats. This section will introduce how to customise and extend :mod:`pcapkit`
to meet your own needs.

------------------------
What's in for Protocols?
------------------------

:class:`~pcapkit.protocols.protocol.Protocol` is the most essential concept
and class in :mod:`pcapkit`. Every protocol is represented by a
:class:`~pcapkit.protocols.protocol.Protocol` subclass, which is responsible
for parsing and/or constructing the protocol packets, as in the network stack.

The following table shows all available protocol classes in :mod:`pcapkit`:

+------------------------------------------------------------------+----------------+-----------------------+-------------------------------------------------------------+
| Protocol Type                                                    | Protocol Class                                                                                       |
+==================================================================+================+==============+======================================================================+
|                                                                  |                | :class:`pcapkit.protocols.link.arp.ARP`                                             |
+                                                                  +                +-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.arp.InARP`                                           |
+                                                                  + ARP Family     +-----------------------+-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.link.rarp.RARP`                   |
+                                                                  +                + RARP Family           +-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.link.rarp.DRARP`                  |
+ Link Layer                                                       +----------------+-----------------------+-------------------------------------------------------------+
| (:class:`~pcapkit.protocols.link.link.Link` subclasses)          | :class:`pcapkit.protocols.link.ethernet.Ethernet`                                                    |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.link.l2tp.L2TP`                                                            |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.link.ospf.OSPF`                                                            |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.link.vlan.VLAN`                                                            |
+------------------------------------------------------------------+----------------+-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.ip.IP`                                           |
+                                                                  +                +-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.ipv4.IPv4`                                       |
+                                                                  +                +-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.ipv6.IPv6`                                       |
+                                                                  +                +-----------------------+-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`     |
+                                                                  +                +                       +-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`     |
+                                                                  + IP Family      +                       +-------------------------------------------------------------+
| Internet Layer                                                   |                | IPv6 Extension Header | :class:`pcapkit.protocols.internet.ipv6_route.IPv6_Route`   |
+ (:class:`~pcapkit.protocols.internet.internet.Internet`          +                +                       +-------------------------------------------------------------+
| subclasses)                                                      |                |                       | :class:`pcapkit.protocols.internet.hopopt.HOPOPT`           |
+                                                                  +                +                       +-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.mh.MH`                   |
+                                                                  +                +-----------------------+-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipsec.IPsec`             |
+                                                                  +                + IPsec Family          +-------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ah.AH`                   |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.internet.ipx.IPX`                                                          |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.internet.hip.HIP`                                                          |
+------------------------------------------------------------------+----------------+-----------------------+-------------------------------------------------------------+
| Transport Layer                                                  | :class:`pcapkit.protocols.transport.tcp.TCP`                                                         |
+ (:class:`~pcapkit.protocols.transport.transport.Transport`       +----------------+-----------------------+-------------------------------------------------------------+
| subclasses)                                                      | :class:`pcapkit.protocols.transport.udp.UDP`                                                         |
+------------------------------------------------------------------+----------------+-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.ftp.FTP`                                      |
+                                                                  + FTP Family     +-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.ftp.FTP_DATA`                                 |
+ Application Layer                                                +----------------+-----------------------+-------------------------------------------------------------+
| (:class:`~pcapkit.protocols.application.application.Application` |                | :class:`pcapkit.protocols.application.http.HTTP`                                    |
+ subclasses)                                                      +                +-----------------------+-------------------------------------------------------------+
|                                                                  | HTTP Family    | :class:`pcapkit.protocols.application.httpv1.HTTP`                                  |
+                                                                  +                +-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.httpv2.HTTP`                                  |
+------------------------------------------------------------------+----------------+-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.misc.pcap.header.Header`                                  |
+                                                                  + PCAP Format    +-----------------------+-------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.misc.pcap.frame.Frame`                                    |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
| Miscellaneous Protocols                                          | PCAP-NG Format | :class:`pcapkit.protocols.misc.pcapng.PCAPNG`                                       |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.misc.raw.Raw`                                                              |
+                                                                  +----------------+-----------------------+-------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.misc.null.NoPayload`                                                       |
+------------------------------------------------------------------+----------------+-----------------------+-------------------------------------------------------------+

New Protocol
------------

To add a new protocol, you need to create a new class inherited from
:class:`~pcapkit.protocols.protocol.Protocol`, or its subclasses, specifically,
the :class:`~pcapkit.protocols.link.link.Link`,
:class:`~pcapkit.protocols.internet.internet.Internet`,
:class:`~pcapkit.protocols.transport.transport.Transport`, and
:class:`~pcapkit.protocols.application.application.Application` classes, which
are the base classes for link, internet, transport, and application layer
protocols, respectively.

.. important::

   The :class:`~pcapkit.protocols.protocol.Protocol` class is the base class
   for all protocols, and it is not recommended to inherit from it directly,
   unless you are going to create a new protocol stack, e.g., a new
   miscellaneous protocol stack as in :mod:`pcapkit.protocols.misc` module.

Besides, you need to implement the corresponding schema and data model for the
new protocol. The schema is a :class:`~pcapkit.protocols.schema.schema.Schema`
subclass that defines the field structure of the protocol, and the data model
is a :class:`~pcapkit.protocols.data.data.Data` subclass that defines the data
attributes of the protocol.

.. note::

   The schema classes are used for parsing and/or constructing the protocol
   packets, each field should be defined as a class attribute with the value of
   a :class:`~pcapkit.corekit.fields.field.Field` subclass instance.

   The data classes are used for storing the parsed protocol packets. Each data
   attribute should be defined as a class attribute with no value besides the
   type annotations of the corresponding field.

Once the protocol class is implemented, you need to register it to the protocol
registry, which is managed by the APIs provided by
:mod:`pcapkit.foundation.registry.protocols` module. Depending on the protocol
type, you need to register the protocol class to the corresponding registry, e.g.,
for a link layer protocol, you need to register it to the link layer protocol
registry thru :func:`~pcapkit.foundation.registry.protocols.register_linktype`
function.

The following table shows the type of protocols and the corresponding registry
functions:

+-------------------+-------------------------------------------------------------------+----------------------------------------------------------------+--------------------+
| Protocol Type     | Registry Function                                                                                                                  | Notes              |
+===================+===================================================================+================================================================+====================+
|                   |                                                                   | :func:`~pcapkit.foundation.registry.protocols.register_pcap`   | Registry functions |
+ Link Layer        + :func:`~pcapkit.foundation.registry.protocols.register_linktype`  +----------------------------------------------------------------+ on the left column +
|                   |                                                                   | :func:`~pcapkit.foundation.registry.protocols.register_pcapng` | are combined calls |
+-------------------+-------------------------------------------------------------------+----------------------------------------------------------------+ to those on the    +
| Internet Layer    | :func:`~pcapkit.foundation.registry.protocols.register_ethertype`                                                                  | right columns.     |
+-------------------+-------------------------------------------------------------------+----------------------------------------------------------------+                    +
| Transport Layer   | :func:`~pcapkit.foundation.registry.protocols.register_transtype`                                                                  | It is recommended  |
+-------------------+-------------------------------------------------------------------+----------------------------------------------------------------+ to use those on    +
|                   |                                                                   | :func:`~pcapkit.foundation.registry.protocols.register_tcp`    | the left columns   |
+ Application Layer + :func:`~pcapkit.foundation.registry.protocols.register_apptype`   +----------------------------------------------------------------+ when registering   +
|                   |                                                                   | :func:`~pcapkit.foundation.registry.protocols.register_udp`    | new protocols.     |
+-------------------+-------------------------------------------------------------------+----------------------------------------------------------------+--------------------+

Samples
~~~~~~~

The following code snippet shows how to create a new protocol class:

.. note::

   Following is a PoC implementation of a new internet layer protocol. For
   demonstration purpose, we use the IPv4 protocol as an example, where the
   comprehensive implementation can be found in the
   :mod:`pcapkit.protocols.internet.ipv4` module.

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.protocols.internet.internet import Internet  # import base class

   from pcapkit.protocols.data.data import Data  # import data class
   from pcapkit.protocols.schema.schema import Schema  # import schema class

   from pcapkit.corekit.fields.ipaddress import IPv4AddressField  # import field class

   from pcapkit.const.reg.ethertype import EtherType  # import protocol code registry
   from pcapkit.foundation.registry.protocols import register_ethertype  # import protocol registry API

   if TYPE_CHECKING:
       from ipaddress import IPv4Address
       from typing import Any, Optional


   class IPv4Data(Data):  # define data model

       ...
       src: 'IPv4Address'  # source address
       dst: 'IPv4Address'  # destination address
       ...


   class IPv4Schema(Schema):  # define fields

       ...
       src = IPv4AddressField(...)
       dst = IPv4AddressField(...)
       ...


   class MyIPv4(Internet[IPv4Data, IPv4Schema],
                schema=IPv4Schema, data=IPv4Data):  # define protocol class

       def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'IPv4Data':
           if length is None:
               length = len(self)  # infer length of packet from data
           schema = self.__header__  # get schema

           return IPv4Data(...)

       def make(self, ..., **kwargs: 'Any') -> 'IPv4Schema':
           ...

           return IPv4Schema(...)


   # register protocol class
   register_ethertype(EtherType.Internet_Protocol_version_4, MyIPv4)

Extending Existing Protocol
---------------------------

In many cases, existing protocols have customisable attributes, e.g., the
option headers in the IPv4 protocol. To extend an existing protocol with
additional methods for handling option headers, and etc., you need to first
redirect to the corresponding protocol class, and check if the protocol class
supports the expected extension. If so, you can add the extension methods to
the protocol class, as it may be discussed in the protocol documentation.

.. warning::

   It is not recommended to directly inherit from the protocol class, as it
   may cause unexpected errors. Instead, you should use the provided helper
   functions to extend the protocol class.

   See :mod:`pcapkit.foundation.registry.protocols` module for available
   helper registry functions and the corresponding protocol classes.

The following table shows the protocol classes with their corresponding
available extensible items and the helper registry functions:

+-------------------+------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
| Protocol Type     | Protocol Class                                             | Extensable Registry                                                                           | Registry Function                                                          |
+===================+============================================================+===============================================================================================+============================================================================+
|                   |                                                            | :func:`IPv4._read_opt_${name} <pcapkit.protocols.internet.ipv4.IPv4._read_opt_unassigned>`    |                                                                            |
+                   + :class:`~pcapkit.protocols.internet.ipv4.IPv4`             +-----------------------------------------------------------------------------------------------+ :func:`~pcapkit.foundation.registry.protocols.register_ipv4_option`        +
|                   |                                                            | :func:`IPv4._make_opt_${name} <pcapkit.protocols.internet.ipv4.IPv4._make_opt_unassigned>`    |                                                                            |
+                   +------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :func:`HIP._read_param_${name} <pcapkit.protocols.internet.hip.HIP._read_param_unassigned>`   |                                                                            |
+                   + :class:`~pcapkit.protocols.internet.hip.HIP`               +-----------------------------------------------------------------------------------------------+ :func:`~pcapkit.foundation.registry.protocols.register_hip_parameter`      +
|                   |                                                            | :func:`HIP._make_param_${name} <pcapkit.protocols.internet.hip.HIP._make_param_unassigned>`   |                                                                            |
+                   +------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.hopopt.HOPOPT`         | :attr:`HOPOPT.__option__ <pcapkit.protocols.internet.hopopt.HOPOPT.__option__>`               | :func:`~pcapkit.foundation.registry.protocols.register_hopopt_option`      |
+ Internet Layer    +------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`   | :attr:`IPv6_Opts.__option__ <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__>`      | :func:`~pcapkit.foundation.registry.protocols.register_ipv6_opts_option`   |
+                   +------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route` | :attr:`IPv6_Route.__routing__ <pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__>` | :func:`~pcapkit.foundation.registry.protocols.register_ipv6_route_routing` |
+                   +------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`MH.__message__ <pcapkit.protocols.internet.mh.MH.__message__>`                         | :func:`~pcapkit.foundation.registry.protocols.register_mh_message`         |
+                   +                                                            +-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.mh.MH`                 | :attr:`MH.__option__ <pcapkit.protocols.internet.mh.MH.__option__>`                           | :func:`~pcapkit.foundation.registry.protocols.register_mh_option`          |
+                   +                                                            +-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`MH.__extension__ <pcapkit.protocols.internet.mh.MH.__extension__>`                     | :func:`~pcapkit.foundation.registry.protocols.register_mh_extension`       |
+-------------------+------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`TCP.__option__ <pcapkit.protocols.transport.tcp.TCP.__option__>`                       | :func:`~pcapkit.foundation.registry.protocols.register_tcp_option`         |
+ Transport Layer   + :class:`~pcapkit.protocols.transport.tcp.TCP`              +-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`TCP.__mp_option__ <pcapkit.protocols.transport.tcp.TCP.__mp_option__>`                 | :func:`~pcapkit.foundation.registry.protocols.register_tcp_mp_option`      |
+-------------------+------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
| Application Layer | :class:`~pcapkit.protocols.application.httpv2.HTTP`        | :attr:`HTTP.__frame__ <pcapkit.protocols.application.httpv2.HTTP.__frame__>`                  | :func:`~pcapkit.foundation.registry.protocols.register_http_frame`         |
+-------------------+------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`PCAPNG.__block__ <pcapkit.protocols.misc.pcapng.PCAPNG.__block__>`                     | :func:`~pcapkit.foundation.registry.protocols.register_pcapng_block`       |
+                   +                                                            +-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`PCAPNG.__option__ <pcapkit.protocols.misc.pcapng.PCAPNG.__option__>`                   | :func:`~pcapkit.foundation.registry.protocols.register_pcapng_option`      |
+ Miscellaneous     + :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`             +-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
| Protocols         |                                                            | :attr:`PCAPNG.__record__ <pcapkit.protocols.misc.pcapng.PCAPNG.__record__>`                   | :func:`~pcapkit.foundation.registry.protocols.register_pcapng_record`      |
+                   +                                                            +-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+
|                   |                                                            | :attr:`PCAPNG.__secrets__ <pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__>`                 | :func:`~pcapkit.foundation.registry.protocols.register_pcapng_secrets`     |
+-------------------+------------------------------------------------------------+-----------------------------------------------------------------------------------------------+----------------------------------------------------------------------------+

.. important::

   All extensable items are to be implemented as class methods, whose first argument
   is the protocol class itself, and the rest arguments are the same as the other
   built-in methods' signatures.

--------------------------------------
And Speaking of Library Foundations...
--------------------------------------

The :mod:`pcapkit` library is built on top of the :mod:`pcapkit.foundation`
module, which provides the basic functionalities for the library. The
:mod:`pcapkit.foundation` module is designed to be extensible, and it is
easy to add new features to the library.

Extractor Engines
-----------------

The :mod:`pcapkit.foundation.engines` module provides several built-in engines
for extracting network packets from the intput PCAP and/or PCAP-NG, etc., files.
All engines are implemented as :class:`~pcapkit.foundation.engines.engine.Engine`
subclasses, which are responsible for parsing the input files and extracting
the network packets for further processing.

The following table shows the available engines and the corresponding supported
file formats:

+---------------------+-----------------------------------------------------+-------------------------------------+
| Engine Type         | Engine Class                                        | Supported File Formats              |
+=====================+=====================================================+=====================================+
|                     | :class:`pcapkit.foundation.engines.pcap.PCAP`       | PCAP only                           |
+ Built-in Engines    +-----------------------------------------------------+-------------------------------------+
|                     | :class:`pcapkit.foundation.engines.pcapng.PCAPNG`   | PCAP-NG only                        |
+---------------------+-----------------------------------------------------+-------------------------------------+
|                     | :class:`pcapkit.foundation.engines.scapy.Scapy`     | all formats supported by `Scapy`_   |
+                     +-----------------------------------------------------+-------------------------------------+
| Third-party Engines | :class:`pcapkit.foundation.engines.dpkt.DPKT`       | all formats supported by `DPKT`_    |
|                     +-----------------------------------------------------+-------------------------------------+
|                     | :class:`pcapkit.foundation.engines.pyshark.PyShark` | all formats supported by `PyShark`_ |
+---------------------+-----------------------------------------------------+-------------------------------------+

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark

Samples
~~~~~~~

The following code snippet shows how to create a new engine class:

.. note::

   Following is a PoC implementation of a new engine based on :mod:`scapy`. For documentation
   purposes, we use the :class:`~pcapkit.foundation.engines.scapy.Scapy` engine as an example,
   where the comprehensive implementation can be found in the :mod:`pcapkit.foundation.engines.scapy`
   module.

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.foundation.engines.engine import Engine  # import base class

   if TYPE_CHECKING:
       from pcapkit.foundation.extraction import Extractor

       from scapy.packet import Packet


   class MyScapy(Engine['Packet']):

       __engine_name__ = 'Scapy'  # friendly name of the engine
       __engine_module__ = 'scapy'  # module name that the engine is based on

       def __init__(self, extractor: 'Extractor') -> 'None':
           # NOTE: the API entry point of the underlying engine module should
           # be imported here, instead of at the top of the module, to avoid
           # dependency issues.
           from scapy import sendrecv  # import API entry point

           self._expkg = sendrecv  # store API entry point
           self._extmp = None  # intermediate storage for the interator
                               # generated by the API entry point

           super().__init__(extractor)  # initialise base class

       # NOTE: The following methods are the core methods of the engine class,
       # which are responsible for parsing the input file and extracting the
       # network packets for further processing. It is expected to create an
       # iterator instance that yields the network packets, and store it in
       # the intermediate storage, i.e., self._extmp for further processing,
       # using the API entry point as in the self._expkg attribute.
       def run(self) -> 'None':
           ext = self._extractor  # get extractor instance

           # NOTE: You may wish to do some pre-processing here, e.g., to
           # check if there's any extraction protocol and/or layer thresholds
           # set by the user (some engines may not support this feature); or
           # to set up the verbose handler for the underlying engine module,
           # as in the following code snippet.

           if ext._flag_v:  # check if verbose mode is enabled
               # NOTE: PyPCAPKit has its own bundled supporting functions for
               # third-party libraries, e.g., the `packet2chain` function is
               # to convert a given Packet instance of the Scapy library to a
               # human-readable string, which is used for verbose output.
               from pcapkit.toolkit.scapy import pack2chain  # import utility function

               ext._vfunc = lambda extractor, packet: print(
                   f'Frame {extractor._frnum:>3d}: {pack2chain(packet)}'
               )  # print verbose message as `Frame XXX: Ethernet:IP:TCP:...`

           # NOTE: Here we use the API entry point, i.e., scapy.sendrecv.sniff,
           # to read the input file and extract the network packets. The API
           # entry point returns an iterable instance, which is then converted
           # as an iterator and stored in the intermediate storage for further
           # processing.
           self._extmp = iter(self._expkg.sniff(offline=ext._ifnm))

       # NOTE: The following methods are the helper methods of the engine class,
       # which are responsible for extracting the network packets from the
       # intermediate storage, i.e., self._extmp, and returning the extracted
       # network packets for further processing. It is also expected to handle
       # necessary actions, including but not limited to, verbose output, file
       # output, reassembly and flow tracing, etc.
       def read_frame(self) -> 'Packet':
           from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                              tcp_reassembly, tcp_traceflow)  # import utility functions
           ext = self._extractor  # get extractor instance

           packet = next(self._extmp)  # get next packet from the iterator

           ext._frnum += 1  # increment frame number
           ext._vfunc(ext, packet)  # print verbose message

           # NOTE: The following code snippet is to handle the file output,
           # i.e., to write the packet to the output file if the output file
           # is specified by the user.
           frnum = f'Frame {ext._frnum}'
           if not ext._flag_q:
               info = packet2dict(packet)  # convert packet to dict-like object

               # NOTE: Now, we need to check if output file is to be a single
               # file. If so, we can directly write the packet to the output
               # file, i.e., ext._ofile; otherwise, we need to create a new
               # dumper instance by initialising ext._ofile, and write the
               # packet to the dumper instance. For more information, please
               # refer to the documentation of DictDumper library.
               if ext._flag_f:
                   ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                   ofile(info, name=frnum)
               else:
                   ext._ofile(info, name=frnum)

           # NOTE: The following code snippet is to handle the reassembly of
           # the network packets, i.e., to reassemble the fragmented packets
           # into a complete packet. Before reassembly, we need to convert
           # the packet to a tailored format, i.e., a dict-like object, which
           # is then passed to the reassembly function. For more information,
           # please refer to the documentation of pcapkit.foundation.reassembly
           # module.
           if ext._flag_r:
               if ext._ipv4:
                   data_ipv4 = ipv4_reassembly(packet, count=ext._frnum)
                   if data_ipv4 is not None:
                       ext._reasm.ipv4(data_ipv4)
               if ext._ipv6:
                   data_ipv6 = ipv6_reassembly(packet, count=ext._frnum)
                   if data_ipv6 is not None:
                       ext._reasm.ipv6(data_ipv6)
               if ext._tcp:
                   data_tcp = tcp_reassembly(packet, count=ext._frnum)
                   if data_tcp is not None:
                       ext._reasm.tcp(data_tcp)

           # NOTE: The following code snippet is to handle the flow tracing of
           # the network packets, i.e., to trace a series of packets as they
           # will compose as a flow and/or stream. Before reassembly, we need
           # to convert the packet to a tailored format, i.e., a dict-like object,
           # which is then passed to the flow tracing function. For more
           # information, please refer to the documentation of
           # pcapkit.foundation.traceflow module.
           if ext._flag_t:
               if ext._tcp:
                   data_tf_tcp = tcp_traceflow(packet, count=ext._frnum)
                   if data_tf_tcp is not None:
                       ext._trace.tcp(data_tf_tcp)

           # NOTE: The following code snippet is to record extracted frames
           # into the internal storage, i.e., ext._frame, for further processing.
           if ext._flag_d:
               ext._frame.append(packet)

           return packet  # return the extracted packet

Output Dumpers
--------------

The :mod:`pcapkit.dumpkit` module wraps the :mod:`DictDumper <dictdumper>`
library, which provides the basic functionalities for dumping the extracted
network packets to the output file. The :mod:`pcapkit.dumpkit` module is
designed to be extensible, and it is easy to add new output formats to the
library, based on the extensibility of the :mod:`DictDumper <dictdumper>`
library.

.. seealso::

   Please refer to the documentation of :mod:`DictDumper <dictdumper>` library
   for more information about the output dumpers.

The following table shows the available output dumpers and the corresponding
formats:

+----------------------------------+------------------------------------------------+------------------+
| Dumper Format                    | Dumper Class                                   | Output Extension |
+==================================+================================================+==================+
| *No Output*                      | :class:`pcapkit.dumpkit.null.NotImplementedIO` | N/A              |
+----------------------------------+------------------------------------------------+------------------+
| PCAP (``cap``/``pcap``)          | :class:`pcapkit.dumpkit.pcap.PCAPIO`           | ``.pcap``        |
+----------------------------------+------------------------------------------------+------------------+
| XML (``xml``/``plist``)          | :class:`dictdumper.plist.PLIST`                | ``.plist``       |
+----------------------------------+------------------------------------------------+------------------+
| JSON (``json``)                  | :class:`dictdumper.json.JSON`                  | ``.json``        |
+----------------------------------+------------------------------------------------+------------------+
| Text (``txt``/``text``/``tree``) | :class:`dictdumper.tree.Tree`                  | ``.txt``         |
+----------------------------------+------------------------------------------------+------------------+

Samples
~~~~~~~

The following code snippet shows how to create a new dumper class:

.. note::

   Following is a PoC implementation of a new dumper for the PCAP format. For
   documentation purposes, we use the :class:`~pcapkit.dumpkit.pcap.PCAPIO`
   dumper as an example, where the comprehensive implementation can be found
   in the :mod:`pcapkit.dumpkit.pcap` module.

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.dumpkit.common import Dumper  # import base class

   from pcapkit.protocols.misc.pcap.header import Header  # import PCAP header class
   from pcapkit.protocols.misc.pcap.frame import Frame  # import PCAP frame class

   if TYPE_CHECKING:
       from typing import Optional


   # NOTE: We need to specify the output file format and extension here at the
   # class definition, as in the following code snippet. Such that PyPCAPKit
   # will be able to automatically register our dumper class to the corresponding
   # dumper registries, and use it to dump the extracted network packets.
   class MyDumper(Dumper, fmt='pcap', ext='.pcap'):

       # NOTE: This property is to define the file format of the dumper.
       # It is expected to be a string, which is used as the file extension
       # of the output file.
       @property
       def kind(self) -> 'str':
           return 'pcap'

       # NOTE: We need to collect some necessary information here thru the necessary
       # arguments, e.g., the file name, link-layer protocol, etc., which will be
       # used to generate the top-level header of the output file.
       def __init__(self, fname: 'str', *, ...) -> 'None':
           # NOTE: We can do some pre-processing here if necessary, e.g., to
           # save the nanosecond-resolution flag, link-layer protocol type, etc.,
           # such that we can use them later when dumping the network packets.
           self._fnum = 1  # initialise frame number counter to 1

           super().__init__(fname, ...)  # initialise base class with the file name
                                         # and other necessary arguments

       # NOTE: We need to overwrite the original ``__call__`` method, cause the
       # PCAP file format is a binary format, thus we need to re-open the output
       # file in binary mode, instead of the default text mode.
       def __call__(self, value: 'Frame', name: 'Optional[str]' = None) -> 'MyDumper':
           with open(self._file, 'ab') as file:
               self._append_value(value, file, name or f'Frame {self._fnum}')  # append value to the file
            return self

       # NOTE: The following method will be called at the initialisation of the
       # dumper class, which is expected to write the top-level header of the
       # output file.
       def _dump_header(self, *, ...) -> 'None':
           packet = Header(...)  # create PCAP header instance based on the given arguments

           with open(self._file, 'wb') as file:
               file.write(packet.data)  # write the header to the output file

       # NOTE: The following method is to write the network packets to the output
       # file. It is expected to convert the network packet to a tailored format,
       # i.e., a Frame instance, which is then converted to the binary format and
       # written to the output file.
       def _append_value(self, value: 'Frame', file: 'IO[bytes]', name: 'str') -> 'None':
           packet = Frame(...)  # create PCAP frame instance based on the given arguments

           file.write(packet.data)  # write the frame to the output file

           # NOTE: We can do some post-processing here if necessary, e.g., to
           # update the frame number counter, etc., such that we can use them
           # later when dumping other network packets.
           self._fnum += 1  # increment frame number counter

Reassembly and Flow Tracing
---------------------------

The :mod:`pcapkit.foundation.reassembly` module provides several built-in
reassembly classes for reassembling the fragmented network packets; and the
:mod:`pcapkit.foundation.traceflow` module provides several built-in flow
tracing classes for tracing the network packets as they will compose as a
flow and/or stream. All reassembly and flow tracing classes are implemented
as :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` and
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` subclasses,
respectively, which are responsible for reassembling and tracing the network
packets for further processing.

The following table shows the available reassembly and flow tracing classes
per the supported protocols:

+------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| Protocol                                       | Reassembly Class                                 | Flow Tracing Class                            |
+================================================+==================================================+===============================================+
| :class:`~pcapkit.protocols.internet.ipv4.IPv4` | :class:`pcapkit.foundation.reassembly.ipv4.IPv4` |                                               |
+------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| :class:`~pcapkit.protocols.internet.ipv6.IPv6` | :class:`pcapkit.foundation.reassembly.ipv6.IPv6` |                                               |
+------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| :class:`~pcapkit.protocols.transport.tcp.TCP`  | :class:`pcapkit.foundation.reassembly.tcp.TCP`   | :class:`pcapkit.foundation.traceflow.tcp.TCP` |
+------------------------------------------------+--------------------------------------------------+-----------------------------------------------+

.. seealso::

   Please refer to the documentation of :mod:`pcapkit.foundation.reassembly` and
   :mod:`pcapkit.foundation.traceflow` modules for more information about the
   reassembly and flow tracing classes, as well as the underlying algorithms.

New Implementation
~~~~~~~~~~~~~~~~~~

To add a new reassembly or flow tracing class, you need to create a new class
inherited from :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`
or :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` class, which
is responsible for reassembling or tracing the network packets for further
processing.

The following code snippet shows how to create a new reassembly class:

.. note::

   Following is a PoC implementation of a new reassembly class for the IPv4
   protocol. For documentation purposes, we use the
   :class:`~pcapkit.foundation.reassembly.ipv4.IPv4` reassembly class as an
   example, where the comprehensive implementation can be found in the
   :mod:`pcapkit.foundation.reassembly.ipv4` module.

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.corekit.infoclass import Info, info_final  # import Info class for data model definitions
   from pcapkit.protocols.internet.ipv4 import IPv4  # import protocol class for attribute definitions

   from pcapkit.foundation.reassembly.reassembly import Reassembly  # import base class

   if TYPE_CHECKING:
       from typing import TypeAlias

   # NOTE: We need to specify some useful data structure before creating the
   # reassembly class, e.g., the data model for the reassembled packet, the
   # data model for the reassembly table, etc., which will be used to store
   # the reassembled packet and the reassembly table, respectively.

   BufferID: 'TypeAlias' = ...  # a tuple-like object to identify the reassembly
                                # table entry's ID, e.g., (src, dst, id, proto)
                                # for IPv4, (src, dst, spi) for IPv6, etc.


   @info_final
   class Packet(Info):

       # NOTE: This is the data model for the extracted packet, which is
       # expected to be a dict-like object, and will be used to store the
       # information from the extracted packets to be reassembled.
       ...


   @info_final
   class DatagramID(Info):

       # NOTE: This is the data model for the reassembled datagram's ID,
       # which is expected to be a dict-like object, and will be used to
       # store the information to identify the reassembled datagram.
       ...


   @info_final
   class Datagram(Info):

       # NOTE: This is the data model for the reassembled datagram, which
       # is expected to be a dict-like object, and will be used to store
       # the information of the reassembled datagram.
       ...


   @info_final
   class Buffer(Info):

       # NOTE: This is the data model for the reassembly table, which is
       # expected to be a dict-like object, and will be used to store the
       # information of each buffered entry in the reassembly table, that
       # is to be reassembled with the following fragmented packets.
       ...


   # NOTE: Now we can create the reassembly class, which is expected to be
   # a subclass of the base class, i.e., Reassembly, and implement the core
   # methods, i.e., reassembly and submit, for reassembling the fragmented
   # packets and submitting the reassembled datagram, respectively.
   class MyReassembly(Reassembly[Packet, Datagram, BufferID, Buffer]):

       __protocol_name__ = 'IPv4'  # name of the protocol
       __protocol_type__ = IPv4  # type of the protocol

       # NOTE: This method is to reassemble the fragmented packets, i.e.,
       # ``info`` formatted as a ``Packet`` instance, into the reassembly
       # table, i.e., ``self._buffer`` formatted as a dict of ``BufferID``
       # mapped to ``Buffer`` instances.
       def reassembly(self, info: 'Packet') -> 'None':
           ...  # reassembly algorithm implementation

           # NOTE: Once the fragmented packets are reassembled, we need to
           # submit the reassembled datagram, i.e., ``Datagram`` instance,
           # to the storage, i.e., ``self._dtgram``, for further processing.
           self._dtgram.extend(
               self.submit(...)  # submit reassembled datagram
           )

       # NOTE: This method is to convert the reassembled datagram, i.e.,
       # ``buf`` formatted as a ``Buffer`` instance, to a ``Datagram``
       # instance, which is then submitted to the storage, i.e.,
       # ``self._dtgram``.
       def submit(self, buf: 'Buffer', * , bufid: 'BufferID') -> 'list[Datagram]':
           datagram = ...  # submit algorithm implementation, e.g., to convert
                           # the reassembled datagram to a list of ``Datagram``
                           # instances, which is then returned for further
                           # processing by the caller

           # NOTE: Before we submit the reassembled datagram, we need to
           # run the registered callback functions, if any, to process the
           # reassembled datagram, e.g., to check if the reassembled datagram
           # is to be discarded, etc.
           for callback in self.__callback_fn__:
               callback(datagram)  # run callback functions
           return datagram

Callback Functions
~~~~~~~~~~~~~~~~~~

It is possible to register callback functions to the reassembly and flow
tracing classes, which will be called at the end of the reassembly and
flow tracing process, respectively. This feature is designed to create
the ability to process the reassembled datagrams and/or flows, e.g., to
check if the datagram and/or flows are to be discarded, etc.

.. seealso::

   For more information, you may refer to the documentation of
   :mod:`pcapkit.foundation.registry.foundation` for the callback
   registry functions:

   - :func:`~pcapkit.foundation.registry.foundation.register_reassembly_ipv4_callback`
   - :func:`~pcapkit.foundation.registry.foundation.register_reassembly_ipv6_callback`
   - :func:`~pcapkit.foundation.registry.foundation.register_reassembly_tcp_callback`
   - :func:`~pcapkit.foundation.registry.foundation.register_traceflow_tcp_callback`

All callback functions are expected to be a callback function, which
accepts a single argument, i.e., the list of reassembled datagrams
and/or flows, and returns :obj:`None`. Any return value will be ignored.

It is possible to modify the reassembled datagrams and/or flows in the
callback functions, e.e., to discard certain reassembled datagrams and/or
flows, etc. However, it is not recommended to modify the reassembled
datagrams and/or flows directly. Should that is the intended behaviour,
you should create a new reassembly and/or flow tracing class, and modify
the corresponding reassembly and/or flow tracing algorithm.
