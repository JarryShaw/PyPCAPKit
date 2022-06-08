How to ...
==========

Usage Samples
-------------

As described above, :mo:d`pcapkit` is quite easy to use, with simply three
verbs as its main interface. Several scenarios are shown as below.

1. extract a PCAP file and dump the result to a specific file
   (with no reassembly)

   .. code-block:: python

      import pcapkit
      # dump to a PLIST file with no frame storage (property frame disabled)
      plist = pcapkit.extract(fin='in.pcap', fout='out.plist', format='plist', store=False)
      # dump to a JSON file with no extension auto-complete
      json = pcapkit.extract(fin='in.cap', fout='out.json', format='json', extension=False)
      # dump to a folder with each tree-view text file per frame
      tree = pcapkit.extract(fin='in.pcap', fout='out', format='tree', files=True)

2. extract a PCAP file and fetch IP packet (both IPv4 and IPv6) from a frame
   (with no output file)

   .. code-block:: python

      >>> import pcapkit
      >>> extraction = pcapkit.extract(fin='in.pcap', nofile=True)
      >>> frame0 = extraction.frame[0]
      # check if IP in this frame, otherwise ProtocolNotFound will be raised
      >>> flag = pcapkit.IP in frame0
      >>> tcp = frame0[pcapkit.IP] if flag else None

3. extract a PCAP file and reassemble TCP payload
   (with no output file nor frame storage)

   .. code-block:: python

      import pcapkit
      # set strict to make sure full reassembly
      extraction = pcapkit.extract(fin='in.pcap', store=False, nofile=True, tcp=True, strict=True)
      # print extracted packet if HTTP in reassembled payloads
      for packet in extraction.reassembly.tcp:
          for reassembly in packet.packets:
              if pcapkit.HTTP in reassembly.protochain:
                  print(reassembly.info)

CLI Samples
-----------

The CLI (command line interface) of :mod:`pcapkit` has two different access.

* through console scripts

  Use command name ``pcapkit [...]`` directly (as shown in samples).

* through Python module

  ``python -m pypcapkit [...]`` works exactly the same as above.

Here are some usage samples:

1. export to a macOS Property List
   (`Xcode`_ has special support for this format)

   .. code-block:: shell

      $ pcapkit in --format plist --verbose
      🚨Loading file 'in.pcap'
       - Frame   1: Ethernet:IPv6:ICMPv6
       - Frame   2: Ethernet:IPv6:ICMPv6
       - Frame   3: Ethernet:IPv4:TCP
       - Frame   4: Ethernet:IPv4:TCP
       - Frame   5: Ethernet:IPv4:TCP
       - Frame   6: Ethernet:IPv4:UDP
      🍺Report file stored in 'out.plist'

2. export to a JSON file (with no format specified)

   .. code-block:: shell

      $ pcapkit in --output out.json --verbose
      🚨Loading file 'in.pcap'
       - Frame   1: Ethernet:IPv6:ICMPv6
       - Frame   2: Ethernet:IPv6:ICMPv6
       - Frame   3: Ethernet:IPv4:TCP
       - Frame   4: Ethernet:IPv4:TCP
       - Frame   5: Ethernet:IPv4:TCP
       - Frame   6: Ethernet:IPv4:UDP
      🍺Report file stored in 'out.json'

3. export to a text tree view file (without extension autocorrect)

   .. code-block:: shell

      $ pcapkit in --output out --format tree --verbose
      🚨Loading file 'in.pcap'
       - Frame   1: Ethernet:IPv6:ICMPv6
       - Frame   2: Ethernet:IPv6:ICMPv6
       - Frame   3: Ethernet:IPv4:TCP
       - Frame   4: Ethernet:IPv4:TCP
       - Frame   5: Ethernet:IPv4:TCP
       - Frame   6: Ethernet:IPv4:UDP
      🍺Report file stored in 'out'

.. _Xcode: https://developer.apple.com/xcode
