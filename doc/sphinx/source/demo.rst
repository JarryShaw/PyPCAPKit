How to ...
==========

Basic Samples
-------------

:mod:`pcapkit` is quite easy to use, with simply three verbs as
its main interface. Several scenarios are shown as below.

1. extract a PCAP file and dump the result to a specific file
   (with no reassembly)

   .. code-block:: python

      from pcapkit import extract
      # dump to a PLIST file with no frame storage (property frame disabled)
      plist = extract(fin='in.pcap', fout='out.plist', format='plist', store=False)
      # dump to a JSON file with no extension auto-complete
      json = extract(fin='in.cap', fout='out.json', format='json', extension=False)
      # dump to a folder with each tree-view text file per frame
      tree = extract(fin='in.pcap', fout='out', format='tree', files=True)

2. extract a PCAP file and fetch IP packet (both IPv4 and IPv6) from a frame
   (with no output file)

   .. code-block:: python

      from pcapkit import IP, extract
      extraction = extract(fin='in.pcap', nofile=True)
      frame0 = extraction.frame[0]
      # check if IP (IPv4 or IPv6) in this frame
      flag = IP in frame0
      if IP in frame0:
         # fetch the IP packet from this frame
         ip = frame0[IP]

3. extract a PCAP file and reassemble TCP payload
   (with no output file nor frame storage)

   .. code-block:: python

      from pcapkit import HTTP, extract
      # set strict to make sure full reassembly
      extraction = extract(fin='in.pcap', store=False, nofile=True, tcp=True, strict=True)
      # print extracted packet if HTTP in reassembled payloads
      for datagram in extraction.reassembly.tcp:
          if datagram.packet is not None and HTTP in datagram.packet:
              print(datagram.packet[HTTP])

CLI Samples
-----------

The CLI (command line interface) of :mod:`pcapkit` has two different access.

* through console scripts

  Use command name ``pcapkit-cli [...]`` directly (as shown in samples).

* through Python module

  ``python -m pypcapkit [...]`` works exactly the same as above.

Here are some usage samples:

1. export to a macOS Property List
   (`Xcode`_ has special support for this format)

   .. code-block:: shell

      $ pcapkit-cli in --format plist --verbose
      🚨Loading file 'in.pcap'
      Frame   1: Ethernet:IPv6:IPv6_ICMP
      Frame   2: Ethernet:IPv6:IPv6_ICMP
      Frame   3: Ethernet:IPv4:TCP
      Frame   4: Ethernet:IPv4:TCP
      Frame   5: Ethernet:IPv4:TCP
      Frame   6: Ethernet:IPv4:UDP:Raw
      🍺Report file stored in 'out.plist'

2. export to a JSON file (with no format specified)

   .. code-block:: shell

      $ pcapkit-cli in --output out.json --verbose
      🚨Loading file 'in.pcap'
      Frame   1: Ethernet:IPv6:IPv6_ICMP
      Frame   2: Ethernet:IPv6:IPv6_ICMP
      Frame   3: Ethernet:IPv4:TCP
      Frame   4: Ethernet:IPv4:TCP
      Frame   5: Ethernet:IPv4:TCP
      Frame   6: Ethernet:IPv4:UDP:Raw
      🍺Report file stored in 'out.json'

3. export to a text tree view file (without extension autocorrect)

   .. code-block:: shell

      $ pcapkit-cli in --output out.txt --format tree --verbose
      🚨Loading file 'in.pcap'
      Frame   1: Ethernet:IPv6:IPv6_ICMP
      Frame   2: Ethernet:IPv6:IPv6_ICMP
      Frame   3: Ethernet:IPv4:TCP
      Frame   4: Ethernet:IPv4:TCP
      Frame   5: Ethernet:IPv4:TCP
      Frame   6: Ethernet:IPv4:UDP:Raw
      🍺Report file stored in 'out.txt'

.. _Xcode: https://developer.apple.com/xcode
