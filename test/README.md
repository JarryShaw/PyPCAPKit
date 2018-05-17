# Test Samples

&emsp; Here we provide several test samples. Though the original PCAP files are not uploaded due to restrictions on file size of GitHub, you may still easiliy get a simple but thorough view of `jspcap`, either on how to use it or on what it can do.

 - [`test_extraction.py`](https://github.com/JarryShaw/jspcap/tree/master/test/test_extraction.py) -- samples on usage of `jspcap.extract`, which extracts a PCAP file and dumps to a specificly formatted output file
 - [`test_ipv6.py`](https://github.com/JarryShaw/jspcap/tree/master/test/test_ipv6.py) -- samples on extraction of IPv6 packets, whilst dumping a tree-view text file
 - [`test_http.py`](https://github.com/JarryShaw/jspcap/tree/master/test/test_http.py) -- samples on extraction of HTTP packets, whilst checking if HTTP is `in` the frame
 - [`test_reassembly.py`](https://github.com/JarryShaw/jspcap/tree/master/test/test_reassembly.py) -- samples on reassembly of TCP payloads, whilst writing the reassembled payloads into an output file
 - [`test_analyse.py`](https://github.com/JarryShaw/jspcap/tree/master/test/test_analyse.py) -- samples on analysis of application layer after reassembly, which writes the extracted HTTP frame to `stdout`
 - [`test_time.py`](https://github.com/JarryShaw/jspcap/tree/master/test/test_time.py) -- samples on a minimum usage of `jspcap.extract`, whilst timing the whole procedure
