# TreeViewer

&nbsp;

 > This program is the assignment of Python 101 (SJTU).

&emsp; `TreeViewer` is a `Tkinter` based pcap extractor application.

&emsp; In the field of computer network administration, pcap (packet capture) consists of an application programming interface (API) for capturing network traffic. Unix-like systems implement pcap in the `libpcap` library; Windows uses a port of `libpcap` known as `WinPcap`.

&emsp; Monitoring software may use `libpcap` and/or `WinPcap` to capture packets travelling over a network and, in newer versions, to transmit packets on a network at the link layer, as well as to get a list of network interfaces for possible use with `libpcap` or `WinPcap`.

 > &emsp; In the core of the `JSPCAP` project, it works with the support of `jspcap` and `jsformat`, which can both be found in three projects above and are maintained in the [`dev`](https://github.com/JarryShaw/jspcap/tree/master/dev/) folder.

&emsp; As for `jspcap` and `jsformat`, they are two open-source library written in Python (version 3.6), with generally no requirements or third-party dependencies.

&emsp; The `jspcap` library provides (by now) basic extractor for pcap files, including its global header, frame header and voluminous networking protocol headers, such as `IP` (both version 4 and 6), `ICMP`, `TCP`, `UDP`, `SCTP`, et al. Memo has logged that an analyser of application layer protocols, which are fragmented when transmission, will be complemented soon.

&emsp; The `jsformat` library works as an implementation of the **Python standard library**, with support of streaming output of `plist` and `json` file. The library also provides a tree view output format, which was inspired from `macOS` plist display on `Xcode` editor and `JavaSript` framework `Vue.js`. Plus, it should provide output format as `XML` with different `DTD`s, like `pdml` and `psml`.

&emsp; And one more thing to say about, that a `macOS` platform original UI using `PyObjc` library and `xib` is under construction. But no idea if it can be finished before the deadline.

&emsp; Notice that the whole project is developed in `Python 3.6` and its compatibility hasn't been tested.
