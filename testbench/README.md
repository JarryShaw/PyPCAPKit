# Test Bench

&emsp; Here you can find several testing version of `pcapkit` under development, which are actually branches of this repository.

---

## Multiprocessing Test Bench

 > [__NOTA BENE__] [`master`](https://github.com/JarryShaw/pcapkit/tree/master#jspcap) : 0.01901674787203471 seconds per packet

### [Prototype](https://github.com/JarryShaw/pcapkit/tree/test/mp/prototype#jspcap)

 > [__DEPRECATED__] fatal error remains

&emsp; This implementation with multiprocessing is a prototype with fatal bugs.

### [Queue](https://github.com/JarryShaw/pcapkit/tree/test/mp/queue#jspcap)

 > [__DEPRECATED__] fatal error remains

&emsp; This implementation using multiprocessing with `queue` is with fatal bugs.

### [Tempfile](https://github.com/JarryShaw/pcapkit/tree/test/mp/tempfile#jspcap)

 > [__DEPRECATED__] fatal error remains

&emsp; This implementation using multiprocessing with `tempfile` is with fatal bugs.

### [Manager](https://github.com/JarryShaw/pcapkit/tree/test/mp/manager#jspcap)

 > [__DEPRECATED__] 0.043863560358683266 seconds per packet

&emsp; This implementation uses multiprocessing in process slides.

### [Server](https://github.com/JarryShaw/pcapkit/tree/test/mp/server#jspcap)

 > [__DEPRECATED__] 0.04677961190541585 seconds per packet

&emsp; This implementation uses multiprocessing with a server process to perform reassembly.

## Reconstructioin Test Bench

### [FileIO](https://github.com/JarryShaw/pypcapkit/tree/test/rc/fileio#pypcapkit)

 > [__MERGED__]

&emsp; Under development of the reconstruction for replacing `BytesIO`s with the original `TextIOWrapper` *file-like* object during extraction.

### [ABC](https://github.com/JarryShaw/pypcapkit/tree/test/rc/abc#pypcapkit)

&emsp; Considering replacing `Info` and `ProtoChain` with `collections.abc`. Plus, reconstruct `ProtoChain` algorithm.
