# DumpKit Manual

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for dump utility classes, which are alike those discribed in [`dictdumper`](https://github.com/JarryShaw/dictdumper) library.

 - [`PCAP`](#pcap)
 - [`NotImplementedIO`](#notimplementedio)

---

## `PCAP`

 > decribed in [`src/dumpkit/__init.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit/__init__.py)

```python
class PCAP(builtins.object)
```

##### PCAP file dumper.

 - Properties:
    * `kind` -- `str`, dumper kind

 - Data models:
    * initialisation
        ```python
        __init__(self, filename, *, protocol)
        ```
        - `filename` -- `str`, output file name
        - `protocol` -- `str`, PCAP link data protocol type
    * callable
        ```python
        __call__(self, frame, **kwargs)
        ```
        - `frame` -- `Info`, frame data

&nbsp;

## `NotImplementedIO`

 > decribed in [`src/dumpkit/__init.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit/__init__.py)

```python
class NotImplementedIO(builtins.object)
```

##### Unspecified output format.

 - Properties:
    * `kind` -- `NotImplemented`
