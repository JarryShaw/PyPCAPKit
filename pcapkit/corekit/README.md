# CoreKit Manual

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for core utility classes.

 - [`Info`](#info)
 - [`VersionInfo`](#versioninfo)
 - [`ProtoChain`](#protochain)

---

## `Info`

 > described in [`src/corekit/infoclass.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit/infoclass.py)

```python
class Info(builtins.dict)
```

##### Turn dictionaries into object-like instances.

 - Properties:
    * indicated as `Info` initialisation procedure

 - Methods:
    * `infotodict` -- recursively convert `Info` object into `dict` type
    * all other methods inherited from `dict`

 - Data modules:
    * **immutable** -- cannot delete or set value of a key
    * any other data modules inherited from `dict`

 - Notes:
    * `Info` objects inherit from `dict` type
    * `Info` objects are iterable, and support all functions as `dict`
    * `Info` objects are one-time-modifying, thus cannot set or delete attributes after initialisation

&nbsp;

## `VersionInfo`

 > described in [`src/corekit/version.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit/version.py)

```python
class VersionInfo(builtins.tuple)
```

##### VersionInfo is alike `sys.version_info`.

 - Properties:
    * `major` -- `int`, major version
    * `minor` -- `int`, minor version

 - Data modules:
    * immutable
    * subscriptable

&nbsp;

## `ProtoChain`

 > described in [`src/corekit/protochain.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit/protochain.py)

```python
class ProtoChain(builtins.object)
```

##### Protocols chain.

 - Properties:
    * `alias` -- `tuple`, aliases of protocols in chain
    * `tuple` -- `tuple`, name of protocols in chain
    * `proto` -- `tuple`, lowercase name of protocols in chain
    * `chain` -- `str`, chain of protocols separated by colons

 - Methods:
    * `index` -- same as `index` function of `tuple` type

 - Data modules:
    * iterable
    * subscriptable
