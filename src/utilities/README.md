# Utilities Manual

&emsp; `jspcap` is an open sourse library for PCAP extarction and analysis, written in __Python 3.6__. The following is a manual for utility functions and classes.

 - [Decorators](#decorators)
 	* [`seekset`](#seekset)
    * [`seekset_ng`](#seekset_ng)
    * [`beholder`](#beholder)
    * [`beholder_ng`](#beholder_ng)
 - [Classes](#classes)
 	* [`Info`](#info)
    * [`VersionInfo`](#versioninfo)
    * [`ProtoChain`](#protochain)
 - [Validations](#validations)
 	* [Validations](#index-validations)
 - [Exceptions](#exceptions)
    * [`BaseError`](#baseerror)
    * [Refined Exceptions](#refined-exceptions)

---

## Decorators

 > described in [`src/utilities/decorators.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities/decorators.py)

&emsp; `jspcap.utilities.decorators` contains several useful decorators, including `seekset` and `beholder`.

### `seekset`

```python
def seekset(func):
    def seekcur(self, *args, **kw):
        ...
        return func(self, *args, **kw)
    return seekcur
```

##### Read file from start then set back to original.

__NOTE__: this decorator works with class methods, which has a *file-like* attribute names `self._file`.

### `seekset_ng`

```python
def seekset_ng(func):
    def seekcur(file, *args, **kw):
        ...
        return func(file, *args, **kw)
    return seekcur
```

##### Read file from start then set back to original.

__NOTE__: positional argument `file` in `seekcur` must be a *file-like* object.

### `beholder`

```python
def beholder(func):
    def behold(self, proto, length, *args, **kwargs):
        ...
        return func(self, proto, length, *args, **kwargs)
    return behold
```

##### Behold extraction procedure.

__NOTE__: this decorator works with class method `self._import_next_layer`, which has a *file-like* attribute names `self._file`.

### `beholder_ng`

```python
def beholder_ng(func):
    def behold(file, length, *args, **kwargs):
        ...
        return func(file, length, *args, **kwargs)
    return behold
```

##### Behold extraction procedure.

__NOTE__: positional argument `file` in `behold` must be a *file-like* object.

&nbsp;

## Classes

&emsp; `jspcap.utilities` contains several useful classes which are fundations of `jspcap`, including `dict`-like class `Info`, `tuple`-like class `VersionInfo`, and protocol collection class `ProtoChain`.

### `Info`

 > described in [`src/utilities/infoclass.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities/infoclass.py)

```python
class Info(builtins.dict)
```

##### Turn dictionaries into object-like instances.

 - Properties:
    * indicated as `Info` initialisation procedure

 - Methods:
    * `infotodict` -- reverse `Info` object into `dict` type
    * all other methods inherited from `dict`

 - Data modules:
    * **immutable** -- cannot delete or set value of a key
    * any other data modules inherited from `dict`

 - Notes:
    * `Info` objects inherit from `dict` type
    * `Info` objects are iterable, and support all functions as `dict`
    * `Info` objects are one-time-modeling, thus cannot set or delete attributes after initialisation

### `VersionInfo`

 > described in [`src/utilities/version.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities/version.py)

```python
class VersionInfo(builtins.object)
```

##### VersionInfo alikes `sys.version_info`.

 - Properties:
    * `major` -- `int`, major version
    * `minor` -- `int`, minor version

 - Data modules:
    * immutable
    * subscriptable

### `ProtoChain`

 > described in [`src/utilities/protochain.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities/protochain.py)

```python
class ProtoChain(builtins.object)
```

##### Protocols chain.

 - Properties:
    * `alias` -- `tuple`, aliases of protocols in chain
    * `tuple` -- `tuple`, name of protocols in chain
    * `proto` -- `tuple`, lowercase name of protocols in chain
    * `chain` -- `str`, chain of protocols seperated by colons

 - Methods:
    * `index` -- same as `index` function of `tuple` type

 - Data modules:
    * iterable
    * subscriptable

&nbsp;

## Validations

 > described in [`src/utilities/validations.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities/validations.py)

&emsp; `jspcap.utilities.validations` contains functions to validate arguments for functions and classes. It first appears in
[`jsntlib`](https://github.com/JarryShaw/jsntlib) as validators.

##### Validators

```python
type_check(*agrs, func=None)
```

|       NAME        |                 DESCRIPTION                 |
| :---------------: | :-----------------------------------------: |
|    `int_check`    |      Check if arguments are integrals.      |
|   `real_check`    |    Check if arguments are real numbers.     |
|  `complex_check`  |   Check if arguments are complex numbers.   |
|  `number_check`   |       Check if arguments are numbers.       |
|   `bytes_check`   |    Check if arguments are `bytes` type.     |
| `bytearray_check` |  Check if arguments are `bytearray` type.   |
|    `str_check`    |     Check if arguments are `str` type.      |
|   `bool_check`    |    Check if arguments are `bytes` type.     |
|   `list_check`    |     Check if arguments are `list` type.     |
|   `tuple_check`   |    Check if arguments are `tuple` type.     |
|    `io_check`     |  Check if arguments are *file-like* type.   |
|   `frag_check`    |   Check if arguments are valid fragments.   |
| `_ip_frag_check`  | Check if arguments are valid IP fragments.  |
| `_tcp_frag_check` | Check if arguments are valid TCP fragments. |

&emsp; __EXCEPT__ `frag_check`, all validators take arbitrary positional arguments with one keyword argument named `func`, which takes a `str` type indicates the caller function of validation procedure.

##### Nota Bene

```python
frag_check(*args, protocol, func=None)
_ip_frag_check(*args, func=None)
_tcp_frag_check(*args, func=None)
```

&emsp; As for `frag_check`, `str` type keyword argument `protocol` indicats what protocol the fragment is reassembled for, which must be either `IP` (`IPv4` & `IPv6`) or `TCP`. Then, `_ip_frag_check` or `_tcp_frag_check` shall be called to validate arguments caller passed into. For more infomation on fragment format, please refer to the documentation of [`IP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ip_reassembly) and [`TCP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#tcp_reassembly).

&nbsp;

## Exceptions

 > described in [`src/utilities/exceptions.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities/exceptions.py)

&emsp; `jspcap.exceptions` refined built-in exceptions. Make it possible to show only user error stack infomation, when exception raised on user's operation.

### `BaseError`

```python
class BaseError(builtins.Exception)
```

##### Base error class of all kinds.

 - Data modules:
    * initialisation takes a special keyword argument `quiet` of `bool` type, referring if print no traceback information when exception raised
    * all other data modules inherited from `Exception`

 - Notes:

    * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.

    * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.

        > this note is deprecated since Python fixed the problem above

    * In Python 2.7, `trace.print_stack(limit=None)` dose not support negative limit.

### Refined Exceptions

```python
class error(jspcap.utilities.exceptions.BaseError, builtins.Exception)
```

|        NAME        |            INHERIT FROM            |                     DESCRIPTION                     |
| :----------------: | :--------------------------------: | :-------------------------------------------------: |
|    `DigitError`    |     `BaseError` / `TypeError`      |       The argument(s) must be (a) number(s).        |
|     `IntError`     |     `BaseError` / `TypeError`      |          The argument(s) must be integral.          |
|    `RealError`     |     `BaseError` / `TypeError`      |    The function is not defined for real number.     |
|   `ComplexError`   |     `BaseError` / `TypeError`      | The function is not defined for `complex` instance. |
|    `BytesError`    |     `BaseError` / `TypeError`      |        The argument(s) must be `bytes` type.        |
|  `BytearrayError`  |     `BaseError` / `TypeError`      |      The argument(s) must be `bytearray` type.      |
|    `BoolError`     |     `BaseError` / `TypeError`      |        The argument(s) must be `bool` type.         |
|   `StringError`    |     `BaseError` / `TypeError`      |         The argument(s) must be `str` type.         |
|    `DictError`     |     `BaseError` / `TypeError`      |        The argument(s) must be `dict` type.         |
|    `ListError`     |     `BaseError` / `TypeError`      |        The argument(s) must be `list` type.         |
|    `TupleError`    |     `BaseError` / `TypeError`      |        The argument(s) must be `tuple` type.        |
|  `IterableError`   |     `BaseError` / `TypeError`      |          The argument(s) must be iterable.          |
|  `CallableError`   |     `BaseError` / `TypeError`      |          The argument(s) must be callable.          |
| `ProtocolUnbound`  |     `BaseError` / `TypeError`      |               Protocol slice unbound.               |
|    `IOObjError`    |     `BaseError` / `TypeError`      |      The argument(s) must be *file-like* type.      |
|   `FormatError`    |   `BaseError` / `AttributeError`   |                  Unknow format(s).                  |
| `UnsupportedCall`  |   `BaseError` / `AttributeError`   |       Unsupported function or property call.        |
|    `FileError`     |      `BaseError` / `IOError`       |                 Wrong file format.                  |
|   `FileNotFound`   | `BaseError` /  `FileNotFoundError` |                   File not found.                   |
| `ProtocolNotFound` |     `BaseError` / `IndexError`     |         Protocol not found in `ProtoChain`.         |
|   `VersionError`   |     `BaseError` / `ValueError`     |                 Unknown IP version.                 |
|  `IndexNotFound`   |     `BaseError` / `ValueError`     |            Protocol not in `ProtoChain`.            |
|  `ProtocolError`   |     `BaseError` / `ValueError`     |              Invalid protocol format.               |
|   `StructError`    |    `BaseError` / `struct.error`    |                   Unpack failed.                    |
|  `FragmentError`   |      `BaseError` / `KeyError`      |               Invalid fragment dict.                |
