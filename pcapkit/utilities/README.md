# Utilities Manual

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for utility functions and classes.

 - [Decorators](#decorators)
 	* [`seekset`](#seekset)
    * [`seekset_ng`](#seekset_ng)
    * [`beholder`](#beholder)
    * [`beholder_ng`](#beholder_ng)
 - [Validations](#validations)
    * [Module Index](#index-validations)
    * [Module Notes](#notes-validations)
 - [Exceptions](#exceptions)
    * [`BaseError`](#baseerror)
    * [Refined Exceptions](#refined-exceptions)
 - [Warnings](#warnings)
    * [`BaseWarning`](#basewarning)
    * [Refined Warnings](#refined-warnings)

---

## Decorators

 > described in [`src/utilities/decorators.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities/decorators.py)

&emsp; `pcapkit.utilities.decorators` contains several useful decorators, including `seekset` and `beholder`.

### `seekset`

```python
def seekset(func):
    def seekcur(self, *args, **kwargs):
        ...
        return func(self, *args, **kwargs)
    return seekcur
```

##### Read file from start then set back to original.

__NOTE__: this decorator works with class methods, which has a *file-like* attribute names `self._file` and file offset pointer `self._seekset`.

### `seekset_ng`

```python
def seekset_ng(func):
    def seekcur(file, *args, seekset=os.SEEK_SET, **kwargs):
        ...
        return func(file, *args, seekset=seekset, **kwargs)
    return seekcur
```

##### Read file from start then set back to original.

__NOTE__: positional argument `file` in `seekcur` must be a *file-like* object and keyword argument `seekset` should be `int` type.

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

## Validations

 > described in [`src/utilities/validations.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities/validations.py)

&emsp; `pcapkit.utilities.validations` contains functions to validate arguments for functions and classes. It first appears in
[`ntlib`](https://github.com/JarryShaw/pyntlib) as validators.

<a name="index-validations"> </a>

```python
type_check(*agrs, func=None)
```

| NAME              | DESCRIPTION                                 |
| :---------------- | :------------------------------------------ |
| `int_check`       | Check if arguments are integrals.           |
| `real_check`      | Check if arguments are real numbers.        |
| `complex_check`   | Check if arguments are complex numbers.     |
| `number_check`    | Check if arguments are numbers.             |
| `bytes_check`     | Check if arguments are `bytes` type.        |
| `bytearray_check` | Check if arguments are `bytearray` type.    |
| `str_check`       | Check if arguments are `str` type.          |
| `bool_check`      | Check if arguments are `bytes` type.        |
| `list_check`      | Check if arguments are `list` type.         |
| `tuple_check`     | Check if arguments are `tuple` type.        |
| `io_check`        | Check if arguments are _file-like_ object.  |
| `info_check`      | Check if arguments are Info instance.       |
| `pkt_check`       | Check if arguments are valid packets.       |
| `frag_check`      | Check if arguments are valid fragments.     |
| `_ip_frag_check`  | Check if arguments are valid IP fragments.  |
| `_tcp_frag_check` | Check if arguments are valid TCP fragments. |

&emsp; __EXCEPT__ `frag_check`, all validators take arbitrary positional arguments with one keyword argument named `func`, which takes a `str` type indicates the caller function of validation procedure.

<a name="notes-validations"> </a>

#### Nota Bene

```python
pkt_check(*args, func=None)
```

&emsp; `pkt_check` is the validator for `TraceFlow`. For more information on packet format, please refer to the documentation of [`TraceFlow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#traceflow).

```python
frag_check(*args, protocol, func=None)
_ip_frag_check(*args, func=None)
_tcp_frag_check(*args, func=None)
```

&emsp; As for `frag_check`, `str` type keyword argument `protocol` indicates what protocol the fragment is reassembled for, which must be either `IP` (`IPv4` & `IPv6`) or `TCP`. Then, `_ip_frag_check` or `_tcp_frag_check` shall be called to validate arguments caller passed into. For more information on fragment format, please refer to the documentation of [`IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly) and [`TCP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#tcp_reassembly).

&nbsp;

## Exceptions

 > described in [`src/utilities/exceptions.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities/exceptions.py)

&emsp; `pcapkit.utilities.exceptions` refined built-in exceptions. Make it possible to show only user error stack information, when exception raised on user's operation.

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
class error(pcapkit.utilities.exceptions.BaseError, builtins.Exception)
```

| NAME                     | INHERIT FROM                        | DESCRIPTION                                         |
| :----------------------- | :---------------------------------- | :-------------------------------------------------- |
| `DigitError`             | `BaseError` / `TypeError`           | The argument(s) must be (a) number(s).              |
| `IntError`               | `BaseError` / `TypeError`           | The argument(s) must be integral.                   |
| `RealError`              | `BaseError` / `TypeError`           | The function is not defined for real number.        |
| `ComplexError`           | `BaseError` / `TypeError`           | The function is not defined for `complex` instance. |
| `BytesError`             | `BaseError` / `TypeError`           | The argument(s) must be `bytes` type.               |
| `BytearrayError`         | `BaseError` / `TypeError`           | The argument(s) must be `bytearray` type.           |
| `BoolError`              | `BaseError` / `TypeError`           | The argument(s) must be `bool` type.                |
| `StringError`            | `BaseError` / `TypeError`           | The argument(s) must be `str` type.                 |
| `DictError`              | `BaseError` / `TypeError`           | The argument(s) must be `dict` type.                |
| `ListError`              | `BaseError` / `TypeError`           | The argument(s) must be `list` type.                |
| `TupleError`             | `BaseError` / `TypeError`           | The argument(s) must be `tuple` type.               |
| `IterableError`          | `BaseError` / `TypeError`           | The argument(s) must be iterable.                   |
| `CallableError`          | `BaseError` / `TypeError`           | The argument(s) must be callable.                   |
| `ProtocolUnbound`        | `BaseError` / `TypeError`           | Protocol slice unbound.                             |
| `IOObjError`             | `BaseError` / `TypeError`           | The argument(s) must be _file-like_ object.         |
| `InfoError`              | `BaseError` / `TypeError`           | The argument(s) must be Info instance.              |
| `FormatError`            | `BaseError` / `AttributeError`      | Unknown format(s).                                  |
| `UnsupportedCall`        | `BaseError` / `AttributeError`      | Unsupported function or property call.              |
| `FileError`              | `BaseError` / `IOError`             | Wrong file format.                                  |
| `FileNotFound`           | `BaseError` / `FileNotFoundError`   | File not found.                                     |
| `ProtocolNotFound`       | `BaseError` / `IndexError`          | Protocol not found in `ProtoChain`.                 |
| `VersionError`           | `BaseError` / `ValueError`          | Unknown IP version.                                 |
| `IndexNotFound`          | `BaseError` / `ValueError`          | Protocol not in `ProtoChain`.                       |
| `ProtocolError`          | `BaseError` / `ValueError`          | Invalid protocol format.                            |
| `ProtocolNotImplemented` | `BaseError` / `NotImplementedError` | Protocol not implemented.                           |
| `FragmentError`          | `BaseError` / `KeyError`            | Invalid fragment dict.                              |
| `PacketError`            | `BaseError` / `KeyError`            | Invalid packet dict.                                |
| `StructError`            | `BaseError` / `struct.error`        | Unpack failed.                                      |

&nbsp;

## Warnings

> described in [`src/utilities/warnings.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities/warnings.py)

&emsp; `pcapkit.utilities.warnings` refined built-in warnings.

### `BaseWarning`

```python
class BaseWarning(builtins.Warning)
```

##### Base warning class of all kinds.

### Refined Warnings

```python
class warning(pcapkit.utilities.warnings.BaseWarning, builtins.Warning)
```

| NAME               | INHERIT FROM                      | DESCRIPTION                    |
| :----------------- | :-------------------------------- | :----------------------------- |
| `FormatWarning`    | `BaseWarning` / `ImportWarning`   | Warning on unknown format(s).  |
| `EngineWarning`    | `BaseWarning` / `ImportWarning`   | Unsupported extraction engine. |
| `FileWarning`      | `BaseWarning` / `RuntimeWarning`  | Warning on file(s).            |
| `LayerWarning`     | `BaseWarning` / `RuntimeWarning`  | Unrecognised layer.            |
| `ProtocolWarning`  | `BaseWarning` / `RuntimeWarning`  | Unrecognised protocol.         |
| `AttributeWarning` | `BaseWarning` / `RuntimeWarning`  | Unsupported attribute.         |
| `DPKTWarning`      | `BaseWarning` / `ResourceWarning` | Warnings on DPKT usage.        |
| `ScapyWarning`     | `BaseWarning` / `ResourceWarning` | Warnings on Scapy usage.       |
| `PySharkWarning`   | `BaseWarning` / `ResourceWarning` | Warnings on PyShark usage.     |
