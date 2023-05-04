User Defined Exceptions
=======================

.. module:: pcapkit.utilities.exceptions

:mod:`pcapkit.exceptions` refined built-in exceptions.
Make it possible to show only user error stack infomation [*]_,
when exception raised on user's operation.

.. autoexception:: pcapkit.utilities.exceptions.BaseError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`TypeError` Category
-------------------------

.. autoexception:: pcapkit.utilities.exceptions.DigitError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.IntError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.RealError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.ComplexError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.BoolError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.BytesError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.StringError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.BytearrayError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.DictError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.ListError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.TupleError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.IterableError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.IOObjError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.ProtocolUnbound
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.CallableError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.InfoError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.IPError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.EnumError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.ComparisonError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.RegistryError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.FieldError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`AttributeError` Category
------------------------------

.. autoexception:: pcapkit.utilities.exceptions.FormatError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.UnsupportedCall
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`IOError` Category
-----------------------

.. autoexception:: pcapkit.utilities.exceptions.FileError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`FileExistsError` Category
-------------------------------

.. autoexception:: pcapkit.utilities.exceptions.FileExists
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`FileNotFoundError` Category
---------------------------------

.. autoexception:: pcapkit.utilities.exceptions.FileNotFound
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`IndexError` Category
--------------------------

.. autoexception:: pcapkit.utilities.exceptions.ProtocolNotFound
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`ValueError` Category
--------------------------

.. autoexception:: pcapkit.utilities.exceptions.VersionError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.IndexNotFound
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.ProtocolError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.EndianError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.KeyExists
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.NoDefaultValue
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.FieldValueError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.SchemaError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`NotImplementedError` Category
-----------------------------------

.. autoexception:: pcapkit.utilities.exceptions.ProtocolNotImplemented
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.VendorNotImplemented
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`struct.error` Category
----------------------------

.. autoexception:: pcapkit.utilities.exceptions.StructError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`KeyError` Category
------------------------

.. autoexception:: pcapkit.utilities.exceptions.MissingKeyError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.FragmentError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoexception:: pcapkit.utilities.exceptions.PacketError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`ModuleNotFoundError` Category
-----------------------------------

.. autoexception:: pcapkit.utilities.exceptions.ModuleNotFound
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, suppress exception message.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] See |tbtrim|_ project for a modern Pythonic implementation.

.. |tbtrim| replace:: ``tbtrim``
.. _tbtrim: https://github.com/gousaiyang/tbtrim
