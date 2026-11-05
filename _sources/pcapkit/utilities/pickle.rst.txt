Pickle Reductions
=================

.. module:: pcapkit.utilities.pickle

:mod:`pcapkit.utilities.pickle` holds the :mod:`pickle` reductions several
:mod:`pcapkit` classes share, so each is written once (:issue:`2714`):

.. list-table::
   :header-rows: 1

   * - Reduction
     - Effect
   * - :class:`ReduceAsProtocol2`
     - a :class:`typing.Generic` subclass or a class with ``__slots__`` pickles
       under protocol 0 and 1, on GraalPy as on CPython
   * - :class:`ReduceToName`
     - a singleton reduces to the module-level name holding it
   * - :class:`ReduceToItems`
     - a multi-valued mapping reduces to a call of its class on its item pairs
   * - :func:`reduce_to`
     - one instance reduces to a call of a given function

A pickle a class wrote before it took one of these still loads, and one it
writes with it loads where the class still reduces by its own.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.utilities.pickle.ReduceAsProtocol2
   :members: __reduce_ex__

.. autoclass:: pcapkit.utilities.pickle.ReduceToName
   :members: __reduce__

.. autoclass:: pcapkit.utilities.pickle.ReduceToItems
   :members: __reduce_ex__

.. autofunction:: pcapkit.utilities.pickle.reduce_to

.. autofunction:: pcapkit.utilities.pickle._reduce_to
