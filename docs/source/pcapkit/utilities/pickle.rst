Pickle Reductions
=================

.. module:: pcapkit.utilities.pickle

:mod:`pcapkit.utilities.pickle` holds the :mod:`pickle` reductions several
:mod:`pcapkit` classes share, so each is written once (:issue:`2714`).
:class:`ReduceAsProtocol2` lets a :class:`typing.Generic` subclass or a slotted
:class:`dict` pickle under protocol 0 and 1, on GraalPy as on CPython;
:class:`ReduceToName` reduces a singleton to the module-level name holding it;
:class:`ReduceToItems` reduces a multi-valued mapping to a call of its class on its
item pairs; and :func:`reduce_to` makes one instance reduce to a call of a given
function. A pickle a class wrote before it took one of these still loads, and one
it writes with it loads where the class still reduces by its own.

.. autoclass:: pcapkit.utilities.pickle.ReduceAsProtocol2
   :members: __reduce_ex__

.. autoclass:: pcapkit.utilities.pickle.ReduceToName
   :members: __reduce__

.. autoclass:: pcapkit.utilities.pickle.ReduceToItems
   :members: __reduce_ex__

.. autofunction:: pcapkit.utilities.pickle.reduce_to

.. autofunction:: pcapkit.utilities.pickle._reduce_to
