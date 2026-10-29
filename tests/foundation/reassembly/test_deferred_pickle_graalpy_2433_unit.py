# -*- coding: utf-8 -*-
""":class:`Deferred` could not be pickled under protocol 0 or 1 on GraalPy 25.4.

GitHub issue :issue:`2433`, fixed by :pr:`2435`.

:issue:`2423` and :issue:`2425` (pinned in
:mod:`tests.foundation.reassembly.test_deferred_pickle_2423_unit`) gave
``Deferred`` a ``__getstate__``/``__setstate__`` pair so protocol 0 and 1 no
longer raised *there*. Neither method is where GraalPy 25.4 actually fails,
though: :meth:`object.__reduce_ex__` hands protocol 0 and 1 to
:func:`copyreg._reduce_ex`, which walks ``type(self).__mro__`` for a base to
compute a base-object state from *before* ``__getstate__`` is ever consulted.
On CPython that walk passes :class:`~typing.Generic` (a heap type there,
whose own ``__new__`` is just the inherited, differently-bound
``object.__new__``) and stops at :class:`object`. On GraalPy, ``Generic`` is
itself a non-heap (built-in) type, so the walk's first check breaks on
``Generic`` directly and calls ``Generic(self)``, raising::

    TypeError: typing.Generic() takes no arguments

:meth:`Deferred.__reduce_ex__` now hard-codes the ``base=object, state=None``
outcome the walk always reached on CPython for protocol 0 and 1, which means
``copyreg._reduce_ex`` -- and its MRO walk -- is no longer called for those
two protocols at all.

A cross-reviewer confirmed this directly against real GraalPy 25.4.4
(``graalpy3.13-community-25.4.4``, downloaded from the
``oracle/graalpython`` GitHub releases and checksum-verified): this
module's tests, together with
:mod:`tests.foundation.reassembly.test_deferred_pickle_2423_unit`, are red
on ``main`` and green on this fix there, and the full
:file:`tests/foundation/reassembly/` suite passes clean on this fix on
both CPython and real GraalPy 25.4.4 (with the generated sample captures
present -- run :file:`examples/generators/make_samples.py` first if
reproducing). GraalPy is not available in this repository's regular
environment, so :class:`DeferredGraalPyPickleTests` below reproduces the
failure mode by monkeypatching :func:`copyreg._reduce_ex` to raise the exact
:exc:`TypeError` real GraalPy does -- RED against ``main`` (which still
routes protocol 0 and 1 through ``object.__reduce_ex__`` ->
``copyreg._reduce_ex``) and GREEN against this fix (which never calls
``copyreg._reduce_ex`` for those two protocols at all).

The cross-review on this fix's first revision found a second, independent
regression in the same method, fixed alongside this test: the protocol 0/1
branch unconditionally built a hard-coded ``(copyreg._reconstructor, ...)``
tuple, silently dropping a *subclass*'s own ``__reduce__`` override at
exactly those two protocols, while protocol 2 and above -- going through
``object.__reduce_ex__`` unchanged, which always checks for and calls a
non-default ``__reduce__`` -- kept honouring it.
:class:`DeferredSubclassReduceOverrideTests` pins the fixed behaviour. It is
new coverage rather than a regression proof: the override check is new to
this fix, not something an earlier release got right and then lost.

"""

import copyreg
import pickle
import unittest
from unittest import mock

from pcapkit.foundation.reassembly.data.data import Deferred as _Deferred
from tests._support import reimport_once_per_class

#: Test tier (#1958): cross-interpreter pickling behaviour, same reasoning as
#: ``tests/foundation/reassembly/test_deferred_pickle_2423_unit.py`` gives for
#: itself -- pinned on ``ALL`` because it is exactly the kind of thing that can,
#: and here did, differ between interpreters.
__tier__ = 'ALL'


def _analyze(proto: 'object', payload: 'bytes') -> 'tuple[object, bytes]':
    """Module-level stand-in analyser; picklable under every protocol."""
    return (proto, payload)


def _rebuild_reduce_override_sub(analyze: 'object', proto: 'object', payload: 'bytes',
                                  marker: 'object') -> '_ReduceOverrideSub':
    """Module-level rebuild function ``_ReduceOverrideSub.__reduce__`` names.

    Has to be importable by qualified name, like ``_analyze`` above, for the
    same reason given in ``test_deferred_pickle_2423_unit.py``'s module
    docstring: :mod:`pickle` locates a reduction's callable by name, and a
    function local to a test method is not importable.

    """
    return _ReduceOverrideSub(analyze, proto, payload, marker)


class _ReduceOverrideSub(_Deferred):
    """A ``Deferred`` subclass overriding ``__reduce__``.

    Module-level for the same reason ``_rebuild_reduce_override_sub`` above
    is: :mod:`pickle` has to be able to locate this class by its qualified
    name to build a real pickle, which a class nested in a test method is
    not.

    """

    #: Set by ``__reduce__`` below; read back by the tests. A plain boolean
    #: rather than object identity, since the restored instance after a real
    #: pickle round trip is a brand-new object built by
    #: ``_rebuild_reduce_override_sub``, not ``self``.
    reduce_called = False

    def __init__(self, analyze: 'object', proto: 'object', payload: 'bytes',
                 marker: 'object') -> 'None':
        super().__init__(analyze, proto, payload)
        self.marker = marker

    def __reduce__(self) -> 'tuple[object, ...]':
        _ReduceOverrideSub.reduce_called = True
        return (_rebuild_reduce_override_sub,
                (self.analyze, self.proto, self.payload, self.marker))


class DeferredGraalPyPickleTests(unittest.TestCase):
    """Protocol 0 and 1 must not route through ``copyreg._reduce_ex`` at all.

    GraalPy 25.4's failure happens inside that function, before
    ``__getstate__`` is ever consulted (see the module docstring), so the fix
    this file pins is that ``Deferred.__reduce_ex__`` never calls it for
    protocol 0 or 1 -- simulated here by making the call raise the same
    :exc:`TypeError` real GraalPy does.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_protocol_0_1_survive_a_copyreg_reduce_ex_failure(self) -> None:
        """RED on ``main`` (pre-:issue:`2433`), GREEN on this fix.

        A cross-reviewer ran this test against real GraalPy 25.4.4 and
        confirmed the result, in addition to the monkeypatched reproduction
        here; see the module docstring for how.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')

        def _raise_like_graalpy(self: 'object', proto: 'object') -> 'object':
            raise TypeError('typing.Generic() takes no arguments')

        with mock.patch.object(copyreg, '_reduce_ex', side_effect=_raise_like_graalpy):
            for protocol in (0, 1):
                with self.subTest(protocol=protocol):
                    restored = pickle.loads(pickle.dumps(deferred, protocol=protocol))
                    self.assertEqual(restored.proto, 42)
                    self.assertEqual(restored.payload, b'payload')
                    self.assertIs(restored.analyze, _analyze)

    def test_protocol_2_and_above_never_call_copyreg_reduce_ex(self) -> None:
        """Protocol >= 2 is untouched by this fix -- it never walked the MRO.

        Patching ``copyreg._reduce_ex`` to blow up therefore has no effect at
        protocol 2 and above, confirming the bypass above is specific to
        protocol 0 and 1 rather than a blanket detour around the function.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        with mock.patch.object(copyreg, '_reduce_ex',
                                side_effect=AssertionError('must not be called')):
            restored = pickle.loads(pickle.dumps(deferred, protocol=2))
            self.assertEqual(restored.proto, 42)
            self.assertEqual(restored.payload, b'payload')


class DeferredSubclassReduceOverrideTests(unittest.TestCase):
    """A subclass's own ``__reduce__`` must be honoured at every protocol.

    Cross-review finding on this fix's first revision: the hard-coded
    protocol 0/1 tuple ignored such an override, while protocol 2 and above
    (going through ``object.__reduce_ex__`` unchanged) did not. New coverage
    rather than a regression proof -- see the module docstring.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)
        _ReduceOverrideSub.reduce_called = False

    def test_override_is_called_under_every_protocol(self) -> None:
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                _ReduceOverrideSub.reduce_called = False
                sub = _ReduceOverrideSub(_analyze, 7, b'x', 'marker-value')
                restored = pickle.loads(pickle.dumps(sub, protocol=protocol))
                self.assertTrue(_ReduceOverrideSub.reduce_called,
                                f'__reduce__ override was bypassed at protocol {protocol}')
                self.assertIsInstance(restored, _ReduceOverrideSub)
                self.assertEqual(restored.proto, 7)
                self.assertEqual(restored.payload, b'x')
                self.assertEqual(restored.marker, 'marker-value')
                self.assertIs(restored.analyze, _analyze)


if __name__ == '__main__':
    unittest.main()
