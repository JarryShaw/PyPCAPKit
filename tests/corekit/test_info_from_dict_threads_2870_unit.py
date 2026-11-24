# -*- coding: utf-8 -*-
"""Threads making a class's first ``Info.from_dict`` at once all finish it (GitHub issue #2870).

The first call works out which keys hold a nested ``Info`` by copying the namespaces of
the class and of its module, then caches the answer in the class's own namespace. Where
the interpreter lets another thread run part way through the copy, a store landing then
makes it raise "dictionary changed size during iteration", which keeps an Ethernet
frame's payload as Raw when its first IPv4 parse races others. So the resolution and its
store hold :data:`pcapkit.utilities.importlib.import_lock`.

CPython copies a namespace in one step, so here the copy of the class's pauses part way
through, until the other thread has made its own first call or ``WAIT`` has passed. A
store made in the pause is the race; with the lock, the other thread waits it out.

"""
import builtins
import threading
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): races two threads on a lock.
__tier__ = 'ALL'

#: Seconds the paused copy waits for the other thread's first call, which the lock holds up.
WAIT = 2.0


class FirstFromDictTests(unittest.TestCase):
    """A class's first ``from_dict``, made by two threads at once."""

    def test_a_first_call_waits_for_one_copying_the_namespace(self) -> 'None':
        """The second thread stores nothing in the class while the first copies its namespace."""
        from pcapkit.corekit import infoclass
        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Inner(Info):
            value: int

        @info_final
        class Outer(Info):
            inner: Inner

        copying, called = threading.Event(), threading.Event()
        results, errors = {}, []  # type: dict[str, Any], list[BaseException]

        class Paused:
            """A namespace whose copy pauses after its first key."""

            def __init__(self, namespace: 'Any') -> 'None':
                self.namespace = namespace

            def keys(self) -> 'Iterator[str]':
                for index, key in enumerate(self.namespace):
                    if index == 1:
                        copying.set()
                        called.wait(WAIT)
                    yield key

            def __getitem__(self, key: 'str') -> 'Any':
                return self.namespace[key]

        def paused_vars(obj: 'Any') -> 'Any':
            if obj is Outer and threading.current_thread() is first and not copying.is_set():
                return Paused(builtins.vars(obj))
            return builtins.vars(obj)

        def call(name: 'str') -> 'None':
            try:
                if name == 'second':
                    copying.wait(WAIT)
                results[name] = Outer.from_dict({'inner': {'value': 1}})
            except BaseException as error:  # pylint: disable=broad-except
                errors.append(error)
            finally:
                if name == 'second':
                    called.set()

        infoclass.vars = paused_vars  # type: ignore[attr-defined]
        self.addCleanup(delattr, infoclass, 'vars')

        first = threading.Thread(target=call, args=('first',), daemon=True)
        second = threading.Thread(target=call, args=('second',), daemon=True)
        first.start()
        second.start()
        for thread in (first, second):
            thread.join(WAIT * 5)
            self.assertFalse(thread.is_alive(), thread)

        self.assertTrue(copying.is_set())
        self.assertEqual(errors, [])
        for name in ('first', 'second'):
            self.assertIs(type(results[name].inner), Inner, name)


if __name__ == '__main__':
    unittest.main()
