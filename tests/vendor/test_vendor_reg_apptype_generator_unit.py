# -*- coding: utf-8 -*-
"""The mechanical shapes :mod:`pcapkit.vendor.reg.apptype.apptype` must keep.

GitHub issue #744: :class:`~pcapkit.const.reg.apptype.apptype.AppType`'s
members are plain, not *annotated*, assignments. An annotated member --
``tcpmux: 'TCP' = 1, 'tcpmux', TransportProtocol.get('tcp') | TransportProtocol.get('udp')``
-- puts one forward-ref string per member into the class's
``__annotations__``. Sphinx's default autodoc calls
``sphinx.util.typing.get_type_hints(parent, ...)`` once per member
(from ``_make_props_from_imported_object`` in
``sphinx/ext/autodoc/_dynamic/_loader.py`` -- the wrapper
around :func:`typing.get_type_hints` that catches the ``NameError`` a
``TYPE_CHECKING``-only forward ref would otherwise raise), each call
re-resolving the *whole* class, which with annotated members makes documenting
this one registry cost 378.8s on CI (measured) -- the single largest stall in the
entire docs build. The
annotation carries no information a lookup needs: member construction reads the
positional tuple, not ``__annotations__``. Measured by #769, dropping it removes
86,838 bytes (7/8 bytes per member, depending on whether its class name is 3 or
4 letters long).

GitHub issue #768: the ``proto`` argument on every one of those members, and
every ``cls.__transport__ is ...`` test in a range-row ``_missing_`` branch,
uses attribute access rather than
:meth:`~pcapkit.const.reg.apptype.apptype.TransportProtocol.get` (524 ns, an
``isinstance`` check, two ``.lower()`` calls, a membership test and a
``__getitem__``) to reach a member plain attribute access returns in 24 ns,
saving 7 bytes each (``TransportProtocol.get('tcp')`` is 28 characters,
``TransportProtocol.tcp`` is 21), for 167,587 bytes (163.7 KiB) of generated
source as measured by #769. The generator only ever emits the declared names
(``TRANSPORTS + ('undefined',)``), so the attribute form cannot miss.

GitHub issue #770: a bare ``undefined = 0`` in the ``BASE`` template is an int
literal, so mypy -- which has no :mod:`aenum` plugin and so treats this class
as a plain one -- infers the class attribute's type as ``int`` while the
``auto()``-valued siblings (``tcp``, ``udp``, ``sctp``, ``dccp``) infer as
``Any``. That makes ``TransportProtocol.undefined`` disagree with its own
``'TransportProtocol'`` annotation at the sites that default to it -- the class
attribute ``__transport__``, and the ``proto`` parameter on ``__new__``,
``get`` and ``get_all``. The template wraps the literal in :func:`~typing.cast`
so mypy infers ``TransportProtocol`` there too, without changing what runs:
:func:`~typing.cast` is the identity function at run time, so
``TransportProtocol.undefined`` is the same ``0`` -- ``TransportProtocol(0) is
undefined`` and ``bool(undefined)`` is ``False`` -- and a genuine
``TransportProtocol`` member: the ``proto`` sentinel default at each of those
sites, and what the base registry's ``_missing_`` extends unassigned/reserved
rows from. Two rejected alternatives, measured rather than argued: an explicit
member annotation (``undefined: 'TransportProtocol' = 0``) does not fix this at
all, it only *relocates* the error -- mypy still reports one ``[assignment]`` at
the member's own declaration line, for 113 errors in 39 files rather than 116,
so ``cast`` is preferred 0/38 against 1/39, not on parity. ``auto() & 0`` is
run-time identical to the bare literal -- value ``0``, no burned counter slot,
``tcp``/``udp``/``sctp``/``dccp`` unaffected -- and is rejected only because it
leans on :mod:`aenum`'s undocumented internal order of operations for resolving
a composed ``auto()``, not because it misbehaves.

``undefined`` takes ``0`` directly and the other real transports use
``auto()``, so that no ``_start_`` has to be defined and the declaration of
``undefined`` is explicit (the owner's ruling on GitHub pull request #874);
``auto()`` picks up the next value after whatever came immediately before it,
explicit literal or not. That makes ``undefined`` the one member among the five
whose wrapper is load-bearing against a mypy error -- see
:meth:`AppTypeGeneratorShapeTests.
test_undefined_member_is_cast_rather_than_a_bare_literal`'s own docstring
for the measurements.

#744 and #768 are pinned two ways: directly against the generator's own
:meth:`~pcapkit.vendor.reg.apptype.apptype.AppType.flag`, which needs no
network access since it is a ``@staticmethod``, and against the files it
actually produced, committed under :mod:`pcapkit.const.reg.apptype`. #770 is
pinned against that same base module -- a plain source-text assertion that the
member stays wrapped in ``cast`` rather than being a bare literal, plus a
direct run through mypy's own API when :mod:`mypy` is importable, since the
source-text shape alone cannot tell a correct fix from a differently-worded
one that stops mypy agreeing.

That second pin is gated the way :mod:`tests._dependency_gates` can actually
see: a module-level ``HAS_MYPY`` flag and an ``@unittest.skipUnless``
decorator, with ``mypy`` mapped in
:data:`~tests._dependency_gates.MODULE_PROVIDERS` and its gap recorded as a
deliberate exclusion (#779). An inline ``try``/``except ImportError:
self.skipTest(...)`` would work, but is invisible to the guard *by
construction* -- :func:`~tests._dependency_gates._gates_of` walks a
definition's decorator list and never its body -- which is the "dark test"
hazard #745 exists to stop, and which #766 carries for the sibling isort check.

What the gate is worth: mypy is a :file:`Pipfile` ``[dev-packages]`` entry and
is in no :file:`pyproject.toml` extra, so no ``pytest`` job in
:file:`.github/workflows/unit-tests.yml` -- every one installs
``.[test,...]`` -- ever has it importable, and this test skips on all of them;
it runs where mypy is installed, which is a developer checkout and ``make
mypy``'s own environment. The skip is counted: it is a
:class:`~tests._dependency_gates.Gap` on each job that reaches it, and
:data:`~tests._dependency_gates.DEPENDENCY_GATE_EXCLUSIONS`\\ ``['HAS_MYPY']``
carries the reason for declining to close it -- a type checker belongs to the
lint tier, not to a pytest install line.

"""

import importlib.util
import unittest

#: Test tier (#1958): checks the shape of the AppType generator's source.
__tier__ = 'LATEST'

__all__ = ['AppTypeGeneratorShapeTests']

#: Whether :mod:`mypy` is importable, for the one test that runs it. A visible
#: ``skipUnless`` flag rather than an inline ``skipTest``, so
#: :func:`~tests._dependency_gates.gated_scopes` counts the gate and
#: :mod:`tests.test_tier_guard` can audit which CI jobs it darkens (#779); see
#: this module's own docstring for why.
HAS_MYPY = importlib.util.find_spec('mypy') is not None


class AppTypeGeneratorShapeTests(unittest.TestCase):
    """Pins to the mechanical shapes of #744, #768 and #770."""

    def test_flag_emits_attribute_access_not_get_calls(self) -> None:
        """GitHub issue #768, against the generator method directly.

        No CSV data and no network access needed: :meth:`AppType.flag` is a
        ``@staticmethod`` over a list of transport protocol names.
        """
        from pcapkit.vendor.reg.apptype.apptype import AppType

        self.assertEqual(AppType.flag(['tcp']), 'TransportProtocol.tcp')
        self.assertEqual(AppType.flag(['udp']), 'TransportProtocol.udp')
        self.assertEqual(AppType.flag(['undefined']), 'TransportProtocol.undefined')

        # Multiple protocols render in TRANSPORTS' declared order regardless
        # of the order they are passed in, so the same set always renders the
        # same source text.
        self.assertEqual(AppType.flag(['udp', 'tcp']),
                         'TransportProtocol.tcp | TransportProtocol.udp')
        self.assertEqual(AppType.flag(['dccp', 'sctp', 'udp', 'tcp']),
                         'TransportProtocol.tcp | TransportProtocol.udp | '
                         'TransportProtocol.sctp | TransportProtocol.dccp')

        for protos in (['tcp'], ['udp', 'tcp'], ['undefined']):
            with self.subTest(protos=protos):
                self.assertNotIn('.get(', AppType.flag(protos))

    def test_generated_registries_carry_no_per_member_annotation(self) -> None:
        """GitHub issue #744, against what the committed files produced.

        Guards against ``TCP.__annotations__`` holding an entry for every
        member on top of its class-level attributes. Only the
        class-level attributes each registry declares exactly once should
        remain: ``__transport__``, ``__registry__``, ``__canonical__``, and
        -- on the memberless base only -- ``__registries__``.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType

        self.assertEqual(set(AppType.__annotations__),
                         {'__transport__', '__registry__', '__registries__', '__canonical__'})

        for cls in (TCP, UDP, SCTP, DCCP):
            with self.subTest(registry=cls.__name__):
                self.assertEqual(set(cls.__annotations__),
                                 {'__transport__', '__registry__', '__canonical__'})
                # Not merely the same size: no member name leaked in either.
                self.assertFalse(set(cls.__annotations__) & set(cls.__members__))

    def test_no_transport_protocol_get_calls_survive_in_generated_output(self) -> None:
        """GitHub issue #768, swept over the generated source text itself.

        Every *generator-emitted* site -- one per member's ``proto``
        argument plus one per ``cls.__transport__ is ...`` range-row test and
        its own ``extend_enum(...)`` call -- uses attribute access, so the
        generated registries have none. The base module keeps one legitimate
        call, ``_dispatch``'s ``TransportProtocol.get(proto.lower())``,
        which resolves a *caller*-supplied string at run time and so cannot
        be a fixed attribute access -- exactly the "other callers" #768 says
        :meth:`~pcapkit.const.reg.apptype.apptype.TransportProtocol.get`
        stays for.
        """
        import inspect

        import pcapkit.const.reg.apptype.apptype as base_mod
        import pcapkit.const.reg.apptype.dccp as dccp_mod
        import pcapkit.const.reg.apptype.sctp as sctp_mod
        import pcapkit.const.reg.apptype.tcp as tcp_mod
        import pcapkit.const.reg.apptype.udp as udp_mod

        self.assertEqual(inspect.getsource(base_mod).count("TransportProtocol.get("), 1)
        for mod in (tcp_mod, udp_mod, sctp_mod, dccp_mod):
            with self.subTest(module=mod.__name__):
                self.assertEqual(inspect.getsource(mod).count("TransportProtocol.get("), 0)

    def test_undefined_member_is_cast_rather_than_a_bare_literal(self) -> None:
        """GitHub issue #770, against the generated source text itself.

        ``undefined`` is the one bare int literal among five members whose
        remaining four (``tcp``, ``udp``, ``sctp``, ``dccp``) are
        ``auto()``-valued, which is exactly the asymmetry #770 is about --
        mypy infers the literal as ``int`` and the ``auto()`` siblings as
        ``Any``, so wrapping the literal in :func:`~typing.cast` is what
        makes all five agree on ``TransportProtocol``.

        Measured directly, to prove the load-bearing claim rather than
        assert it: with ``undefined`` unwrapped to a bare ``0`` (everything
        else unchanged), the mypy run
        :meth:`test_undefined_member_infers_as_transport_protocol_under_mypy`
        below performs reports real errors -- see that method's own
        docstring for the exact count. Unwrapping ``tcp`` instead, leaving
        ``undefined`` wrapped, leaves that run clean, since ``tcp`` stays
        ``auto()``-valued and so infers as ``Any`` either way.
        """
        import inspect
        import re

        import pcapkit.const.reg.apptype.apptype as base_mod

        source = inspect.getsource(base_mod)

        # Neither check uses assertIn/assertNotRegex directly: both format
        # their default failure message from the *whole* ~200 KiB generated
        # module (assertIn via unittest.util.safe_repr(source, short=False),
        # assertNotRegex the same way) -- measured at 219,113 chars for the
        # first check alone. A plain containment test plus a bounded
        # snippet on failure keeps a real failure's message short instead,
        # for both checks alike.
        if "undefined = cast('TransportProtocol', 0)" not in source:
            self.fail("the cast is gone; expected "
                     "\"undefined = cast('TransportProtocol', 0)\"")

        # Not for the single-edit case above -- stripping the wrapper alone
        # (``undefined = 0``, nothing else touched) already fails the
        # containment check above, since the exact wrapped string is then
        # simply absent; measured directly against that scenario. This is
        # for the two-edit case the containment check cannot see: the
        # correct, wrapped line stays exactly as it should, and a second,
        # unwrapped ``undefined = 0`` sits somewhere else in the source --
        # a leftover from a bad edit, e.g. -- which a plain substring test
        # has no way to notice since the string it looks for is still
        # there. ``undefined = auto()`` bare is checked too: the owner's
        # ruling on GitHub pull request #874 rules that shape out, and a
        # regression to it would otherwise pass unnoticed, since it changes
        # no run-time value at all.
        for pattern in (r'\n[ \t]*undefined = 0[ \t]*\n',
                        r'\n[ \t]*undefined = auto\(\)[ \t]*\n'):
            match = re.search(pattern, source)
            if match is not None:
                self.fail('found an unwrapped undefined member near: %r'
                         % source[max(0, match.start() - 40):match.end() + 40])

    @unittest.skipUnless(HAS_MYPY, 'mypy is not installed')
    def test_undefined_member_infers_as_transport_protocol_under_mypy(self) -> None:
        """GitHub issue #770, run directly through mypy's own API.

        The source-text shape checked above cannot tell a correct fix from a
        differently-worded one that stops mypy agreeing, so this runs mypy
        itself against just the generated base module and requires a clean
        result -- the flags below are :file:`Makefile`'s own, but mypy also
        picks up :file:`mypy.ini` by discovery from the current working
        directory, exactly as ``make mypy`` does, so the effective config is
        stricter than these four flags alone would suggest.

        Measured directly: stripping just ``undefined``'s ``cast`` wrapper --
        ``undefined = 0``, every other member and the rest of the source
        unchanged -- gives three ``[assignment]`` errors -- ``__transport__``,
        ``__new__``'s ``proto`` default, and
        :meth:`~pcapkit.const.reg.apptype.apptype.AppType._unregistered_member`'s
        own ``proto`` default (#860), plainly ``TransportProtocol``-typed --
        plus one ``[arg-type]`` error per ``_missing_`` branch that passes
        ``TransportProtocol.undefined`` where it is then typed as a bare
        ``int``. ``get``'s and ``get_all``'s own ``proto`` parameters are
        annotated ``'TransportProtocol | str | int'`` (GitHub PR #836) -- a
        union a bare ``int`` default satisfies without error -- so they are
        not among the three. Stripping ``tcp``'s wrapper instead, leaving
        ``undefined`` wrapped, stays clean -- ``tcp`` is ``auto()``-valued,
        which infers as ``Any`` regardless of the wrapper (see
        :meth:`test_undefined_member_is_cast_rather_than_a_bare_literal`'s
        own docstring for that measurement). This test itself only ever runs
        mypy against the shipped source and requires zero errors of any code.

        This is not in :file:`.github/workflows/unit-tests.yml`'s reach --
        mypy is a :file:`Pipfile` ``[dev-packages]`` entry, not a
        :file:`pyproject.toml` extra, so no ``pytest`` job there ever has it
        importable -- and the ``HAS_MYPY`` gate above skips it there rather
        than erroring. That gate is a decorator precisely so
        :mod:`tests._dependency_gates` can count the skip instead of it being
        invisible; see this module's own docstring.
        """
        from mypy import api as mypy_api

        import pcapkit.const.reg.apptype.apptype as base_mod

        stdout, stderr, status = mypy_api.run([
            '--follow-imports=silent',
            '--ignore-missing-imports',
            '--show-column-numbers',
            '--show-error-codes',
            # Runs against a real file under the package, not a throwaway
            # string, so leaving the default cache directory on would write
            # a ~20 MiB .mypy_cache/ into the tree for one unit test -- most
            # of this method's run time, and disk this test has no business
            # spending. /dev/null is mypy's own documented "no cache" sentinel.
            '--cache-dir=/dev/null',
            base_mod.__file__,
        ])

        self.assertEqual(status, 0, msg=stdout + stderr)
        self.assertNotIn('[assignment]', stdout)

    def test_transport_protocol_undefined_still_zero(self) -> None:
        """GitHub issue #770: the ``cast`` changes nothing at run time.

        :func:`~typing.cast` is the identity function at run time, so
        ``TransportProtocol.undefined`` has to stay the same genuine
        ``TransportProtocol`` member with value ``0`` -- ``TransportProtocol(0)
        is undefined`` and ``bool(undefined)`` is ``False`` -- rather than
        merely being *typed* as one.

        ``TransportProtocol.tcp | TransportProtocol.undefined is
        TransportProtocol.tcp`` is not asserted: with no ``IntFlag`` base
        (GitHub issue #808), ``|`` on a plain :class:`~aenum.IntEnum` falls
        through to ``int.__or__`` and returns a bare :class:`int`, never a
        ``TransportProtocol`` -- not even one identical to an existing member
        -- so there is no singleton for ``is`` to find on *either* side of
        ``|``, and pinning ``int(tcp | undefined) == int(tcp)`` would only be
        pinning integer arithmetic.
        """
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIsInstance(TransportProtocol.undefined, TransportProtocol)
        self.assertEqual(int(TransportProtocol.undefined), 0)


if __name__ == '__main__':
    unittest.main()
