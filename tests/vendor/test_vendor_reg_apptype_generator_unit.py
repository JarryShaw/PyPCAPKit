# -*- coding: utf-8 -*-
"""Three mechanical shapes :mod:`pcapkit.vendor.reg.apptype.apptype` must keep.

GitHub issue #744: every one of :class:`~pcapkit.const.reg.apptype.apptype.AppType`'s
~12,391 members used to be an *annotated* assignment --
``tcpmux: 'TCP' = 1, 'tcpmux', TransportProtocol.get('tcp') | TransportProtocol.get('udp')``
-- which put one forward-ref string per member into the class's
``__annotations__``. Sphinx's default autodoc calls
``sphinx.util.typing.get_type_hints(parent, ...)`` once per member
(``sphinx/ext/autodoc/_dynamic/_loader.py:367`` and ``:419`` -- the wrapper
around :func:`typing.get_type_hints` that catches the ``NameError`` a
``TYPE_CHECKING``-only forward ref would otherwise raise), each call
re-resolving the *whole* class, which is what made documenting this one
registry cost 378.8s on CI -- the single largest stall in the entire docs
build. The annotation carried no information a lookup needs: member
construction reads the positional tuple, not ``__annotations__``. Measured on
this checkout: dropping it removes 86,838 bytes (7/8 bytes per member,
depending on whether its class name is 3 or 4 letters long).

GitHub issue #768: the ``proto`` argument on every one of those members, and
every ``cls.__transport__ is ...`` test in a range-row ``_missing_`` branch,
called :meth:`~pcapkit.const.reg.apptype.apptype.TransportProtocol.get`
(524 ns, an ``isinstance`` check, two ``.lower()`` calls, a membership test
and a ``__getitem__``) to reach a member plain attribute access returns in
24 ns -- 23,941 call sites this checkout measured rewritten to the attribute
form, saving 7 bytes each (``TransportProtocol.get('tcp')`` is 28 characters,
``TransportProtocol.tcp`` is 21), for 167,587 bytes (163.7 KiB) of generated
source. The generator only ever emits the five declared names
(``TRANSPORTS + ('undefined',)``), so the attribute form cannot miss.

GitHub issue #770: ``undefined = 0`` in the ``BASE`` template is a bare int
literal, so mypy -- which has no :mod:`aenum` plugin and so treats this class
as a plain one -- infers the class attribute's type as ``int`` while the
``auto()``-valued siblings (``tcp``, ``udp``, ``sctp``, ``dccp``) infer as
``Any``. That is what made ``TransportProtocol.undefined`` disagree with its
own ``'TransportProtocol'`` annotation at the four sites that default to it --
the class attribute ``__transport__``, and the ``proto`` parameter on
``__new__``, ``get`` and ``get_all``. The fix wraps the literal in
:func:`~typing.cast` so mypy infers ``TransportProtocol`` there too, without
changing what runs: :func:`~typing.cast` is the identity function at run time,
so ``TransportProtocol.undefined`` stays the same ``0`` -- ``TransportProtocol(0)
is undefined`` and ``bool(undefined)`` is ``False`` -- and the same genuine
``TransportProtocol`` member it always was: the ``proto`` sentinel default at
all four sites, and what the base registry's ``_missing_`` extends
unassigned/reserved rows from. Two rejected alternatives, measured rather than
argued: an explicit member annotation (``undefined: 'TransportProtocol' = 0``)
does not fix this at all, it only *relocates* the error -- mypy still reports
one ``[assignment]`` at the member's own declaration line, for 113 errors in
39 files rather than 116, so ``cast`` is preferred 0/38 against 1/39, not on
parity. ``auto() & 0`` is run-time identical to the bare literal -- value
``0``, no burned counter slot, ``tcp``/``udp``/``sctp``/``dccp`` unaffected --
and is rejected only because it leans on :mod:`aenum`'s undocumented internal
order of operations for resolving a composed ``auto()``, not because it
misbehaves.

The first two are pinned two ways: directly against the generator's own
:meth:`~pcapkit.vendor.reg.apptype.apptype.AppType.flag`, which needs no
network access since it is a ``@staticmethod``, and against the five files it
actually produced, committed under :mod:`pcapkit.const.reg.apptype`. #770 is
pinned against that same base module -- a plain source-text assertion that the
member stays wrapped in ``cast`` rather than reverting to a bare literal, plus
a direct run through mypy's own API when :mod:`mypy` is importable, since the
source-text shape alone cannot tell a correct fix from a differently-worded
one that stops mypy agreeing. That second pin skips outright when mypy is not
importable, the same shape
:class:`~tests.project.test_isort_clean.TestIsortIsCleanOnThePackage` uses for
isort: mypy is a :file:`Pipfile` ``[dev-packages]`` entry (line 48) and is in
no :file:`pyproject.toml` extra, so no ``pytest`` job in
:file:`.github/workflows/unit-tests.yml` -- every one installs ``.[test,...]``
-- ever has it importable, and this test skips there rather than erroring.
That inline skip is, by #766's own description of the shape, invisible to
:mod:`tests._dependency_gates`'s own guard: gating it instead with a
``HAS_MYPY`` flag and ``@unittest.skipUnless`` was measured and rejected, not
merely not attempted -- ``mypy`` has no entry in that module's
``MODULE_PROVIDERS`` table and is in no :file:`pyproject.toml` extra to add
one for, so doing so breaks
:class:`~tests.test_tier_guard.DependencyGateCoverageTests` outright: a
``KeyError`` from :func:`~tests._dependency_gates.extras_providing` plus two
more failures raising ``AssertionError``, measured as 4 errors and 2 failures
of its 9 tests. #779 tracks closing that gap generally.

"""

import unittest

__all__ = ['AppTypeGeneratorShapeTests']


class AppTypeGeneratorShapeTests(unittest.TestCase):
    """Pins to the three mechanical changes #744, #768 and #770 made."""

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
        """GitHub issue #744, against what the five committed files produced.

        Before the fix, ``TCP.__annotations__`` alone held 6,150 entries --
        6,147 members plus its three class-level attributes. Only the
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

        23,941 *generator-emitted* sites this checkout measured -- one per
        member's ``proto`` argument plus one per ``cls.__transport__ is ...``
        range-row test and its own ``extend_enum(...)`` call -- were
        rewritten and have none. The 23,942nd site is the one legitimate
        survivor, ``_dispatch``'s ``TransportProtocol.get(proto.lower())``,
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

        ``undefined = 0`` is a bare int literal, so mypy infers the class
        attribute's type as ``int`` while the ``auto()``-valued siblings
        infer as ``Any`` -- mypy has no :mod:`aenum` plugin, so it never sees
        this as an enum at all. Wrapping the literal in
        :func:`~typing.cast` is what makes mypy infer ``TransportProtocol``
        instead, so the member has to stay wrapped rather than reverting to
        the bare form that reintroduces the four ``[assignment]`` errors.
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
            self.fail("the cast is gone; expected \"undefined = cast('TransportProtocol', 0)\"")

        match = re.search(r'\n[ \t]*undefined = 0[ \t]*\n', source)
        if match is not None:
            self.fail('found a bare literal near: %r'
                     % source[max(0, match.start() - 40):match.end() + 40])

    def test_undefined_member_infers_as_transport_protocol_under_mypy(self) -> None:
        """GitHub issue #770, run directly through mypy's own API.

        The source-text shape checked above cannot tell a correct fix from a
        differently-worded one that stops mypy agreeing, so this runs mypy
        itself against just the generated base module and requires a clean
        result -- the flags below are :file:`Makefile`'s own, but mypy also
        picks up :file:`mypy.ini` by discovery from the current working
        directory, exactly as ``make mypy`` does, so the effective config is
        stricter than these four flags alone would suggest. Before the fix
        this reproduces the issue's own repro exactly: 4 errors, all
        ``[assignment]``, at the class attribute ``__transport__`` and the
        ``proto`` default on ``__new__``, ``get`` and ``get_all``.

        This is not in :file:`.github/workflows/unit-tests.yml`'s reach --
        mypy is a :file:`Pipfile` ``[dev-packages]`` entry, not a
        :file:`pyproject.toml` extra, so no ``pytest`` job there ever has it
        importable -- and skips outright rather than erroring when it is not
        installed. See this module's own docstring for why that inline skip,
        rather than a tracked ``HAS_MYPY`` gate, is the deliberate choice.
        """
        try:
            from mypy import api as mypy_api
        except ImportError:
            self.skipTest('mypy is not installed')

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

    def test_transport_protocol_undefined_still_zero_and_composes(self) -> None:
        """GitHub issue #770: the ``cast`` changes nothing at run time.

        :func:`~typing.cast` is the identity function at run time, so
        ``TransportProtocol.undefined`` has to stay the same genuine
        ``TransportProtocol`` member with value ``0`` -- ``TransportProtocol(0)
        is undefined`` and ``bool(undefined)`` is ``False`` -- rather than
        merely being *typed* as one. There is no flag composition naming
        ``undefined`` in this module or its siblings to preserve; what the
        value has to keep is its role as the ``proto`` sentinel default and
        its neutrality under ``|``, checked directly below.
        """
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIsInstance(TransportProtocol.undefined, TransportProtocol)
        self.assertEqual(int(TransportProtocol.undefined), 0)
        self.assertIs(TransportProtocol.tcp | TransportProtocol.undefined, TransportProtocol.tcp)


if __name__ == '__main__':
    unittest.main()
