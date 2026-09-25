# -*- coding: utf-8 -*-
"""Two mechanical shapes :mod:`pcapkit.vendor.reg.apptype.apptype` must keep.

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

Both are pinned two ways: directly against the generator's own
:meth:`~pcapkit.vendor.reg.apptype.apptype.AppType.flag`, which needs no
network access since it is a ``@staticmethod``, and against the five files it
actually produced, committed under :mod:`pcapkit.const.reg.apptype`.

"""

import unittest

__all__ = ['AppTypeGeneratorShapeTests']


class AppTypeGeneratorShapeTests(unittest.TestCase):
    """Pins to the two mechanical changes #744 and #768 made."""

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


if __name__ == '__main__':
    unittest.main()
