# -*- coding: utf-8 -*-
"""GitHub issue #2356: makers resolve a :obj:`str` enum name for a ``None`` default.

:meth:`~pcapkit.protocols.protocol.Protocol._make_index` resolves a :obj:`str`
name against the enum of the argument's default when no ``..._namespace`` is
given, so the makers whose argument defaults to ``None`` -- the MPL option's
``seed_type`` and the SMF_DPD option's ``tid_type`` (of both HOPOPT and
IPv6-Opts), and the HTTP/1.* start line's ``status`` -- raised
:exc:`~pcapkit.utilities.exceptions.ProtocolNotImplemented` for a name such as
``'IPv4'``. They now fall back to the argument's own enum, and a name builds
the same octets as the member it names.

The classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so that they belong to the
:mod:`pcapkit` import that is live when the test runs.

"""

import importlib
import unittest

from tests._support import reimport_once_per_class

#: The protocol classes sharing the option makers, by module and class name.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
)


class TestMakeStrEnumNameNoneDefault(unittest.TestCase):
    """Pin :obj:`str` enum names for the makers whose argument defaults to ``None``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protocols(self) -> 'list[type]':
        return [getattr(importlib.import_module(mod), name) for mod, name in PROTOCOLS]

    def test_mpl_seed_type_by_name(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.seed_id import SeedID

        for cls in self._protocols():
            proto = object.__new__(cls)
            for member in (SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER, SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER):
                with self.subTest(protocol=cls.__name__, seed_type=member.name):
                    by_member = proto._make_opt_mpl(Option.MPL_Option, seed_type=member, seed=1)
                    by_name = proto._make_opt_mpl(Option.MPL_Option, seed_type=member.name, seed=1)
                    self.assertEqual(by_name.pack(), by_member.pack())
                    self.assertEqual(by_name.flags['type'], int(member))

    def test_smf_dpd_tid_type_by_name(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.tagger_id import TaggerID

        for cls in self._protocols():
            proto = object.__new__(cls)
            for member, tid in ((TaggerID.IPv4, b'\x0a\x00\x00\x01'), (TaggerID.DEFAULT, b'\x01\x02')):
                with self.subTest(protocol=cls.__name__, tid_type=member.name):
                    by_member = proto._make_opt_smf_dpd(Option.SMF_DPD, mode='I_DPD', tid_type=member,
                                                        tid=tid, id=b'\x01')
                    by_name = proto._make_opt_smf_dpd(Option.SMF_DPD, mode='I_DPD', tid_type=member.name,
                                                      tid=tid, id=b'\x01')
                    self.assertEqual(by_name.pack(), by_member.pack())

    def test_http_status_by_name(self) -> None:
        from pcapkit.const.http.status_code import StatusCode
        from pcapkit.protocols.application.httpv1 import HTTP

        proto = object.__new__(HTTP)
        for member in (StatusCode.CODE_200, StatusCode.CODE_404):
            with self.subTest(status=member.name):
                line = proto._make_start_line('1.1', status=member.name)
                self.assertTrue(line.startswith(b'HTTP/1.1 %d ' % int(member)), line)

    def test_an_explicit_namespace_still_wins(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.seed_id import SeedID

        for cls in self._protocols():
            proto = object.__new__(cls)
            with self.subTest(protocol=cls.__name__):
                code = int(SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER)
                made = proto._make_opt_mpl(Option.MPL_Option, seed_type='short', seed=1,
                                           seed_type_namespace={code: 'short'})
                self.assertEqual(made.flags['type'], code)


if __name__ == '__main__':
    unittest.main()
