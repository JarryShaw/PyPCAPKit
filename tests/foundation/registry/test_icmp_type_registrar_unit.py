# -*- coding: utf-8 -*-
"""``register_icmp_type`` routes each ICMP type to its own family's registry.

The wrapper takes the family from the enum its code is a member of, validates
the code against that enum, and writes through the family class's own
``register_type``. Each test restores the shipped entry it overrides.

"""

import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): a handful of hand-picked routing and rejection cases.
__tier__ = 'ALL'


class RegisterICMPTypeTests(unittest.TestCase):
    """Routing and validation of :func:`register_icmp_type`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_icmpv4_code_writes_icmpv4_registry_only(self) -> None:
        """An ICMPv4 type lands in ``ICMPv4.__type__`` and nowhere else."""
        from pcapkit.const.icmp.type import Type
        from pcapkit.foundation.registry.protocols import register_icmp_type
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        code = Type.Timestamp
        original = ICMPv4.__type__.get(code)
        try:
            register_icmp_type(code, 'none')
            self.assertEqual(ICMPv4.__type__[code], 'none')
            self.assertIsNone(ICMPv6.__type__.get(code))
        finally:
            if original is None:
                ICMPv4.__type__.pop(code, None)
            else:
                ICMPv4.__type__[code] = original

    def test_icmpv6_code_writes_icmpv6_registry_only(self) -> None:
        """An ICMPv6 type lands in ``ICMPv6.__type__`` and nowhere else."""
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.foundation.registry.protocols import register_icmp_type
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        code = Type.Router_Renumbering
        original = ICMPv6.__type__.get(code)
        try:
            register_icmp_type(code, 'none')
            self.assertEqual(ICMPv6.__type__[code], 'none')
            self.assertIsNone(ICMPv4.__type__.get(code))
        finally:
            if original is None:
                ICMPv6.__type__.pop(code, None)
            else:
                ICMPv6.__type__[code] = original

    def test_rejects_a_code_that_is_not_an_icmp_type(self) -> None:
        """A bare int, or a member of another enum, leaves both registries untouched."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_icmp_type
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.utilities.exceptions import RegistryError

        before = (dict(ICMPv4.__type__), dict(ICMPv6.__type__))
        with self.assertRaises(RegistryError):
            register_icmp_type(8, 'none')  # type: ignore[arg-type]
        with self.assertRaises(RegistryError):
            register_icmp_type(TransType.ICMP, 'none')  # type: ignore[arg-type]
        self.assertEqual(before, (dict(ICMPv4.__type__), dict(ICMPv6.__type__)))

    def test_rejects_a_method_name_with_no_parser(self) -> None:
        """A name with no ``_read_data_type_*`` method is refused before any write."""
        from pcapkit.const.icmp.type import Type
        from pcapkit.foundation.registry.protocols import register_icmp_type
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.utilities.exceptions import RegistryError

        code = Type.Timestamp
        original = ICMPv4.__type__.get(code)
        with self.assertRaises(RegistryError):
            register_icmp_type(code, 'no_such_kind')
        self.assertEqual(ICMPv4.__type__.get(code), original)


if __name__ == '__main__':
    unittest.main()
