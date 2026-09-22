"""#649 -- the four MPTCP error messages that carried a doubled separator.

Four :exc:`~pcapkit.utilities.exceptions.ProtocolError` messages in the MPTCP
option handlers were spelled ``f'{self.alias}: : [OptNo …]'``, so they rendered
with an empty field between the protocol alias and the option number::

    TCP: : [OptNo 30] 1: invalid flags combination

The defect is presentational -- the exception type, the option number and the
subtype were always right, and nothing downstream parses these strings -- but it
is the string a user sees when an MP_JOIN or DSS option is rejected, and an empty
field reads as a value that failed to interpolate.

The correct form is not a matter of taste. The same file spells the same prefix
without the doubling in 28 other places, all
``f'{self.alias}: [OptNo {schema.kind}] …'``, so the four were outliers against a
house form in their own module; the fix moves them into it and the count becomes
32. Two sibling test modules already quote the single-separator form in their
docstrings, which is further evidence of what was intended.

Every message here is asserted **in full** rather than by substring. That is the
point of the change: a substring assertion on ``'invalid flags combination'``
passes both before and after it, so the two places that already exercise these
messages could not have caught this, and needed no edit --

* ``test_tcp_mptcp_join_flag_ordering_unit.py:404``, which asserts
  ``assertIn('invalid flags combination', str(caught.exception))`` against
  ``_make_mptcp_join``, and
* ``test_tcp_udp_unit.py:1629``, which asserts
  ``assertRaisesRegex(ProtocolError, 'invalid flags combination')`` against
  ``_read_mptcp_join``.

Two, not one: both match a substring that straddles the defect, and both still
pass unchanged. Neither module is touched by this change.

All four lines arrived together in ``3bba8a1748`` (2023-04-10) and were untouched
until now.

"""
from __future__ import annotations

import pathlib
import unittest
from typing import TYPE_CHECKING

import importlib.util

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields for a segment built through the public constructor, spelled with
#: the parameter names :meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>`
#: actually declares. The same mapping, and the same reason for not reusing
#: :data:`examples.generators.options.TCP_BASE`, as
#: :data:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit.TCP_HEADER`.
TCP_HEADER = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False,
    'psh': False, 'rst': False, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}

#: The rendering of a rejected MP_JOIN, in full. ``30`` is
#: :attr:`Option.Multipath_TCP <pcapkit.const.tcp.option.Option.Multipath_TCP>`
#: and ``1`` is :attr:`MPTCPOption.MP_JOIN
#: <pcapkit.const.tcp.mp_tcp_option.MPTCPOption.MP_JOIN>`; both format as their
#: integer value because both registries are :class:`~enum.IntEnum`-flavoured.
JOIN_MESSAGE = 'TCP: [OptNo 30] 1: invalid flags combination'

#: The rendering of a DSS option missing its required fields, in full. ``2`` is
#: :attr:`MPTCPOption.DSS <pcapkit.const.tcp.mp_tcp_option.MPTCPOption.DSS>`.
DSS_MESSAGE = 'TCP: [OptNo 30] 2: missing required fields'

#: What the four messages read before the fix, kept as a literal so each test can
#: assert it is gone rather than only that the new form is present.
DOUBLED_PREFIX = 'TCP: : '


class DummyData(dict):
    """Attribute access over a mapping, for standing in as an option schema."""

    __getattr__ = dict.__getitem__


def build_mptcp(*, syn: 'bool' = False, ack: 'bool' = False, **option: 'Any') -> 'Any':
    """Build a segment carrying one MPTCP option, through the public constructor.

    Args:
        syn: Whether to set the ``SYN`` flag, which selects the MP_JOIN layout.
        ack: Whether to set the ``ACK`` flag, which selects the MP_JOIN layout.
        **option: The option's own arguments, including ``subtype``.

    Returns:
        The constructed :class:`~pcapkit.protocols.transport.tcp.TCP` instance.

    Note:
        :mod:`pcapkit` is imported inside the function rather than at module
        level, for the reason the sibling MPTCP modules document at length: other
        modules in this suite purge ``pcapkit``'s submodules from
        :data:`sys.modules`, so a name bound at collection time can end up
        pointing at a schema class built from a stale ``Schema`` base.

    """
    from pcapkit.const.tcp.option import Option as Enum_Option
    from pcapkit.protocols.transport.tcp import TCP

    return TCP(syn=syn, ack=ack,
               options=[(Enum_Option.Multipath_TCP, option)],  # type: ignore[arg-type]
               **TCP_HEADER)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPMPTCPErrorMessageUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_read_mptcp_join_message(self) -> None:
        """``_read_mptcp_join``'s fall-through, the message #649 was reported against.

        Reached by calling the dispatcher directly on a *parsed* flagless segment.
        The public read path cannot get here --
        :func:`~pcapkit.protocols.schema.transport.tcp.mptcp_data_selector`
        rejects a flagless MP_JOIN with a ``FieldError`` before the dispatcher
        runs -- so the branch is latent, but latent only by virtue of a guard in
        a different file, and the string is still what a caller reaching it sees.
        The segment is parsed rather than having ``_flags`` written onto a bare
        ``object.__new__(TCP)``, because a hand-written attribute proves nothing
        about what production puts there.

        """
        import struct

        from pcapkit.const.tcp.flags import Flags as Enum_Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        # A bare 20-octet header -- data offset 5, no options -- with no flags set.
        raw = struct.pack('!HHIIBBHHH', 1, 2, 0, 0, 5 << 4, 0x00, 0, 0, 0)
        proto = TCP(raw, len(raw))
        self.assertEqual(proto._flags, Enum_Flags(0))

        schema = DummyData(kind=Option.Multipath_TCP, subtype=MPTCPOption.MP_JOIN)
        with self.assertRaises(ProtocolError) as caught:
            proto._read_mptcp_join(schema, options=DummyData())  # type: ignore[arg-type]

        self.assertEqual(str(caught.exception), JOIN_MESSAGE)
        self.assertNotIn(DOUBLED_PREFIX, str(caught.exception))

    def test_make_mptcp_join_message(self) -> None:
        """``_make_mptcp_join``'s fall-through, through the public constructor.

        Unlike the read side this one *is* reachable from a caller: a segment with
        neither SYN nor ACK carrying an MP_JOIN matches none of the three
        :rfc:`8684` section 3.2 layouts, and #634 is what lets the library's own
        error through rather than a bare :exc:`TypeError` from the membership
        test above it.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            build_mptcp(syn=False, ack=False,
                        subtype=MPTCPOption.MP_JOIN, hmac=bytes(20))

        self.assertEqual(str(caught.exception), JOIN_MESSAGE)
        self.assertNotIn(DOUBLED_PREFIX, str(caught.exception))

    def test_make_mptcp_dss_messages(self) -> None:
        """Both of ``_make_mptcp_dss``'s guards, which are two lines, not one.

        The two carry the identical message, so asserting the string once would
        not show that both were fixed. They are reached separately instead:

        * ``dsn`` given and ``ssn``/``dl_len``/``checksum`` absent -- the
          data-level fields a DSN requires are missing.
        * ``dsn`` absent and one of them given -- a data-level field present with
          no DSN to belong to.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'dsn without its data-level fields': {'dsn': 1},
            'data-level field without a dsn': {'ssn': 1},
        }
        for label, option in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError) as caught:
                    build_mptcp(subtype=MPTCPOption.DSS, **option)

                self.assertEqual(str(caught.exception), DSS_MESSAGE)
                self.assertNotIn(DOUBLED_PREFIX, str(caught.exception))

    def test_no_doubled_separator_survives_anywhere_in_the_module(self) -> None:
        """The source-level sweep, so a fifth site cannot be added unnoticed.

        The four were found by grepping for the pattern rather than by reading the
        one that was reported, and three of the four came from that grep. A test
        that pins only the four strings would not notice a fifth appearing, so
        the absence is asserted over the whole file -- and the single-separator
        count is asserted too, since deleting the four lines outright would
        satisfy an absence check on its own.

        """
        import pcapkit.protocols.transport.tcp as tcp_module

        source = pathlib.Path(tcp_module.__file__).read_text(encoding='utf-8')

        self.assertNotIn("f'{self.alias}: : ", source)
        self.assertEqual(source.count("f'{self.alias}: : "), 0)

        # 28 before the fix, 32 after: the four joined the house form rather than
        # being removed. A guard against "fixed" by deletion.
        #
        # NOTE TO A FUTURE EDITOR: this count is deliberately exact, and it is
        # therefore a tripwire on the whole module rather than on the four lines
        # #649 was about. Adding or removing *any* `f'{self.alias}: [OptNo …]'`
        # message anywhere in this ~3000-line file will fail this assertion for a
        # reason that has nothing to do with the doubled separator. That is
        # intended -- the alternative, asserting only the absence, passes if the
        # four lines are deleted outright -- so when you legitimately change the
        # number of such messages, update the number here rather than loosening
        # the assertion. The one above it, on the doubled form, is the one that
        # must stay at 0 forever.
        self.assertEqual(source.count("f'{self.alias}: [OptNo"), 32)


if __name__ == '__main__':
    unittest.main()
