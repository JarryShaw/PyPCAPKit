# -*- coding: utf-8 -*-
"""An option in the last two octets of a HOPOPT or IPv6-Opts header fails in-library.

GitHub issue #1195: an ``SMF_DPD`` option of ``Opt Data Len`` zero, placed in
the last two octets of the header (``3b00010200000800``), raised a bare
:exc:`TypeError` from
:func:`~pcapkit.protocols.schema.internet.hopopt.smf_i_dpd_id_len`. The option
starts with a :class:`~pcapkit.corekit.fields.misc.ForwardMatchField` three
octets wide, which came back one octet short at the end of the stream, yet
:meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>` rewound
the full three. The option was therefore re-read from the preceding ``PadN``
padding octet, as a ``Pad1`` option, so ``len`` was skipped and left as
:data:`~pcapkit.corekit.fields.field.NO_VALUE`.

Every case builds its own octets in memory and reads no capture. The classes
are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so that they belong to the
:mod:`pcapkit` import that is live when the test runs.

"""

import importlib
import io
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Next Header ``No Next Header``, ``Hdr Ext Len`` zero, then a ``PadN`` option
#: carrying two octets, leaving the last two octets of the header for the option
#: under test.
PREFIX = bytes.fromhex('3b00' '01020000')

#: The protocol classes sharing the option schema, by module and class name.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
)

#: ``RPL_Option_0x23`` fails here for an unrelated reason, tracked in #1196.
EXCLUDED = {0x23}


class TestSMFDPDTruncatedLength(unittest.TestCase):
    """Pin the error an option in the last two octets of the header raises."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protocols(self) -> 'list[type]':
        return [getattr(importlib.import_module(mod), name) for mod, name in PROTOCOLS]

    def test_smf_dpd_raises_field_value_error(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaisesRegex(FieldValueError, 'invalid SMF DPD option length: 0'):
                        cls(io.BytesIO(PREFIX + bytes.fromhex('0800')))

    def test_no_option_type_raises_a_non_library_error(self) -> None:
        from pcapkit.utilities.exceptions import BaseError

        for cls in self._protocols():
            for code in range(256):
                if code in EXCLUDED:
                    continue
                with self.subTest(protocol=cls.__name__, type=f'0x{code:02x}'):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        try:
                            cls(io.BytesIO(PREFIX + bytes([code, 0])))
                        except BaseError:
                            pass


if __name__ == '__main__':
    unittest.main()
