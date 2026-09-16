# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.ngap`.

The fixture is 58 bytes of real aligned PER, built inline rather than read from
a capture: this is a unit-tier module, so :file:`tests/conftest.py` will not let
it read a generated capture, and an SCTP frame carrying it is cheap to construct
with :meth:`SCTP.make <pcapkit.protocols.transport.sctp.SCTP.make>`.

Two axes have to keep working, and only one of them needs |pycrate|_:

* **With** it, the fixture decodes and every surfaced field is asserted against
  the value that was encoded, and the encoding round-trips byte for byte.
* **Without** it, :mod:`pcapkit` still imports, :class:`NGAP` is still
  registered, and an NGAP payload degrades rather than raising. Those tests run
  unconditionally -- the missing-dependency path is reached by resetting the
  module's import cache, so it is exercised on a machine that *has* |pycrate|_
  too, which is the only way it gets covered in CI.

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate

"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest import mock

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_PYCRATE = importlib.util.find_spec('pycrate_asn1dir') is not None

#: An ``NGSetupRequest`` in aligned PER, 58 octets. Four IEs: Global RAN Node ID
#: (a ``globalGNB-ID`` whose ``gNB-ID`` is the 24-bit string ``0x000102``), RAN
#: Node Name ``pcapkit-gnb``, a one-entry Supported TA List for TAC ``0x000001``,
#: and Default Paging DRX ``v128``.
NGSETUP_REQUEST = bytes.fromhex(
    '00150036000004001b00080002f839100001020052400d0500706361706b69742d676e62'
    '0066000d00000000010002f839000000080015400140'
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NGAPUnitTests(unittest.TestCase):

    ##########################################################################
    # Helpers.
    ##########################################################################

    @staticmethod
    def _protocol():
        """An :class:`NGAP` instance with no packet bound to it."""
        from pcapkit.protocols.application.ngap import NGAP

        return object.__new__(NGAP)

    @staticmethod
    def _sctp_frame(payload: bytes, ppid: int = 60) -> bytes:
        """An SCTP packet whose single DATA chunk carries ``payload``."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        proto = SCTP.__new__(SCTP)
        return SCTP.make(
            proto, srcport=9899, dstport=38412, vtag=0x11223344,
            chunks=[(Chunk.Payload_Data, dict(I=True, U=True, B=True, E=True, tsn=1,
                                              stream_id=0, stream_seq=0, ppid=ppid,
                                              data=payload))],
        ).pack()

    ##########################################################################
    # Enumerations. These need no pycrate -- that is the point of them being
    # pasted in rather than generated at import time.
    ##########################################################################

    def test_enumerations_are_defined_without_pycrate(self) -> None:
        from pcapkit.protocols.application.ngap import (Criticality, PDUKind, ProcedureCode,
                                                        ProtocolIE)

        # Counts as measured against pycrate 0.8.1's NGAP_Constants. A drift
        # here means the pasted-in block was regenerated against a different
        # specification revision, which is worth noticing deliberately.
        self.assertEqual(len(ProcedureCode), 81)
        self.assertEqual(len(ProtocolIE), 438)
        self.assertEqual(len(Criticality), 3)
        self.assertEqual(len(PDUKind), 3)

        self.assertEqual(int(ProcedureCode.NGSetup), 21)
        self.assertEqual(int(ProcedureCode.InitialContextSetup), 14)
        self.assertEqual(int(ProtocolIE.GlobalRANNodeID), 27)
        self.assertEqual(int(ProtocolIE.RANNodeName), 82)
        self.assertEqual(int(ProtocolIE.SupportedTAList), 102)

        # An IE's ID name and its open type's name differ here, which is why
        # ``IE.type`` exists alongside ``IE.id``.
        self.assertEqual(int(ProtocolIE.DefaultPagingDRX), 21)

        self.assertEqual(PDUKind.INITIATING_MESSAGE, 'initiatingMessage')
        self.assertEqual(PDUKind.SUCCESSFUL_OUTCOME, 'successfulOutcome')
        self.assertEqual(PDUKind.UNSUCCESSFUL_OUTCOME, 'unsuccessfulOutcome')

    def test_criticality_resolves_names_and_rejects_a_fourth_value(self) -> None:
        from pcapkit.protocols.application.ngap import Criticality

        # pycrate hands back the ASN.1 identifier as a string, so the member
        # names have to be spelled that way for the lookup to be direct.
        self.assertIs(Criticality.get('reject'), Criticality.reject)
        self.assertIs(Criticality.get('ignore'), Criticality.ignore)
        self.assertIs(Criticality.get('notify'), Criticality.notify)
        self.assertIs(Criticality.get(2), Criticality.notify)
        self.assertIs(Criticality.get(Criticality.reject), Criticality.reject)
        self.assertEqual(Criticality.reject.name, 'reject')

        # Closed ENUMERATED: three values and no extension marker, so a fourth
        # is a bug rather than a newer release.
        with self.assertRaises(ValueError):
            Criticality(3)

    def test_unknown_procedure_and_ie_extend_rather_than_raise(self) -> None:
        from pcapkit.protocols.application.ngap import ProcedureCode, ProtocolIE

        # A pycrate carrying a newer NGAP than the pasted block decodes IEs
        # this package does not name; they must report, not explode.
        self.assertEqual(ProcedureCode(200).name, 'Unassigned_200')
        self.assertEqual(int(ProcedureCode(200)), 200)
        self.assertEqual(ProtocolIE(113).name, 'Unassigned_113')   # a real gap
        self.assertEqual(ProtocolIE(9000).name, 'Unassigned_9000')

        # ProcedureCode is INTEGER (0..255) and ProtocolIE-ID is (0..65535).
        with self.assertRaises(ValueError):
            ProcedureCode(256)
        with self.assertRaises(ValueError):
            ProtocolIE(65536)

    ##########################################################################
    # Registration and metadata. No pycrate needed.
    ##########################################################################

    def test_registered_on_both_ngap_payload_protocol_identifiers(self) -> None:
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.protocols.application.ngap import NGAP
        from pcapkit.protocols.transport.sctp import SCTP

        for ppid in (PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol,  # noqa: E501
                     PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP):  # noqa: E501
            with self.subTest(ppid=int(ppid)):
                self.assertIn(ppid, SCTP.__proto__)
                entry = SCTP.__proto__[ppid]
                # A ModuleDescriptor until the first dispatch resolves it.
                module = getattr(entry, 'module', None)
                if module is None:
                    self.assertIs(entry, NGAP)
                else:
                    self.assertEqual(module, 'pcapkit.protocols.application.ngap')
                    self.assertEqual(entry.name, 'NGAP')

    def test_name_length_and_length_hint(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP

        ngap = self._protocol()
        self.assertEqual(ngap.name, 'NG Application Protocol')
        self.assertEqual(ngap.layer, 'Application')
        self.assertEqual(ngap.__length_hint__(), 4)

        # ``length`` is the whole PDU: NGAP prefixes it with no header.
        ngap.__header__ = mock.Mock(data=NGSETUP_REQUEST)
        self.assertEqual(ngap.length, 58)

        # An application protocol carries no numeral registry index.
        from pcapkit.utilities.exceptions import IntError
        with self.assertRaises(IntError):
            NGAP.__index__()

    def test_exported_from_the_package_namespaces(self) -> None:
        import pcapkit
        from pcapkit.protocols.application import NGAP as ApplicationNGAP
        from pcapkit.protocols.application.ngap import NGAP
        from pcapkit.protocols.data.application import NGAP as DataNGAP
        from pcapkit.protocols.schema.application import NGAP as SchemaNGAP

        self.assertIs(pcapkit.NGAP, NGAP)
        self.assertIs(ApplicationNGAP, NGAP)
        self.assertIn('NGAP', pcapkit.protocols.__proto__)
        self.assertIs(pcapkit.protocols.__proto__['NGAP'], NGAP)
        self.assertIsNot(DataNGAP, NGAP)
        self.assertIsNot(SchemaNGAP, NGAP)

    ##########################################################################
    # The missing-dependency path, exercised whether or not pycrate is present.
    ##########################################################################

    def test_read_without_pycrate_raises_protocol_error(self) -> None:
        from pcapkit.protocols.application import ngap as ngap_module
        from pcapkit.utilities.exceptions import ProtocolError

        ngap = self._protocol()
        ngap.__cached__ = {}
        ngap._data = NGSETUP_REQUEST
        ngap.__header__ = mock.Mock(data=NGSETUP_REQUEST)

        with mock.patch.object(ngap_module, '_PYCRATE', None):
            with self.assertRaises(ProtocolError) as caught:
                ngap.read()
        self.assertIn('pycrate', str(caught.exception))
        self.assertIn('pypcapkit[NGAP]', str(caught.exception))

    def test_make_without_pycrate_raises_protocol_error(self) -> None:
        from pcapkit.protocols.application import ngap as ngap_module
        from pcapkit.utilities.exceptions import ProtocolError

        ngap = self._protocol()

        with mock.patch.object(ngap_module, '_PYCRATE', None):
            with self.assertRaises(ProtocolError) as caught:
                ngap.make(procedure=21, message='NGSetupRequest', value={'protocolIEs': []})
        self.assertIn('pycrate', str(caught.exception))

    def test_load_pycrate_caches_a_failed_import(self) -> None:
        from pcapkit.protocols.application import ngap as ngap_module

        # ``None`` in sys.modules makes ``from pycrate_asn1dir.NGAP import ...``
        # raise ImportError, which is the branch a machine without pycrate takes.
        with mock.patch.object(ngap_module, '_PYCRATE', NotImplemented):
            with mock.patch.dict(sys.modules, {'pycrate_asn1dir.NGAP': None}):
                self.assertIsNone(ngap_module.load_pycrate())
                # Cached, so a capture full of NGAP does not retry the import.
                self.assertIsNone(ngap_module._PYCRATE)
            self.assertIsNone(ngap_module.load_pycrate())

    def test_make_requires_procedure_and_message(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        ngap = self._protocol()
        for kwargs in ({}, {'procedure': 21}, {'message': 'NGSetupRequest'}):
            with self.subTest(**kwargs):
                with self.assertRaises(ProtocolError):
                    ngap.make(**kwargs)

    def test_make_from_raw_bytes_needs_no_pycrate(self) -> None:
        from pcapkit.protocols.application import ngap as ngap_module

        ngap = self._protocol()
        with mock.patch.object(ngap_module, '_PYCRATE', None):
            schema = ngap.make(data=NGSETUP_REQUEST)
        self.assertEqual(schema.data, NGSETUP_REQUEST)

    def test_sctp_payload_degrades_to_raw_without_pycrate(self) -> None:
        """A capture parses end to end with no |pycrate|_ installed.

        This is the behaviour the optional dependency buys its optionality with:
        the payload reaches :class:`~pcapkit.protocols.misc.raw.Raw` through
        :func:`~pcapkit.utilities.decorators.beholder` rather than aborting the
        frame, and keeps the PPID's name while doing so.

        """
        import io

        from pcapkit.protocols.application import ngap as ngap_module
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.sctp import SCTP

        raw = self._sctp_frame(NGSETUP_REQUEST)
        with mock.patch.object(ngap_module, '_PYCRATE', None):
            packet = SCTP(io.BytesIO(raw), len(raw))

        self.assertEqual(int(packet.ppid), 60)
        self.assertIsInstance(packet.payload, Raw)
        self.assertEqual(bytes(packet.payload), NGSETUP_REQUEST)
        self.assertEqual(str(packet.protochain),
                         'SCTP:PayloadProtocolIdentifier_3GPP_NG_Application_Protocol')

    ##########################################################################
    # Decoding. These need pycrate.
    ##########################################################################

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_fixture_decodes_and_surfaces_the_promised_fields(self) -> None:
        from pcapkit.protocols.application.ngap import (NGAP, Criticality, PDUKind,
                                                        ProcedureCode, ProtocolIE)

        info = NGAP(NGSETUP_REQUEST).info

        self.assertIs(info.kind, PDUKind.INITIATING_MESSAGE)
        self.assertIs(info.procedure, ProcedureCode.NGSetup)
        self.assertIs(info.criticality, Criticality.reject)
        self.assertEqual(info.message, 'NGSetupRequest')
        self.assertEqual(len(info.ies), 4)

        self.assertEqual(
            [(ie.id, ie.criticality, ie.type) for ie in info.ies],
            [(ProtocolIE.GlobalRANNodeID, Criticality.reject, 'GlobalRANNodeID'),
             (ProtocolIE.RANNodeName, Criticality.ignore, 'RANNodeName'),
             (ProtocolIE.SupportedTAList, Criticality.reject, 'SupportedTAList'),
             # IE 21 is id-DefaultPagingDRX; its open type is PagingDRX.
             (ProtocolIE.DefaultPagingDRX, Criticality.ignore, 'PagingDRX')],
        )

        # ``value`` holds the message body converted in full, so ``ies`` is a
        # view of it rather than the only way in.
        self.assertEqual(len(info.value['protocolIEs']), 4)

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_generic_conversion_preserves_asn1_shapes(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP
        from pcapkit.protocols.data.application.ngap import BitString, Choice, Sequence

        info = NGAP(NGSETUP_REQUEST).info

        # CHOICE -> Choice, keeping the alternative's name.
        node_id = info.ies[0].value
        self.assertIsInstance(node_id, Choice)
        self.assertEqual(node_id.name, 'globalGNB-ID')
        self.assertIsInstance(node_id.value, Sequence)

        # OCTET STRING stays bytes; a hyphenated ASN.1 name is reachable by
        # subscription, which is why the conversion does not rewrite keys.
        self.assertEqual(node_id.value['pLMNIdentity'], b'\x02\xf8\x39')
        gnb = node_id.value['gNB-ID']
        self.assertIsInstance(gnb, Choice)

        # BIT STRING -> BitString, so the bit length survives.
        self.assertIsInstance(gnb.value, BitString)
        self.assertEqual(gnb.value.value, 0x000102)
        self.assertEqual(gnb.value.length, 24)

        # SEQUENCE OF -> list; PrintableString / ENUMERATED stay str.
        self.assertEqual(info.ies[1].value, 'pcapkit-gnb')
        self.assertEqual(info.ies[3].value, 'v128')
        ta_list = info.ies[2].value
        self.assertIsInstance(ta_list, list)
        self.assertEqual(len(ta_list), 1)
        self.assertEqual(ta_list[0]['tAC'], b'\x00\x00\x01')
        slices = ta_list[0]['broadcastPLMNList'][0]['tAISliceSupportList']
        self.assertEqual(slices[0]['s-NSSAI']['sST'], b'\x01')

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_read_make_round_trip_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP

        ngap = NGAP(NGSETUP_REQUEST)
        rebuilt = ngap.make(**NGAP._make_data(ngap.info))
        self.assertEqual(rebuilt.data, NGSETUP_REQUEST)

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_make_data_reports_every_field_make_consumes(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP

        info = NGAP(NGSETUP_REQUEST).info
        kwargs = NGAP._make_data(info)

        self.assertEqual(set(kwargs),
                         {'kind', 'procedure', 'criticality', 'message', 'value', 'data'})
        self.assertIs(kwargs['kind'], info.kind)
        self.assertIs(kwargs['procedure'], info.procedure)
        self.assertIsNone(kwargs['data'])

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_make_accepts_plain_python_values(self) -> None:
        from pcapkit.protocols.application.ngap import NGAP, Criticality, ProcedureCode

        ngap = self._protocol()
        schema = ngap.make(
            kind='initiatingMessage',
            procedure=ProcedureCode.NGSetup,
            criticality=Criticality.reject,
            message='NGSetupRequest',
            value={'protocolIEs': [
                {'id': 82, 'criticality': 'ignore',
                 'value': ('RANNodeName', 'pcapkit-gnb')},
            ]},
        )
        # Decodes back to what went in, which is the check that matters -- the
        # byte string itself is pycrate's business.
        info = NGAP(schema.data).info
        self.assertEqual(info.message, 'NGSetupRequest')
        self.assertEqual(len(info.ies), 1)
        self.assertEqual(info.ies[0].value, 'pcapkit-gnb')

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_make_rejects_a_message_the_specification_cannot_encode(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        ngap = self._protocol()
        with self.assertRaises(ProtocolError) as caught:
            ngap.make(procedure=21, message='NotAMessageType', value={})
        self.assertIn('cannot encode', str(caught.exception))

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_malformed_payloads_raise_protocol_error_not_pycrate_errors(self) -> None:
        """Nothing from |pycrate|_'s own exception hierarchies may escape.

        It raises from two unrelated ones -- ``pycrate_asn1rt.err.ASN1Err`` and
        ``pycrate_core.charpy.CharpyErr`` -- and a truncated payload can also
        surface as ``KeyError`` or ``IndexError`` from inside the codec. Every
        one of those has to arrive as
        :exc:`~pcapkit.utilities.exceptions.ProtocolError`, or an NGAP packet
        fails differently from every other protocol in the library.

        """
        from pcapkit.protocols.application.ngap import NGAP
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'truncated header': NGSETUP_REQUEST[:2],
            'truncated body': NGSETUP_REQUEST[:7],
            'truncated mid-IE': NGSETUP_REQUEST[:40],
            'invalid choice index': b'\xff' * 8,
            'not asn.1 at all': bytes(range(16)),
            'ascii text': b'this is not a PDU',
            'trailing garbage': NGSETUP_REQUEST + b'\xde\xad\xbe\xef',
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                try:
                    info = NGAP(payload).info
                except ProtocolError as exc:
                    self.assertIn('NGAP:', str(exc))
                else:
                    # Decoding a prefix or ignoring a suffix is legitimate PER
                    # behaviour; what matters is that it did not raise something
                    # raw. Assert it produced a usable model.
                    self.assertIsNotNone(info.message)

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_end_to_end_through_sctp(self) -> None:
        """PPID 60 dispatches an SCTP DATA chunk to :class:`NGAP`."""
        import io

        from pcapkit.protocols.application.ngap import NGAP, ProcedureCode
        from pcapkit.protocols.transport.sctp import SCTP

        raw = self._sctp_frame(NGSETUP_REQUEST)
        packet = SCTP(io.BytesIO(raw), len(raw))

        self.assertEqual(int(packet.ppid), 60)
        self.assertIsInstance(packet.payload, NGAP)
        self.assertIs(packet.payload.info.procedure, ProcedureCode.NGSetup)
        self.assertEqual(packet.payload.info.message, 'NGSetupRequest')
        self.assertEqual(str(packet.protochain), 'SCTP:NGAP')

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_reset_val_is_never_called_on_the_parse_path(self) -> None:
        """The ~105 ms trap, asserted rather than left to a comment.

        ``NGAP_PDU.reset_val()`` walks all 318 submodules of the compiled
        specification. Calling it once per decode costs some 700x the decode
        itself, and ``from_aper()`` overwrites the stored value regardless, so
        it buys nothing. A future edit that adds it back is a 700x regression
        with no visible symptom, which is exactly the kind of thing a test
        should hold.

        """
        from pcapkit.protocols.application.ngap import NGAP, load_pycrate

        pdu = load_pycrate()
        with mock.patch.object(type(pdu), 'reset_val') as reset:
            NGAP(NGSETUP_REQUEST).info
        reset.assert_not_called()

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_consecutive_decodes_do_not_share_state(self) -> None:
        """The module-level PDU object is stateful; the models must not be.

        ``get_val()`` hands back the decoder's own containers rather than
        copies, so a model that held a reference into them would be rewritten by
        the next decode. Two decodes and a comparison is what catches that.

        """
        from pcapkit.protocols.application.ngap import NGAP

        first = NGAP(NGSETUP_REQUEST).info
        snapshot = (first.message, [ie.id for ie in first.ies],
                    first.ies[1].value, first.ies[0].value.name)

        other = self._protocol().make(
            procedure=9, message='ErrorIndication', value={'protocolIEs': []})
        second = NGAP(other.data).info
        self.assertEqual(second.message, 'ErrorIndication')

        self.assertEqual((first.message, [ie.id for ie in first.ies],
                          first.ies[1].value, first.ies[0].value.name), snapshot)


if __name__ == '__main__':
    unittest.main()
