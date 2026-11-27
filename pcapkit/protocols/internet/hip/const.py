# -*- coding: utf-8 -*-
"""constants for HIP protocol

.. versionadded:: 1.7.0

"""

from pcapkit.const.hip.cipher import Cipher as Enum_Cipher
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as Enum_ECDSACurve
from pcapkit.const.hip.eddsa_curve import EdDSACurve as Enum_EdDSACurve
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as Enum_HIAlgorithm
from pcapkit.const.hip.hit_suite import HITSuite as Enum_HITSuite

__all__ = [
    'LOCATOR_SET_LEN',
    'ORCHID_PREFIX', 'HIT_SUITE_HASH', 'HI_ALGORITHM_SUITE', 'CIPHER_KEY_LEN',
    'ECDSA_CURVE_LEN', 'EDDSA_CURVE_LEN',
]

#: Packet-context key under which
#: :class:`~pcapkit.protocols.internet.hip.schema.LocatorSetParameter` keeps its
#: own ``Length`` for the benefit of
#: :func:`~pcapkit.protocols.internet.hip.schema.locator_set_padding_len`.
#:
#: It exists because the contents of ``LOCATOR_SET`` are a
#: :class:`~pcapkit.corekit.fields.collections.ListField` of nested schemas,
#: and a nested schema packed through one **shares the
#: enclosing packet context**: :meth:`Schema.pack
#: <pcapkit.protocols.schema.Schema.pack>` opens with
#: ``packet.update(self.__dict__)``, and
#: :class:`~pcapkit.protocols.internet.hip.schema.Locator` declares a ``len`` of
#: its own. So by the time ``padding`` is evaluated -- after the list, since
#: fields are packed in declaration order -- ``pkt['len']`` is the *last
#: locator's* ``len``, not the parameter's -- 4 for any IPv6 locator,
#: whatever the locator count.
#:
#: The shadowing is specific to the packing path. :meth:`Schema.unpack
#: <pcapkit.protocols.schema.Schema.unpack>` hands each field
#: ``packet.copy()``, so nested writes do not propagate back and ``pkt['len']``
#: stays the parameter's there. Snapshotting under a key no nested schema
#: declares is what makes one callback correct on both paths rather than
#: accidentally correct on one.
LOCATOR_SET_LEN = '__locator_set_len__'

#: The 28-bit ORCHIDv2 prefix ``2001:20::/28`` of a HIT (:rfc:`7343#section-2`),
#: whose next four bits, the OGA ID, name its HIT Suite (:rfc:`7401#section-3.1`).
#:
#: .. versionadded:: 1.9.0
ORCHID_PREFIX = 0x2001002

#: RHASH of each HIT Suite that has one, as a :mod:`hashlib` name. It is the hash
#: of the suite's HMAC (:rfc:`7401#section-6.4.1`) and of its signatures.
#: EdDSA/cSHAKE128 is left out, as its HMAC is KMAC128 (:rfc:`9374#section-3.4.2`).
#:
#: .. versionadded:: 1.9.0
HIT_SUITE_HASH = {
    Enum_HITSuite.RSA_DSA_SHA_256: 'sha256',
    Enum_HITSuite.ECDSA_SHA_384: 'sha384',
    Enum_HITSuite.ECDSA_LOW_SHA_1: 'sha1',
}

#: The HIT Suite of each Host Identity algorithm :rfc:`7401` defines
#: (:rfc:`7401#section-5.2.10`, Table 10).
#:
#: .. versionadded:: 1.9.0
HI_ALGORITHM_SUITE = {
    Enum_HIAlgorithm.DSA: Enum_HITSuite.RSA_DSA_SHA_256,
    Enum_HIAlgorithm.RSA: Enum_HITSuite.RSA_DSA_SHA_256,
    Enum_HIAlgorithm.ECDSA: Enum_HITSuite.ECDSA_SHA_384,
    Enum_HIAlgorithm.ECDSA_LOW: Enum_HITSuite.ECDSA_LOW_SHA_1,
}

#: Length, in octets, of the encryption key KEYMAT draws for each HIP cipher
#: (:rfc:`7401#section-6.5`).
#:
#: .. versionadded:: 1.9.0
CIPHER_KEY_LEN = {
    Enum_Cipher.NULL_ENCRYPT: 0,
    Enum_Cipher.AES_128_CBC: 16,
    Enum_Cipher.AES_256_CBC: 32,
}

#: Length, in octets, of a coordinate on each ECDSA curve (:rfc:`4754#section-3`).
#:
#: .. versionadded:: 1.9.0
ECDSA_CURVE_LEN = {
    Enum_ECDSACurve.NIST_P_256: 32,
    Enum_ECDSACurve.NIST_P_384: 48,
}

#: Length, in octets, of a public key on each EdDSA curve without pre-hashing
#: (:rfc:`8032#section-5`).
#:
#: .. versionadded:: 1.9.0
EDDSA_CURVE_LEN = {
    Enum_EdDSACurve.EdDSA25519: 32,
    Enum_EdDSACurve.EdDSA448: 57,
}
