# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.pcapng`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.pcapng.block_type:BlockType': 'int',
    'pcapkit.const.pcapng.filter_type:FilterType': 'int',
    'pcapkit.const.pcapng.hash_algorithm:HashAlgorithm': 'int',
    'pcapkit.const.pcapng.option_type:OptionType': 'str',
    'pcapkit.const.pcapng.record_type:RecordType': 'int',
    'pcapkit.const.pcapng.secrets_type:SecretsType': 'int',
    'pcapkit.const.pcapng.tls_key_label:TLSKeyLabel': 'str',
    'pcapkit.const.pcapng.verdict_type:VerdictType': 'int',
}
