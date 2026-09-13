from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[1]


def ensure_package(name: str, path: pathlib.Path) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        module.__path__ = [str(path)]
        module.__package__ = name
        sys.modules[name] = module
    return module


def load_module(module_name: str, relative_path: str):
    parts = module_name.split('.')
    for index in range(1, len(parts)):
        package_name = '.'.join(parts[:index])
        package_path = ROOT.joinpath(*parts[:index])
        ensure_package(package_name, package_path)

    spec = importlib.util.spec_from_file_location(module_name, ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load module {module_name!r} from {relative_path!r}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def bootstrap_core_modules() -> dict[str, object]:
    load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')
    compat = load_module('pcapkit.utilities.compat', 'pcapkit/utilities/compat.py')
    exceptions = load_module('pcapkit.utilities.exceptions', 'pcapkit/utilities/exceptions.py')
    warnings = load_module('pcapkit.utilities.warnings', 'pcapkit/utilities/warnings.py')
    multidict = load_module('pcapkit.corekit.multidict', 'pcapkit/corekit/multidict.py')
    decorators = load_module('pcapkit.utilities.decorators', 'pcapkit/utilities/decorators.py')
    protochain = load_module('pcapkit.corekit.protochain', 'pcapkit/corekit/protochain.py')
    return {
        'compat': compat,
        'exceptions': exceptions,
        'warnings': warnings,
        'multidict': multidict,
        'decorators': decorators,
        'protochain': protochain,
    }


def install_fake_protocol_module() -> type:
    ensure_package('pcapkit.protocols', ROOT / 'pcapkit' / 'protocols')

    protocol_module = types.ModuleType('pcapkit.protocols.protocol')

    class ProtocolBase:
        alias = 'PROTOCOL'

        @classmethod
        def id(cls) -> tuple[str, ...]:
            return (cls.__name__,)

        @classmethod
        def expand_comp(cls, value) -> tuple[object, ...]:
            if isinstance(value, cls):
                return (type(value), value.alias.upper(), *(name.upper() for name in type(value).id()))
            if isinstance(value, type) and issubclass(value, cls):
                return (value, value.__name__.upper(), *(name.upper() for name in value.id()))
            if isinstance(value, str):
                return (value.upper(),)
            return (value,)

    protocol_module.ProtocolBase = ProtocolBase
    sys.modules['pcapkit.protocols.protocol'] = protocol_module
    return ProtocolBase


def install_fake_payload_protocols(raw_cls: type, null_cls: type) -> None:
    ensure_package('pcapkit.protocols.misc', ROOT / 'pcapkit' / 'protocols' / 'misc')

    raw_module = types.ModuleType('pcapkit.protocols.misc.raw')
    raw_module.Raw = raw_cls
    sys.modules['pcapkit.protocols.misc.raw'] = raw_module

    null_module = types.ModuleType('pcapkit.protocols.misc.null')
    null_module.NoPayload = null_cls
    sys.modules['pcapkit.protocols.misc.null'] = null_module


def purge_modules(prefixes: Iterable[str]) -> None:
    for name in list(sys.modules):
        if any(name == prefix or name.startswith(prefix + '.') for prefix in prefixes):
            sys.modules.pop(name, None)


def close_extractor(extractor: object) -> None:
    stream = getattr(extractor, '_ifile', None)
    if stream is not None and hasattr(stream, 'close'):
        stream.close()
