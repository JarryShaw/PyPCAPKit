# -*- coding: utf-8 -*-
"""The grouped, keyword-only parameters of ``Extractor`` and ``extract()`` -- #2836.

Design B of #2834: ``fin`` stays positional, every other parameter is keyword-only
with its real default, and the output, reassembly, flow tracing and input settings
are the :mod:`pcapkit.foundation.options` classes. ``reassembly`` and ``traceflow``
also take a list of registered names, and no names turn the feature off with a
warning. The options are exported from :mod:`pcapkit` too. The flat keywords are
gone with no shim, nothing is written without ``dump``, ``fin`` is opened as
named, and an unknown ``layer`` raises; the layer names have one source.

Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

import inspect
import io
import os
import pickle
import shutil
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pins the package's main entry points, and its options'
#: immutability and pickling.
__tier__ = 'ALL'

#: The signature ruled on #2834, as ``(name, default)`` pairs after ``fin``.
RULED = (('dump', None), ('engine', 'default'), ('layer', None), ('protocol', None),
         ('context', None), ('reassembly', None), ('traceflow', None), ('stream', None),
         ('auto', True), ('store', True), ('verbose', False))

#: Every keyword #2836 removes, with a value it used to take.
REMOVED = {
    'trace': ['tcp'], 'nofile': True, 'fout': 'out', 'format': 'json', 'extension': False, 'files': True,
    'ip': True, 'ipv4': True, 'ipv6': True, 'tcp': True, 'dtls': True,
    'reasm_strict': False, 'reasm_store': False, 'reasm_timeout': 1.0, 'reasm_protocols': ['tcp'],
    'trace_fout': 'flows', 'trace_format': 'json', 'trace_byteorder': 'big', 'trace_nanosecond': True,
    'trace_bidirectional': False, 'trace_analyse': True,
    'buffer_size': 1024, 'buffer_save': True, 'buffer_path': 'buffer', 'no_eof': True,
}


class _Case(unittest.TestCase):
    """Imports once per class, in a scratch working directory."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)

    def extract(self, *args: 'Any', **kwargs: 'Any') -> 'Any':
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(*args, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor


class SignatureTests(_Case):
    """``extract()`` takes exactly ``Extractor``'s parameters, as ruled."""

    def test_extract_mirrors_the_extractor(self) -> None:
        from pcapkit import extract
        from pcapkit.foundation.extraction import Extractor

        mirrored = list(inspect.signature(Extractor.__init__).parameters.values())[1:]
        self.assertEqual(list(inspect.signature(extract).parameters.values()), mirrored)

    def test_fin_is_positional_and_the_rest_keyword_only_with_real_defaults(self) -> None:
        from pcapkit.foundation.extraction import Extractor

        fin, *rest = list(inspect.signature(Extractor.__init__).parameters.values())[1:]
        self.assertEqual((fin.name, fin.kind, fin.default),
                         ('fin', inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty))
        self.assertEqual([(param.name, param.default) for param in rest], list(RULED))
        self.assertEqual({param.kind for param in rest}, {inspect.Parameter.KEYWORD_ONLY})

    def test_every_removed_keyword_is_refused(self) -> None:
        for keyword, value in REMOVED.items():
            # NOTE: ``RegistryError`` is a ``TypeError`` too, so the message tells them apart.
            with self.subTest(keyword=keyword), self.assertRaises(TypeError) as caught:
                self.extract(sample_path('in.pcap'), **{keyword: value})
            self.assertIn(f'unexpected keyword argument {keyword!r}', str(caught.exception))
        with self.assertRaises(TypeError):
            self.extract(sample_path('in.pcap'), 'out')
        with self.assertRaises(TypeError):
            self.extract()

    def test_engine_must_be_a_name(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        for engine in (None, 3):
            with self.subTest(engine=engine), self.assertRaises(RegistryError) as caught:
                self.extract(sample_path('in.pcap'), engine=engine)
            self.assertEqual(str(caught.exception), f"'Extractor(engine={engine!r})': expected an engine name")


class OptionClassTests(_Case):
    """Each options class is an immutable ``Info`` built from keywords alone."""

    def _classes(self) -> 'dict[str, tuple[type, dict[str, Any]]]':
        from pcapkit.foundation.options import (DumpOptions, ReassemblyOptions, StreamOptions,
                                                TraceFlowOptions)

        return {
            'DumpOptions': (DumpOptions, {'fout': 'out'}),
            'ReassemblyOptions': (ReassemblyOptions, {'protocols': ['tcp']}),
            'TraceFlowOptions': (TraceFlowOptions, {'protocols': ['tcp']}),
            'StreamOptions': (StreamOptions, {}),
        }

    def test_defaults_are_the_real_ones(self) -> None:
        import sys

        expected = {
            'DumpOptions': {'fout': 'out', 'format': 'tree', 'files': False, 'extension': True},
            'ReassemblyOptions': {'protocols': ('tcp',), 'strict': True, 'store': True, 'timeout': None},
            'TraceFlowOptions': {'protocols': ('tcp',), 'fout': './tmp', 'format': 'pcap',
                                 'byteorder': sys.byteorder, 'nanosecond': False, 'bidirectional': True,
                                 'analyze': False, 'timeout': None},
            'StreamOptions': {'buffer_size': io.DEFAULT_BUFFER_SIZE, 'buffer_save': False,
                              'buffer_path': None, 'no_eof': False},
        }
        for name, (klass, required) in self._classes().items():
            with self.subTest(options=name):
                self.assertEqual(dict(klass(**required)), expected[name])

    def test_parameters_are_keyword_only_and_closed(self) -> None:
        from pcapkit.corekit.infoclass import Info

        for name, (klass, required) in self._classes().items():
            with self.subTest(options=name):
                self.assertTrue(issubclass(klass, Info))
                params = inspect.signature(klass).parameters.values()
                self.assertEqual({param.kind for param in params}, {inspect.Parameter.KEYWORD_ONLY})
                with self.assertRaises(TypeError):
                    klass(*(required.values() or [1024]))
                with self.assertRaises(TypeError):
                    klass(**required, no_such_option=True)

    def test_options_are_immutable_and_pickle(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        for name, (klass, required) in self._classes().items():
            with self.subTest(options=name):
                options = klass(**required)
                key = next(iter(options))
                with self.assertRaises(UnsupportedCall):
                    setattr(options, key, None)
                self.assertEqual(getattr(options, key), dict(options)[key])
                self.assertEqual(pickle.loads(pickle.dumps(options)), options)

    def test_protocols_are_lower_cased_once_each(self) -> None:
        from pcapkit.foundation.options import ReassemblyOptions, TraceFlowOptions

        self.assertEqual(ReassemblyOptions(protocols=('IPv4', 'tcp', 'ipv4')).protocols, ('ipv4', 'tcp'))
        self.assertEqual(TraceFlowOptions(protocols=iter(['TCP'])).protocols, ('tcp',))

    def test_protocols_must_be_a_list_of_names(self) -> None:
        from pcapkit.foundation.options import ReassemblyOptions, TraceFlowOptions
        from pcapkit.utilities.exceptions import RegistryError

        for klass in (ReassemblyOptions, TraceFlowOptions):
            for protocols in ('tcp', b'tcp', True, None, ['tcp', 6]):
                with self.subTest(options=klass.__name__, protocols=protocols), \
                        self.assertRaises(RegistryError):
                    klass(protocols=protocols)


    def test_fout_must_be_a_file_name(self) -> None:
        from pcapkit.foundation.options import DumpOptions
        from pcapkit.utilities.exceptions import RegistryError

        for fout in (None, 3, b'out'):
            with self.subTest(fout=fout), self.assertRaises(RegistryError):
                DumpOptions(fout=fout)  # type: ignore[arg-type]

    def test_no_names_are_allowed(self) -> None:
        from pcapkit.foundation.options import ReassemblyOptions, TraceFlowOptions

        self.assertEqual(ReassemblyOptions(protocols=[]).protocols, ())
        self.assertEqual(TraceFlowOptions(protocols=iter(())).protocols, ())

    def test_options_are_exported_where_extract_is(self) -> None:
        import pcapkit
        import pcapkit.all
        import pcapkit.foundation
        import pcapkit.interface
        from pcapkit.foundation.options import (DumpOptions, ReassemblyOptions, StreamOptions,
                                                TraceFlowOptions)

        for klass in (DumpOptions, ReassemblyOptions, TraceFlowOptions, StreamOptions):
            self.assertEqual(klass.__module__, 'pcapkit.foundation.options')
            for module in (pcapkit, pcapkit.interface, pcapkit.foundation, pcapkit.all):
                with self.subTest(options=klass.__name__, module=module.__name__):
                    self.assertIn(klass.__name__, module.__all__)
                    self.assertIs(getattr(module, klass.__name__), klass)

    def test_unshipped_names_and_paths_are_gone(self) -> None:
        import pcapkit
        import pcapkit.all
        import pcapkit.foundation
        import pcapkit.foundation.extraction
        import pcapkit.foundation.reassembly
        import pcapkit.foundation.traceflow
        import pcapkit.interface

        moved = {pcapkit.foundation.extraction: ('DumpOptions', 'StreamOptions'),
                 pcapkit.foundation.reassembly: ('ReassemblyOptions',),
                 pcapkit.foundation.traceflow: ('TraceFlowOptions',)}
        for module, names in moved.items():
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertNotIn(name, module.__all__)
        for module in (*moved, pcapkit, pcapkit.interface, pcapkit.foundation, pcapkit.all):
            with self.subTest(module=module.__name__, name='TraceOptions'):
                self.assertFalse(hasattr(module, 'TraceOptions'))


class DumpTests(_Case):
    """Nothing is written without ``dump``, and ``fin`` is opened as named."""

    def test_no_dump_writes_nothing(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self.extract(sample_path('in.pcap'))
        self.assertEqual(extractor.length, 6)
        self.assertEqual(os.listdir(self.tmp), [])
        for name in ('format', 'output'):
            with self.subTest(attribute=name), self.assertRaises(UnsupportedCall) as caught:
                getattr(extractor, name)
            self.assertEqual(str(caught.exception),
                             f"'Extractor(dump=None)' object has no attribute {name!r}")

    def test_dump_writes_where_it_says(self) -> None:
        from pcapkit.foundation.options import DumpOptions

        extractor = self.extract(sample_path('in.pcap'), dump=DumpOptions(fout='o1.json', format='json'))
        self.assertEqual((extractor.output, extractor.format), ('o1.json', 'json'))
        self.assertEqual(os.listdir(self.tmp), ['o1.json'])

    def test_fin_gets_no_pcap_suffix(self) -> None:
        from pcapkit.utilities.exceptions import FileNotFound

        shutil.copy(sample_path('in.pcap'), os.path.join(self.tmp, 'capture.pcap'))
        with self.assertRaises(FileNotFound):
            self.extract('capture')
        self.assertEqual(self.extract('capture.pcap').length, 6)

    def test_dump_and_stream_take_only_their_classes(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        for keyword in ('dump', 'stream'):
            with self.subTest(keyword=keyword), self.assertRaises(RegistryError):
                self.extract(sample_path('in.pcap'), **{keyword: True})

    def test_stream_options_reach_the_reader(self) -> None:
        from pcapkit.corekit.io import SeekableReader
        from pcapkit.foundation.options import StreamOptions

        class Unseekable(io.BytesIO):
            def seekable(self) -> bool:
                return False

        with open(sample_path('in.pcap'), 'rb') as file:
            stream = Unseekable(file.read())
        extractor = self.extract(stream, stream=StreamOptions(buffer_size=4096))
        self.assertIsInstance(extractor._ifile, SeekableReader)  # pylint: disable=protected-access
        self.assertEqual(extractor._ifile._buffer_size, 4096)  # pylint: disable=protected-access
        self.assertEqual(extractor.length, 6)


class LayerTests(_Case):
    """``layer`` takes a layer name or a protocol class, and refuses anything else."""

    def test_an_unknown_layer_raises(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        for layer in ('bogus', 'Internets', 3):
            with self.subTest(layer=layer), self.assertRaises(FormatError) as caught:
                self.extract(sample_path('in.pcap'), layer=layer)
            self.assertEqual(str(caught.exception), f'unknown layer: {layer!r}; expected one of '
                             "'link', 'internet', 'transport', 'application', 'none'")

    def test_the_layer_names_have_one_source(self) -> None:
        import typing

        from pcapkit.__main__ import get_parser
        from pcapkit.foundation import extraction

        names = typing.get_args(extraction.Layers)
        self.assertEqual(names, ('link', 'internet', 'transport', 'application', 'none'))
        self.assertIs(extraction._LAYERS, names)  # pylint: disable=protected-access
        (layer,) = [action for action in get_parser()._actions  # pylint: disable=protected-access
                    if '--layer' in action.option_strings]
        self.assertIs(layer.choices, names)

    def test_a_protocol_class_names_its_layer(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        def layers(frame: 'Any') -> 'list[str]':
            names = []
            while frame.payload is not None and type(frame.payload).__name__ != 'NoPayload':
                frame = frame.payload
                names.append(type(frame).__name__)
            return names

        # ``Extractor`` itself, as ``extract()`` only passes the class on
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            by_class = Extractor(sample_path('in.pcap'), layer=IPv4)
        self.addCleanup(close_extractor, by_class)
        by_name = self.extract(sample_path('in.pcap'), layer='Internet')
        self.assertEqual(by_class._exlyr, 'internet')  # pylint: disable=protected-access
        self.assertEqual([layers(frame) for frame in by_class.frame], [layers(frame) for frame in by_name.frame])
        self.assertEqual(layers(by_class.frame[2]), ['Ethernet', 'IPv4', 'Raw'])


class NamesTests(_Case):
    """``reassembly`` and ``traceflow`` take registered names, or their options."""

    def test_names_and_options_are_one_request(self) -> None:
        from pcapkit.foundation.options import ReassemblyOptions, TraceFlowOptions

        by_names = self.extract(sample_path('in.pcap'), reassembly=['IPv4', 'tcp'], traceflow=['tcp'])
        by_options = self.extract(sample_path('in.pcap'), reassembly=ReassemblyOptions(protocols=['ipv4', 'tcp']),
                                  traceflow=TraceFlowOptions(protocols=['tcp']))
        for extractor in (by_names, by_options):
            self.assertEqual(list(extractor._reasm), ['ipv4', 'tcp'])  # pylint: disable=protected-access
        self.assertEqual(repr(by_names.reassembly), repr(by_options.reassembly))
        self.assertEqual([tuple(flow.index) for flow in by_names.traceflow.tcp],
                         [tuple(flow.index) for flow in by_options.traceflow.tcp])
        self.assertEqual(os.listdir(self.tmp), ['tmp'])

    def test_an_unregistered_name_raises_before_anything_is_written(self) -> None:
        from pcapkit.foundation.options import DumpOptions
        from pcapkit.utilities.exceptions import FormatError

        for keyword in ('reassembly', 'traceflow'):
            with self.subTest(keyword=keyword), self.assertRaises(FormatError):
                self.extract(sample_path('in.pcap'), dump=DumpOptions(fout='nested/out'),
                             **{keyword: ['tcp', 'no-such-protocol']})
        self.assertEqual(os.listdir(self.tmp), [])

    def test_no_names_turn_the_feature_off_with_a_warning(self) -> None:
        from pcapkit import extract
        from pcapkit.foundation.options import ReassemblyOptions, TraceFlowOptions
        from pcapkit.utilities.exceptions import UnsupportedCall
        from pcapkit.utilities.warnings import AttributeWarning

        cases = (('reassembly', [], 'reassembler'), ('reassembly', ReassemblyOptions(protocols=()), 'reassembler'),
                 ('traceflow', [], 'flow tracer'), ('traceflow', TraceFlowOptions(protocols=[]), 'flow tracer'))
        for keyword, value, what in cases:
            with self.subTest(keyword=keyword, value=value):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    extractor = extract(sample_path('in.pcap'), **{keyword: value})
                self.addCleanup(close_extractor, extractor)
                self.assertEqual([str(w.message) for w in caught if issubclass(w.category, AttributeWarning)],
                                 [f"'Extractor({keyword}=...)' names no {what}; treated as off, "
                                  f'as {keyword}=None'])
                with self.assertRaises(UnsupportedCall) as raised:
                    getattr(extractor, keyword)
                self.assertEqual(str(raised.exception),
                                 f"'Extractor({keyword}=None)' object has no attribute {keyword!r}")
                self.assertEqual(extractor.length, 6)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_trace_settings_are_checked_before_anything_is_created(self) -> None:
        from pcapkit.foundation.options import DumpOptions, TraceFlowOptions
        from pcapkit.utilities.exceptions import EndianError, FormatError

        cases = ((TraceFlowOptions(protocols=['tcp'], format='bogus'), FormatError,
                  "unknown flow tracing format: 'bogus'"),
                 (TraceFlowOptions(protocols=['tcp'], byteorder='mid'), EndianError,  # type: ignore[arg-type]
                  "unknown flow tracing byte order: 'mid'"))
        for traceflow, error, message in cases:
            with self.subTest(traceflow=traceflow), self.assertRaises(error) as caught:
                self.extract(sample_path('in.pcap'), dump=DumpOptions(fout='nested/out'), traceflow=traceflow)
            self.assertEqual(str(caught.exception), message)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_flag_is_not_a_list_of_names(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        for keyword in ('reassembly', 'traceflow'):
            for value in (True, 'tcp'):
                with self.subTest(keyword=keyword, value=value), self.assertRaises(RegistryError):
                    self.extract(sample_path('in.pcap'), **{keyword: value})

    def test_a_tracer_the_engine_has_no_adapter_for_is_dropped_with_a_warning(self) -> None:
        from pcapkit import extract
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.traceflow import TraceFlow
        from pcapkit.utilities.warnings import AttributeWarning

        class Dummy(TraceFlow):
            def dump(self, packet: 'Any') -> None:
                pass

            def trace(self, packet: 'Any', *, output: bool = False) -> 'Any':
                return 'dummy'

            def submit(self) -> 'tuple[Any, ...]':
                return ()

        Extractor.register_traceflow('dummy', Dummy)
        self.addCleanup(Extractor.__traceflow__.pop, 'dummy')
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = extract(sample_path('in.pcap'), traceflow=['tcp', 'dummy'])
        self.addCleanup(close_extractor, extractor)
        # the default engine has no ``dummy`` adapter, so drops it and traces TCP alone
        self.assertIn("'Extractor(engine=default)' object does not support Dummy flow tracing; "
                      "so 'dummy' will be ignored",
                      [str(w.message) for w in caught if issubclass(w.category, AttributeWarning)])
        self.assertEqual(list(extractor._trace), ['tcp'])  # pylint: disable=protected-access
        self.assertEqual(len(extractor.traceflow.tcp), 2)

    def test_follow_tcp_stream_traces_tcp(self) -> None:
        from pcapkit.foundation.options import TraceFlowOptions
        from pcapkit.interface.misc import follow_tcp_stream
        from pcapkit.utilities.exceptions import FormatError

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertEqual(len(follow_tcp_stream(sample_path('in.pcap'))), 2)
            streams = follow_tcp_stream(sample_path('in.pcap'),
                                        traceflow=TraceFlowOptions(protocols=['tcp'], fout='flows',
                                                                   bidirectional=False))
        self.assertEqual(len(streams), 3)
        self.assertEqual(sorted(os.listdir(self.tmp)), ['flows', 'tmp'])
        with self.assertRaises(FormatError) as caught:
            follow_tcp_stream(sample_path('in.pcap'), traceflow=TraceFlowOptions(protocols=['dummy']))
        self.assertEqual(str(caught.exception), "follow_tcp_stream traces TCP, but traceflow names ['dummy']")

    def test_follow_tcp_stream_takes_its_options_by_keyword(self) -> None:
        from pcapkit.foundation.options import TraceFlowOptions
        from pcapkit.interface.misc import follow_tcp_stream

        params = list(inspect.signature(follow_tcp_stream).parameters.values())
        self.assertEqual([param.name for param in params], ['fin', 'verbose', 'engine', 'traceflow'])
        self.assertEqual({param.kind for param in params[1:]}, {inspect.Parameter.KEYWORD_ONLY})
        for args in ((False,), (False, 'default'), (False, 'default', TraceFlowOptions(protocols=['tcp']))):
            with self.subTest(args=args), self.assertRaises(TypeError):
                follow_tcp_stream(sample_path('in.pcap'), *args)  # type: ignore[misc]
        self.assertEqual(os.listdir(self.tmp), [])


if __name__ == '__main__':
    unittest.main()
