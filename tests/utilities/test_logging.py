from __future__ import annotations

import importlib.util
import io
import logging
import os
import unittest

from tests._support import load_module, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Name of the logger at the root of the package hierarchy.
ROOT = 'pcapkit'


def pristine() -> None:
    """Return the process-wide ``pcapkit`` logger to its library-neutral state.

    The :mod:`logging` registry is global and outlives any module purge, so a
    test that attaches a handler would otherwise leak it into every later test
    in the run.
    """
    root = logging.getLogger(ROOT)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.NOTSET)
    root.propagate = True
    root.addHandler(logging.NullHandler())


class LoggingEnvironmentTests(unittest.TestCase):
    """The environment-variable flags, which are read at import time."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self._saved = {key: os.environ.get(key) for key in ('PCAPKIT_DEVMODE', 'PCAPKIT_VERBOSE', 'PCAPKIT_SPHINX')}

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        purge_modules(['pcapkit'])
        pristine()

    def test_boolean_environment_flags_are_parsed(self) -> None:
        os.environ['PCAPKIT_DEVMODE'] = 'yes'
        os.environ['PCAPKIT_VERBOSE'] = 'on'
        os.environ['PCAPKIT_SPHINX'] = 'true'

        logging_module = load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')

        self.assertTrue(logging_module.DEVMODE)
        self.assertTrue(logging_module.VERBOSE)
        self.assertTrue(logging_module.SPHINX_TYPE_CHECKING)

    def test_invalid_boolean_environment_values_fall_back_to_false(self) -> None:
        os.environ['PCAPKIT_DEVMODE'] = 'maybe'
        os.environ['PCAPKIT_VERBOSE'] = 'sometimes'
        os.environ['PCAPKIT_SPHINX'] = 'idk'

        logging_module = load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')

        self.assertFalse(logging_module.DEVMODE)
        self.assertFalse(logging_module.VERBOSE)
        self.assertFalse(logging_module.SPHINX_TYPE_CHECKING)

    def test_utilities_package_re_exports_common_helpers(self) -> None:
        package = load_module('pcapkit.utilities', 'pcapkit/utilities/__init__.py')

        self.assertIn('logger', package.__all__)
        self.assertTrue(callable(package.warn))
        self.assertTrue(callable(package.stacklevel))

    def test_utilities_package_re_exports_the_configuration_api(self) -> None:
        package = load_module('pcapkit.utilities', 'pcapkit/utilities/__init__.py')

        for name in ('configure', 'reset', 'get_logger', 'ensure_output'):
            with self.subTest(name=name):
                self.assertIn(name, package.__all__)
                self.assertTrue(callable(getattr(package, name)))


class LoggingImportTimeTests(unittest.TestCase):
    """Importing a library must not configure the application's logging."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self._saved = os.environ.get('PCAPKIT_DEVMODE')
        os.environ.pop('PCAPKIT_DEVMODE', None)
        pristine()

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop('PCAPKIT_DEVMODE', None)
        else:
            os.environ['PCAPKIT_DEVMODE'] = self._saved
        purge_modules(['pcapkit'])
        pristine()

    def test_fresh_import_attaches_only_a_null_handler(self) -> None:
        load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')
        root = logging.getLogger(ROOT)

        self.assertEqual(len(root.handlers), 1)
        self.assertIsInstance(root.handlers[0], logging.NullHandler)

    def test_fresh_import_sets_no_level_and_leaves_propagation_on(self) -> None:
        load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')
        root = logging.getLogger(ROOT)

        # NOTSET means the level is inherited from the application's own
        # configuration rather than dictated by the library
        self.assertEqual(root.level, logging.NOTSET)
        self.assertTrue(root.propagate)

    def test_fresh_import_does_not_write_to_stderr(self) -> None:
        logging_module = load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')

        # the module keeps a stderr handler around for the devmode bootstrap and
        # as a one-line restore path, but must not have attached it
        self.assertNotIn(logging_module.handler, logging.getLogger(ROOT).handlers)

    def test_devmode_bootstraps_the_historical_stderr_handler(self) -> None:
        os.environ['PCAPKIT_DEVMODE'] = '1'

        logging_module = load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')
        root = logging.getLogger(ROOT)

        self.assertTrue(logging_module.DEVMODE)
        self.assertEqual(root.level, logging.DEBUG)
        self.assertIn(logging_module.handler, root.handlers)

    def test_re_executing_the_module_does_not_stack_handlers(self) -> None:
        for _ in range(3):
            load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')

        self.assertEqual(len(logging.getLogger(ROOT).handlers), 1)


class LoggerHierarchyTests(unittest.TestCase):
    """Per-module loggers, so a consumer can address one subtree at a time."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def test_get_logger_maps_module_names_onto_the_hierarchy(self) -> None:
        from pcapkit.utilities.logging import get_logger, logger

        self.assertIs(get_logger(None), logger)
        self.assertIs(get_logger(ROOT), logger)
        self.assertEqual(get_logger('pcapkit.foundation.extraction').name,
                         'pcapkit.foundation.extraction')

    def test_get_logger_keeps_foreign_names_inside_the_hierarchy(self) -> None:
        from pcapkit.utilities.logging import get_logger

        # ``python -m pcapkit.vendor`` reports ``__name__ == '__main__'``; a
        # logger by that bare name would be a sibling of ``pcapkit`` and so
        # unreachable from any pcapkit-level configuration
        self.assertEqual(get_logger('__main__').name, 'pcapkit.__main__')
        self.assertEqual(get_logger('somewhere.else').name, 'pcapkit.somewhere.else')

    def test_public_root_logger_is_still_importable_and_named_pcapkit(self) -> None:
        from pcapkit.utilities.logging import logger

        self.assertIs(logger, logging.getLogger(ROOT))
        self.assertEqual(logger.name, ROOT)

    @unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
    def test_modules_log_through_their_own_child_logger(self) -> None:
        cases = {
            'pcapkit.foundation.extraction': 'pcapkit.foundation.extraction',
            'pcapkit.foundation.registry.protocols': 'pcapkit.foundation.registry.protocols',
            'pcapkit.foundation.registry.foundation': 'pcapkit.foundation.registry.foundation',
            'pcapkit.foundation.reassembly.reassembly': 'pcapkit.foundation.reassembly.reassembly',
            'pcapkit.foundation.traceflow.traceflow': 'pcapkit.foundation.traceflow.traceflow',
            'pcapkit.foundation.traceflow.tcp': 'pcapkit.foundation.traceflow.tcp',
            'pcapkit.foundation.engines.pcap': 'pcapkit.foundation.engines.pcap',
            'pcapkit.foundation.engines.pcapng': 'pcapkit.foundation.engines.pcapng',
            'pcapkit.utilities.exceptions': 'pcapkit.utilities.exceptions',
            'pcapkit.utilities.warnings': 'pcapkit.utilities.warnings',
            'pcapkit.utilities.decorators': 'pcapkit.utilities.decorators',
            'pcapkit.dumpkit.common': 'pcapkit.dumpkit.common',
        }
        for module_name, expected in cases.items():
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                self.assertEqual(module.logger.name, expected)


class LoggingConfigureTests(unittest.TestCase):
    """The public configuration API, at runtime rather than at import."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def test_configure_sets_level_and_attaches_a_stream_handler(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        stream = io.StringIO()
        self.assertIs(configure(logging.DEBUG, stream=stream), logger)

        self.assertEqual(logger.level, logging.DEBUG)
        logger.debug('configured at runtime')
        self.assertIn('configured at runtime', stream.getvalue())

    def test_configure_accepts_a_level_name(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        configure('WARNING')
        self.assertEqual(logger.level, logging.WARNING)

    def test_configure_honours_a_custom_format(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        stream = io.StringIO()
        configure(logging.INFO, stream=stream, fmt='%(levelname)s|%(name)s|%(message)s')

        logger.info('formatted')
        self.assertEqual(stream.getvalue().strip(), 'INFO|pcapkit|formatted')

    def test_configure_replaces_handlers_by_default(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        first, second = io.StringIO(), io.StringIO()
        configure(logging.INFO, stream=first)
        configure(logging.INFO, stream=second)

        logger.info('only the second')
        self.assertEqual(first.getvalue(), '')
        self.assertIn('only the second', second.getvalue())

    def test_configure_can_add_a_second_destination(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        first, second = io.StringIO(), io.StringIO()
        configure(logging.INFO, stream=first)
        configure(stream=second, replace=False)

        logger.info('both of them')
        self.assertIn('both of them', first.getvalue())
        self.assertIn('both of them', second.getvalue())

    def test_configure_accepts_a_ready_made_handler(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        configure(logging.INFO, handler=handler)

        self.assertIn(handler, logger.handlers)
        logger.info('via handler')
        self.assertIn('via handler', stream.getvalue())

    def test_configure_rejects_both_stream_and_handler(self) -> None:
        from pcapkit.utilities.logging import configure

        with self.assertRaises(ValueError):
            configure(stream=io.StringIO(), handler=logging.NullHandler())

    def test_configure_can_target_a_single_subtree(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        stream = io.StringIO()
        configure(logging.DEBUG, stream=stream)
        configure(logging.WARNING, name='pcapkit.foundation.registry')

        logging.getLogger('pcapkit.foundation.registry.protocols').debug('bookkeeping')
        logging.getLogger('pcapkit.foundation.extraction').debug('worth seeing')

        self.assertNotIn('bookkeeping', stream.getvalue())
        self.assertIn('worth seeing', stream.getvalue())
        self.assertEqual(logger.level, logging.DEBUG)

    def test_configure_can_stop_propagation(self) -> None:
        from pcapkit.utilities.logging import configure, logger

        configure(propagate=False)
        self.assertFalse(logger.propagate)

    def test_reset_restores_the_library_neutral_state(self) -> None:
        from pcapkit.utilities.logging import configure, logger, reset

        configure(logging.DEBUG, stream=io.StringIO(), propagate=False)
        self.assertIs(reset(), logger)

        self.assertEqual(logger.level, logging.NOTSET)
        self.assertTrue(logger.propagate)
        self.assertEqual(len(logger.handlers), 1)
        self.assertIsInstance(logger.handlers[0], logging.NullHandler)

    def test_one_line_restore_of_the_historical_stderr_output(self) -> None:
        from pcapkit.utilities.logging import DEFAULT_FORMAT, configure, logger

        stream = io.StringIO()
        configure(logging.INFO, stream=stream, fmt=DEFAULT_FORMAT)

        logger.info('as it used to be')
        self.assertIn('[INFO]', stream.getvalue())
        self.assertIn('as it used to be', stream.getvalue())

    def test_ensure_output_adds_a_handler_only_when_there_is_none(self) -> None:
        from pcapkit.utilities.logging import configure, ensure_output, logger

        # stop propagation first: the ancestry walk would otherwise find the
        # handlers the test runner itself attaches to the root logger, which is
        # the correct answer but not the one under test here
        configure(propagate=False)

        stream = io.StringIO()
        self.assertTrue(ensure_output(logging.DEBUG, stream=stream))
        logger.debug('nowhere else to go')
        self.assertIn('nowhere else to go', stream.getvalue())

        # once the application has configured its own output, leave it alone
        chosen = io.StringIO()
        configure(logging.DEBUG, stream=chosen, propagate=False)
        self.assertFalse(ensure_output(logging.DEBUG, stream=io.StringIO()))
        logger.debug('to the chosen stream')
        self.assertIn('to the chosen stream', chosen.getvalue())

    def test_ensure_output_respects_an_application_that_configured_the_root(self) -> None:
        from pcapkit.utilities.logging import ensure_output, logger

        # an application whose handlers live on the root logger has already
        # decided where records go, even though ``pcapkit`` itself has none
        root = logging.getLogger()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root.addHandler(handler)
        try:
            self.assertFalse(ensure_output(logging.DEBUG))
            self.assertEqual([entry for entry in logger.handlers
                              if not isinstance(entry, logging.NullHandler)], [])
        finally:
            root.removeHandler(handler)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistryLogLevelTests(unittest.TestCase):
    """Registration bookkeeping is the library's own business, so ``debug``."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def test_registry_bookkeeping_is_logged_at_debug_not_info(self) -> None:
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.registry.foundation import register_reassembly_ipv4_callback

        def callback(datagrams: list) -> None:
            """Throwaway callback."""

        saved = list(IPv4.__callback_fn__)
        try:
            with self.assertLogs('pcapkit.foundation.registry.foundation',
                                 level=logging.DEBUG) as caught:
                register_reassembly_ipv4_callback(callback)
        finally:
            IPv4.__callback_fn__[:] = saved

        self.assertEqual(len(caught.records), 1)
        record = caught.records[0]
        self.assertEqual(record.levelno, logging.DEBUG)
        self.assertIn('registered IPv4 reassembly callback', record.getMessage())

    def test_no_registry_module_still_logs_at_info(self) -> None:
        import pcapkit.foundation.registry.foundation  # noqa: F401
        import pcapkit.foundation.registry.protocols  # noqa: F401

        root = os.path.dirname(os.path.dirname(os.path.abspath(
            pcapkit.foundation.registry.protocols.__file__)))
        for name in ('registry/protocols.py', 'registry/foundation.py'):
            with self.subTest(module=name):
                with open(os.path.join(root, name), encoding='utf-8') as file:
                    source = file.read()
                self.assertNotIn('logger.info(', source)
                self.assertIn('logger.debug(', source)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExtractorLoggingTests(unittest.TestCase):
    """The debug trail should explain what pcapkit did with a file."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])
        pristine()

    def test_extraction_emits_a_debug_trail(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from tests._support import sample_path

        with self.assertLogs('pcapkit', level=logging.DEBUG) as caught:
            extractor = Extractor(fin=sample_path('arp.pcap'), nofile=True, store=False)

        messages = [record.getMessage() for record in caught.records]
        self.assertTrue(any('opening input file' in message for message in messages), messages)
        self.assertTrue(any('extraction engine' in message for message in messages), messages)
        self.assertTrue(any('reading frames from' in message for message in messages), messages)
        self.assertTrue(any('frame(s) from' in message for message in messages), messages)
        self.assertEqual(extractor.length, 2)

        # nothing on the parsing path should be shouting at info or above
        self.assertEqual([record.getMessage() for record in caught.records
                          if record.levelno >= logging.INFO and 'EOF' not in record.getMessage()],
                         [])

    def test_verbose_extraction_still_reaches_a_destination(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from tests._support import sample_path

        # ``verbose=True`` asks to see the frames; removing the import-time
        # stderr handler must not turn that into silence
        with self.assertLogs('pcapkit', level=logging.DEBUG) as caught:
            Extractor(fin=sample_path('arp.pcap'), nofile=True, store=False, verbose=True)

        frames = [record.getMessage() for record in caught.records
                  if record.getMessage().startswith('Frame ')]
        self.assertEqual(len(frames), 2)
        self.assertTrue(frames[0].startswith('Frame   1: '), frames)


if __name__ == '__main__':
    unittest.main()
