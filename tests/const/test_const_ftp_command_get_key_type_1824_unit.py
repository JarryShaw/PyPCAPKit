# -*- coding: utf-8 -*-
"""``Command.get`` refuses a non-``str`` key the way ``Method.get`` does.

GitHub issue #1824. Guards against :meth:`~pcapkit.const.ftp.command.Command.get`
being a :class:`staticmethod` that calls ``key.upper()`` on whatever it is
given, under which ``Command.get(b'\\x01')`` builds an unregistered member keyed by the
:class:`bytes` object, and ``Command.get(-1)`` raises a builtin
:exc:`AttributeError` whether or not ``default`` is supplied.
:meth:`~pcapkit.const.http.method.Method.get` is a :class:`classmethod`
delegating to :meth:`~pcapkit.corekit.enum.EnumLookup.get` (#908).

``Command.get`` follows it: a non-``str`` key goes to the base, whose call
to ``Command._validate_value`` (added by #1823) raises
:exc:`~pcapkit.utilities.exceptions.EnumValueError`. ``default`` is not
forwarded there, exactly as ``Method.get`` forwards none, because this
override's ``default`` is the *value* of the unregistered member it builds on a
name miss rather than the base's already-registered fallback -- so a refused key
raises whatever ``default`` is.

A ``str`` key is untouched: case-insensitive per :rfc:`959#section-5`, with the
unregistered-member fallback keeping the caller's own casing as its value and
the upper-cased form as its name, as the ``NOTE`` in the override says.

"""
import inspect
import unittest


class NonStrKeyTests(unittest.TestCase):
    """A non-``str`` key is refused with the in-library error and mints nothing."""

    def setUp(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        self.before = (len(Command._member_map_), len(Command._value2member_map_))

    def tearDown(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        self.assertEqual((len(Command._member_map_), len(Command._value2member_map_)),
                         self.before, 'a non-str lookup must not grow either table')

    def _refused(self, key: 'object', **kwargs: 'object') -> 'BaseException':
        from pcapkit.const.ftp.command import Command
        from pcapkit.utilities.exceptions import EnumValueError

        with self.assertRaises(EnumValueError) as caught:
            Command.get(key, **kwargs)  # type: ignore[arg-type]
        self.assertIs(type(caught.exception), EnumValueError)
        self.assertEqual(str(caught.exception), f'{key!r} is not a valid Command')
        return caught.exception

    def test_a_bytes_key_raises_instead_of_returning_a_bytes_keyed_member(self) -> 'None':
        """Guards against returning ``<Command.b'\\x01': None>`` -- a member, not an error."""
        self._refused(b'\x01')
        self._refused(b'ABOR')

    def test_an_int_key_raises_the_in_library_error(self) -> 'None':
        """Guards against a builtin :exc:`AttributeError` from ``key.upper()``."""
        error = self._refused(-1)
        self.assertNotIsInstance(error, AttributeError)
        self.assertIsInstance(error, ValueError)

    def test_an_int_key_with_a_default_still_raises(self) -> 'None':
        """``default`` names the unregistered member's value, so it cannot rescue a
        refused key -- not even when it is a registered command's value."""
        self._refused(-1, default='XYZW')
        self._refused(-1, default='ABOR')

    def test_other_non_str_keys_raise_too(self) -> 'None':
        self._refused(None)
        self._refused(1.5)

    def test_the_refusal_matches_method_get(self) -> 'None':
        """Same exception class and message shape as ``Method.get``, with a default."""
        from pcapkit.const.http.method import Method
        from pcapkit.utilities.exceptions import EnumValueError

        for key in (-1, b'\x01'):
            with self.subTest(key=key):
                with self.assertRaises(EnumValueError) as method:
                    Method.get(key, default='GET')  # type: ignore[arg-type]
                command = self._refused(key, default='ABOR')
                self.assertIs(type(command), type(method.exception))
                self.assertEqual(str(command).replace('Command', 'Method'),
                                 str(method.exception))


class StrKeyTests(unittest.TestCase):
    """A ``str`` key keeps the case-insensitive lookup and the fallback."""

    def setUp(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        self.before = (len(Command._member_map_), len(Command._value2member_map_))

    def tearDown(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        self.assertEqual((len(Command._member_map_), len(Command._value2member_map_)),
                         self.before, 'a str lookup must not grow either table')

    def test_a_registered_key_resolves(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        self.assertIs(Command.get('ABOR'), Command.ABOR)  # type: ignore[attr-defined]
        self.assertIs(Command.get('ABOR', 'XYZW'), Command.ABOR)  # type: ignore[attr-defined]

    def test_a_registered_key_in_another_case_resolves(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        for key in ('abor', 'Abor', 'aBoR'):
            with self.subTest(key=key):
                self.assertIs(Command.get(key), Command.ABOR)  # type: ignore[attr-defined]
                self.assertIs(Command.get(key, 'XYZW'), Command.ABOR)  # type: ignore[attr-defined]

    def test_an_unregistered_key_keeps_the_callers_case(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        lower, upper = Command.get('xyzw'), Command.get('XYZW')
        self.assertEqual((lower.value, lower.name), ('xyzw', 'XYZW'))
        self.assertEqual((upper.value, upper.name), ('XYZW', 'XYZW'))
        self.assertNotEqual(lower, upper)
        self.assertNotIn(lower, list(Command))

    def test_an_unregistered_key_takes_its_value_from_default(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        built = Command.get('xyzw', 'Placeholder')
        self.assertEqual((built.value, built.name), ('Placeholder', 'XYZW'))


class ShapeTests(unittest.TestCase):
    """The override's shape, in the generated module and in its template."""

    def test_get_is_a_classmethod_that_delegates(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        descriptor = inspect.getattr_static(Command, 'get')
        self.assertIsInstance(descriptor, classmethod)
        self.assertIn('return super().get(key)', inspect.getsource(descriptor.__func__))

    def test_the_docstring_records_the_change(self) -> 'None':
        from pcapkit.const.ftp.command import Command

        doc = inspect.getdoc(Command.get) or ''
        self.assertRegex(doc, r'Raises:\n\s+EnumValueError: If ``key`` is not a :class:`str`')
        self.assertIn(':issue:`1824`', doc)
        # The module is generated, so the version note is on the docs page
        # rather than in the docstring, which
        # tests/project/test_no_version_directives_in_generated_tables_1884_unit.py
        # checks (#1884).
        self.assertNotIn('.. versionchanged::', doc)

    def test_the_crawler_template_carries_the_same_get(self) -> 'None':
        """The fix lives in :data:`pcapkit.vendor.ftp.command.LINE`, so a
        regeneration cannot discard it. Rendering the template needs no network."""
        from pcapkit.const.ftp.command import Command
        from pcapkit.vendor.ftp.command import LINE

        rendered = LINE('Command', 'FTP Command', '<ENUM>', '<FEAT>', 'pcapkit.vendor.ftp.command')
        # NOTE: through ``getattr_static`` because both descriptor kinds carry
        # ``__func__`` there, while ``Command.get.__func__`` exists only on the
        # bound classmethod -- so this compares sources on either shape.
        source = inspect.getsource(inspect.getattr_static(Command, 'get').__func__)
        self.assertIn(source.rstrip('\n'), rendered)
        # A count rather than ``assertIn``, so a failure reports a number instead
        # of the whole rendered module.
        self.assertEqual(rendered.count('            return super().get(key)  '), 1,
                         "the template's Command.get does not delegate a non-str key")


class FEATCodeUnaffectedTests(unittest.TestCase):
    """``FEATCode.get`` delegates a non-``str`` key to the base, so it has no such defect."""

    def test_a_non_str_key_raises_the_in_library_error(self) -> 'None':
        from pcapkit.const.ftp.command import FEATCode
        from pcapkit.utilities.exceptions import EnumValueError

        for key in (b'\x01', -1, None):
            with self.subTest(key=key):
                with self.assertRaises(EnumValueError):
                    FEATCode.get(key)

    def test_its_default_is_the_bases_registered_fallback(self) -> 'None':
        """Unlike ``Command.get``'s, ``FEATCode.get``'s ``default`` is the base's own,
        so a refused key falls back to it, as on every registry that inherits it."""
        from pcapkit.const.ftp.command import FEATCode

        self.assertIs(FEATCode.get(-1, '<base>'), FEATCode.base)  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
