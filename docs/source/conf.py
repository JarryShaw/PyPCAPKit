# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import builtins
import datetime
import enum
import importlib
import inspect
import logging
import os
import pkgutil
import re
import typing
from typing import TYPE_CHECKING

import aenum
from docutils import nodes
from sphinx import addnodes
from sphinx.ext.autodoc.preserve_defaults import DefaultValue, update_default_value
from sphinx.transforms.post_transforms import SphinxPostTransform
from sphinx.util.inspect import stringify_signature

# NB: private modules of ``sphinx-autodoc-typehints``, used deliberately -- see
# ``bind_type_checking_names``, ``restore_class_signature`` and
# ``read_constructor_types_from_init`` below for what they buy and why
# reimplementing them here would be worse. This file is written against the
# release that ``docs/requirements.txt`` pins, which the ``docs`` extra in
# ``pyproject.toml`` pins too, and
# ``tests/project/test_docs_typehints_pin_1856_unit.py`` keeps the pins equal, so
# there is no other release to branch for. A bump that moves these modules fails
# this import loudly at build time, which is the outcome to want: the alternative
# is a build that silently goes back to emitting unresolvable annotations.
from sphinx_autodoc_typehints._docstring import handler as typehints_docstring_handler
from sphinx_autodoc_typehints._documented import hints as typehints_hints
from sphinx_autodoc_typehints._objects import constructor_name as typehints_constructor_name
from sphinx_autodoc_typehints._resolve import guarded_names, resolve_type_guarded_imports
from sphinx_autodoc_typehints._signature.handler import process_signature as typehints_process_signature

# NB: this must precede ``import pcapkit``. ``pcapkit.utilities.logging`` reads
# ``PCAPKIT_SPHINX`` at *import* time to compute ``SPHINX_TYPE_CHECKING``, and
# importing ``pcapkit`` already pulls in the schema modules -- so setting it any
# later leaves every ``if SPHINX_TYPE_CHECKING:`` TypedDict undefined and autodoc
# cannot document them.
os.environ['PCAPKIT_SPHINX'] = '1'

import pcapkit
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.sentinels import NO_VALUE
from pcapkit.protocols.schema.schema import Schema

if TYPE_CHECKING:
    from types import FunctionType, ModuleType
    from typing import Any, Dict, List, Optional
    from docutils.nodes import document
    from sphinx.application import Sphinx
    from sphinx.config import Config
    from sphinx.environment import BuildEnvironment

logger = logging.getLogger('pcapkit-sphinx')
logger.setLevel(logging.INFO)

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'PyPCAPKit'
copyright = f'2017-{datetime.date.today().year}, Jarry Shaw'  # pylint: disable=redefined-builtin
author = 'Jarry Shaw'

# The full version, including alpha/beta/rc tags
release = pcapkit.__version__


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    # NB: ``sphinx.ext.autodoc.typehints`` is *not* listed here. It is an
    # internal submodule of ``sphinx.ext.autodoc`` rather than an extension in
    # its own right -- it exposes no ``setup()``, so loading it explicitly only
    # earns a warning. The typehint rendering comes from the third-party
    # ``sphinx_autodoc_typehints`` below.
    'sphinx.ext.autodoc',
    'sphinx.ext.extlinks',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',

    'sphinx_autodoc_typehints',

    "sphinxext.opengraph",

    'sphinx_copybutton',

    'sphinxcontrib.mermaid',
]

# Opt-in roles for the tracker references that the prose cites constantly. A bare
# ``#NNN`` renders as literal text -- nothing in Sphinx resolves it -- so every
# citation in a docstring or an ``.rst`` page is unclickable in the built docs.
#
# These are deliberately opt-in per site rather than an automatic ``#NNN`` rule,
# because no digit-keyed pattern can tell a citation from a packet-diagram label:
# ``#\d{3}`` misses every two- and four-digit number, while ``#\d+`` catches the
# one-digit RFC diagram labels in ``pcapkit/protocols/internet/hip.py``,
# ``pcapkit/protocols/transport/sctp.py`` and
# ``pcapkit/protocols/schema/internet/hip.py`` -- ``DH GROUP ID #1``,
# ``Gap Ack Block #1`` and the like -- which are not references to anything. A role
# nobody writes cannot corrupt them.
#
# The caption is ``#%s`` for both ``:issue:`` and ``:pr:`` so that converting a bare
# citation or an explicit link changes the markup and not the rendered text. A
# citation written as an inline literal is the one exception: converting it turns
# monospace into a link in body font. The two roles exist separately because the
# issue-versus-pull-request distinction is itself a documented convention (see
# ``contributing/conventions/documentation.rst``), and a single role would flatten it
# in the source even though GitHub redirects between ``/issues/NNN`` and ``/pull/NNN``
# either way.
#
# ``:discussion:`` is needed because some cited numbers are GitHub
# Discussions rather than issues -- the issues API returns 404 for them, so
# ``:issue:`` would link to a page that does not exist.
#
# ``:wikipedia:`` and ``:iana:`` are defined ahead of their first use, deliberately.
# ``extlinks`` does not check the template at setup time, and the ``ExternalLinksChecker``
# post-transform that does read every entry, cited or not, returns early while
# ``extlinks_detect_hardcoded_links`` stays at its default ``False``. So in this
# configuration an uncited role does not change the build; that is not a general law.
# Their argument is a slug or a path rather than a number, hence the ``%s`` caption,
# and the ``:iana:`` argument is the path after ``/assignments/``. Prose should give an
# explicit title, ``:iana:`ARP parameters <arp-parameters/arp-parameters.xhtml>```,
# since the bare caption renders the raw slug or path as the visible text.
extlinks = {
    'issue': ('https://github.com/JarryShaw/PyPCAPKit/issues/%s', '#%s'),
    'pr': ('https://github.com/JarryShaw/PyPCAPKit/pull/%s', '#%s'),
    'discussion': ('https://github.com/JarryShaw/PyPCAPKit/discussions/%s', '#%s'),
    'wikipedia': ('https://en.wikipedia.org/wiki/%s', '%s'),
    'iana': ('https://www.iana.org/assignments/%s', '%s'),
}

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'dictdumper': ('https://dictdumper.jarryshaw.me/en/latest/', None),
    'chardet': ('https://chardet.readthedocs.io/en/latest/', None),
    'dpkt': ('https://dpkt.readthedocs.io/en/latest/', None),
    'scapy': ('https://scapy.readthedocs.io/en/latest/', None),
    'cryptography': ('https://cryptography.io/en/latest/', None),
    'requests': ('https://requests.readthedocs.io/en/latest/', None),
    'bs4': ('https://www.crummy.com/software/BeautifulSoup/bs4/doc/', None),
}

# NOTE: Deliberately *not* in the mapping above, having been checked rather than
# assumed. Every entry costs an inventory fetch on each build and warns for the
# whole build when it cannot be resolved, so an entry that resolves nothing is
# worse than no entry at all.
#
#   * ``pypcapfile`` publishes no documentation site -- its ``objects.inv`` 404s.
#   * ``pyshark``, ``pypcap``, ``aenum`` and ``emoji`` do serve a real
#     ``objects.inv``, but each contains only ``std:doc``/``std:label`` entries
#     and *zero* ``py:`` objects (5-8 objects apiece), so no ``:mod:``,
#     ``:class:`` or ``:func:`` cross-reference into them could ever resolve.
#
# Those packages are therefore referenced as plain external links instead, the
# ``.. _PyPCAP: https://github.com/pynetwork/pypcap`` style used throughout
# ``pcapkit/foundation/engines/3rdparty.rst``.

autodoc_default_options = {
    # 'members': True,
    'member-order': 'bysource',
    # 'special-members': '__init__',
    # 'undoc-members': True,
    'exclude-members': '__weakref__, _abc_impl, _unbound_fields, _wtforms_meta, _meta, _schema, _missing_',
    'ignore-module-all': True,
    # 'private-members': True,
    'show-inheritance': True,
}
autodoc_typehints = 'signature'
# NB: a default renders as its source text rather than its ``repr()``. By value,
# every ``byteorder=sys.byteorder`` showed the build host's ``'little'``, and the
# ``corekit.fields`` pages showed ``default=<pcapkit.corekit.sentinels.NoValueType
# object>`` and ``callback=<function NumberField.<lambda>>`` (:issue:`1859`).
autodoc_preserve_defaults = True
#autodoc_member_order = 'bysource'
#autodoc_member_order = 'alphabetic'
autoclass_content = 'class'

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = True
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_custom_sections = None
napoleon_preprocess_types = True
napoleon_attr_annotations = True

manpages_url = 'https://linux.die.net/man/{section}/{page}'

todo_include_todos = True

set_type_checking_flag = True
# NB: ``typehints_formatter`` is set below, beside ``format_aenum_class``.
typehints_fully_qualified = False
always_document_param_types = False
typehints_document_rtype = True

# NB: a ``:rtype: None`` field says nothing the rendered signature has not already
# said, and injecting it is actively harmful in one measured case: for a docstring
# whose field list is followed by a directive,
# ``sphinx_autodoc_typehints`` computes an insertion point *inside* that directive
# and splits it from its content. ``PCAP_CT.run`` was the case -- its trailing
# ``Note:`` lost its body and the build reported ``Content block expected for the
# "note" directive; none found``. Skipping the ``None`` returns removes the noise
# and the corruption together; non-``None`` returns are still documented.
typehints_document_rtype_none = False

# NB: ``False`` stays because ``True`` was measured, not because nobody tried it.
# ``furo`` renders a sticky page-local TOC drawer on every page, and ``True`` adds
# every documented object to it: across full builds either way the drawer on
# ``pcapkit/const/reg.rst`` goes from 5 entries to 12,960, on
# ``pcapkit/protocols/internet/mh.rst`` from 6 to 1,233, and tree-wide from 729 to
# 22,261 -- while 120 of the 188 pages stay under 20 either way, so the entries
# land on precisely the pages already hardest to read. ``True`` also took the build
# from 109s to 1,052s.
#
# Capping the depth does not rescue it. The drawer's depth is a per-document
# ``:tocdepth:`` field rather than a setting of its own -- though ``rst_prolog``
# can default that field tree-wide, so a global cap is available. Either way the
# only depth that keeps ``mh``'s drawer small is 2, and that is *worse* than
# ``False`` rather than equal to it: it still admits the page's own top-level
# class, and it drops two genuine headings (``Type Stubs``, ``Auxiliary
# Functions``) that ``False`` shows.
toc_object_entries = False

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []  # type: list[str]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
#html_theme = 'alabaster'
html_theme = 'furo'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
    #'show_powered_by': False,
    #'github_user': 'JarryShaw',
    #'github_repo': 'PyPCAPKit',
    #'github_banner': True,
    #'github_type': 'star',
    # 'show_related': False,
    # 'note_bg': '#FFF59C',
    # 'travis_button': True,
    # 'codecov_button': True,

    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "top_of_page_button": "edit",  # None

    "source_repository": "https://github.com/JarryShaw/PyPCAPKit/",
    "source_branch": "main",
    "source_directory": "docs/source/",

    "light_css_variables": {
        "font-stack": "Georgia, serif",
        "font-stack--monospace": "'Consolas', 'Menlo', 'DejaVu Sans Mono', 'Bitstream Vera Sans Mono', monospace",
    },
    "dark_css_variables": {
        "font-stack": "Georgia, serif",
        "font-stack--monospace": "'Consolas', 'Menlo', 'DejaVu Sans Mono', 'Bitstream Vera Sans Mono', monospace",
    },
}
html_title = "PyPCAPKit"

ogp_site_url = "https://pypcapkit.jarryshaw.me/"

# Mermaid diagrams render at their natural size and shrink only to fit the page
# width. The ``sphinxcontrib-mermaid`` defaults -- ``mermaid_height = '500px'`` with
# the SVG stretched to the full page width -- fit every diagram into the same fixed
# box, so a tall class hierarchy shrank until its text could not be read and its
# edges ran together. ``useMaxWidth`` has to be off as well, or Mermaid writes
# ``width="100%"`` on the SVG in place of its own size and ``fit-content`` has
# nothing to size the box from. ``startOnLoad`` repeats the plugin's default, which
# this setting replaces wholesale. ``_static/mermaid.css`` centres a diagram
# narrower than the page, as the full-width box did.
mermaid_width = 'fit-content'
mermaid_height = 'auto'
mermaid_init_config = {'startOnLoad': False, 'flowchart': {'useMaxWidth': False}}
html_css_files = ['mermaid.css']


def maybe_skip_member(app: 'Sphinx', what: str, name: str,  # pylint: disable=unused-argument
                      obj: 'Any', skip: bool, options: 'Dict[str, Any]') -> bool:  # pylint: disable=unused-argument
    if name == '_abc_impl':
        return True
    if name == '__init__':
        if '__create_fn__' in obj.__qualname__:
            return True
    return skip


def skip_enum_value_hook(app: 'Sphinx', what: str, name: str,  # pylint: disable=unused-argument
                         obj: 'Any', skip: bool, options: 'Dict[str, Any]') -> 'Optional[bool]':  # pylint: disable=unused-argument
    """Skip the enum machinery's own ``_generate_next_value_`` hook.

    The enum metaclass copies ``_generate_next_value_`` into the namespace of
    every enumeration it creates, so ``:members:`` finds it as the documented
    class's own member. ``exclude-members`` cannot remove it: autodoc applies
    that first and then lets ``autodoc-skip-member`` overrule it, and
    napoleon's handler, with ``napoleon_include_private_with_doc`` on, includes
    a private member that has a docstring and was defined in a class body --
    true of the standard library's hooks and of ``aenum``'s ``StrEnum`` one.
    None of them is part of any pcapkit enumeration's interface.

    Args:
        app: Sphinx application.
        what: Type of the object whose member is being considered.
        name: Name of the member.
        obj: The member itself.
        skip: Whether autodoc would skip it.
        options: Directive options.

    Returns:
        :obj:`True` for a ``_generate_next_value_`` that pcapkit does not
        define itself, and :obj:`None` for anything else, which leaves the
        decision to the other handlers.

    """
    if name == '_generate_next_value_':
        module = getattr(obj, '__module__', None) or ''
        if module.partition('.')[0] != 'pcapkit':
            return True
    return None


def bind_guarded_names(mock_imports: 'List[str]', module: 'ModuleType') -> None:
    """Execute one module's ``if TYPE_CHECKING:`` block and bind its names there.

    :func:`resolve_type_guarded_imports` only records the names (it bound them into
    the module itself before ``sphinx-autodoc-typehints`` 3.14), and the library
    lays them over the module's globals around the annotation reads it patches,
    then takes them away again. Sphinx's own signature introspection is
    not one of those reads. ``Schema.__new__`` takes ``*args: '_VT'`` and returns
    the guarded ``'Self'``, so :func:`typing.get_type_hints` raised
    :exc:`NameError` for it and the schema class signatures fell back to the bare
    ``_VT``. The Python domain then found both
    :data:`pcapkit.corekit.multidict._VT` and
    :data:`pcapkit.protocols.schema.schema._VT` for it, warned, and linked the
    first, which is the wrong one. Binding what the library recorded restores
    what the releases before 3.14 did.

    Only a name the module lacks is bound. A name the module binds at runtime keeps
    that binding, as the library's own overlay leaves it.

    Args:
        mock_imports: The ``autodoc_mock_imports`` setting.
        module: The module whose block is executed.

    """
    resolve_type_guarded_imports(mock_imports, module)
    namespace = vars(module)
    for name, value in guarded_names(module).items():
        namespace.setdefault(name, value)


def bind_type_checking_names(app: 'Sphinx', env: 'BuildEnvironment',  # pylint: disable=unused-argument
                             docnames: 'List[str]') -> None:  # pylint: disable=unused-argument
    """Execute every ``pcapkit`` module's ``if TYPE_CHECKING:`` block.

    Annotations throughout the package are quoted and their types imported only
    under :data:`~typing.TYPE_CHECKING`, which is right at runtime and awkward
    here. Autodoc reads a class attribute's type with
    :func:`typing.get_type_hints`, and a single unresolvable name makes that raise
    :exc:`NameError` for the *whole class*; Sphinx then falls back to the raw
    ``__annotations__`` strings. So ``pre: 'ToSPrecedence'`` was rendered as the
    bare word ``ToSPrecedence``, which the Python domain has to resolve by
    suffix-matching -- and both :class:`pcapkit.const.ipv4.tos_pre.ToSPrecedence`
    and its generator :class:`pcapkit.vendor.ipv4.tos_pre.ToSPrecedence` end in
    it. That is where the bulk of the ``more than one target found`` warnings came
    from, and roughly half of the links Sphinx picked went to the vendor crawler
    rather than to the enumeration the attribute actually holds.

    Binding the guarded names into each module up front lets
    :func:`typing.get_type_hints` succeed, so the annotation is stringified from
    the resolved object and carries its full dotted path. Nothing is suppressed:
    the references are qualified rather than silenced.

    ``sphinx-autodoc-typehints`` already executes the block per module, but lazily,
    only for the objects it happens to process. Walking every module here binds the
    names up front, so :func:`typing.get_type_hints` succeeds for anything autodoc
    renders, whether or not the library reaches it. Its implementation is reused
    rather than rewritten because it executes the block one statement at a time,
    so an unimportable optional dependency (``pcap``, ``pcapfile``) cannot strand
    the names declared after it. :func:`bind_guarded_names` does the binding, per
    module.

    It runs on ``env-before-read-docs`` rather than on ``builder-inited``, after the
    library's own handler for that event. That handler clears what the library
    recorded from the blocks it ran, so the record of a walk done before
    it would be discarded, and the library would run those blocks again as reading
    reached them.

    One consequence is worth knowing before it is met as a mystery: making the
    annotations resolvable also makes a malformed one **fatal**. A quoted
    annotation with stray whitespace inside the quotes -- ``rank: ' int'``, the
    space that belongs after the colon typed one character late -- is meaningless
    to a type checker, and is harmless while the annotation fails earlier with
    :exc:`NameError`, which :func:`sphinx.util.typing.get_type_hints` catches.
    Once it resolves, Python 3.14's :mod:`annotationlib` rejects the leading space
    with a :exc:`SyntaxError` that :func:`~sphinx.util.typing.get_type_hints` does
    *not* catch, so it aborts the whole build. Such annotations existed and are
    fixed at source; another would stop the build rather than be worked around
    here, which is the right way round for a typo.

    Args:
        app: Sphinx application.
        env: Build environment.
        docnames: The documents about to be read.

    """
    for info in pkgutil.walk_packages(pcapkit.__path__, 'pcapkit.',
                                      onerror=lambda name: None):
        try:
            module = importlib.import_module(info.name)
        except Exception as exc:  # pylint: disable=broad-except
            # A module that cannot be imported has no documentable annotations
            # either, so this is not worth failing the build over -- but it is
            # worth saying out loud rather than passing silently.
            logger.info('skipped unimportable module %s: %s', info.name, exc)
            continue
        bind_guarded_names(app.config.autodoc_mock_imports, module)


#: Every name :mod:`builtins` binds -- ``dict``, ``set``, ``type`` and the rest.
BUILTIN_NAMES = frozenset(dir(builtins))


def resolve_builtins_exactly(app: 'Sphinx', doctree: 'document') -> None:  # pylint: disable=unused-argument
    """Stop a bare builtin name in a type being suffix-matched to a pcapkit member.

    The Python domain resolves a reference carrying a ``refspecific`` attribute
    by *fuzzy* search when no exact match exists: any documented object whose
    name ends in ``.dict`` will do. Every type it builds implicitly carries that
    attribute -- the doc-field types (``:type:``, ``:vartype:``) set it to
    :data:`True`, and an annotation sets it to :data:`False`, which counts all
    the same, because the domain only asks whether the attribute is *present*.
    So ``dict`` in an annotation found the registry members
    :attr:`TCP.dict <pcapkit.const.reg.apptype.tcp.TCP.dict>` and
    ``UDP.dict`` and linked to the first, with a ``more than one target found``
    warning; ``type`` and ``set`` went the same way. A registry growing one
    member named like a builtin would mislink it *silently*.

    Dropping the attribute for a builtin name leaves only the exact lookup, by
    the bare name and within the current module and class. That finds nothing
    for ``dict``, so :mod:`~sphinx.ext.intersphinx` links it to the Python docs.

    An explicit role is left alone: ``:class:`.dict``` asks for the fuzzy
    search by its leading dot, and only a role's node carries ``refwarn``.

    Args:
        app: Sphinx application.
        doctree: The document just read.

    """
    for node in doctree.findall(addnodes.pending_xref):
        attributes = node.attributes
        if (attributes.get('refdomain') == 'py' and 'refspecific' in attributes
                and 'refwarn' not in attributes
                and attributes.get('reftarget') in BUILTIN_NAMES):
            del attributes['refspecific']


#: Enum member docstrings as autodoc read them, held from
#: :func:`save_enum_member_docstring` until :func:`restore_enum_member_docstring`.
_ENUM_MEMBER_DOCSTRINGS = {}  # type: Dict[str, List[str]]


def is_enum_member(name: str) -> bool:
    """Whether ``name`` is the fully qualified name of an enum member.

    Decided from the name, because autodoc does not hand over the member: for
    ``PayloadProtocolIdentifier.H_323`` Sphinx 9.1 passes the plain ``int`` 13.

    Args:
        name: Fully qualified name of the object being documented.

    Returns:
        :data:`True` if the name before the last dot is an enumeration and the
        last part is one of its members.

    """
    parent_name, _, member = name.rpartition('.')
    try:
        parent = pkgutil.resolve_name(parent_name)
    except (ImportError, AttributeError, ValueError):
        return False
    return isinstance(parent, enum.EnumMeta) and member in parent.__members__


def save_enum_member_docstring(app: 'Sphinx', what: str, name: str,  # pylint: disable=unused-argument
                               obj: 'Any', options: 'Any', lines: 'List[str]') -> None:  # pylint: disable=unused-argument
    """Keep an enum member's docstring before :mod:`~sphinx.ext.napoleon` reads it.

    Napoleon takes the first line of every attribute docstring as Google's
    inline ``type: description`` form and splits it at the first colon. A
    registry member's docstring is the registry's own text, so the colon is
    usually a URL's: ``H.323 [http://standard.pictel.com/...]`` rendered as
    *Type:* ``H.323 [http`` above the description ``//standard.pictel.com/...``,
    on 51 members. The bogus type was also parsed as a cross-reference, which is
    where the ``http`` and ``Echo`` ``more than one target found`` warnings came
    from.

    Args:
        app: Sphinx application.
        what: Type of the object being documented.
        name: Fully qualified name of the object.
        obj: The object itself.
        options: Directive options.
        lines: The docstring, which is not changed here.

    """
    if what == 'attribute' and is_enum_member(name):
        _ENUM_MEMBER_DOCSTRINGS[name] = list(lines)


def restore_enum_member_docstring(app: 'Sphinx', what: str, name: str,  # pylint: disable=unused-argument
                                  obj: 'Any', options: 'Any', lines: 'List[str]') -> None:  # pylint: disable=unused-argument
    """Undo napoleon's inline type on an enum member, from the saved docstring.

    An enum member's type is its enumeration, which autodoc already shows, so a
    ``:type:`` field napoleon added there is always a misread line. Only that
    case is undone: a docstring napoleon rewrote in any other way keeps the
    rewrite.

    Args:
        app: Sphinx application.
        what: Type of the object being documented.
        name: Fully qualified name of the object.
        obj: The object itself.
        options: Directive options.
        lines: The docstring after napoleon, restored in place.

    """
    original = _ENUM_MEMBER_DOCSTRINGS.pop(name, None)
    if original is None:
        return
    if (any(line.startswith(':type:') for line in lines)
            and not any(line.startswith(':type:') for line in original)):
        lines[:] = original


def format_aenum_class(annotation: 'Any', config: 'Config') -> 'Optional[str]':  # pylint: disable=unused-argument
    """Name a class that :mod:`aenum` defines by its qualified name.

    ``typehints_fully_qualified`` is off, so a class renders by its bare name, and
    :mod:`aenum` publishes no inventory to link to. A union of an :mod:`aenum`
    class and its standard library namesake therefore read ``IntEnum | IntEnum``:
    the first linked to :class:`enum.IntEnum`, the second plain text
    (:issue:`1858`). Qualifying the :mod:`aenum` one tells them apart.

    The name is the one the package exports, ``aenum.IntEnum``, rather than the
    ``aenum._enum`` module that defines the class. ``sphinx-autodoc-typehints``
    3.15 renders ``Bases:`` lines too, so ``NumberField[IntEnum | IntEnum]``
    reads apart there as well.

    Args:
        annotation: The type being rendered, or a part of one.
        config: Sphinx configuration.

    Returns:
        A ``:py:class:`` role naming an :mod:`aenum` class, or :data:`None` to
        leave anything else to the default rendering.

    """
    module = getattr(annotation, '__module__', None)
    if not isinstance(annotation, type) or not isinstance(module, str) or module.partition('.')[0] != 'aenum':
        return None
    name = annotation.__qualname__
    owner = 'aenum' if getattr(aenum, name, None) is annotation else module
    return f':py:class:`{owner}.{name}`'


# NB: only one formatter can be configured, so any other formatter-based fix has
# to share this one.
typehints_formatter = format_aenum_class

#: A name followed by an attribute access or a call, in the source text of a default.
DOTTED_HEAD = re.compile(r'(?<![\w.])([A-Za-z_]\w*)(?=[.(])')


def unalias_defaults(signature: 'inspect.Signature', namespace: 'Dict[str, Any]') -> 'inspect.Signature':
    """Name each class a preserved default reaches through an import alias by its own name.

    ``autodoc_preserve_defaults`` renders a default as its source text, and the
    protocol modules import their registries under private aliases, so a
    ``make()`` signature read ``next=Enum_TransType.UDP`` (:issue:`1859`). The
    alias is the module's own spelling; the class is
    :class:`~pcapkit.const.reg.transtype.TransType`, which the parameter field
    names, so the default reads ``next=TransType.UDP``.

    Only a name the module binds to a class of another name is replaced, and only
    where it heads an attribute access or a call, as in an enumeration member or
    ``Enum_FilterType(0)``. A module, such as ``sys`` in ``sys.byteorder``, is
    left alone.

    Args:
        signature: The signature, its defaults as autodoc preserved them.
        namespace: The globals of the module defining the callable.

    Returns:
        The signature with those defaults renamed.

    """
    def rename(match: 're.Match[str]') -> str:
        value = namespace.get(match.group(1))
        return value.__name__ if isinstance(value, type) and value.__name__ != match.group(1) else match.group(1)

    parameters = []
    for param in signature.parameters.values():
        if isinstance(param.default, DefaultValue):
            text = DOTTED_HEAD.sub(rename, param.default.name)
            # NB: an unchanged parameter is kept as is, since a DefaultValue
            # compares by identity and the caller compares the signatures.
            if text != param.default.name:
                param = param.replace(default=DefaultValue(text))
        parameters.append(param)
    return signature.replace(parameters=parameters)


def name_aliased_defaults(app: 'Sphinx', obj: 'Any', bound_method: bool) -> None:  # pylint: disable=unused-argument
    """Rename the aliased classes in the defaults autodoc just preserved.

    autodoc emits ``autodoc-before-process-signature`` once it has written the
    preserved defaults to the callable's ``__signature__``, and reads the
    signature after it, so :func:`unalias_defaults` is applied there.

    Args:
        app: Sphinx application.
        obj: The function or method whose signature autodoc is about to read.
        bound_method: Whether it is read as a bound method.

    """
    if not app.config.autodoc_preserve_defaults or not (inspect.isfunction(obj) or inspect.ismethod(obj)):
        return
    signature = getattr(obj, '__signature__', None)
    namespace = getattr(inspect.unwrap(getattr(obj, '__func__', obj)), '__globals__', None)
    if not isinstance(signature, inspect.Signature) or namespace is None:
        return
    renamed = unalias_defaults(signature, namespace)
    if renamed == signature:
        return
    # NB: as autodoc stores it, since a bound method takes no attribute of its own.
    try:
        obj.__signature__ = renamed
    except AttributeError:
        obj.__dict__['__signature__'] = renamed


def passes_through(new: 'FunctionType') -> bool:
    """Whether a ``__new__`` takes nothing but ``*args`` and ``**kwargs``.

    Such a ``__new__`` leaves the parameters to ``__init__``.
    :class:`~pcapkit.protocols.protocol.ProtocolBase`, :class:`Info`,
    :class:`Schema` and the reassembly and flow-tracing bases each define one.

    Args:
        new: The ``__new__`` function.

    Returns:
        :data:`True` if its parameters after ``cls`` are exactly ``*args`` and
        ``**kwargs``.

    """
    try:
        parameters = list(inspect.signature(new).parameters.values())[1:]
    except (TypeError, ValueError):
        return False
    return [param.kind for param in parameters] == [inspect.Parameter.VAR_POSITIONAL,
                                                    inspect.Parameter.VAR_KEYWORD]


def hidden_init(cls: type) -> 'Optional[FunctionType]':
    """The ``__init__`` a call to ``cls`` runs, where a ``__new__`` hides it from autodoc.

    Sphinx 9.1 takes a class signature from any ``__new__`` the class defines or
    inherits before it looks at ``__init__``. ``sphinx-autodoc-typehints`` 3.15
    takes the ``__new__`` where it and the ``__init__`` sit at the same depth of the MRO, as
    :func:`inspect.signature` does, and otherwise leaves Sphinx's choice alone
    when the ``__init__`` it picks carries no annotations, or names parameters the
    other does not. So a ``__new__`` passing ``*args`` and ``**kwargs`` through
    wins over the ``__init__`` that names the parameters, and ``FTP`` rendered as
    ``FTP(*args, **kwargs)``. A ``__new__`` deeper in the MRO wins over a nearer
    ``__init__`` too, so :class:`~pcapkit.dumpkit.pcap.PCAPIO` rendered the
    ``(fname, **kwargs)`` of :class:`dictdumper.dumper.Dumper` (:issue:`1860`).

    The MRO is walked as :func:`inspect.signature` walks it, but past each
    ``__new__`` that only passes its arguments through. A ``__new__`` with
    parameters of its own is the constructor, and autodoc reads it already.

    :class:`Info` and :class:`Schema` give each subclass its own ``__init__`` on
    its first construction (see :func:`~pcapkit.corekit.infoclass.info_final`),
    so the ``__init__`` a subclass inherits from them before then is not the one
    a call runs. Such a class keeps the catch-all, which is also what
    :func:`inspect.signature` reports for it.

    Args:
        cls: The class being documented.

    Returns:
        The ``__init__`` function, or :data:`None` where autodoc already reads
        the constructor or where it is not known until the class is first
        constructed.

    """
    if not inspect.isfunction(inspect.unwrap(cls.__new__)):
        return None
    for klass in cls.__mro__:
        namespace = vars(klass)
        new = namespace.get('__new__')
        if isinstance(new, staticmethod):
            new = new.__func__
        if inspect.isfunction(new) and not passes_through(new):
            return None
        if '__init__' in namespace:
            init = namespace['__init__']
            if not inspect.isfunction(init) or (klass in (Info, Schema) and klass is not cls):
                return None
            return init
    return None


def init_signature(app: 'Sphinx', init: 'FunctionType') -> str:
    """Render an ``__init__``'s parameters as a class signature.

    The instance parameter is dropped, as a call to the class does not pass it.
    The types are left out, as ``sphinx-autodoc-typehints`` leaves them out of
    every signature in this build and puts them in the parameter fields. The
    defaults go through ``autodoc_preserve_defaults`` and
    :func:`unalias_defaults` as autodoc's own signatures do. A generated
    ``__init__`` has no source for that to read, so its
    :data:`~pcapkit.corekit.sentinels.NO_VALUE` defaults are written as the
    generator writes them, whatever the sentinel's ``repr()``.

    Args:
        app: Sphinx application.
        init: The ``__init__`` function.

    Returns:
        The parenthesised parameter list.

    """
    preserve = app.config.autodoc_preserve_defaults
    if preserve:
        update_default_value(init, False)
    signature = inspect.signature(init)
    if preserve:
        signature = unalias_defaults(signature, init.__globals__)
    parameters = list(signature.parameters.values())[1:]
    if preserve:
        parameters = [param.replace(default=DefaultValue('NO_VALUE')) if param.default is NO_VALUE else param
                      for param in parameters]
    text = stringify_signature(signature.replace(parameters=parameters),
                               show_annotation=False, show_return_annotation=False)
    return text.replace('\\', '\\\\') if app.config.strip_signature_backslash else text


def restore_class_signature(app: 'Sphinx', what: str, name: str, obj: 'Any',
                            options: 'Dict[str, Any]', signature: 'Optional[str]',
                            return_annotation: 'Optional[str]') -> 'Optional[tuple[str, None]]':
    """Give a class the signature that a call to it takes.

    * A class whose ``__init__`` a ``__new__`` hides (see :func:`hidden_init`)
      gets that ``__init__``'s parameters.
    * An enumeration gets ``(*values)``, the lookup by value. The standard
      library's ``__signature__`` gives a class with no members the
      functional-API form instead, ``(new_class_name, /, names, *, module=None,
      ...)``, which is how :class:`~pcapkit.const.reg.apptype.apptype.AppType`,
      :class:`~pcapkit.const.pcapng.filter_type.FilterType` and
      ``FrameType.Flags`` rendered (:issue:`1862`).

    The handler of ``sphinx-autodoc-typehints`` is still run first, for what it
    records: it notes each object autodoc documents, and only a noted class has
    its type parameters added to its header. Its signature is then replaced.

    Args:
        app: Sphinx application.
        what: Type of the object being documented.
        name: Fully qualified name of the object.
        obj: The object itself.
        options: Directive options.
        signature: Signature autodoc has so far, if any.
        return_annotation: Return annotation autodoc has so far, if any.

    Returns:
        The signature and no return annotation for such a class; :data:`None`
        otherwise, to let the other handlers run.

    """
    if what not in {'class', 'exception'} or not isinstance(obj, type):
        return None
    if isinstance(obj, enum.EnumMeta):
        restored = '(*values)'
    else:
        init = hidden_init(obj)
        if init is None:
            return None
        restored = init_signature(app, init)
    typehints_process_signature(app, what, name, obj, options, signature, return_annotation)
    return restored, None


def constructor_for_types(cls: type) -> str:
    """Which constructor ``sphinx-autodoc-typehints`` reads a class's parameter types from.

    The library reads them from the constructor :func:`inspect.signature` would
    choose, so a pass-through ``__new__`` defined beside the ``__init__`` wins,
    and a class docstring's parameter list loses its types: ``strict``,
    ``store`` and ``timeout`` on the reassembly classes, ``fout`` and the rest on
    the flow-tracing ones, ``dict_`` on :class:`Info` (:issue:`1860`). The
    ``__init__`` that :func:`hidden_init` finds is read instead, as the releases
    before 3.14 read it.

    An overloaded ``__init__`` keeps the library's choice. Reading it would add an
    ``Overloads`` field to each class, which no release showed for these classes,
    and the protocol classes, whose shared ``__init__`` is overloaded, list no
    constructor parameters for types to go on.

    Args:
        cls: The class being documented.

    Returns:
        ``'__init__'`` or ``'__new__'``.

    """
    chosen = typehints_constructor_name(cls)
    if chosen == '__new__':
        init = hidden_init(cls)
        if init is not None and not typing.get_overloads(init):
            return '__init__'
    return chosen


def read_constructor_types_from_init(app: 'Sphinx') -> None:  # pylint: disable=unused-argument
    """Have ``sphinx-autodoc-typehints`` choose constructors with :func:`constructor_for_types`.

    The library has no setting for the choice, so the modules of it that read the
    choice for the docstring types are pointed at this one.

    Args:
        app: Sphinx application.

    """
    for module in (typehints_docstring_handler, typehints_hints):
        # NB: read first, so a release that drops the name fails here rather
        # than gaining an attribute nothing reads.
        getattr(module, 'constructor_name')
        module.constructor_name = constructor_for_types


class DropTableWrapperIds(SphinxPostTransform):
    """Take a wrapped table's ids off the ``table-wrapper`` container furo adds.

    furo wraps each table in a container so it can scroll, and copies every
    attribute of the table onto it, ``ids`` included. A titled ``list-table``
    carries an id, so the page carried that id on the wrapper as well as on the
    table -- the titled tables on ``const/reg.html`` (:issue:`1861`). The table
    keeps its ids, so a reference to it still lands on it.

    """

    formats = ('html',)
    #: After furo's own wrapper transform, at the default 500.
    default_priority = 510

    def run(self, **kwargs: 'Any') -> None:
        for container in self.document.findall(nodes.container):
            if 'table-wrapper' not in container['classes']:
                continue
            inner = {id_ for child in container.children if isinstance(child, nodes.table)
                     for id_ in child['ids']}
            container['ids'] = [id_ for id_ in container['ids'] if id_ not in inner]


def follow_builtins_alias(app: 'Sphinx', modname: 'Optional[str]',  # pylint: disable=unused-argument
                          attribute: str) -> 'Optional[str]':
    """Keep viewcode on the module that binds a name whose object reports :mod:`builtins`.

    The ``BufferID`` aliases are subscripted ``Tuple``, and ``Tuple`` in
    :mod:`pcapkit.utilities.compat` is the builtin :class:`tuple`, so each alias
    reports ``__module__ == 'builtins'``. viewcode followed that, recorded a
    module with no source, and listed it in its module index, which then linked a
    ``builtins.html`` that is never written (:issue:`1863`).

    Args:
        app: Sphinx application.
        modname: The module the object is documented in.
        attribute: Its name there.

    Returns:
        ``modname`` for such an object, and :data:`None` for anything else, which
        leaves viewcode to follow it as usual.

    """
    if not modname:
        return None
    try:
        value = pkgutil.resolve_name(f'{modname}:{attribute}')
    except (ImportError, AttributeError, ValueError):
        return None
    return modname if getattr(value, '__module__', None) == 'builtins' else None


# NB: handlers used to sit here -- ``remove_module_docstring``,
# ``process_docstring``, ``process_fields`` and ``source_read`` -- each with its
# ``app.connect`` call commented out in ``setup`` below, so none of them had run
# for as long as they had been in the file. They are deleted rather than restored,
# because restoring them would either duplicate work done properly elsewhere or make the
# build unusable:
#
#   ``remove_module_docstring`` and ``process_docstring`` were both attempts at the
#   same thing -- flipping :data:`typing.TYPE_CHECKING` and reloading each module
#   so autodoc could see the ``if TYPE_CHECKING:`` names. ``bind_type_checking_names``
#   above solves that, per module and without mutating a global mid-build.
#
#   ``process_fields`` only ever printed; the ``lines.append`` that was its point
#   was itself commented out.
#
#   ``source_read`` printed every document's entire source text, which on this
#   project is several thousand pages of build log.
#
# If the ``TYPE_CHECKING`` behaviour is ever wanted again, ``bind_type_checking_names``
# is where it belongs, not a reload hook.


def setup(app: 'Sphinx') -> None:
    # NB: after ``sphinx_autodoc_typehints``, whose ``env-before-read-docs``
    # handlers connect at the default 500; see ``bind_type_checking_names``.
    app.connect('env-before-read-docs', bind_type_checking_names, priority=600)
    app.connect('autodoc-skip-member', maybe_skip_member)
    # NB: before napoleon's ``autodoc-skip-member`` handler, which connects at the
    # default 500 and returns ``False`` for this hook; the first answer that is
    # not ``None`` is the one autodoc uses.
    app.connect('autodoc-skip-member', skip_enum_value_hook, priority=400)
    app.connect('builder-inited', read_constructor_types_from_init)
    # NB: below ``sphinx_autodoc_typehints``, which connects at the default 500 and
    # would otherwise win the tie on registration order -- conf.py's ``setup`` runs
    # after the extensions in ``extensions`` have been set up. Its signature is
    # the one this replaces.
    app.connect('autodoc-process-signature', restore_class_signature, priority=400)
    # NB: after the ``update_defvalue`` that autodoc's legacy documenters connect
    # at the default 500; the current ones preserve the defaults before emitting.
    app.connect('autodoc-before-process-signature', name_aliased_defaults, priority=600)
    app.connect('viewcode-follow-imported', follow_builtins_alias)
    app.add_post_transform(DropTableWrapperIds)
    app.connect('doctree-read', resolve_builtins_exactly)
    # NB: either side of napoleon's ``autodoc-process-docstring`` handler, which
    # connects at the default 500.
    app.connect('autodoc-process-docstring', save_enum_member_docstring, priority=400)
    app.connect('autodoc-process-docstring', restore_enum_member_docstring, priority=600)
