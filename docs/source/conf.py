# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import datetime
import importlib
import logging
import os
import pkgutil
from typing import TYPE_CHECKING

# NB: a private module of ``sphinx-autodoc-typehints``, used deliberately -- see
# ``bind_type_checking_names`` below for what it buys and why reimplementing it
# here would be worse. If a future release moves it the import fails loudly at
# build time, which is the outcome to want: the alternative is a build that
# silently goes back to emitting unresolvable annotations.
from sphinx_autodoc_typehints._resolver import resolve_type_guarded_imports

# NB: this must precede ``import pcapkit``. ``pcapkit.utilities.logging`` reads
# ``PCAPKIT_SPHINX`` at *import* time to compute ``SPHINX_TYPE_CHECKING``, and
# importing ``pcapkit`` already pulls in the schema modules -- so setting it any
# later leaves every ``if SPHINX_TYPE_CHECKING:`` TypedDict undefined and autodoc
# cannot document them.
os.environ['PCAPKIT_SPHINX'] = '1'

import pcapkit

if TYPE_CHECKING:
    from typing import Any, Dict, Optional
    from sphinx.application import Sphinx

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
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',

    'sphinx_autodoc_typehints',

    "sphinxext.opengraph",

    'sphinx_copybutton',

    'sphinxcontrib.mermaid',
]

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
    "source_branch": "master",
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


def maybe_skip_member(app: 'Sphinx', what: str, name: str,  # pylint: disable=unused-argument
                      obj: 'Any', skip: bool, options: 'Dict[str, Any]') -> bool:  # pylint: disable=unused-argument
    if name == '_abc_impl':
        return True
    if name == '__init__':
        if '__create_fn__' in obj.__qualname__:
            return True
    return skip


def bind_type_checking_names(app: 'Sphinx') -> None:
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

    ``sphinx-autodoc-typehints`` already does this per module, lazily, for the
    objects it processes -- but it skips classes outright, since it keys off
    ``__globals__`` which a class does not have, so class attributes never
    benefited. Its implementation is reused rather than rewritten because it
    executes the block one statement at a time, so an unimportable optional
    dependency (``pcap``, ``pcapfile``) cannot strand the names declared after it.

    One consequence is worth knowing before it is met as a mystery: making the
    annotations resolvable also makes a malformed one **fatal**. A quoted
    annotation with stray whitespace inside the quotes -- ``rank: ' int'``, the
    space that belongs after the colon typed one character late -- is meaningless
    to a type checker and was previously harmless here, because these annotations
    failed earlier with :exc:`NameError`, which
    :func:`sphinx.util.typing.get_type_hints` catches. Now they resolve, and Python
    3.14's :mod:`annotationlib` rejects the leading space with a
    :exc:`SyntaxError` that :func:`~sphinx.util.typing.get_type_hints` does *not*
    catch, so it aborts the whole build. Two such annotations existed and both are
    fixed at source; a third would stop the build rather than be worked around
    here, which is the right way round for a typo.

    Args:
        app: Sphinx application.

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
        resolve_type_guarded_imports(app.config.autodoc_mock_imports, module)


def claim_attribute_signature(app: 'Sphinx', what: str, name: str,  # pylint: disable=unused-argument
                              obj: 'Any', options: 'Dict[str, Any]',  # pylint: disable=unused-argument
                              signature: 'Optional[str]',  # pylint: disable=unused-argument
                              return_annotation: 'Optional[str]') -> 'Optional[tuple]':  # pylint: disable=unused-argument
    """Stop a class-valued attribute being given the class's own signature.

    Several class attributes here hold a *class* as their value --
    :attr:`Protocol.__schema__ <pcapkit.protocols.protocol.Protocol.__schema__>` and
    the ``__protocol_type__`` of each reassembly and flow-tracing class. Autodoc
    documents them as attributes, so it collects no signature for them, but
    ``sphinx_autodoc_typehints`` keys its own handler off ``callable(obj)`` alone,
    sees a class, and hands one back. Sphinx 9.1 then stores it with
    ``signatures[0] = ...`` on a list it never populated, which raises
    ``IndexError: list assignment index out of range`` -- and autodoc turns that
    into ``error while formatting signature for ...`` and drops the member from the
    page entirely.

    Claiming the event first is what prevents that. The returned value has to be
    non-:data:`None` to win ``emit_firstresult`` yet must not look like a
    ``(args, retann)`` pair, so it is the empty tuple: falsy, and of the wrong
    length for the ``len(result) == 2`` guard Sphinx applies before unpacking. An
    attribute has no signature of its own to lose, so nothing is suppressed here
    beyond a value that was never meaningful.

    ``callable(obj)`` keeps this off ordinary attributes and off properties, whose
    ``obj`` is the :class:`property` itself and therefore not callable -- those
    already resolve correctly and are left alone.

    Args:
        app: Sphinx application.
        what: Type of the object being documented.
        name: Fully qualified name of the object.
        obj: The object itself.
        options: Directive options.
        signature: Signature autodoc has so far, if any.
        return_annotation: Return annotation autodoc has so far, if any.

    Returns:
        The empty tuple for a class-valued attribute, to claim the event without
        recording a signature; :data:`None` otherwise, to let other handlers run.

    """
    if what in {'attribute', 'property'} and callable(obj):
        return ()
    return None


# NB: four handlers used to sit here -- ``remove_module_docstring``,
# ``process_docstring``, ``process_fields`` and ``source_read`` -- each with its
# ``app.connect`` call commented out in ``setup`` below, so none of them had run
# for as long as they had been in the file. They are deleted rather than restored,
# because restoring them would either duplicate work now done properly or make the
# build unusable:
#
#   ``remove_module_docstring`` and ``process_docstring`` were two attempts at the
#   same thing -- flipping :data:`typing.TYPE_CHECKING` and reloading each module
#   so autodoc could see the ``if TYPE_CHECKING:`` names. ``bind_type_checking_names``
#   above now solves that, per module and without mutating a global mid-build.
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
    app.connect('builder-inited', bind_type_checking_names)
    app.connect('autodoc-skip-member', maybe_skip_member)
    # NB: below ``sphinx_autodoc_typehints``, which connects at the default 500 and
    # would otherwise win the tie on registration order -- conf.py's ``setup`` runs
    # after the extensions in ``extensions`` have been set up.
    app.connect('autodoc-process-signature', claim_attribute_signature, priority=400)
