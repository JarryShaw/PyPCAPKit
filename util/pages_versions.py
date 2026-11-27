# -*- coding: utf-8 -*-
"""Write ``versions.json`` and ``404.html`` into the GitHub Pages build (#3077).

GitHub Pages serves ``main``'s build alone, and Read the Docs serves every version.
:data:`VERSIONS` maps each version's path segment -- ``latest``, ``stable`` and every
release tag but :data:`UNBUILT` -- to its URL there. GitHub Pages serves
:data:`NOT_FOUND` for any path it lacks: under one of those segments it sends the
reader to the same page on Read the Docs, the query and fragment kept, and anywhere
else it says the page is not found.

deploy-pages.yml's ``Write the version redirects`` runs it on the built site, as
``python util/pages_versions.py docs/build/html``, and reads the release tags from
``origin``, as the checkout holds none. It fails rather than overwrite either file
in the build.

"""

from __future__ import annotations

import argparse
import html
import json
import math
import pathlib
import re
import string
import subprocess  # nosec: B404
import sys
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterable, Optional, Union

#: The site root, which ``ogp_site_url`` in docs/source/conf.py names too.
SITE = 'https://jarryshaw.github.io/PyPCAPKit/'
#: Where Read the Docs serves each version, under its slug.
READ_THE_DOCS = 'https://pypcapkit.jarryshaw.me/en/'
#: The versions built from a branch: ``develop`` as ``latest``, and the ``stable``
#: branch, Stable Branch's mirror of ``main``, as ``stable``.
BRANCHES = ('latest', 'stable')
#: A release tag, whose Read the Docs slug is its name. A ``conda-*`` tag is none.
RELEASE = re.compile(r'v(?P<release>\d+(?:\.\d+)*)(?:(?P<pre>a|b|rc)(?P<pre_n>\d+))?'
                     r'(?:\.post(?P<post>\d+))?(?:\.dev(?P<dev>\d+))?')
#: The release tags Read the Docs holds no build of, so their Pages paths stay not
#: found rather than redirect to its 404 (#3135). Each is active there with its only
#: build failed, as its API (``/api/v3/projects/pypcapkit/versions/``) lists them.
#: Pinned rather than fetched, so a publish does not hang on that API; a tag whose
#: build is retried and succeeds leaves the set, and one whose build fails joins it.
UNBUILT = frozenset({
    'v1.0.0b1',
    'v1.3.1.dev0', 'v1.3.1.dev1', 'v1.3.1.dev2',
    'v1.3.5.post38', 'v1.3.5.post39', 'v1.3.5.post40', 'v1.3.5.post42', 'v1.3.5.post43',
    'v1.4.0',
    'v1.5.0a1', 'v1.5.0b1', 'v1.5.0b2', 'v1.5.0b4',
})
#: The two files, at the build's root.
VERSIONS = 'versions.json'
NOT_FOUND = '404.html'
#: The page GitHub Pages serves for a missing path. ``$base`` is the site's path,
#: under which GitHub Pages serves this project.
PAGE = string.Template('''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<title>Page not found - PyPCAPKit</title>
<script>
(function () {
  var base = $base_js;
  var path = location.pathname;
  if (path.slice(0, base.length) !== base) return;
  var rest = path.slice(base.length);
  var slash = rest.indexOf("/");
  var segment = slash < 0 ? rest : rest.slice(0, slash);
  var page = slash < 0 ? "" : rest.slice(slash + 1);
  if (!segment) return;
  fetch(base + "versions.json").then(function (response) {
    return response.ok ? response.json() : {};
  }).then(function (versions) {
    if (Object.prototype.hasOwnProperty.call(versions, segment)) {
      location.replace(versions[segment] + page + location.search + location.hash);
    }
  }).catch(function () {});
})();
</script>
</head>
<body>
<h1>Page not found</h1>
<p>Nothing is at this address. <a href="$site">Go to the PyPCAPKit documentation</a>.</p>
</body>
</html>
''')


def key(tag: 'str') -> 'tuple[tuple[int, ...], tuple[int, int], int, Union[int, float], str]':
    """``tag``'s place in PEP 440's order, its name breaking a tie."""
    match = RELEASE.fullmatch(tag)
    if match is None:
        raise ValueError(f'{tag} is no release tag')
    release = tuple(int(part) for part in match['release'].split('.'))
    while release and release[-1] == 0:
        release = release[:-1]
    if match['pre']:
        pre = (('a', 'b', 'rc').index(match['pre']), int(match['pre_n']))
    elif match['dev'] is not None and match['post'] is None:
        pre = (-1, 0)  # X.devN precedes X's pre-releases
    else:
        pre = (3, 0)
    post = -1 if match['post'] is None else int(match['post'])
    dev = math.inf if match['dev'] is None else int(match['dev'])
    return release, pre, post, dev, tag


def versions(tags: 'Iterable[str]') -> 'dict[str, str]':
    """Each version's path segment, the branches' then the built release tags' by version, and its URL."""
    releases = sorted({tag for tag in tags if RELEASE.fullmatch(tag) and tag not in UNBUILT}, key=key)
    return {name: f'{READ_THE_DOCS}{name}/' for name in (*BRANCHES, *releases)}


def page() -> 'str':
    """The ``404.html`` GitHub Pages serves."""
    return PAGE.substitute(base_js=json.dumps(urllib.parse.urlsplit(SITE).path), site=html.escape(SITE))


def remote_tags(remote: 'str') -> 'list[str]':
    """The tags ``remote`` lists."""
    listing = subprocess.run(['git', 'ls-remote', '--tags', '--refs', remote],  # nosec: B603 B607
                             capture_output=True, text=True, check=True, timeout=120).stdout
    return [line.split('\trefs/tags/', 1)[1] for line in listing.splitlines() if '\trefs/tags/' in line]


def write(build: 'pathlib.Path', mapping: 'dict[str, str]') -> 'None':
    """Write :data:`VERSIONS` from ``mapping``, and :data:`NOT_FOUND`, into ``build``."""
    for name in (VERSIONS, NOT_FOUND):
        if (build / name).exists():
            raise FileExistsError(f'{build / name} is already in the build, so writing it would overwrite a page')
    (build / VERSIONS).write_text(json.dumps(mapping, indent=2) + '\n', encoding='utf-8')
    (build / NOT_FOUND).write_text(page(), encoding='utf-8')


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('build', type=pathlib.Path, help='the built site, such as docs/build/html')
    parser.add_argument('--remote', default='origin', help='the git remote whose tags name the releases')
    args = parser.parse_args(argv)
    if not (args.build / 'index.html').is_file():
        print(f'::error title=No documentation build::{args.build} holds no index.html')
        return 1
    names = remote_tags(args.remote)
    for name in names:
        if name.startswith('v') and not RELEASE.fullmatch(name):
            print(f'::warning title=Not a release tag::{name} names no release, so {VERSIONS} leaves it out')
    mapping = versions(names)
    if len(mapping) == len(BRANCHES):
        print(f'::error title=No release tags::{args.remote} lists no release tag')
        return 1
    write(args.build, mapping)
    print(f'Wrote {len(mapping)} versions to {args.build / VERSIONS}, and {args.build / NOT_FOUND}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
