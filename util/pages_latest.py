# -*- coding: utf-8 -*-
"""Write ``latest/`` into the root documentation build, a redirect stub per page (#3077).

GitHub Pages serves ``main``'s build at the site root, and ``/latest/`` names the
same pages: each HTML file of the build gets a stub at its path under
:data:`FOLDER` that sends the reader to the page at the root, the query and
fragment kept, with a canonical link naming the root page. A stub per page keeps
every deep link working at a fraction of a copy's size; files other than HTML,
the static files and the inventory, get none.

deploy-pages.yml's ``Write the /latest/ redirects`` runs it on the built site, as
``python util/pages_latest.py docs/build/html``, before the root publish carries
it. It fails rather than overwrite a ``latest/`` the build itself holds.

"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import sys
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

#: The site root, which ``ogp_site_url`` in docs/source/conf.py names too.
SITE = 'https://jarryshaw.github.io/PyPCAPKit/'
#: The folder of stubs, under the build.
FOLDER = 'latest'
#: A stub. ``location.replace`` keeps the fragment, which the ``refresh`` fallback
#: drops, and leaves no history entry behind.
STUB = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting to {canonical_text}</title>
<link rel="canonical" href="{canonical}">
<script>location.replace({target_js} + location.search + location.hash);</script>
<meta http-equiv="refresh" content="0; url={target}">
</head>
<body><p>This page is at <a href="{target}">{canonical_text}</a>.</p></body>
</html>
'''


def stub(page: 'pathlib.PurePosixPath') -> 'str':
    """The stub for ``page``, a path relative to the build, written to ``latest/<page>``."""
    path = urllib.parse.quote(page.as_posix())
    target = '../' * len(page.parts) + path
    return STUB.format(canonical=html.escape(SITE + path), canonical_text=html.escape(SITE + page.as_posix()),
                       target=html.escape(target), target_js=json.dumps(target))


def write(build: 'pathlib.Path') -> 'int':
    """Write a stub for each HTML file of ``build``, and return how many."""
    folder = build / FOLDER
    if folder.exists():
        raise FileExistsError(f'{folder} is already in the build, so its stubs would overwrite a page')
    pages = sorted(pathlib.PurePosixPath(path.relative_to(build).as_posix()) for path in build.rglob('*.html'))
    for page in pages:
        target = folder.joinpath(*page.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(stub(page), encoding='utf-8')
    return len(pages)


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('build', type=pathlib.Path, help='the built site, such as docs/build/html')
    args = parser.parse_args(argv)
    if not (args.build / 'index.html').is_file():
        print(f'::error title=No documentation build::{args.build} holds no index.html')
        return 1
    print(f'Wrote {write(args.build)} redirects under {args.build / FOLDER}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
