.PHONY: bootstrap setup dist release docs samples test test-all coverage

export PIPENV_VENV_IN_PROJECT=1
export PIPENV_CACHE_DIR ?= $(CURDIR)/.pipenv-cache
export PIP_CACHE_DIR ?= $(CURDIR)/.pip-cache
export all_proxy=

# Recipes below use bash features (brace expansion), so bash is required; take it
# from PATH rather than a fixed prefix, as Homebrew, Linuxbrew and system installs
# all put it somewhere different.
SHELL  := $(shell command -v bash 2>/dev/null || echo /bin/bash)
VERSION = $(shell cat pcapkit/__init__.py | grep "^__version__" | sed "s/__version__ = '\(.*\)'/\1/")

# ``lxml`` needs libxml2/libxslt; on a brewed system they live under the brew
# prefix, which differs between macOS (/opt/homebrew, /usr/local) and Linuxbrew.
BREW ?= $(shell command -v brew 2>/dev/null)
ifneq ($(BREW),)
BREW_PREFIX ?= $(shell $(BREW) --prefix)/opt
else
BREW_PREFIX ?= /opt/homebrew/opt
endif

LIBXML2_PREFIX := $(BREW_PREFIX)/libxml2
LIBXSLT_PREFIX := $(BREW_PREFIX)/libxslt

ifneq ($(wildcard $(LIBXML2_PREFIX)/bin/xml2-config),)
export PATH := $(LIBXML2_PREFIX)/bin:$(PATH)
export CPPFLAGS := -I$(LIBXML2_PREFIX)/include $(CPPFLAGS)
export LDFLAGS := -L$(LIBXML2_PREFIX)/lib $(LDFLAGS)
export PKG_CONFIG_PATH := $(LIBXML2_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
export XML2_CONFIG := $(LIBXML2_PREFIX)/bin/xml2-config
endif

ifneq ($(wildcard $(LIBXSLT_PREFIX)/bin/xslt-config),)
export PATH := $(LIBXSLT_PREFIX)/bin:$(PATH)
export CPPFLAGS := -I$(LIBXSLT_PREFIX)/include $(CPPFLAGS)
export LDFLAGS := -L$(LIBXSLT_PREFIX)/lib $(LDFLAGS)
export PKG_CONFIG_PATH := $(LIBXSLT_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
export XSLT_CONFIG := $(LIBXSLT_PREFIX)/bin/xslt-config
endif

bootstrap: pipenv
setup: pipenv

update: pipenv vendor
dist: update isort dist-clean dist-build dist-upload

dist-clean:
	mkdir -p sdist eggs wheels
	[ -d dist ] && find dist -iname '*.egg' -exec mv {} eggs \; || true
	[ -d dist ] && find dist -iname '*.whl' -exec mv {} wheels \; || true
	[ -d dist ] && find dist -iname '*.tar.gz' -exec mv {} sdist \; || true

dist-build:
	pipenv run python -m build

dist-upload:
	pipenv run twine check dist/*
	pipenv run twine upload dist/* -r pypi --skip-existing
	pipenv run twine upload dist/* -r testpypi --skip-existing

git-tag:
	git tag --sign "v$(VERSION)"
	git push --tags

pipenv:
	pipenv install --skip-lock --dev

vendor:
	pipenv run pcapkit-vendor

# Sample captures under sample/ are not tracked (see .gitignore); regenerate the
# ones the runtime, regression and integration tests read.
samples:
	pipenv run python util/make_samples.py

# Mirrors the selection run by .github/workflows/unit-tests.yml, i.e. the tests
# that need no sample captures beyond the committed ones.
test:
	pipenv run python -m pytest -q --ignore=tests/integration --ignore-glob='*_runtime.py' --ignore-glob='*_regression.py'

# Everything, including the fixture-dependent runtime/regression/integration tests.
test-all: samples
	pipenv run python -m pytest -q

coverage: samples
	pipenv run coverage run -m pytest -q
	pipenv run coverage report

docs:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C docs html

docs-clean:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C docs clean

docs-autobuild:
	PCAPKIT_SPHINX=1 SPHINXOPTS="--watch ../pcapkit" pipenv run $(MAKE) -C docs livehtml

isort:
	pipenv run isort -l100 -ppcapkit --skip-glob '**/__init__.py' pcapkit $(wildcard temp/sort.py)
	pipenv run isort -l100 -ppcapkit pcapkit/{const,vendor}/*/*.py
	pipenv run isort -l100 -ppcapkit util/*.py

vermin:
	mkdir -p temp
	pipenv run vermin pcapkit --backport argparse --backport enum --backport importlib --backport ipaddress --backport typing --backport typing_extensions --no-parse-comments --eval-annotations -vv pcapkit > temp/vermin.txt
	command -v code >/dev/null && code temp/vermin.txt || cat temp/vermin.txt

pylint:
	pipenv run pylint --load-plugins=pylint.extensions.check_elif,pylint.extensions.docstyle,pylint.extensions.emptystring,pylint.extensions.overlapping_exceptions --disable=all --enable=F,E,W,R,basic,classes,format,imports,refactoring,else_if_used,docstyle,compare-to-empty-string,overlapping-except --disable=blacklisted-name,invalid-name,missing-class-docstring,missing-function-docstring,missing-module-docstring,design,too-many-lines,eq-without-hash,old-division,no-absolute-import,input-builtin,too-many-nested-blocks,broad-except,singleton-comparison,ungrouped-imports --max-line-length=120 --init-import=yes pcapkit

mypy:
	pipenv run mypy --follow-imports=silent --ignore-missing-imports --show-column-numbers --show-error-codes pcapkit

bandit:
	pipenv run bandit -r pcapkit

profile:
	$(MAKE) -C test profile

mypy-types:
	pipenv run mypy --install-types
