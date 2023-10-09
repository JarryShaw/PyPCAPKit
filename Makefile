.PHONY: dist release docs

export PIPENV_VENV_IN_PROJECT=1
export all_proxy=

SHELL  := /opt/homebrew/bin/bash
VERSION = $(shell cat pcapkit/__init__.py | grep "^__version__" | sed "s/__version__ = '\(.*\)'/\1/")

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
	pipenv run pip install -U pip setuptools wheel pysocks
	pipenv update
	pipenv install --dev
	pipenv clean

vendor:
	pipenv run pcapkit-vendor

docs:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C docs html

docs-clean:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C docs clean

docs-autobuild:
	PCAPKIT_SPHINX=1 SPHINXOPTS="--watch ../pcapkit" pipenv run $(MAKE) -C docs livehtml

isort:
	pipenv run isort -l100 -ppcapkit --skip-glob '**/__init__.py' pcapkit temp/sort.py
	pipenv run isort -l100 -ppcapkit pcapkit/{const,vendor}/*/*.py
	pipenv run isort -l100 -ppcapkit util/*.py

vermin:
	pipenv run vermin pcapkit --backport argparse --backport enum --backport importlib --backport ipaddress --backport typing --backport typing_extensions --no-parse-comments --eval-annotations -vv pcapkit > temp/vermin.txt
	code temp/vermin.txt

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
