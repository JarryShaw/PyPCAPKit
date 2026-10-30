## 1.5.1 -- 2026-10-30

- **Fixed** -- `dictdumper` 0.8.5 fixed the mapping-key/XML-escaping defects ([#772](https://github.com/JarryShaw/PyPCAPKit/issues/772), [#1261](https://github.com/JarryShaw/PyPCAPKit/issues/1261)) that `pcapkit.dumpkit.common` had been working around since before 0.8.5 existed, so the two fixes stacked and double-escaped every dumped value ([#2442](https://github.com/JarryShaw/PyPCAPKit/issues/2442), [#2445](https://github.com/JarryShaw/PyPCAPKit/pull/2445)). The redundant workarounds are removed; the unrelated `keep_none` ([#1257](https://github.com/JarryShaw/PyPCAPKit/issues/1257)) and `tree_numbers` ([#1266](https://github.com/JarryShaw/PyPCAPKit/issues/1266)) workarounds, and a UTC-conversion fix for `make_dumper()`'s `_append_date` override that predates the stacking bug, are untouched.

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
