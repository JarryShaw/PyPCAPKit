## 1.6.0 -- unreleased

Wave 2 of the roadmap, per the contributing docs' enhancement-proposal page: the protocol pairs that wanted a shared abstract base, and the two that simply had no dissector at all.

- **Added** -- `Radiotap`, a dissector for the fixed 8-octet start of the radiotap header (<https://www.radiotap.org/>) capture tools prepend to an 802.11 frame. `LinuxSLL`/ `LinuxSLL1`/ `LinuxSLL2` dispatch to it for the `ARPHRD_IEEE80211_RADIOTAP` case instead of falling back to `Raw`. Decodes `it_version`, `it_pad` and `it_len`, and walks the present-flags chain (including its bit-31 extended-word chaining) far enough to count its words; the optional-field region those bits select is skipped whole rather than decoded field by field, and the 802.11 MAC frame behind it -- which has no dissector anywhere in this package yet -- is kept as `Raw`. The last of [#2460](https://github.com/JarryShaw/PyPCAPKit/issues/2460)'s five `arphrd_type` follow-ups to get a dissector of its own -- `FRAD` ([#2499](https://github.com/JarryShaw/PyPCAPKit/pull/2499)), `NETLINK` ([#2507](https://github.com/JarryShaw/PyPCAPKit/pull/2507)) and `IPGRE`/`IP6GRE` ([#2501](https://github.com/JarryShaw/PyPCAPKit/issues/2501)) are tracked on their own reviews.

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
