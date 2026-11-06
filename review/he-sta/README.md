# Experimental FreeBSD HE station review materials

Author: Denis Lemire — Aspiring independent contributor and FreeBSD enthusiast.
Dated author-review snapshot, 5 November 2026. No maintainer approval implied.

Canonical proposed source: [codex/80211ax-sta-review](https://github.com/denislemire/freebsd-src/tree/codex/80211ax-sta-review),
head `247377f1b50386c87d95fc53ed315d99e57ddf17`, based on main
`12f90bbd3029fedea93e9bb0b1f02c3afafe237b`: 21 signed logical commits,
17 files, 1,313 insertions and 46 deletions. This companion branch adds review
materials only; its kernel/ifconfig implementation is identical to that head.
Use the canonical branch for the proposed integration diff.

- [Reviewer guide, PDF](https://denis.lemire.name/download/enabling-he-wifi-in-freebsd.pdf): architecture, invariants, hardware,
  debugging methods, positive/negative results, terminology and remaining work.
- [Standalone helper kit](tests/README.md): run native/actual-extracted routines
  against the source checkout, with normal and ASan/UBSan builds. The kit was
  extracted, manifest-checked and run on Darwin; ATF/Kyua placement is unresolved.
- [Sanitized evidence](evidence/): whitelisted metrics, binary/archive identities,
  retransmissions, completed-collector and recovery facts. Whole raw archives,
  dumps and identifying captures are deliberately absent.
- [Source notice inventory](LICENSE-INVENTORY.md): inspect each original notice.

## Demonstrated scope and boundaries

Experimental opt-in 5 GHz station path, RTL8852BT + U6 Mesh, tested at 40 MHz.
Hardware capability, transmitted offer and accepted state remain distinct.
Fresh CURRENT GENERIC/WITNESS/INVARIANTS builds and three same-binary controls
pass: default-off VHT, HE/software crypto and HE/hardware crypto. Software crypto
remains slower (roughly 38–39/17 Mbps simultaneous TCP), cause not isolated.
Intel/MediaTek are compile coverage only. CURRENT userland is existing 16-series,
not rebuilt for the 35 upstream commits between source checkpoints.

The separately identified STABLE port passes native CLI, IPv6 timed renewal,
automatic HE startup and an ordinary default reboot with IPv4/IPv6 data and
integrity. This is experimental port evidence, not an integrated stable backport.
Normal-boot rate evidence is a current-station firmware-fed HE cache snapshot,
not a newly observed firmware event or the sampled packet's encoding. Earlier
CURRENT trials separately observed firmware events and addressed HE receive.

Earlier matched light-instrumentation CURRENT medians were 285.6/141.2 Mbps VHT
and 324.2/185.1 Mbps HE (up/down). Fixed order and shared RF limit inference;
different cohorts/instrumentation are not interchangeable throughput estimates.

Positive live queued-key discard remains unobserved; the actual helper's positive
branch is covered by modeled queues. Suspend/resume, long soak, other APs/radios,
80 MHz, GTK lifecycle and broader recovery need work. Provisional ioctl/API,
capability policy and cross-driver key/queue contracts need maintainer review.
No full Wi-Fi 6 certification, warning-free kernel, upstream acceptance or
backport is claimed. Checksums identify artifacts; they do not prove correctness
or external reproduction. Code/tests/prose were developed with AI assistance;
Denis remains responsible for provenance and claims.

The guide's LaTeX source is included. Build with pdflatex twice, then render and
inspect the PDF. Guide prose is CC BY 4.0, copyright 2026 Denis Lemire; code and
tests retain their individual notices. No private laboratory notebook is needed
to review the source or run the helper kit.
