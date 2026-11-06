# HE station helper review kit

Author: Denis Lemire. Source checkpoint:
`247377f1b50386c87d95fc53ed315d99e57ddf17`, based on FreeBSD main
`12f90bbd3029fedea93e9bb0b1f02c3afafe237b`.

This companion kit runs tests against the review checkout's implementation.
It contains no kernel images, credentials, network identifiers or raw captures.
The kernel implementation and the tests retain their own copyright and license
notices. The test location/framework remains a review question; this standalone
runner does not claim integration with FreeBSD's installed ATF/Kyua suite.

## Running

Use a full checkout containing the proposed source and the baseline Git object.
Install Python 3 and Clang with AddressSanitizer/UndefinedBehaviorSanitizer.
Run as an ordinary user:

```sh
sh ./run-review-tests.sh /absolute/path/freebsd-src /absolute/path/new-test-output \
    > /absolute/path/helper-tests.log 2>&1
```

The output directory must not already exist. The runner copies required test
inputs there, extracts the actual candidate routines, records input identities,
and builds/runs normal and sanitizer variants. It leaves the source checkout
unchanged. `CC` and `PYTHON` select tools. `HE_TEST_BASE` deliberately overrides
the recorded layout baseline when porting; comparing a changed header with
itself would defeat the layout check. A sparse checkout can supply the exact
matching nl80211.h through `NL80211_HEADER`; a full checkout needs no override.

The runner was executed successfully on Darwin against the checkpoint above.
The corresponding native routines and individual extracted suites have also
been exercised on the separately recorded CURRENT and STABLE source sets;
that does not mean this new packaging script itself has run on every platform.

## Coverage and interpretation

| Suite | What it tests | Boundary |
| --- | --- | --- |
| Native capability parser | Lengths, compact width maps, PPE bounds, captured element and synthetic layouts | Parsing an AP advertisement is not negotiation. |
| Owned IEs | Expansion, cleanup, allocation failure and preserved baseline record size | Allocator and selected kernel interfaces are modeled. |
| MCS maps | Asymmetric local TX/peer RX and local RX/peer TX, unsupported/basic maps | No firmware rate selection is simulated. |
| HE Operation | Fixed and optional field bounds, retained operation state | No AP-wide interoperability certification. |
| Peer/request/response | Actual extracted transaction routines with rejection, reset and fallback cases | Mutexes are no-ops in this userspace model. |
| Encoder | Capacity checks, independent expected bytes and parsed round trips | Paired parser/encoder agreement alone is not the semantic oracle. |
| Bitrate | Actual HE arithmetic across MCS, NSS, width, GI, RU/DCM and invalid cases | Calculated PHY rate is not delivered TCP throughput. |
| RX metadata | Actual converter and preserved 112-byte layout/old offsets | Does not prove every driver's RX descriptor handling. |
| Key retirement | Actual discard helper, modeled circular queues, ownership and completion outside queue locks | Positive live queued-packet removal remains unobserved; scheduling is not modeled. |

All tests must exit zero. A sanitizer report is a failure, not an expected
artifact to ignore. Preserve the failing output and reproducer before changing
the implementation. These are userspace sanitizer runs, not a sanitized kernel.
The bounded libFuzzer harness is included separately for parser/encoder bounds
and round-trip invariants; the normal runner does not repeat the long fuzz run.

Hardware results belong in the review guide's exact kernel/module and workload
matrix. Do not use these helper suites as a substitute for those experiments.
