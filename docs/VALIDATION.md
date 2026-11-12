# Repair validation — 12 November 2026

The original audit identified 15 failed targeted checks, including tracker data loss and two sanitizer-confirmed out-of-bounds reads. The repaired protocol and state model replace the affected paths. The original audit remains historical evidence, not a description of this revision.

## Executed locally

Environment: Apple Silicon macOS, Apple Clang 17, C++17, OpenSSL 3.6.1, and Python 3.12. Both tracker processes use independent storage directories in the tests. Runtime tests use only loopback TCP and isolated temporary users/files.

| Validation | Result | Evidence |
| --- | --- | --- |
| Ordinary build, unit checks, and integration tests | 22 integration cases passed; opt-in 1 GiB case run separately | [Normal log](validation-normal.log) |
| Metadata/parser/crypto unit checks | Passed, including 4096 randomized malformed payloads and the former hash-count overflow boundary | Normal log and `tests/unit.cpp` |
| AddressSanitizer + UndefinedBehaviorSanitizer | 22 integration cases passed without reported memory/undefined-behavior errors | [ASan/UBSan log](validation-asan.log) |
| ThreadSanitizer | 22 integration cases passed without reported races | [TSan log](validation-tsan.log) |
| Large file | 1 GiB transferred, whole-file hashes independently matched | [Measurement JSON](large-file-result.json) and [standalone test log](validation-large-file.log) |

The ordinary and sanitizer logs enumerate 23 tests, with the opt-in large-file test skipped in those runs. That test was executed separately and passed. Thus all 23 distinct behavioral cases were exercised successfully in the ordinary build. The sanitizer integration runs cover the 22 smaller cases. ASan/UBSan also passed the standalone unit binary.

Apple's sanitizer runtime reports that leak detection is unsupported on this platform. Address/undefined-behavior checks used `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1`. **No claim of a completed local LeakSanitizer or Linux run is made.** The repository's Ubuntu/GCC workflow is configured to run normal, ASan/UBSan with leak detection, and ThreadSanitizer jobs when the changes are pushed. That remote workflow has not been executed as part of this local task.

## Original finding to regression mapping

| Original issue | Correction and verifying case |
| --- | --- |
| Stale tracker erases acknowledged writes | Durable immutable logs; recovery, complete shutdown, independent partition writes, and conflicting-write convergence tests |
| Failover loses login | Stable signed session; cross-tracker/failover test and failure during an active download |
| Other tracker's seeders appear offline | Replicated sessions and leases; cross-tracker discovery test |
| Duplicate logins differ between trackers | Connected requests share a preferred writer; duplicate login rejected through either endpoint; partition behavior documented |
| One download blocks the CLI | Managed background jobs; simultaneous files, live progress, and commands during a stalled piece |
| Failed download hangs on nonexistent response | Explicit failure result; dead-peer and whole-file-hash mismatch tests return to a responsive CLI |
| Blackhole peer blocks indefinitely | Fixed complete-frame deadline and retry on another peer; stalled/disconnected/corrupted peer tests |
| Short TCP read treated as message completion | Explicit length framing; split requests, coalesced requests, split signed metadata replies |
| Incomplete hash list causes heap overread | Exact count/size/hash validation before workers; unit boundary and malformed upload metadata tests under ASan |
| Unterminated receive buffer causes stack overread | No C-string receive buffers; oversized/untrusted response rejection and fallback under ASan |
| Unauthenticated SYNC replaces all state | HMAC-authenticated replica role; legacy SYNC and forged replica envelope rejected |
| Logout leaves peer serving | Local share deactivation plus tracker authorization; previously issued ticket rejected after logout |
| Renamed download changes network identity | Preserve original filename; two real seeders and downloading from the renamed copy after the original stops |
| Stop-share affects another group | Group-scoped local mapping and server registration; same filename with spaces/colon shared in two groups |
| Malformed port crashes process | Validated conversion; bad endpoint rejected and subsequent RPC still succeeds |
| Missing group leave reports success | Existence/membership preconditions; nonexistent group rejected |
| Owner cannot leave | Deterministic ownership transfer or deletion when empty; explicit owner-leave test |
| File basename collisions combine different data | Canonical metadata checked before seeder admission; conflicting-content test |
| Group ID substring breaks CLI parsing | Token-based argument positions; group `a` with quoted filename and directory destination |
| Failed transfer overwrites an existing destination | Temporary file plus no-overwrite publication; existing bytes preserved and failed outputs removed |
| State disappears after both trackers stop | Persistent per-origin journals; full-shutdown/restart test |
| Completed status is not persistent | Atomic history storage; client restart with the same endpoint and user |
| Truncated journal append loses valid state | Incomplete tail repaired while authenticated complete records retained |
| Retry re-applies a mutation or reuses unrelated result | Durable result cache and keyed argument fingerprint; identical retry succeeds, changed arguments with same ID fail |
| Ticket remains usable after group membership ends | Per-piece current authorization; old ticket rejected after leave |
| Thread races/resource leaks from detached handlers | Fixed worker queues, RAII sockets/files, joined threads, guarded state, bounded jobs; exercised under TSan and ASan |
| Documentation claims unmeasured results | Rewritten README/report; original PDF archived; actual measurement and limitations recorded here |

## One-GiB measurement

A single normal-build run transferred a sparse, zero-filled 1,073,741,824-byte source on loopback:

- Upload hashing and tracker registration: **0.777 seconds**.
- Download, complete-file verification, and seeder registration: **1.778 seconds**.
- Downloader peak **sampled** RSS: **14592 KiB (14.2 MiB)**, sampled every 100 ms.
- Independent source/destination SHA1: `2a492f15396a6768bcbca016993f4b4c8b0b5307`.

This is one local diagnostic run with one seeder and cached/sparse data. It is not a multi-machine throughput benchmark, a comparison against the old implementation, a statistically measured speedup, or an exact maximum-memory guarantee. Sampling can miss brief peaks. The tests also transfer nonrepeating random content at piece boundaries and across multiple pieces, including a smaller final piece.

## Reproduce

From the repository root:

```sh
make test
P2P_LARGE_TEST=1 python3 tests/integration.py Integration.test_one_gib_transfer
```

To save a new large-file measurement, set `P2P_BENCHMARK_OUTPUT` to the desired JSON path. This overwrites that measurement file deliberately. All source/destination fixture data is removed when the test exits.

For sanitizers, rebuild first so the selected flags actually apply:

```sh
make clean
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 make SANITIZE=address test
make clean
TSAN_OPTIONS=halt_on_error=1 make SANITIZE=thread test
```

Use `detect_leaks=1` on a platform with LeakSanitizer support. `P2P_BIN_ROOT` can select an independently built directory containing `tracker/tracker` and `client/client`, as used to keep the local sanitizer builds separate from the ordinary build. The tests fail on sanitizer diagnostics, unexpected process exit, and failed shutdown; they do not count a process crash as an accepted malformed-input result.

## Practical limits

The implementation has explicit resource limits and no journal compactor. Partial-download resume, NAT traversal, and encrypted transport are outside the assignment implementation. Tracker conflicts during partitions follow deterministic eventual-consistency rules, described in the [technical report](TECHNICAL_REPORT.md). Tests establish these concrete behaviors; they are not a formal proof or a promise that every possible failure sequence has been exhausted.
