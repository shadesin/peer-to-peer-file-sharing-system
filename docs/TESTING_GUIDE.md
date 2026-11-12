# Testing guide

Run shell commands from the repository root unless a different working directory is specified. Commands such as `login` and `upload_file` belong in the running client's prompt, not your shell.

## 1. Start with the automatic checks

```sh
make test
```

Expected: unit checks pass, including 4096 malformed-message inputs; the integration runner reports `Ran 23 tests` and `OK (skipped=1)`. That means 22 behavioral cases passed and the separate large-file test was skipped.

To run all 23 behavioral cases, including a 1 GiB transfer:

```sh
P2P_LARGE_TEST=1 make test
```

To run just the large case after building:

```sh
P2P_LARGE_TEST=1 python3 tests/integration.py Integration.test_one_gib_transfer
```

The large test independently compares source/destination SHA1, checks exact size, and prints timing plus sampled downloader RSS. Its source is sparse and zero-filled. Other tests use random nonrepeating content. Passing the local timing test is not a network speedup benchmark.

These tests create their own accounts, temporary directories, ports, and two independent tracker journals. You do not need to start trackers or clients yourself. They terminate their own processes and remove fixture files. Failure logs are saved under `tests/last-run-logs/`.

## 2. Run a selected scenario

Every command below starts an isolated fixture. Build first with `make`.

| Scenario | Test method after `Integration.` |
| --- | --- |
| Empty file, 1 byte, piece boundaries, renamed copies, persistent completion | `test_piece_boundaries_renaming_and_persistent_status` |
| Three real clients and two sources for one download | `test_two_real_seeders_and_original_identity_after_rename` |
| Seeder/downloader through different trackers; authenticated failover | `test_cross_tracker_sessions_and_authenticated_failover` |
| Stale tracker returns; both trackers shut down and restart | `test_recovery_preserves_acknowledged_writes_and_full_shutdown` |
| Different writes on both sides of a partition | `test_partitioned_independent_writes_merge_without_loss` |
| Conflicting partition writes converge to one documented winner | `test_partition_conflicts_converge_to_documented_winner` |
| Concurrent registrations through both trackers | `test_concurrent_connected_writes_are_not_lost` |
| Corrupt pieces and disconnect partway through a piece | `test_corrupted_and_disconnected_peers_retry_elsewhere` |
| Peer accepts but sends nothing; two different downloads at once | `test_stalled_peer_deadline_and_simultaneous_downloads` |
| Tracker fails while a download is active; automatic seeder registration survives | `test_tracker_failure_during_download_preserves_jobs_and_registration` |
| All peers unavailable; no hang or partial final file | `test_failed_download_reports_failure_without_hanging_or_partial_output` |
| Correct piece hashes but wrong full-file hash | `test_full_file_hash_mismatch_does_not_publish` |
| Fragmented/coalesced messages, bad ports/counts, unauthenticated replication | `test_fragmented_and_coalesced_protocol_and_malformed_requests` |
| Fragmented signed replies and forged response fallback | `test_fragmented_tracker_responses_and_forged_response_failover` |
| Logout, group-scoped stop-share, and unauthorized peer requests | `test_group_scope_logout_and_unauthorized_peer_access` |
| A previously issued ticket after membership is revoked | `test_leaving_group_revokes_previously_issued_ticket` |
| Same name, different contents; failed stop-share leaves other shares intact | `test_conflicting_content_and_failed_share_are_isolated` |
| Existing destination remains byte-for-byte unchanged | `test_existing_destination_is_preserved` |
| Owner transfers group ownership, then empty group disappears | `test_owner_leave_transfers_or_deletes_group` |
| Same request ID retry versus changed arguments under the same ID | `test_idempotent_mutation_retries` |
| Interrupted journal append | `test_incomplete_journal_tail_is_recovered` |
| Group `a`, spaces/colon in a filename, directory destination, 255-byte basename, invalid source | `test_command_argument_positions_and_invalid_files` |

Example:

```sh
python3 tests/integration.py Integration.test_partitioned_independent_writes_merge_without_loss
```

Several cases can be selected in one invocation:

```sh
python3 tests/integration.py \
  Integration.test_corrupted_and_disconnected_peers_retry_elsewhere \
  Integration.test_stalled_peer_deadline_and_simultaneous_downloads \
  Integration.test_tracker_failure_during_download_preserves_jobs_and_registration
```

Use these automatic tests for network partitions, forged frames, stalled sockets, and partially written journals. They construct those conditions deterministically; killing a tracker alone is not a network-partition test.

## 3. Prepare an isolated manual demo

Build and make a fresh run directory:

```sh
make
DEMO="$(mktemp -d /tmp/p2p-demo.XXXXXX)"
mkdir -p "$DEMO/tracker1" "$DEMO/tracker2" "$DEMO/alice" "$DEMO/bob" "$DEMO/carol"
printf '127.0.0.1:5001\n127.0.0.1:6001\n' > "$DEMO/tracker_info.txt"
python3 - "$DEMO" <<'PY'
import os
import sys
from pathlib import Path
p = Path(sys.argv[1])
with (p / 'payload.bin').open('wb') as f:
    for _ in range(16):
        f.write(os.urandom(1024 * 1024))
(p / 'empty.bin').write_bytes(b'')
(p / 'notes with spaces: demo.txt').write_text('Assignment 3 manual demo\n')
print('Demo directory:', p)
PY
```

Write down the printed directory. The five terminals below each need these variables, substituting that actual directory for the example:

```sh
REPO=/Users/souradeepdas/Desktop/Piku/p2p/peer-to-peer-file-sharing-system
DEMO=/tmp/p2p-demo.REPLACE_WITH_PRINTED_SUFFIX
```

If ports 5001/6001 or 7000–7002 are occupied, choose unused ports and update the configuration/client addresses consistently.

Terminal 1:

```sh
cd "$DEMO/tracker1"
"$REPO/tracker/tracker" "$DEMO/tracker_info.txt" 1
```

Terminal 2, after tracker 1 starts:

```sh
cd "$DEMO/tracker2"
"$REPO/tracker/tracker" "$DEMO/tracker_info.txt" 2
```

Both use the same key beside the shared configuration, but maintain independent journals in their working directories.

Terminal 3, Alice:

```sh
cd "$DEMO/alice"
"$REPO/client/client" 127.0.0.1:7000 "$DEMO/tracker_info.txt"
```

Terminal 4, Bob:

```sh
cd "$DEMO/bob"
"$REPO/client/client" 127.0.0.1:7001 "$DEMO/tracker_info.txt"
```

Terminal 5, Carol:

```sh
cd "$DEMO/carol"
"$REPO/client/client" 127.0.0.1:7002 "$DEMO/tracker_info.txt"
```

Inside a client prompt, shell variables such as `$DEMO` do **not** expand. The relative paths in the following examples work because each client was started in its own demo directory.

## 4. Establish users, permissions, and the first file

Alice:

```text
create_user alice pw
login alice pw
create_group demo
upload_file demo ../payload.bin
```

Bob:

```text
create_user bob pw
login bob pw
list_files demo
join_group demo
```

Expected: `list_files` before acceptance returns a membership error. A successful join request alone does not grant access.

Carol:

```text
create_user carol pw
login carol pw
join_group demo
```

Alice:

```text
list_requests demo
accept_request demo bob
accept_request demo carol
```

Bob:

```text
list_files demo
download_file demo payload.bin ./renamed.bin
show_downloads
```

Expected: start returns promptly; completion prints `SUCCESS file downloaded` and then seeder registration. `show_downloads` displays `[C] [demo] payload.bin`. The network name remains `payload.bin` even though Bob's local file is `renamed.bin`.

In a separate shell, with the actual `DEMO` variable:

```sh
cmp "$DEMO/payload.bin" "$DEMO/bob/renamed.bin"
shasum -a 1 "$DEMO/payload.bin" "$DEMO/bob/renamed.bin"
```

Expected: `cmp` produces no output and exits zero; both SHA1 values match. Do not regard a success message alone as a full integrity test.

## 5. Exercise sharing and failure behavior manually

| Action | Expected observation |
| --- | --- |
| Carol downloads `payload.bin` while Alice and Bob share it | Worker logs show pieces from both endpoints for a sufficiently large file |
| Alice runs `stop_share demo payload.bin`, then Carol downloads again to a new destination | Bob can still supply the original filename from his renamed local copy |
| Bob stops sharing after Alice already stopped | With no seeder left, another download returns an error, and the CLI remains responsive |
| Bob downloads into his existing `./renamed.bin` | Error; existing bytes remain unchanged |
| Bob runs `leave_group missing` | Error; no fabricated success |
| Carol calls `accept_request` while Alice owns the group | Owner-permission error |
| Bob requests membership twice before acceptance | Second request rejected as already pending |
| Alice shares the same filename in another group and stops it only there | The share in `demo` remains available |
| Alice leaves the group | Ownership transfers to the first remaining member in sorted user-ID order |
| The final member leaves | The group disappears |

Use a **new destination name** for every successful repeated download because overwrite is intentionally prohibited. Restore any stopped share by uploading the same original file again before moving to the next scenario.

For a logout test, leave Alice as the only seeder, then log Alice out and request another copy. Expect no available seeder. The automatic logout test is stronger: it also reuses a valid ticket against Alice's old peer address and verifies that serving is denied.

For real multi-file concurrency, upload two different files and issue two `download_file` commands without waiting, then `show_downloads` and `list_groups`. The CLI should respond during both jobs. Small local files may finish before you can type another command; the automatic stalled-peer concurrency case guarantees an observable overlap.

## 6. Failover and stale-tracker recovery

Keep a client logged in. In tracker 1's terminal, type `quit` or press Ctrl+C. In the existing client, run:

```text
create_group survived
list_groups
```

Expected: both succeed through tracker 2 without another login.

While tracker 1 is still stopped, register another account in a logged-out/new client, or create another group. Restart tracker 1 using its original command **and working directory**. Verify the new account/group remains available. Do not delete either journal to simulate recovery: that changes the test into storage loss.

For a full restart, gracefully quit the clients, stop both trackers, and restart both from the same directories and key. Existing users/groups must remain. Client shares are not automatically restored; log in and upload again to share. Completed history can be inspected by restarting the same client endpoint in the same working directory, logging in as the same user, and running `show_downloads`.

Use the automatic `test_tracker_failure_during_download_preserves_jobs_and_registration` for failure at a deterministic point during a transfer. A fast local transfer may finish before a manual interruption.

## 7. File sizes and file types

Test these byte sizes: `0`, `1`, `524287`, `524288`, `524289`, several MiB, and `1073741824`.

Expected piece counts: 0, 1, 1, 1, 2, then `ceil(bytes / 524288)`. The final piece can be smaller. The existing automated boundary test covers the smaller cases; the opt-in test covers 1 GiB.

For manual file-type coverage, use a text file, PNG/JPEG, ZIP archive, and a copy of a binary executable. For each, upload, download to a fresh path, and compare with `cmp` plus SHA1. Quote names and paths containing spaces. Sharing is byte-oriented; extensions should not affect correctness.

To test mutation/corruption, upload a disposable source, then alter its bytes before downloading. A healthy second seeder should allow retry and successful completion; with only corrupted sources, expect a failed job and no published final file. Use the scripted corrupt-peer test for reproducibility.

## 8. Memory and concurrency diagnostics on this Mac

```sh
make clean
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 make SANITIZE=address test
make clean
TSAN_OPTIONS=halt_on_error=1 make SANITIZE=thread test
make clean
make
```

Expected: the suite passes without AddressSanitizer, UndefinedBehaviorSanitizer, or ThreadSanitizer diagnostics. The final clean/build restores ordinary binaries. Apple's runtime does not support LeakSanitizer here; the configured Linux workflow enables it. Linux/GCC and leak-detection results have not yet been established locally.

## 9. Interpret results accurately

- Partition reconciliation is eventual consistency. Independent writes survive and replicas converge; simultaneous conflicting isolated writes have a deterministic winner. Do not expect instantaneous global agreement while communication is broken.
- A crashed client may stay in discovery for up to its 20-second lease, but a downloader must time out and try another peer. Logout explicitly revokes sharing immediately.
- In-progress downloads do not resume after restart. Completed history persists; active share registrations must be reestablished after client restart.
- Authentication does not encrypt traffic. Use a trusted network for this assignment demo.
- A passing test suite demonstrates the exercised cases; it is not a proof of correctness for every possible interleaving or a production reliability certification.

For the executed results and issue-to-test mapping, see [validation](VALIDATION.md). For the design and protocol, see [the technical report](TECHNICAL_REPORT.md).
