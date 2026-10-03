# ACL peer-map optimization experiment

This branch is based on `feature/manual-node-ip` at
`bb625b17f017502b8bba0ca8d856e12c5a41dd55`. It contains general Headscale
optimizations, with no dependency on an application, identity provider,
application database, or custom device schema. Measurements were taken on
2026-10-03 on an Apple M1 Pro (8 logical CPUs, 16 GiB RAM), with Go 1.27.0.

## Changes

- Index node IPv4/IPv6 addresses by sorted address ranges. Match each compiled
  ACL against the index and against approved subnet routes, then emit symmetric
  peer relationships from its source/destination memberships.
- Evaluate global matchers once, including for policies with self/via grants.
  Self memberships are compiled once per user per build. Via memberships may
  only create edges incident to the node owning the per-node filter.
- Deduplicate overlapping relationships with lazily allocated bitsets and retain
  the previous builder's input-node ordering. No persistent adjacency cache is
  introduced: each build uses the current snapshot.
- Share immutable global matcher IPSets in `MatchersForNode`; only self/via
  additions are compiled and cached per node. Existing invalidation remains.
- Return an empty via-steering result immediately when no via grants exist.
- Reduce ordinary IP/CIDR packet-filter destinations directly, avoiding temporary
  IPSet allocations. Noncanonical CIDRs still fail closed. Wildcards and address
  ranges retain the existing parser path; capability-grant handling is unchanged.

The compiled ACL remains the authority. The index is not based on organizational
units, fixed roles, or any application's naming conventions.

## Correctness checks

`peer_map_test.go` retains the base branch's pairwise implementation as a
**test-only oracle**. Thirty deterministic generated snapshots are checked
against ten policy shapes, before and after ownership/address/route changes.
Cases include default allow, explicit deny, overlapping rules, duplicate IPs,
IPv6, source subnets, approved/unapproved routes, exit nodes, capabilities,
self grants, mixed self destinations, and via grants. Shared per-node matchers
are compared by access decisions in both directions. Reloading deny verifies
that memberships do not survive policy replacement.

The packet-filter fast path is compared with the original IPSet parser for
IPv4/IPv6, mapped addresses, routes, exit routes, wildcards, ranges, malformed
inputs, and noncanonical CIDRs. Existing policy/state/mapper/type regression
checks and the race checks pass. The selected server tests
`TestViaGrantHACompat`, `TestViaGrantMapCompat`, and `TestNetworkWeather` also
passed (64.33 s), exercising real server behavior without Terraform tooling.

## Peer-map measurements

The committed `BenchmarkPeerMapScale` fixture is application-independent:
100 segments, tagged endpoints, two personal devices per user, segmented
TCP 80/443 access, administrator access to the endpoint prefix, and self access.

Three repetitions of three builds each produced these ranges:

| Tagged endpoints | Users | Total nodes | Indexed peer-map time | Allocated MiB/build |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 100 | 1,200 | 2.6–16.7 ms | 1.12 |
| 10,000 | 1,000 | 12,000 | 92–156 ms | 35.55 |
| 10,000 | 2,000 | 14,000 | 138–328 ms | 54.28 |
| 20,000 | 2,000 | 24,000 | 199–483 ms | 124.01 |

Allocated bytes are cumulative allocations per operation, **not** peak RSS.
Other tests/builds were active on the workstation; these are diagnostic results,
not a dedicated-host capacity result or production SLA.

A separate single-build comparison of the same 1,200-node fixture against the
frozen base implementation measured 17.45 s / 1,497.64 MiB allocated for pairwise
versus 2.02 ms / 1.12 MiB allocated for indexed. This demonstrates removal of the
rule-by-pair scan for this sparse policy shape, not a universal speedup ratio.

The older ten-user dense-self benchmark at 10,000 nodes took 495 ms and allocated
245.4 MiB with the indexed builder. Density still matters: broad allow-all rules
and large owner groups generate many relationships.

## Full-state diagnostic probes and limits

Temporary probes outside this checkout exercised real State, mapper, and batcher
with synthetic channels, concurrency 128, 8 Go CPUs, and a 4 GiB soft heap limit.
They do not represent thousands of authenticated Noise sessions or real clients.
The following measurements were taken during development, before the final
shared-matcher optimization:

- At 10,000 tagged endpoints, 2,000 users, and 4,000 personal nodes, target policy
  application completed in 1.30–1.87 s.
- The administrator map contained 10,001 peers, approximately 6.24 MB of
  uncompressed JSON, and took 55–71 ms after the no-via fast path.
- Both full connect-wave probes stopped at `panic: test timed out after 5m0s`
  during the first wave. They did **not** validate reconnect or revocation at
  14,000 nodes. Stacks showed packet-filter reduction and repeated matcher
  construction, motivating the final two optimizations.
- The final shared-matcher version has not been rerun through that full scenario.
  The repository's fail-fast rule stops repeating the same failed scenario;
  this limitation must remain visible rather than treating partial stages as a pass.

A previous 1,200-node intermediate build completed the full synthetic scenario,
including revocation, but it is not a full-fleet validation of the final patch.

There is still quadratic **output** for dense policies, and bitsets can consume
`N² / 8` bytes when every node has peers. Route-heavy policies scan subnet routers
per matcher. This change does not implement distributed state, HA replication,
incremental policy recompilation, admission fairness, or DERP capacity scaling.

## Reproduce the committed checks

```sh
go test ./hscontrol/policy/... ./hscontrol/state/... ./hscontrol/mapper/... ./hscontrol/types/... -timeout 10m
go test -race ./hscontrol/policy/... ./hscontrol/state/... ./hscontrol/mapper/... -timeout 10m
go test ./hscontrol/policy/v2 -run '^$' -bench '^(BenchmarkIndexedPeerMapComparison|BenchmarkPeerMapScale)$' -benchtime=1x -count=1 -timeout 10m
go test ./hscontrol/policy/v2 -run '^$' -bench '^BenchmarkPeerMapScale/endpoints=.*/users=.*/indexed$' -benchtime=3x -count=3 -timeout 5m
```

Run the repository's Nix dev shell for the full suite. In this local environment,
`go test ./hscontrol/... -timeout 10m` passed the other packages but failed in
`servertest`: the Terraform API tests require `tofu`, absent from PATH, and the
remaining server-test suite exceeded its 10-minute deadline. This is not recorded
as a full-suite pass.

The Docker integration runner was invoked after reading both integration READMEs
and passing `hi doctor`:

```sh
go run ./cmd/hi run TestACLAutogroupSelf --timeout=1200s --clean-before=false --stats
```

Docker integration did not reach connectivity assertions. After more than
20 minutes of total runner time, a diagnostic SIGQUIT showed the test waiting
in `tsic.New` / `BuildAndRunWithBuildOptions` / Docker `BuildImage`, building
`Dockerfile.tailscale-HEAD`. The generated Headscale server was running, but
client setup had not completed. The probe was stopped intentionally and its
owned containers were cleaned by the runner; this is **not** a confirmed ACL
failure or an integration pass. Artifacts: run `20261003-120005-f660ca` in
`control_logs/`, plus the captured stack in `/private/tmp/headscale-index-integration.log`.

The changed policy packages passed golangci-lint (v2 installed for this local
check). The repository's Nix environment was unavailable locally.

Before rollout, finish bounded mass admission/reconnect and packet-level revoke
checks of the final patch on a dedicated Linux host with real Noise sessions,
then repeat the 1,000 / 5,000 / 10,000 / target-node matrix. No server rollout was
performed by this experiment.
