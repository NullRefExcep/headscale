# ACL peer-map optimization experiment

This branch is based on `feature/manual-node-ip` at
`bb625b17f017502b8bba0ca8d856e12c5a41dd55`. It contains general Headscale
optimizations, with no dependency on an application, identity provider,
application database, or custom device schema. Initial measurements were taken on
2026-10-03 on an Apple M1 Pro (8 logical CPUs, 16 GiB RAM), with Go 1.27.0.
Subsequent Linux measurements and real-client runs are recorded below.

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


## Linux measurements and real clients (2026-10-03)

The Linux host `10.59.0.16` has an AMD Ryzen 9 9900X (24 logical CPUs),
60.48 GiB RAM, and 8 GiB swap. Tests used an isolated checkout of production
commit `25c2a777550687bf37b5bf6993755b8b169455b8`, leaving the host's original
checkout and existing service containers alone.

The final indexed implementation's Linux microbenchmark (Go 1.27.0,
GOMAXPROCS=8) measured:

| IoT endpoints | Users | Total nodes | Indexed build | Allocated MiB/build |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 100 | 1,200 | 0.787 ms | 1.12 |
| 10,000 | 1,000 | 12,000 | 16.962 ms | 35.55 |
| 10,000 | 2,000 | 14,000 | 28.990 ms | 54.59 |
| 20,000 | 2,000 | 24,000 | 59.243 ms | 124.01 |

The frozen pairwise comparison at 1,200 nodes took 2.731 s and allocated
approximately 1,497 MiB. These are ACL construction measurements; they do not
establish control-plane capacity for 14,000 real clients. The real-client
self-grant and compact-CIDR equivalence checks also passed on Linux.

### Real-client scenario

`TestACLRealClientScale` is opt-in and runs a real kernel-TUN `tailscaled` in
one container per endpoint. Readers and an administrator each own two personal
devices. Tagged IoT devices belong to independent segments. Policies permit
own-device access, segment TCP 80/443 access, and administrator access to the
IoT prefix. Enrollment uses reusable test auth keys, rather than OIDC.

At each completed stage the test verifies all Noise map streams and all clients'
peer counts/online metadata, samples allowed and denied TCP traffic, restarts
Headscale, waits for every stream to reconnect, revokes one segment's access,
and verifies TCP denial while administrator and own-device access survive.
Packet probes sample representative nodes; this is not sustained throughput,
a DERP bandwidth benchmark, or a test of every node pair. The test is sequential
segment enrollment followed by a simultaneous server outage/reconnect, rather
than simultaneous first registration of all clients.

The client image is `ts-42c1b1-head-b48553:latest`, image SHA
`c659bcd7a8eb628e03dca936ab85e5d127dd2cf9195812bac751191f081ee12e`,
Tailscale `1.103.0-dev20260929`, commit
`a0e471a35b8f38ee6abcfded937d3979ede68234`. This is one development version,
not a stable-client compatibility matrix.

The optimized server image `headscale-acl-optimized:25c2a777` uses a normal
`CGO_ENABLED=0 go build`, without the integration Dockerfile's `-N -l` flags.
Image SHA: `93abcefa7bf1e5e6af5279e303590a740d826dafc8c6c8da251bcdafc34ba324`.
Server log level is `warn`. The integration harness still enables profiling
and Docker statistics collection, so these are instrumented runs. Embedded DERP
is enabled. Four independent Docker bridges split the generators; sampled
administrator TCP traffic crosses bridges.

### Completed stages and resource limit

| Run ID | IoT | Personal devices | Total real clients | Build | All streams reconnected | ACL applied | TCP denial observed |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| `20261003-140529-6f3584` | 500 | 102 | 602 | debug, trace | 41.076 s | 0.027 s | 4.058 s |
| `20261003-145210-babb29` | 100 | 22 | 122 | optimized, warn | 34.729 s | 0.022 s | 4.043 s |
| `20261003-145812-c77f95` completed stage | 500 | 202 | 702 | optimized, warn | 41.476 s | 0.038 s | 4.060 s |
| `20261003-153359-84a7f0` intermediate stage | 480 | 162 | 642 | optimized, warn | 41.127 s | 0.026 s | 4.056 s |
| `20261003-153359-84a7f0` final stage | 800 | 162 | 962 | optimized, warn | 41.264 s | 0.041 s | 4.072 s |

Reconnect times start before Docker's server restart and include its roughly
30-second stop grace period. At 702 clients Headscale was ready at 32.422 s,
all streams were back at 41.476 s, and all peer checks finished at 47.033 s.
TCP denial includes the failed curl request's timeout (about four seconds),
so it is an observation bound, not a precise four-second ACL propagation time.

Run `20261003-145812-c77f95` attempted 1,500 IoT plus 202 personal devices.
It completed the 702-client stage, then the resource watchdog stopped the suite
at approximately 1,040 real client containers when swap use reached 555.2 MiB.
Available RAM was 15.13 GiB; the last completed enrollment batch had 835 IoT.
The runner exited 143 after intentional stop. Later stages did not complete
and must not be recorded as passing. The watchdog reserves 10 GiB available RAM,
limits swap use to 512 MiB, and reserves 12 GiB disk space.

Headscale's sampled peak CPU was 26.11% of one core in that ramp. Its peak
cgroup memory charge was 8,274.1 MiB, including file cache and kernel memory;
this is not the Go heap. A diagnostic sample around 880 clients showed 418.64
MiB anonymous memory, 1,204.74 MiB file pages and 1,267.24 MiB slab. These are
instantaneous measurements, not peak process RSS. Most generated clients used
approximately 30–35 MiB each, before their host kernel/network overhead. The
host runs both server and generators, so its resource boundary does not
establish a Headscale-only node limit.

The bounded final run `20261003-153359-84a7f0` reached 800 IoT and 162 personal
devices, representing 80 reader identities plus one administrator (81 users).
A further 80 provisioning identities own no nodes after tag assignment.
All scenario phases completed at `2026-10-03T13:02:50Z`: server ready in
32.225 s, all Noise streams reconnected in 41.264 s, all peer checks completed
in 49.025 s, ACL applied in 41 ms, and sampled TCP denial observed in 4.072 s.
The final phase record was fsynced after administrator and own-device access
checks. These are completed scenario assertions, not a full runner PASS.

During subsequent artifact collection/cleanup, the resource watchdog stopped
the suite at `13:03:41Z`, with swap 642.5 MiB and available RAM 13.88 GiB.
The runner exited 143 and removed 963 remaining containers. Its captured
Headscale stderr had 742 lines and no panic/fatal/error matches. The final
run's sampled server CPU peak was 43.15% of one core; cgroup memory peak
7,755.4 MiB. Separately sampled anonymous memory peaked at 632.46 MiB.
Cgroup charge includes cached files and kernel memory, and anonymous memory
is not an isolated Go-heap measurement. The complete host monitor and durable
phase ledger distinguish the passing final stage from the interrupted teardown.

Thus 962 real clients completed the functional/reconnect/revoke scenario on
this shared server; approximately 1,040 client containers were created during
the larger ramp. Neither number establishes a maximum for Headscale itself.
The 10,000-IoT/1,000–2,000-user target remains unverified with real clients.
Next capacity work needs separate generators and a repeatable outage/revocation
matrix, plus stable-client versions and admission bursts; ACL microbenchmark
results alone cannot replace those checks.

After both runs the owned containers and four-bridge networks were removed.
All six neighbor thresholds were restored to their original values. Existing
service containers were left running; logs, the isolated checkout, and reusable
test images remain for reproduction. No production deployment was performed.

### Generator issues found and corrected

An initial 500-IoT attempt stopped during enrollment with a client-command
timeout. Kernel logs showed `arp_cache: neighbor table overflow`, while
Headscale's full captured log had no panic/error or slow matching request.
The host's original neighbor thresholds were 128/512/1024. Temporarily raising
IPv4 and IPv6 `net.*.neigh.default.gc_thresh{1,2,3}` to 4096/16384/65536 allowed
the 602-client retry to pass. Original values were saved and restored after the runs.

A single bridge also cannot carry the planned fleet: Linux 6.8 has 1,024 bridge
ports. A subsequent single-bridge ramp was stopped before that limit and replaced
with four bridges. See the [Docker bridge connection-limit documentation](https://docs.docker.com/engine/network/drivers/bridge/#connection-limit-for-bridge-networks)
and [Linux 6.8 bridge constants](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/bridge/br_private.h).
Neither interrupted attempt is a capacity pass or an ACL failure.

The local Docker VM has about 8 GiB RAM. The remote Intel Mac at `10.59.0.25`
also has an approximately 8 GiB Docker VM and existing workloads. Neither was
used as a generator in this experiment. Distributed generators remain needed
to validate 10,000 IoT plus 1,000–2,000 users without sharing the server's RAM.

### Reproduce the real-client run

After the repository-required `make sync-server` (using an isolated destination),
set the prebuilt-image overrides and invoke the integration runner on Linux:

```sh
HEADSCALE_INTEGRATION_TAILSCALE_IMAGE=ts-42c1b1-head-b48553:latest \
HEADSCALE_INTEGRATION_HEADSCALE_IMAGE=headscale-acl-optimized:25c2a777 \
HEADSCALE_INTEGRATION_SCALE_IOT=800 \
go run ./cmd/hi run TestACLRealClientScale --timeout=3600s --clean-before=false --stats
```

Use a resource monitor and an exclusive run ID; cleanup must target only the
owned containers and empty networks. The test writes fsynced phase records to
`control_logs/real-scale-*/scale-progress-*.jsonl`, preserving completed stages
when the process is intentionally stopped. Full logs and host resource samples
are retained under `/root/workspace/acl-bench-tools/` on the Linux host. Do not
publish raw auth-key/debug logs without sanitizing ephemeral credentials.


## Distributed stable-client follow-up (2026-10-03)

The follow-up uses `tools/acl_scale_distributed.py` (procedure in
`integration/README.md`) with Linux `10.59.0.16`, the local ARM Mac, and the
Intel Mac `10.59.0.25`. Existing services remain running. The Mac Docker VMs
have approximately 8 GiB RAM each; the occupied remote VM started with only
2.44 GiB available. Generator caps are 100 local clients and 20 remote clients;
Linux receives the remaining fleet. Reserve thresholds are 10 GiB on Linux
and 1.5 GiB per Mac, with at most 512 MiB additional swap versus the baseline.

Clients use official stable Tailscale 1.102.5, commit
`5fb2a81b065b0a0bbbfc67ab20a0d9c6a1108115`, pinned multi-architecture manifest
`sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065`.
Native derived images add curl, an HTTP fixture, and only the test CA:

| Host | Architecture | Derived image SHA256 |
| --- | --- | --- |
| Linux | amd64 | `4887343d0ee8b58417e1bf95c9c55aef5e27bf5f26522ecb78cf651e734c074d` |
| Local Mac | arm64 | `cd317ee3297ab5f4efb5af977448c92d5af54ee21e1a2411efd1dd8de8b378d5` |
| Remote Mac | amd64 | `92a989913f797f04d9b66a113ce6e7a8b2e231a7537c1f8213b3cf2116de7c48` |

The controller remains production commit `25c2a777`, normal optimized build,
limited to 8 CPUs and 8 GiB RAM. TLS is enabled on a test-only LAN-bound port,
and the embedded DERP is isolated from external relays. Profiling, mapresponse
capture, deadlock instrumentation and high-cardinality debug metrics from the
`hi` harness are absent. Client traffic still uses real kernel TUN interfaces.
This follows the [official Tailscale container guidance](https://tailscale.com/docs/features/containers/docker)
and [Headscale embedded DERP guidance](https://headscale.net/stable/ref/derp/).

The first smoke stopped after TCP revocation because the test incorrectly
assigned reader segment indices: the administrator occupied index zero.
No controller errors were logged. The fixture index was corrected, and the
new smoke `20261003134746ad4b` passed both stages and cleanup:

| IoT | Personal devices | Total clients | Placement Linux/local/remote | Reconnect | Policy command | TCP denial |
| ---: | ---: | ---: | --- | ---: | ---: | ---: |
| 10 | 22 | 32 | 0 / 16 / 16 | 2.003 s | 1.137 s | 5.316 s |
| 20 | 22 | 42 | 1 / 21 / 20 | 3.283 s | 1.128 s | 5.316 s |

Cross-host own-device, administrator-to-IoT and deny checks passed. All peer
counts/online/relay metadata and all Noise streams were checked, including
post-restart and post-revocation maps. The first stage separates the controller
from every client generator; larger runs also generate clients on Linux.
Thus the available hardware does not provide a dedicated server-only
large-fleet capacity measurement.

Policy timing here includes the SSH transport, file write and CLI invocation.
It is not directly comparable to the previous container-local API timings.
Reconnect starts before `docker restart --time 5`; curl denial includes the
request timeout. Sampled HTTP traffic is not a sustained DERP throughput test.
Both successful smoke stages are followed by `scenario_pass` and `cleaned`.
Full smoke artifacts are in `/private/tmp/headscale-distributed-smoke-fixed`.


## Distributed stable-client ramp, 2026-10-03

Production code: `25c2a777550687bf37b5bf6993755b8b169455b8`.
Tailscale 1.102.5, pinned manifest
`sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065`.
Linux Ryzen 9 9900X, 60.48 GiB RAM; local ARM and remote Intel Macs
contributed 100 and 20 clients respectively. 100 segments, 101 personal
owners, 202 personal clients; additional provisioning users do not own tagged IoT.
Normal server build, no per-map debug dumps or CPU profiling.

| IoT | Total clients | All streams reconnected (s) | Policy command (s) | TCP denial observed (s) |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 302 | 17.04 | 1.77 | 6.25 |
| 500 | 702 | 5.38 | 1.30 | 5.52 |
| 1000 | 1202 | 13.58 | 1.36 | 11.88 |
| 1300 | 1502 | 32.35 | 1.41 | 5.98 |
| 1400 | 1602 | 15.54 | 1.43 | 6.07 |
| 1500 | 1702 | 17.73 | 1.18 | 5.04 |

Every completed stage checked all client peer counts and online/relay metadata,
self-device connectivity, segment IoT access, denied foreign personal access,
admin access, controller restart, policy revocation and restored unaffected access.
Cross-Mac traffic used the embedded DERP; Linux peers established direct paths.
A relay ping timed out during a deliberate controller restart.

At 1802 enrolled clients, the generator guard stopped the run: Linux
MemAvailable reached 9.43 GiB, below the 10 GiB reserve. This stage is not
qualified. Linux swap increased only 4.25 MiB over the 640 MiB starting baseline.
Maximum sampled controller CPU was 215.5% (about 2.16 cores); PID 1 VmHWM
was 1184.06 MiB. These limits describe this shared generator/controller setup,
not the maximum fleet size Headscale can support.

Reconnect timings include Docker's five-second stop grace and observer queries.
Policy command timings include SSH and CLI work; denial includes curl timeout
and polling. They are not precise netmap delivery or revocation latency percentiles.
No equivalent unoptimized real-client ramp was run: the previous indexed-versus-
pairwise microbenchmarks demonstrate algorithmic gains, while this ramp
demonstrates current functional capacity only.

Full Docker log scan: 78,637 initial-map generation errors, 78,636 batcher-add
errors, 78,635 HTTP internal errors, 354 send warnings, 354 change-application
errors and 116 client-write errors. The dominant initial-map error was
`batcher shutting down while generating map response`; errors clustered around
intentional restarts and final stop. Successful recovery does not make this
shutdown retry storm acceptable for production readiness.

The scenario stopped as intended at its resource guard, but artifact collection
then timed out transferring a 92,919,745-byte Docker log. Manual cleanup removed
all 1802 clients, controller and 12 dedicated bridges across the three hosts;
six temporary neighbor sysctls were restored to 128/512/1024. Original services
were preserved. The collector now bounds artifact transfer so this specific
timeout cannot bypass cleanup.

Raw phases/resources: `/private/tmp/headscale-distributed-ramp`. Complete Docker
log and scan summary: Linux
`/root/workspace/acl-bench-tools/distributed-tls/20261003135117d36d/`.


## Proposal implementation and paired measurements, 2026-10-03

Implemented the ready-channel send fast path and snapshot-scoped requested-peer
resolution in State and mapper patch filtering. Requested IDs are deduplicated
through the existing adjacency order; self, absent and ACL-hidden nodes are
omitted. A regression test verifies ordering, duplicates, hidden/unknown IDs,
immediate visibility after snapshot replacement and retained old-view immutability.
No Slopscale source was copied; this independently implements the ideas in the
user's proposal.

Selected peers still require an adjacency scan, preserving arbitrary adjacency
order without adding a second per-node membership index. They resolve only
requested views, avoiding the full peer-view allocation and hash lookup for each
visible node. This is an allocation and constant-factor improvement, not an
O(requested IDs) lookup algorithm.

Paired benchmarks on the same Apple M1 Pro, Go 1.27, GOMAXPROCS=8, normal
compiler settings, three repeats per version (medians):

| Operation | Before | After | Speedup | Bytes/op before → after |
| --- | ---: | ---: | ---: | ---: |
| Ready connection send | 240.2 ns | 61.73 ns | 3.89× | 248 → 0 |
| One named peer, 1200 nodes | 12.373 µs | 3.485 µs | 3.55× | 9736 → 8 |
| One named peer, 12000 nodes | 150.457 µs | 34.181 µs | 4.40× | 98312 → 8 |
| One named peer, 14000 nodes | 191.806 µs | 39.940 µs | 4.80× | 114696 → 8 |

The send path drops from three allocations to zero; named peers from two to one.
Raw results: `/private/tmp/headscale-proposals-before.log` and
`/private/tmp/headscale-proposals-after.log`. Full mapper, state and change
package tests passed with `-race` (42.25, 72.61 and 1.64 seconds respectively).
These benchmark improvements must not be multiplied into a claimed fleet limit.

Deferred: empty-response suppression and OriginKnows need explicit coverage of
policy/DNS/DERP/removal and mixed batches; compact adjacency changes snapshot
representation and should follow measured memory pressure; metric-handle caching
needs a contention profile. None is necessary for the two demonstrated gains.
The shutdown retry storm remains an unresolved operational finding, rather than
a performance claim or silently suppressed error.


Implementation commit: `18244872` on `feature/acl-peer-map-optimization`.
Linux selected correctness tests and three-repeat benchmarks passed; ready send
median 59.84 ns, named peers 12000/14000 nodes 20.001/23.365 µs, 8 bytes/op.
There is no paired Linux baseline for these new operations, so speedup ratios
above use only the paired Mac results. New-image SHA256:
`fd3848351ca2a717de0f7648be7c29a30f03460a496e16556e41cda1e1d45b4f`.

Repeated the exact previous three-host smoke scenario with the new image:

| Clients | Reconnect before → after (s) | Policy command before → after (s) | TCP denial before → after (s) |
| ---: | ---: | ---: | ---: |
| 32 | 2.003 → 3.469 | 1.137 → 1.346 | 5.316 → 5.592 |
| 42 | 3.283 → 3.618 | 1.128 → 1.239 | 5.316 → 5.408 |

The new real-client scenario passed all checks and exited zero, including cleanup.
The full server log is empty at warn/error level. All labelled containers and
bridges were absent on all three hosts after cleanup; neighbor sysctls returned
to their original values. Raw phases/resources/metrics:
`/private/tmp/headscale-proposals-real`; Linux complete log:
`/root/workspace/acl-bench-tools/distributed-tls/202610031455221f90/headscale-full.log`.

These one-run wall-clock smoke results show no end-to-end speedup: they are
slightly slower and dominated by container/SSH scheduling and curl timeouts.
They establish compatibility of the new paths, not a new capacity limit or
statistically significant reconnect regression. The 1702-client qualified ramp
is from before this follow-up implementation; it has not been repeated at
full size afterward.

Go lint for the production/test diff passed; standalone collector Ruff F check
and git whitespace check passed. Higher-priority next work is to reproduce and
fix admission/shutdown ordering under a large reconnect fleet, then repeat
comparable large before/after runs with isolated controller and generator hosts.
