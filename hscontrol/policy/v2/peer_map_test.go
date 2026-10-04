package v2

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Frozen pairwise implementation is the semantic oracle for the indexed builder.
func (pm *PolicyManager) buildPeerMapPairwiseReference(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Precompute each node's subnet routes and exit-node status once; the
	// O(n^2) pair scans below would otherwise recompute them for every pair.
	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	// If we have a global filter, use it for all nodes (normal case).
	// Via grants require the per-node path because the global filter
	// skips via grants (compileFilterRules: if len(grant.Via) > 0 { continue }).
	if !pm.needsPerNodeFilter {
		ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

		// Build the map of all peers according to the matchers.
		for i := range nodes.Len() {
			for j := i + 1; j < nodes.Len(); j++ {
				if nodes.At(i).ID() == nodes.At(j).ID() {
					continue
				}

				ri, rj := routeInfo[nodes.At(i).ID()], routeInfo[nodes.At(j).ID()]
				if nodes.At(i).CanAccessWithRoutes(pm.matchers, nodes.At(j), ri.subnet, rj.subnet, rj.isExit) ||
					nodes.At(j).CanAccessWithRoutes(pm.matchers, nodes.At(i), rj.subnet, ri.subnet, ri.isExit) {
					ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j).ID())
					ret[nodes.At(j).ID()] = append(ret[nodes.At(j).ID()], nodes.At(i).ID())
				}
			}
		}

		return ret
	}

	// For autogroup:self or via grants, build per-node peer relationships
	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	// Pre-compute per-node matchers using unreduced compiled rules
	// We need unreduced rules to determine peer relationships correctly.
	// Reduced rules only show destinations where the node is the target,
	// but peer relationships require the full bidirectional access rules.
	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	for _, node := range nodes.All() {
		unreduced := pm.filterRulesForNodeLocked(node)
		nodeMatchers[node.ID()] = matcher.MatchesFromFilterRules(unreduced)
	}

	// Check each node pair for peer relationships.
	// Start j at i+1 to avoid checking the same pair twice and creating duplicates.
	// We use symmetric visibility: if EITHER node can access the other, BOTH see
	// each other. This matches the global filter path behavior and ensures that
	// one-way access rules (e.g., admin -> tagged server) still allow both nodes
	// to see each other as peers, which is required for network connectivity.
	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			// Check all access directions for symmetric peer visibility.
			// For via grants, filter rules exist on the via-designated node
			// (e.g., router-a) with sources being the client (group-a).
			// We need to check BOTH:
			//   1. nodeI.CanAccess(matchersI, nodeJ) — can nodeI reach nodeJ?
			//   2. nodeJ.CanAccess(matchersI, nodeI) — can nodeJ reach nodeI
			//      using nodeI's matchers? (reverse direction: the matchers
			//      on the via node accept traffic FROM the source)
			// Same for matchersJ in both directions.
			canIAccessJ := hasFilterI && nodeI.CanAccessWithRoutes(matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)
			canJAccessI := hasFilterJ && nodeJ.CanAccessWithRoutes(matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canJReachI := hasFilterI && nodeJ.CanAccessWithRoutes(matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canIReachJ := hasFilterJ && nodeI.CanAccessWithRoutes(matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)

			if canIAccessJ || canJAccessI || canJReachI || canIReachJ {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())
			}
		}
	}

	return ret
}

func TestIndexedPeerMapMatchesPairwise(t *testing.T) {
	policies := append(make([]string, 0, 7+len(benchPolicies)), []string{
		`{}`,
		`{"acls":[]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
		`{"acls":[{"action":"accept","src":["u1@","u2@"],"dst":["autogroup:self:*"]}]}`,
		`{"acls":[{"action":"accept","src":["10.0.0.0/8","fd00::/8"],"dst":["100.64.0.0/16:*","fd7a:115c:a1e0::/48:*"]}]}`,
		`{"tagOwners":{"tag:srv":["u1@"],"tag:router":["u1@"]},"acls":[{"action":"accept","src":["u1@"],"dst":["tag:srv:*","autogroup:self:*"]},{"action":"accept","src":["u2@"],"dst":["autogroup:internet:*"]}],"grants":[{"src":["u2@"],"dst":["10.0.0.0/8"],"via":["tag:router"],"ip":["*"]}]}`,
		`{"grants":[{"src":["*"],"dst":["100.64.0.0/16"],"app":{"example.com/cap": [{}]}}]}`,
	}...)
	for _, p := range benchPolicies {
		policies = append(policies, p.policy)
	}

	for seed := range 30 {
		rng := rand.New(rand.NewPCG(uint64(seed), 42)) //nolint:gosec // Reproducible test data.

		users, nodes := benchNodes(10 + rng.IntN(70))
		for i, node := range nodes {
			// Cover overlapping ranges, shared addresses, dual stack, approved versus
			// unapproved routes, and IPv4-only/IPv6-only exit nodes.
			ip := netip.AddrFrom4([4]byte{100, 64, 0, byte(rng.IntN(35))}) //nolint:gosec
			v6 := netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%x", i+1))
			node.IPv4, node.IPv6 = &ip, &v6

			if rng.IntN(3) == 0 {
				route := netip.MustParsePrefix([]string{"10.0.0.0/8", "10.1.0.0/16", "fd00::/8", "0.0.0.0/0", "::/0"}[rng.IntN(5)])
				node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
				node.ApprovedRoutes = []netip.Prefix{route}
			}

			if rng.IntN(8) == 0 {
				node.IPv4 = nil
			}

			if rng.IntN(8) == 0 {
				node.ApprovedRoutes = nil
			}
		}

		for policyIndex, policy := range policies {
			t.Run(fmt.Sprintf("seed=%d/policy=%d", seed, policyIndex), func(t *testing.T) {
				pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
				require.NoError(t, err)
				require.Equal(t, pm.buildPeerMapPairwiseReference(nodes.ViewSlice()), pm.BuildPeerMap(nodes.ViewSlice()))

				for _, viewer := range nodes[:3] {
					shared, err := pm.MatchersForNode(viewer.View())
					require.NoError(t, err)

					original := pm.matchers
					if pm.needsPerNodeFilter {
						original = matcher.MatchesFromFilterRules(pm.filterRulesForNodeLocked(viewer.View()))
					}

					for _, peer := range nodes {
						require.Equal(t, viewer.CanAccess(original, peer), viewer.CanAccess(shared, peer))
						require.Equal(t, peer.CanAccess(original, viewer), peer.CanAccess(shared, viewer))
					}
				}

				changed := slices.Clone(nodes)
				changed[2] = nodes[2].View().AsStruct()
				changed[2].Tags = nil
				changed[2].User, changed[2].UserID = &users[1], &users[1].ID
				changed[2].IPv4 = new(netip.MustParseAddr("100.64.254.254"))
				changed[2].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}}
				changed[2].ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}
				_, err = pm.SetNodes(changed.ViewSlice())
				require.NoError(t, err)
				require.Equal(t, pm.buildPeerMapPairwiseReference(changed.ViewSlice()), pm.BuildPeerMap(changed.ViewSlice()))
				// A reload must not reuse stale memberships from the previous snapshot.
				_, err = pm.SetPolicy([]byte(`{"acls":[]}`))
				require.NoError(t, err)
				require.Empty(t, pm.BuildPeerMap(nodes.ViewSlice()))
			})
		}
	}
}

func BenchmarkIndexedPeerMapComparison(b *testing.B) {
	for _, pol := range benchPolicies {
		for _, count := range []int{1000, 10000} {
			users, nodes := benchNodes(count)
			pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
			require.NoError(b, err)
			b.Run(fmt.Sprintf("%s/n=%d/indexed", pol.name, count), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					pm.BuildPeerMap(nodes.ViewSlice())
				}
			})

			if count == 1000 {
				b.Run(fmt.Sprintf("%s/n=%d/pairwise", pol.name, count), func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						pm.buildPeerMapPairwiseReference(nodes.ViewSlice())
					}
				})
			}
		}
	}
}

// segmentedPeerMapFixture models generic tagged endpoints, user-owned devices,
// segmented access, an administrator, and autogroup:self. No application-specific
// identity provider or database is needed.
func segmentedPeerMapFixture(endpointCount, userCount int) ([]types.User, types.Nodes, []byte) {
	const segments = 100

	users := make([]types.User, userCount)
	groups := make(map[string][]string)
	owners := make(map[string][]string)
	acls := append(make([]map[string]any, 0, 2+segments), []map[string]any{
		{"action": "accept", "src": []string{"u1@"}, "dst": []string{"100.64.0.0/16:*"}},
		{"action": "accept", "src": []string{"autogroup:member"}, "dst": []string{"autogroup:self:*"}},
	}...)

	for i := range users {
		users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i+1)}
		group := fmt.Sprintf("group:segment-%d", i%segments)
		groups[group] = append(groups[group], users[i].Name+"@")
	}

	for i := range segments {
		tag := fmt.Sprintf("tag:segment-%d", i)
		owners[tag] = []string{"u1@"}
		acls = append(acls, map[string]any{"action": "accept", "src": []string{fmt.Sprintf("group:segment-%d", i)}, "dst": []string{tag + ":80,443"}})
	}

	nodes := make(types.Nodes, 0, endpointCount+2*userCount)
	for i := range endpointCount + 2*userCount {
		id := i + 1
		ip := netip.AddrFrom4([4]byte{100, 64, byte(id / 256), byte(id % 256)}) //nolint:gosec

		node := &types.Node{ID: types.NodeID(id), IPv4: &ip}
		if i < endpointCount {
			node.Tags = []string{fmt.Sprintf("tag:segment-%d", i%segments)}
		} else {
			user := &users[(i-endpointCount)/2]
			node.UserID, node.User = &user.ID, user
			personalID := i - endpointCount + 1
			ip = netip.AddrFrom4([4]byte{100, 65, byte(personalID / 256), byte(personalID % 256)}) //nolint:gosec
		}

		nodes = append(nodes, node)
	}

	policy, err := json.Marshal(map[string]any{"groups": groups, "tagOwners": owners, "acls": acls})
	if err != nil {
		panic(err)
	}

	return users, nodes, policy
}

func BenchmarkPeerMapScale(b *testing.B) {
	for _, size := range []struct{ endpoints, users int }{{1000, 100}, {10000, 1000}, {10000, 2000}, {20000, 2000}} {
		users, nodes, policy := segmentedPeerMapFixture(size.endpoints, size.users)
		pm, err := NewPolicyManager(policy, users, nodes.ViewSlice())
		require.NoError(b, err)
		b.Run(fmt.Sprintf("endpoints=%d/users=%d/indexed", size.endpoints, size.users), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				pm.BuildPeerMap(nodes.ViewSlice())
			}
		})

		if size.endpoints == 1000 {
			b.Run("endpoints=1000/users=100/pairwise", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					pm.buildPeerMapPairwiseReference(nodes.ViewSlice())
				}
			})
		}
	}
}

func TestSegmentedPeerMapMatchesPairwise(t *testing.T) {
	users, nodes, policy := segmentedPeerMapFixture(300, 100)
	pm, err := NewPolicyManager(policy, users, nodes.ViewSlice())
	require.NoError(t, err)
	require.Equal(t, pm.buildPeerMapPairwiseReference(nodes.ViewSlice()), pm.BuildPeerMap(nodes.ViewSlice()))
}
