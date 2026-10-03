package v2

import (
	"math/bits"
	"net/netip"
	"slices"
	"sort"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
)

// peerAddressIndex is private to one snapshot build. It indexes both address
// families, retains duplicate addresses, and separately checks subnet routers.
// A router matches overlapping approved routes, not only its own addresses.
type peerAddress struct {
	ip   netip.Addr
	node int
}

type peerAddressIndex struct {
	nodes     views.Slice[types.NodeView]
	addresses []peerAddress
	routes    [][]netip.Prefix
	routers   []int
	exits     []int
	marks     []uint64
	epoch     uint64
}

func newPeerAddressIndex(nodes views.Slice[types.NodeView]) *peerAddressIndex {
	idx := &peerAddressIndex{
		nodes:  nodes,
		routes: make([][]netip.Prefix, nodes.Len()),
		marks:  make([]uint64, nodes.Len()),
	}
	for i, node := range nodes.All() {
		for _, ip := range node.IPs() {
			idx.addresses = append(idx.addresses, peerAddress{ip: ip, node: i})
		}

		idx.routes[i] = node.SubnetRoutes()
		if len(idx.routes[i]) > 0 {
			idx.routers = append(idx.routers, i)
		}

		if node.IsExitNode() {
			idx.exits = append(idx.exits, i)
		}
	}

	slices.SortFunc(idx.addresses, func(a, b peerAddress) int { return a.ip.Compare(b.ip) })

	return idx
}

// matchingNodes implements one side of Node.canAccess: address membership OR
// subnet overlap, plus the destination-only exit-node/internet special case.
func (idx *peerAddressIndex) matchingNodes(m *matcher.Match, source bool) []int {
	idx.epoch++

	var matched []int

	add := func(i int) {
		if idx.marks[i] != idx.epoch {
			idx.marks[i] = idx.epoch
			matched = append(matched, i)
		}
	}

	ranges := m.DestinationRanges()
	if source {
		ranges = m.SourceRanges()
	}

	for _, r := range ranges {
		start := sort.Search(len(idx.addresses), func(i int) bool {
			return idx.addresses[i].ip.Compare(r.From()) >= 0
		})
		for i := start; i < len(idx.addresses) && idx.addresses[i].ip.Compare(r.To()) <= 0; i++ {
			add(idx.addresses[i].node)
		}
	}

	for _, i := range idx.routers {
		if (source && m.SrcsOverlapsPrefixes(idx.routes[i]...)) ||
			(!source && m.DestsOverlapsPrefixes(idx.routes[i]...)) {
			add(i)
		}
	}

	if !source && len(idx.exits) > 0 && m.DestsIsTheInternet() {
		for _, i := range idx.exits {
			add(i)
		}
	}

	return matched
}

type peerMembership struct {
	sources      []int
	destinations []int
}

func (idx *peerAddressIndex) memberships(rules []tailcfg.FilterRule) []peerMembership {
	matches := matcher.MatchesFromFilterRules(rules)

	ret := make([]peerMembership, 0, len(matches))
	for i := range matches {
		ret = append(ret, peerMembership{
			sources:      idx.matchingNodes(&matches[i], true),
			destinations: idx.matchingNodes(&matches[i], false),
		})
	}

	return ret
}

func (pm *PolicyManager) buildIndexedPeerMapLocked(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID {
	idx := newPeerAddressIndex(nodes)
	// Bitsets deduplicate edges from overlapping rules without a map allocation
	// per edge, and preserve the old builder's input-node ordering on output.
	adjacent := make([][]uint64, nodes.Len())
	words := (nodes.Len() + 63) / 64
	add := func(i, j int) {
		if nodes.At(i).ID() == nodes.At(j).ID() {
			return
		}

		if adjacent[i] == nil {
			adjacent[i] = make([]uint64, words)
		}

		if adjacent[j] == nil {
			adjacent[j] = make([]uint64, words)
		}

		adjacent[i][j/64] |= uint64(1) << (j % 64)
		adjacent[j][i/64] |= uint64(1) << (i % 64)
	}
	// Global rules apply to every node even when self/via rules are present.
	// Factor each matcher into source and destination sets, then emit its edges.
	for i := range pm.matchers {
		sources := idx.matchingNodes(&pm.matchers[i], true)

		destinations := idx.matchingNodes(&pm.matchers[i], false)
		for _, src := range sources {
			for _, dst := range destinations {
				add(src, dst)
			}
		}
	}

	if pm.needsPerNodeFilter {
		// Only edges incident to the filter owner may use its self/via rules.
		// Cache self memberships by user, avoiding both compilation and hashing
		// of the same potentially large rule set for every owned device.
		selfCache := make(map[uint][]peerMembership)
		viaCache := make(map[deephash.Sum][]peerMembership)

		apply := func(owner int, memberships []peerMembership) {
			for _, members := range memberships {
				if slices.Contains(members.sources, owner) {
					for _, dst := range members.destinations {
						add(owner, dst)
					}
				}

				if slices.Contains(members.destinations, owner) {
					for _, src := range members.sources {
						add(owner, src)
					}
				}
			}
		}
		for owner, node := range nodes.All() {
			if !node.IsTagged() && node.User().Valid() {
				userID := node.User().ID()

				members, ok := selfCache[userID]
				if !ok {
					var rules []tailcfg.FilterRule

					for i := range pm.compiledGrants {
						cg := &pm.compiledGrants[i]
						if cg.category == grantCategorySelf {
							rules = append(rules, compileAutogroupSelf(cg, node, pm.userNodeIdx)...)
						}
					}

					members = idx.memberships(rules)
					selfCache[userID] = members
				}

				apply(owner, members)
			}

			var rules []tailcfg.FilterRule

			for i := range pm.compiledGrants {
				cg := &pm.compiledGrants[i]
				if cg.category == grantCategoryVia {
					rules = append(rules, compileViaForNode(cg, node)...)
				}
			}

			if len(rules) == 0 {
				continue
			}

			hash := deephash.Hash(&rules)

			members, ok := viaCache[hash]
			if !ok {
				members = idx.memberships(rules)
				viaCache[hash] = members
			}

			apply(owner, members)
		}
	}

	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	for i, row := range adjacent {
		for wordIndex, word := range row {
			for word != 0 {
				j := wordIndex*64 + bits.TrailingZeros64(word)
				ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j).ID())
				word &= word - 1
			}
		}
	}

	return ret
}
