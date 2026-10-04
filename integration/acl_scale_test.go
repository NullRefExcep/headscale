package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestACLRealClientScale is opt-in: every endpoint runs a real tailscaled.
// HEADSCALE_INTEGRATION_SCALE_IOT selects the IoT count (a multiple of ten).
func TestACLRealClientScale(t *testing.T) {
	IntegrationSkip(t)

	count, _ := strconv.Atoi(os.Getenv("HEADSCALE_INTEGRATION_SCALE_IOT"))
	if count == 0 {
		t.Skip("explicit HEADSCALE_INTEGRATION_SCALE_IOT required")
	}

	require.True(t, count >= 20 && count%10 == 0)

	segments := min(100, count/10)

	names := make([]string, 0, 1+segments)

	names = append(names, "scale-admin")
	for i := range segments {
		names = append(names, fmt.Sprintf("scale-reader-%d", i))
	}

	makePolicy := func(revoke bool) *policyv2.Policy {
		owners := map[string][]string{"tag:iot": {"scale-admin@"}}

		rules := []map[string]any{{"action": "accept", "src": []string{"scale-admin@"}, "dst": []string{"100.64.0.0/16:*", "tag:iot:*"}}}
		for _, name := range names {
			rules = append(rules, map[string]any{"action": "accept", "src": []string{name + "@"}, "dst": []string{name + "@:*"}})
		}

		for i := range segments {
			tag := fmt.Sprintf("tag:segment-%d", i)

			owners[tag] = []string{"scale-admin@"}
			if !revoke || i != 0 {
				rules = append(rules, map[string]any{"action": "accept", "src": []string{fmt.Sprintf("scale-reader-%d@", i)}, "proto": "tcp", "dst": []string{tag + ":80,443"}})
			}
		}

		raw, err := json.Marshal(map[string]any{
			"tagOwners": owners, "acls": rules,
			"nodeAttrs": []map[string]any{{"target": []string{"autogroup:member"}, "ipPool": []string{"100.65.0.0/16"}}, {"target": []string{"tag:iot"}, "ipPool": []string{"100.64.0.0/16"}}},
		})
		require.NoError(t, err)

		var policy policyv2.Policy
		require.NoError(t, json.Unmarshal(raw, &policy))

		return &policy
	}
	progress, err := os.CreateTemp(t.TempDir(), "headscale-scale-progress-")
	require.NoError(t, err)

	require.NoError(t, progress.Close())
	defer os.Remove(progress.Name())

	require.NoError(t, os.MkdirAll("../control_logs", 0o700))

	artifactDir, err := os.MkdirTemp("../control_logs", "real-scale-") //nolint:usetesting // Persist partial stages on the host after container cleanup.
	require.NoError(t, err)
	artifact, err := os.CreateTemp(artifactDir, "scale-progress-*.jsonl")
	require.NoError(t, err)

	defer artifact.Close()

	logProgress := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		require.NoError(t, os.WriteFile(progress.Name(), []byte(message), 0o600))
		entry, err := json.Marshal(map[string]string{"time_utc": time.Now().UTC().Format(time.RFC3339), "message": message, "run_id": os.Getenv("HEADSCALE_INTEGRATION_RUN_ID")})
		require.NoError(t, err)
		_, err = artifact.Write(append(entry, '\n'))
		require.NoError(t, err)
		require.NoError(t, artifact.Sync())
		t.Log(message)
	}
	started := time.Now()
	networks := make(map[string]NetworkSpec, 4)

	for i := range 4 {
		users := []string{}

		for segment := i; segment < segments; segment += 4 {
			users = append(users, fmt.Sprintf("scale-reader-%d", segment), fmt.Sprintf("scale-iot-%d", segment))
		}

		networks[fmt.Sprintf("scale-net-%d", i)] = NetworkSpec{Users: users}
	}

	adminNetwork := networks["scale-net-0"]
	adminNetwork.Users = append(adminNetwork.Users, "scale-admin")
	networks["scale-net-0"] = adminNetwork
	scenario, err := NewScenario(ScenarioSpec{Users: names, NodesPerUser: 2, Versions: []string{"head"}, Networks: networks})

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	require.NoError(t, scenario.CreateHeadscaleEnv([]tsic.Option{tsic.WithNetfilter("off"), tsic.WithWebserver(80)}, hsic.WithACLPolicy(makePolicy(false)), hsic.WithTestName("acl-real-client-scale"), hsic.WithConfigEnv(map[string]string{"HEADSCALE_LOG_LEVEL": "warn"})))
	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	stages := []int{min(500, count) / segments * segments, min(1000, count) / segments * segments, count}
	previous := 0
	authKeys := make(map[string]string, segments)
	joined := make(map[string]bool, count)

	for _, activeCount := range stages {
		if activeCount == previous {
			continue
		}

		require.Equal(t, 0, (activeCount-previous)%segments)
		require.NoError(t, headscale.SetPolicy(makePolicy(false)))

		for i := range segments {
			name := fmt.Sprintf("scale-iot-%d", i)
			if previous == 0 {
				user, err := scenario.CreateUser(name)
				require.NoError(t, err)

				tags := []string{"tag:iot", fmt.Sprintf("tag:segment-%d", i)}
				key, err := scenario.CreatePreAuthKeyWithTags(mustParseID(user.Id), true, false, tags)
				require.NoError(t, err)

				authKeys[name] = key.Key
			}

			require.NoError(t, scenario.CreateTailscaleNodesInUser(name, "head", (activeCount-previous)/segments, tsic.WithNetwork(scenario.userToNetwork[name]), tsic.WithNetfilter("off"), tsic.WithWebserver(80)))
			clients, err := scenario.GetClients(name)
			require.NoError(t, err)

			var joins errgroup.Group
			joins.SetLimit(16)

			for _, client := range clients {
				if joined[client.ContainerID()] {
					continue
				}

				joined[client.ContainerID()] = true

				joins.Go(func() error {
					err := client.Login(headscale.GetEndpoint(), authKeys[name])
					if err != nil {
						return err
					}

					return client.WaitForRunning(2 * time.Minute)
				})
			}

			require.NoError(t, joins.Wait())
			logProgress("scale phase=enroll segment=%d iot=%d elapsed=%s", i, previous+(i+1)*(activeCount-previous)/segments, time.Since(started))
		}

		all, err := scenario.ListTailscaleClients()
		require.NoError(t, err)
		require.Len(t, all, activeCount+2*len(names))

		waitConnected := func() {
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				info, err := headscale.DebugBatcher()
				if !assert.NoError(c, err) {
					return
				}

				connected := 0

				for _, node := range info.ConnectedNodes {
					if node.Connected && node.ActiveConnections > 0 {
						connected++
					}
				}

				assert.Equal(c, activeCount+2*len(names), connected)
			}, 3*time.Minute, time.Second, "all real Noise map streams must be connected")
		}
		waitConnected()

		checkMaps := func(revoked bool) {
			var checks errgroup.Group
			checks.SetLimit(16)

			for _, name := range names {
				clients, err := scenario.GetClients(name)
				require.NoError(t, err)

				expected := activeCount/segments + 1
				if name == "scale-admin" {
					expected = activeCount + 1
				}

				if revoked && name == "scale-reader-0" {
					expected = 1
				}

				for _, client := range clients {
					checks.Go(func() error {
						return client.WaitForPeers(expected, 2*time.Minute, 100*time.Millisecond)
					})
				}
			}

			for i := range segments {
				clients, err := scenario.GetClients(fmt.Sprintf("scale-iot-%d", i))
				require.NoError(t, err)

				expected := 4
				if revoked && i == 0 {
					expected = 2
				}

				for _, client := range clients {
					checks.Go(func() error {
						return client.WaitForPeers(expected, 2*time.Minute, 100*time.Millisecond)
					})
				}
			}

			require.NoError(t, checks.Wait())
		}
		checkMaps(false)
		logProgress("scale phase=ready total=%d elapsed=%s", len(all), time.Since(started))

		readers, err := scenario.GetClients("scale-reader-0")
		require.NoError(t, err)
		admins, err := scenario.GetClients("scale-admin")
		require.NoError(t, err)
		iot, err := scenario.GetClients("scale-iot-0")
		require.NoError(t, err)

		url := "http://" + iot[0].MustIPv4().String() + "/etc/hostname"

		assert.EventuallyWithT(t, func(c *assert.CollectT) { _, err := readers[0].CurlFailFast(url); assert.NoError(c, err) }, time.Minute, time.Second, "reader TCP access before revocation")

		ownURL := "http://" + readers[1].MustIPv4().String() + "/etc/hostname"

		assert.EventuallyWithT(t, func(c *assert.CollectT) { _, err := readers[0].CurlFailFast(ownURL); assert.NoError(c, err) }, time.Minute, time.Second, "own-device TCP access")

		foreign, err := scenario.GetClients("scale-reader-1")
		require.NoError(t, err)
		_, err = readers[0].CurlFailFast("http://" + foreign[0].MustIPv4().String() + "/etc/hostname")
		require.Error(t, err, "foreign personal device must be isolated")

		remoteIoT, err := scenario.GetClients("scale-iot-1")
		require.NoError(t, err)

		remoteURL := "http://" + remoteIoT[0].MustIPv4().String() + "/etc/hostname"

		assert.EventuallyWithT(t, func(c *assert.CollectT) { _, err := admins[0].CurlFailFast(remoteURL); assert.NoError(c, err) }, time.Minute, time.Second, "admin TCP access across Docker bridge networks")

		restart := time.Now()

		require.NoError(t, headscale.Restart())
		logProgress("scale phase=server_ready total=%d seconds=%.3f", len(all), time.Since(restart).Seconds())
		waitConnected()
		logProgress("scale phase=all_streams_reconnected total=%d seconds=%.3f", len(all), time.Since(restart).Seconds())
		checkMaps(false)
		logProgress("scale phase=reconnect total=%d seconds=%.3f", len(all), time.Since(restart).Seconds())

		revoke := time.Now()

		require.NoError(t, headscale.SetPolicy(makePolicy(true)))
		logProgress("scale phase=policy_applied seconds=%.3f", time.Since(revoke).Seconds())
		assert.EventuallyWithT(t, func(c *assert.CollectT) { _, err := readers[0].CurlFailFast(url); assert.Error(c, err) }, 2*time.Minute, time.Second, "revoked IoT TCP access must be denied")
		logProgress("scale phase=packet_denied seconds=%.3f", time.Since(revoke).Seconds())
		checkMaps(true)
		assert.EventuallyWithT(t, func(c *assert.CollectT) { _, err := admins[0].CurlFailFast(url); assert.NoError(c, err) }, time.Minute, time.Second, "admin access must survive revocation")
		assert.EventuallyWithT(t, func(c *assert.CollectT) { _, err := readers[0].CurlFailFast(ownURL); assert.NoError(c, err) }, time.Minute, time.Second, "own-device access must survive revocation")
		logProgress("scale phase=complete total=%d elapsed=%s", len(all), time.Since(started))

		previous = activeCount
	}
}
