/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dnscache

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/go-cmp/cmp"

	"sigs.k8s.io/kindnet/pkg/nstest"
)

func TestNFLogAgent_syncRules(t *testing.T) {
	nstest.ExecInUserns(t, testNFLogAgent_syncRules)
}

func testNFLogAgent_syncRules(t *testing.T) {
	tests := []struct {
		name             string
		podCIDRv4        string
		podCIDRv6        string
		expectedNftables string
		nameservers      []string
	}{
		{
			name: "empty",
			expectedNftables: `
table inet kindnet-dnscache {
        chain prerouting {
                type filter hook prerouting priority raw; policy accept;
        }
        chain output {
                type filter hook output priority raw; policy accept;
                meta mark 0x0000006e udp sport 53 notrack
        }
}
`,
		},
		{
			name:        "dual",
			podCIDRv4:   "10.0.0.0/24",
			podCIDRv6:   "2001:db8::/112",
			nameservers: []string{"1.1.1.1", "fd00::1"},
			expectedNftables: `
table inet kindnet-dnscache {
        set set-v4-nameservers {
                type ipv4_addr
                elements = { 1.1.1.1 }
        }

        set set-v6-nameservers {
                type ipv6_addr
                elements = { fd00::1 }
        }
        chain prerouting {
                type filter hook prerouting priority raw; policy accept;
                ip saddr 10.0.0.0/24 ip daddr @set-v4-nameservers udp dport 53 queue flags bypass to 103
                ip6 saddr 2001:db8::/112 ip6 daddr @set-v6-nameservers udp dport 53 queue flags bypass to 103
        }
        chain output {
                type filter hook output priority raw; policy accept;
                meta mark 0x0000006e udp sport 53 notrack
        }
}
`,
		},
		{
			name:        "dual odd mask",
			podCIDRv4:   "10.0.0.0/17",
			podCIDRv6:   "2001:db8::/77",
			nameservers: []string{"1.1.1.1", "fd00::1"},
			expectedNftables: `
table inet kindnet-dnscache {
        set set-v4-nameservers {
                type ipv4_addr
                elements = { 1.1.1.1 }
        }

        set set-v6-nameservers {
                type ipv6_addr
                elements = { fd00::1 }
        }
        chain prerouting {
                type filter hook prerouting priority raw; policy accept;
                ip saddr 10.0.0.0/17 ip daddr @set-v4-nameservers udp dport 53 queue flags bypass to 103
                ip6 saddr 2001:db8::/77 ip6 daddr @set-v6-nameservers udp dport 53 queue flags bypass to 103
        }
        chain output {
                type filter hook output priority raw; policy accept;
                meta mark 0x0000006e udp sport 53 notrack
        }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &DNSCacheAgent{
				podCIDRv4:   tt.podCIDRv4,
				podCIDRv6:   tt.podCIDRv6,
				nameServers: tt.nameservers,
			}

			if err := n.SyncRules(context.Background()); err != nil {
				t.Fatalf("DNSCacheAgent.SyncRules() error = %v", err)
			}
			// A resync must keep the table and its base chains, deleting a base
			// chain drops the packets waiting in every nfqueue of the namespace.
			handles := baseHandles(t)
			if err := n.SyncRules(context.Background()); err != nil {
				t.Fatalf("DNSCacheAgent.SyncRules() resync error = %v", err)
			}
			if diff := cmp.Diff(handles, baseHandles(t)); diff != "" {
				t.Errorf("resync recreated the table or its chains (-first +resync):\n%s", diff)
			}

			cmd := exec.Command("nft", "list", "table", "inet", tableName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft list table error = %v", err)
			}
			got := string(out)
			if !compareMultilineStringsIgnoreIndentation(got, tt.expectedNftables) {
				t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, tt.expectedNftables, cmp.Diff(got, tt.expectedNftables))
			}
			CleanRules()
			cmd = exec.Command("nft", "list", "table", "inet", tableName)
			out, err = cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("nft list ruleset unexpected success")
			}
			if !strings.Contains(string(out), "No such file or directory") {
				t.Errorf("unexpected error %v %s", err, string(out))
			}
		})
	}
}

func compareMultilineStringsIgnoreIndentation(str1, str2 string) bool {
	// Remove all indentation from both strings
	re := regexp.MustCompile(`(?m)^\s+`)
	str1 = re.ReplaceAllString(str1, "")
	str2 = re.ReplaceAllString(str2, "")

	return str1 == str2
}

var handleRE = regexp.MustCompile(`(?m)^\s*(?:table|chain|flowtable) .* # handle \d+$`)

// baseHandles returns the table, chain and flowtable lines of "nft -a list table",
// whose kernel handles change when the object is deleted and created again.
func baseHandles(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("nft", "-a", "list", "table", "inet", tableName).CombinedOutput()
	if err != nil {
		ruleset, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
		t.Fatalf("nft -a list table error = %v, output: %s\nruleset:\n%s", err, string(out), ruleset)
	}
	return handleRE.FindAllString(string(out), -1)
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// tableHandle returns the kernel handle of the table, which changes when the
// table is deleted and created again.
func tableHandle(t *testing.T) string {
	t.Helper()
	for _, line := range baseHandles(t) {
		if strings.HasPrefix(strings.TrimSpace(line), "table ") {
			return line
		}
	}
	t.Fatalf("table %s not found", tableName)
	return ""
}

// TestDNSCacheAgent_RecreateOnlyWhenRejected checks that a sync over a table a
// previous version left behind updates it in place, and recreates it only
// when the kernel refuses the in-place update.
func TestDNSCacheAgent_RecreateOnlyWhenRejected(t *testing.T) {
	nstest.ExecInUserns(t, testDNSCacheAgent_RecreateOnlyWhenRejected)
}

func testDNSCacheAgent_RecreateOnlyWhenRejected(t *testing.T) {
	n := &DNSCacheAgent{
		podCIDRv4:   "10.0.0.0/24",
		podCIDRv6:   "2001:db8::/112",
		nameServers: []string{"1.1.1.1", "fd00::1"},
	}
	ctx := context.Background()

	// leftover writes the table as a previous version could have left it. The
	// objects in override replace the ones with the same name, or are added.
	leftover := func(t *testing.T, override map[string]string) {
		t.Helper()
		objects := []struct{ name, definition string }{
			{"prerouting", `chain prerouting { type filter hook prerouting priority raw; policy accept; }`},
			{"output", `chain output { type filter hook output priority raw; policy accept; }`},
			{"set-v4-nameservers", `set set-v4-nameservers { type ipv4_addr; elements = { 192.0.2.1 } }`},
			{"set-v6-nameservers", `set set-v6-nameservers { type ipv6_addr; }`},
		}
		var b strings.Builder
		fmt.Fprintf(&b, "flush ruleset\ntable inet %s {\n", tableName)
		for _, o := range objects {
			if definition, ok := override[o.name]; ok {
				b.WriteString(definition)
				delete(override, o.name)
			} else {
				b.WriteString(o.definition)
			}
			b.WriteString("\n")
		}
		for _, definition := range override {
			b.WriteString(definition + "\n")
		}
		b.WriteString("}\n")
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(b.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f: %v: %s\n%s", err, out, b.String())
		}
	}

	tests := []struct {
		name     string
		override map[string]string
		recreate bool
	}{
		{name: "same layout"},
		{name: "chain policy differs, updated in place", override: map[string]string{
			"output": `chain output { type filter hook output priority raw; policy drop; }`}},
		{name: "stale regular chain and set are kept", override: map[string]string{
			"old": `chain old { }`, "oldset": `set oldset { type ipv4_addr; }`}},
		{name: "base chain priority differs", recreate: true, override: map[string]string{
			"prerouting": `chain prerouting { type filter hook prerouting priority filter; policy accept; }`}},
		{name: "base chain hook differs", recreate: true, override: map[string]string{
			"prerouting": `chain prerouting { type filter hook input priority raw; policy accept; }`}},
		{name: "base chain exists as regular chain", recreate: true, override: map[string]string{
			"prerouting": `chain prerouting { }`}},
		{name: "set key type differs", recreate: true, override: map[string]string{
			"set-v4-nameservers": `set set-v4-nameservers { type ipv6_addr; }`}},
		{name: "set flags differ", recreate: true, override: map[string]string{
			"set-v4-nameservers": `set set-v4-nameservers { type ipv4_addr; flags interval; }`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leftover(t, tt.override)
			before := baseHandles(t)
			beforeTable := tableHandle(t)

			if err := n.SyncRules(ctx); err != nil {
				t.Fatalf("SyncRules() error = %v", err)
			}
			if recreated := beforeTable != tableHandle(t); recreated != tt.recreate {
				t.Errorf("table recreated = %v, want %v (handles before %v, after %v)", recreated, tt.recreate, before, baseHandles(t))
			}
			if !tt.recreate {
				if diff := cmp.Diff(before, baseHandles(t)); diff != "" {
					t.Errorf("in-place sync recreated a base chain (-leftover +sync):\n%s", diff)
				}
			}

			// Whatever the path, the result is the ruleset of a clean sync,
			// except for stale objects the in-place sync does not remove.
			got := run(t, "nft", "list", "table", "inet", tableName)
			CleanRules()
			if err := n.SyncRules(ctx); err != nil {
				t.Fatalf("clean SyncRules() error = %v", err)
			}
			want := run(t, "nft", "list", "table", "inet", tableName)
			if !strings.Contains(tt.name, "stale") && !compareMultilineStringsIgnoreIndentation(got, want) {
				t.Errorf("sync over the leftover table differs from a clean sync (-clean +leftover):\n%s", cmp.Diff(want, got))
			}
			if strings.Contains(got, "192.0.2.1") {
				t.Errorf("set elements of the leftover table were kept:\n%s", got)
			}

			// The next sync is in place again.
			before = baseHandles(t)
			if err := n.SyncRules(ctx); err != nil {
				t.Fatalf("second SyncRules() error = %v", err)
			}
			if diff := cmp.Diff(before, baseHandles(t)); diff != "" {
				t.Errorf("second sync recreated the table or its chains (-first +second):\n%s", diff)
			}
		})
	}
}

// TestDNSCacheAgent_ResyncKeepsQueuedPackets checks that a DNS query waiting in
// the agent's nfqueue for its verdict survives a resync, and that it does not
// survive the recreation of the table, which unregisters the hooks of its base
// chains.
func TestDNSCacheAgent_ResyncKeepsQueuedPackets(t *testing.T) {
	nstest.ExecInUserns(t, testDNSCacheAgent_ResyncKeepsQueuedPackets)
}

func testDNSCacheAgent_ResyncKeepsQueuedPackets(t *testing.T) {
	const (
		podIP      = "10.0.0.5"
		nameserver = "10.96.0.10"
	)
	// Local to local traffic traverses prerouting on lo, where the agent's
	// rule queues the DNS queries from the pod range to the nameservers.
	run(t, "ip", "link", "set", "lo", "up")
	run(t, "ip", "addr", "add", podIP+"/24", "dev", "lo")
	run(t, "ip", "addr", "add", nameserver+"/32", "dev", "lo")

	n := &DNSCacheAgent{
		podCIDRv4:   "10.0.0.0/24",
		nameServers: []string{nameserver},
	}
	ctx := context.Background()
	if err := n.SyncRules(ctx); err != nil {
		t.Fatalf("SyncRules() error = %v", err)
	}

	// The queue does not set the verdict, the packets wait in it.
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueID,
		MaxPacketLen: maxDNSSize,
		MaxQueueLen:  64,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	queued := make(chan uint32, 8)
	qctx, cancel := context.WithCancel(ctx)
	defer cancel()
	err = nf.RegisterWithErrorFunc(qctx,
		func(a nfqueue.Attribute) int { queued <- *a.PacketID; return 0 },
		func(error) int { return 0 })
	if err != nil {
		t.Fatal(err)
	}

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(nameserver), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(podIP)}, &net.UDPAddr{IP: net.ParseIP(nameserver), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// sendAndHold sends a query and returns its id once it waits in the queue.
	sendAndHold := func() uint32 {
		t.Helper()
		if _, err := client.Write([]byte("query")); err != nil {
			t.Fatal(err)
		}
		select {
		case id := <-queued:
			return id
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the query to reach the queue")
			return 0
		}
	}
	// received reports whether the server gets a packet within the timeout.
	received := func(timeout time.Duration) bool {
		t.Helper()
		if err := server.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatal(err)
		}
		_, _, err := server.ReadFrom(make([]byte, 64))
		return err == nil
	}

	id := sendAndHold()
	if err := n.SyncRules(ctx); err != nil {
		t.Fatalf("SyncRules() error = %v", err)
	}
	if err := nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
		t.Fatal(err)
	}
	if !received(5 * time.Second) {
		t.Fatal("the query waiting in the queue was dropped by the resync")
	}

	// Recreating the table, what the agent did on every sync before.
	id = sendAndHold()
	if err := n.writeRules(true); err != nil {
		t.Fatal(err)
	}
	// The verdict returns no error, the kernel answers ENOENT asynchronously.
	if err := nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
		t.Fatal(err)
	}
	if received(time.Second) {
		t.Fatal("expected the recreation of the table to drop the query waiting in the queue")
	}
}
