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

package fastpath

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"sigs.k8s.io/kindnet/pkg/nstest"
)

// addVethPair adds veth0 and veth1 to the network namespace of the test.
func addVethPair(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1").CombinedOutput(); err != nil {
		t.Fatalf("failed to create veth pair: %v: %s", err, out)
	}
}

func TestFastPathAgent_syncRules(t *testing.T) {
	nstest.ExecInUserns(t, testFastPathAgent_syncRules)
}

func testFastPathAgent_syncRules(t *testing.T) {
	addVethPair(t)
	tests := []struct {
		name string
		// devices passed to each successive sync
		syncs            [][]string
		expectedNftables string
	}{
		{
			name:  "simple",
			syncs: [][]string{nil, nil},
			expectedNftables: `
table inet kindnet-fastpath {
    set kindnet-set-devices {
            type ifname
    }

    flowtable kindnet-flowtables {
            hook ingress priority filter + 5
    }

    chain kindnet-fastpath-chain {
            type filter hook forward priority mangle; policy accept;
            iifname != @kindnet-set-devices return
            oifname != @kindnet-set-devices return
            ct state established ct packets > 0 flow add @kindnet-flowtables counter packets 0 bytes 0
    }
}
`,
		},
		{
			name:  "new device",
			syncs: [][]string{{"veth0"}, {"veth0", "veth1"}},
			expectedNftables: `
table inet kindnet-fastpath {
    set kindnet-set-devices {
            type ifname
            elements = { "veth0",
                         "veth1" }
    }

    flowtable kindnet-flowtables {
            hook ingress priority filter + 5
            devices = { "veth0", "veth1" }
    }

    chain kindnet-fastpath-chain {
            type filter hook forward priority mangle; policy accept;
            iifname != @kindnet-set-devices return
            oifname != @kindnet-set-devices return
            ct state established ct packets > 0 flow add @kindnet-flowtables counter packets 0 bytes 0
    }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &FastPathAgent{}

			// A resync must keep the table, its base chain and its flowtable,
			// unregistering a hook drops the packets waiting in every nfqueue
			// of the namespace.
			var handles []string
			for i, devices := range tt.syncs {
				if err := n.syncRules(t.Context(), devices); err != nil {
					t.Fatalf("FastPathAgent.syncRules(%v) error = %v", devices, err)
				}
				if i == 0 {
					handles = baseHandles(t)
				} else if diff := cmp.Diff(handles, baseHandles(t)); diff != "" {
					t.Errorf("resync recreated the table, its chains or its flowtable (-first +resync):\n%s", diff)
				}
			}

			cmd := exec.Command("nft", "list", "table", "inet", tableName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft list table error = %v", err)
			}
			// nft versions differ on quoting the flowtable devices
			got := strings.ReplaceAll(string(out), `"`, "")
			want := strings.ReplaceAll(tt.expectedNftables, `"`, "")
			if !compareMultilineStringsIgnoreIndentation(got, want) {
				t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, want, cmp.Diff(got, want))
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

// listTable returns the table as nft prints it, without the quotes some nft
// versions put around the flowtable devices.
func listTable(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", tableName).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table error = %v, output: %s", err, string(out))
	}
	return strings.ReplaceAll(string(out), `"`, "")
}

// TestFastPathAgent_RecreateOnlyWhenRejected checks that a sync over a table a
// previous version left behind updates it in place, and recreates it only
// when the kernel refuses the in-place update.
func TestFastPathAgent_RecreateOnlyWhenRejected(t *testing.T) {
	nstest.ExecInUserns(t, testFastPathAgent_RecreateOnlyWhenRejected)
}

func testFastPathAgent_RecreateOnlyWhenRejected(t *testing.T) {
	addVethPair(t)
	n := &FastPathAgent{}
	devices := []string{"veth0", "veth1"}
	ctx := context.Background()

	// leftover writes the table as a previous version could have left it. The
	// objects in override replace the ones with the same name, or are added.
	leftover := func(t *testing.T, override map[string]string) {
		t.Helper()
		objects := []struct{ name, definition string }{
			{kindnetSetDevices, `set kindnet-set-devices { type ifname; elements = { "stale0" } }`},
			{kindnetFlowtable, `flowtable kindnet-flowtables { hook ingress priority filter + 5; devices = { veth0 }; }`},
			{fastPathChain, `chain kindnet-fastpath-chain { type filter hook forward priority mangle; policy accept; }`},
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
			fastPathChain: `chain kindnet-fastpath-chain { type filter hook forward priority mangle; policy drop; }`}},
		{name: "stale regular chain and set are kept", override: map[string]string{
			"old": `chain old { }`, "oldset": `set oldset { type ipv4_addr; }`}},
		{name: "base chain priority differs", recreate: true, override: map[string]string{
			fastPathChain: `chain kindnet-fastpath-chain { type filter hook forward priority filter; policy accept; }`}},
		{name: "base chain exists as regular chain", recreate: true, override: map[string]string{
			fastPathChain: `chain kindnet-fastpath-chain { }`}},
		{name: "set flags differ", recreate: true, override: map[string]string{
			kindnetSetDevices: `set kindnet-set-devices { type ifname; flags constant; }`}},
		{name: "flowtable priority differs", recreate: true, override: map[string]string{
			kindnetFlowtable: `flowtable kindnet-flowtables { hook ingress priority filter + 10; devices = { veth0 }; }`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leftover(t, tt.override)
			before := baseHandles(t)
			beforeTable := tableHandle(t)

			if err := n.syncRules(ctx, devices); err != nil {
				t.Fatalf("syncRules() error = %v", err)
			}
			if recreated := beforeTable != tableHandle(t); recreated != tt.recreate {
				t.Errorf("table recreated = %v, want %v (handles before %v, after %v)", recreated, tt.recreate, before, baseHandles(t))
			}
			if !tt.recreate {
				if diff := cmp.Diff(before, baseHandles(t)); diff != "" {
					t.Errorf("in-place sync recreated the base chain or the flowtable (-leftover +sync):\n%s", diff)
				}
			}

			// Whatever the path, the result is the ruleset of a clean sync,
			// except for stale objects the in-place sync does not remove.
			got := listTable(t)
			CleanRules()
			if err := n.syncRules(ctx, devices); err != nil {
				t.Fatalf("clean syncRules() error = %v", err)
			}
			want := listTable(t)
			if !strings.Contains(tt.name, "stale") && !compareMultilineStringsIgnoreIndentation(got, want) {
				t.Errorf("sync over the leftover table differs from a clean sync (-clean +leftover):\n%s", cmp.Diff(want, got))
			}
			if strings.Contains(got, "stale0") {
				t.Errorf("set elements of the leftover table were kept:\n%s", got)
			}

			// The next sync is in place again.
			before = baseHandles(t)
			if err := n.syncRules(ctx, devices); err != nil {
				t.Fatalf("second syncRules() error = %v", err)
			}
			if diff := cmp.Diff(before, baseHandles(t)); diff != "" {
				t.Errorf("second sync recreated the table, its chain or its flowtable (-first +second):\n%s", diff)
			}
		})
	}
}
