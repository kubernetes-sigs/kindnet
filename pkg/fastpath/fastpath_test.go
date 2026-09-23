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
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netns"
)

func TestFastPathAgent_syncRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

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
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Save the current network namespace
			origns, err := netns.Get()
			if err != nil {
				t.Fatal(err)
			}
			defer origns.Close()

			// Create a new network namespace
			newns, err := netns.New()
			if err != nil {
				t.Fatal(err)
			}
			defer newns.Close()

			if out, err := exec.Command("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1").CombinedOutput(); err != nil {
				t.Fatalf("failed to create veth pair: %v: %s", err, out)
			}

			// A resync must keep the table, its base chain and its flowtable,
			// unregistering a hook drops the packets waiting in every nfqueue
			// of the namespace.
			var handles []string
			for i, devices := range tt.syncs {
				if err := n.syncRules(devices); err != nil {
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
			// Switch back to the original namespace
			netns.Set(origns)
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
		t.Fatalf("nft -a list table error = %v, output: %s", err, string(out))
	}
	return handleRE.FindAllString(string(out), -1)
}
