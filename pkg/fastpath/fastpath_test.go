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
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"sigs.k8s.io/kindnet/pkg/nstest"
)

func TestFastPathAgent_syncRules(t *testing.T) {
	nstest.ExecInUserns(t, testFastPathAgent_syncRules)
}

func testFastPathAgent_syncRules(t *testing.T) {
	tests := []struct {
		name             string
		expectedNftables string
	}{
		{
			name: "simple",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &FastPathAgent{}
			if err := n.syncRules(nil); err != nil {
				t.Fatalf("FastPathAgent.SyncRules() error = %v", err)
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
