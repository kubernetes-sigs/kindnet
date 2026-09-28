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

package nat64

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"sigs.k8s.io/kindnet/pkg/nstest"
)

func TestNAT64Agent_SyncRules(t *testing.T) {
	nstest.ExecInUserns(t, testNAT64Agent_SyncRules)
}

func testNAT64Agent_SyncRules(t *testing.T) {
	tests := []struct {
		name             string
		expectedNftables string
	}{
		{
			name: "simple",
			expectedNftables: `table ip6 kindnet-nat64 {
        chain prerouting {
                type filter hook prerouting priority raw - 10; policy accept;
                meta mark 0x0000000e return
                ip6 daddr 64:ff9b::/96 meta l4proto udp tproxy to [::1]:60693 meta mark set 0x0000000d notrack accept
                ip6 daddr 64:ff9b::/96 meta l4proto tcp tproxy to [::1]:45217 meta mark set 0x0000000d notrack accept
                meta mark 0x0000000d drop
        }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &NAT64Agent{
				udpProxyPort: 60693,
				tcpProxyPort: 45217,
			}

			if err := n.SyncRules(context.Background()); err != nil {
				t.Fatalf("NAT64Agent.SyncRules() error = %v", err)
			}

			cmd := exec.Command("nft", "list", "table", "ip6", tableName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft list table error = %v", err)
			}
			got := string(out)
			if !compareMultilineStringsIgnoreIndentation(got, tt.expectedNftables) {
				t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, tt.expectedNftables, cmp.Diff(got, tt.expectedNftables))
			}
			CleanRules()
			cmd = exec.Command("nft", "list", "table", "ip6", tableName)
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
