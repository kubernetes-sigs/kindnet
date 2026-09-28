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

package network

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"sigs.k8s.io/kindnet/pkg/nstest"
)

const skewTable = "skew"

// skewRuleset is the state a previous version left in the kernel. Every
// rejection scenario sends a transaction that does not fit it.
var skewRuleset = fmt.Sprintf(`
flush ruleset
table inet %s {
	chain base { type filter hook postrouting priority srcnat - 5; policy accept; }
	chain regular { }
	chain refs { type filter hook input priority filter; ip saddr @used accept; }
	set v4 { type ipv4_addr; }
	set iv4 { type ipv4_addr; flags interval; }
	set used { type ipv4_addr; }
}
`, skewTable)

var inet = &nftables.Table{Name: skewTable, Family: nftables.TableFamilyINet}

// TestIsNetlinkRejection_KernelRejections checks that the errors the kernel
// replies with are reported as rejections, and that a rejected transaction
// applies nothing, which is what lets the caller send a different one.
func TestIsNetlinkRejection_KernelRejections(t *testing.T) {
	nstest.ExecInUserns(t, testIsNetlinkRejection_KernelRejections)
}

func testIsNetlinkRejection_KernelRejections(t *testing.T) {
	tests := []struct {
		name string
		// op appends the transaction to the connection.
		op func(t *testing.T, nft *nftables.Conn)
		// errnos the kernel is known to return, it depends on the version.
		errnos []syscall.Errno
	}{
		{
			name: "base chain with another priority",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "base", Table: inet, Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityFilter})
			},
			errnos: []syscall.Errno{unix.EOPNOTSUPP, unix.EEXIST},
		},
		{
			name: "base chain with another hook",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "base", Table: inet, Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 5)})
			},
			errnos: []syscall.Errno{unix.EOPNOTSUPP, unix.EEXIST},
		},
		{
			name: "base chain over a regular chain",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "regular", Table: inet, Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityFilter})
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "set with another key type",
			op: func(t *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				if err := nft.AddSet(&nftables.Set{Name: "v4", Table: inet, KeyType: nftables.TypeIP6Addr}, nil); err != nil {
					t.Fatal(err)
				}
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "set with other flags",
			op: func(t *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				if err := nft.AddSet(&nftables.Set{Name: "iv4", Table: inet, KeyType: nftables.TypeIPAddr}, nil); err != nil {
					t.Fatal(err)
				}
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "delete a set used by a rule",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.DelSet(&nftables.Set{Name: "used", Table: inet})
			},
			errnos: []syscall.Errno{unix.EBUSY},
		},
		{
			name: "rule in a chain that does not exist",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddRule(&nftables.Rule{Table: inet, Chain: &nftables.Chain{Name: "missing"},
					Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
			},
			errnos: []syscall.Errno{unix.ENOENT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadRuleset(t, skewRuleset)
			before := listRuleset(t)

			nft, err := nftables.New()
			if err != nil {
				t.Fatal(err)
			}
			tt.op(t, nft)
			err = nft.Flush()
			if err == nil {
				t.Fatalf("the kernel accepted the transaction, ruleset:\n%s", listRuleset(t))
			}
			if !isAny(err, tt.errnos) {
				t.Errorf("error = %v, want one of %v", err, tt.errnos)
			}
			if !IsNetlinkRejection(err) {
				t.Errorf("IsNetlinkRejection(%v) = false, the kernel rejected the transaction", err)
			}
			if after := listRuleset(t); after != before {
				t.Errorf("the rejected transaction changed the ruleset:\n--- before\n%s\n--- after\n%s", before, after)
			}
		})
	}
}

// TestIsNetlinkRejection_SocketErrors reproduces the errors that come from
// the netlink socket rather than from the kernel reply: the caller gets an
// error and the ruleset may have changed anyway, so a retry must not assume
// the kernel state is the one before the call.
func TestIsNetlinkRejection_SocketErrors(t *testing.T) {
	nstest.ExecInUserns(t, testIsNetlinkRejection_SocketErrors)
}

func testIsNetlinkRejection_SocketErrors(t *testing.T) {
	t.Run("read deadline expired", func(t *testing.T) {
		loadRuleset(t, "flush ruleset")
		nft, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
			return c.SetReadDeadline(time.Now())
		}))
		if err != nil {
			t.Fatal(err)
		}
		nft.AddTable(inet)
		err = nft.Flush()
		if err == nil {
			t.Fatal("Flush() succeeded with an expired read deadline")
		}
		var opErr *netlink.OpError
		if !errors.As(err, &opErr) || !opErr.Timeout() {
			t.Errorf("error = %v, want a netlink timeout", err)
		}
		if IsNetlinkRejection(err) {
			t.Errorf("IsNetlinkRejection(%v) = true, want false", err)
		}
		if out, err := exec.Command("nft", "list", "table", "inet", skewTable).CombinedOutput(); err != nil {
			t.Errorf("the table was not created although the send succeeded: %v: %s", err, out)
		}
	})

	t.Run("send on a closed socket", func(t *testing.T) {
		loadRuleset(t, "flush ruleset")
		nft, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
			return c.Close()
		}))
		if err != nil {
			t.Fatal(err)
		}
		nft.AddTable(inet)
		err = nft.Flush()
		if err == nil {
			t.Fatal("Flush() succeeded on a closed socket")
		}
		if !errors.Is(err, unix.EBADF) {
			t.Errorf("error = %v, want EBADF", err)
		}
		if IsNetlinkRejection(err) {
			t.Errorf("IsNetlinkRejection(%v) = true, want false", err)
		}
		if exec.Command("nft", "list", "table", "inet", skewTable).Run() == nil {
			t.Error("the table was created although the send failed")
		}
	})
}

// TestIsNetlinkRejection_Shapes covers the error shapes without a kernel: a
// rejection can carry the same errno as a failed system call, only the
// wrapping tells them apart.
func TestIsNetlinkRejection_Shapes(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("failed to add Set"),
		unix.ENOMEM,
		&netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", unix.ENOMEM)},
		&netlink.OpError{Op: "send", Err: os.NewSyscallError("sendmsg", unix.EAGAIN)},
		&netlink.OpError{Op: "receive", Err: os.ErrDeadlineExceeded},
	} {
		if IsNetlinkRejection(err) {
			t.Errorf("IsNetlinkRejection(%v) = true, want false", err)
		}
	}
	for _, err := range []error{
		&netlink.OpError{Op: "receive", Err: unix.ENOMEM},
		fmt.Errorf("conn.Receive: %w", errors.Join(&netlink.OpError{Op: "receive", Err: unix.EEXIST}, &netlink.OpError{Op: "receive", Err: unix.EINVAL})),
	} {
		if !IsNetlinkRejection(err) {
			t.Errorf("IsNetlinkRejection(%v) = false, want true", err)
		}
	}
}

func isAny(err error, errnos []syscall.Errno) bool {
	for _, errno := range errnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

func loadRuleset(t *testing.T, ruleset string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v: %s\n%s", err, out, ruleset)
	}
}

func listRuleset(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list ruleset: %v: %s", err, out)
	}
	return string(out)
}
