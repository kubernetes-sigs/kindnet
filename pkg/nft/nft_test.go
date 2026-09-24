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

package nft

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// These tests pin the kernel behaviour the package relies on, they need root
// and run each in its own network namespace.

const (
	tableName = "nft-test"
	udpPort   = 12345
	queueNum  = 200
)

// enterNetns runs the rest of the test in a new network namespace.
func enterNetns(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}
	runtime.LockOSThread()
	origns, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	newns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netns.Set(origns)
		newns.Close()
		origns.Close()
		runtime.UnlockOSThread()
	})
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

var handleRE = regexp.MustCompile(`(?m)^\s*(?:table|chain|flowtable) .* # handle \d+$`)

// handles returns the table, chain and flowtable lines of the table with their
// kernel handles, which change when the object is deleted and created again.
func handles(t *testing.T) []string {
	t.Helper()
	return handleRE.FindAllString(run(t, "nft", "-a", "list", "table", "inet", tableName), -1)
}

func newConn(t *testing.T) *nftables.Conn {
	t.Helper()
	tx, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func outputChain(table *nftables.Table) *nftables.Chain {
	return &nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityRaw,
	}
}

// udpQueueRule queues the UDP packets to udpPort, without bypass so they wait
// for a verdict.
func udpQueueRule(table *nftables.Table, chain *nftables.Chain) *nftables.Rule {
	return &nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(udpPort)},
		&expr.Queue{Num: queueNum},
	}}
}

// daddrInSetRule accepts the IPv4 packets whose destination is in the set.
func daddrInSetRule(table *nftables.Table, chain *nftables.Chain, set *nftables.Set) *nftables.Rule {
	return &nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
}

func addrElements(addrs ...string) []nftables.SetElement {
	var elements []nftables.SetElement
	for _, a := range addrs {
		elements = append(elements, nftables.SetElement{Key: netip.MustParseAddr(a).AsSlice()})
	}
	return elements
}

// intervalElements returns the IPv4 prefixes as the [first, next) intervals
// an interval set expects.
func intervalElements(cidrs ...string) []nftables.SetElement {
	var elements []nftables.SetElement
	for _, c := range cidrs {
		p := netip.MustParsePrefix(c).Masked()
		first := p.Addr().As4()
		next := binary.BigEndian.Uint32(first[:]) + 1<<(32-p.Bits())
		elements = append(elements,
			nftables.SetElement{Key: first[:]},
			nftables.SetElement{Key: binary.BigEndian.AppendUint32(nil, next), IntervalEnd: true},
		)
	}
	return elements
}

// TestTable_Resync checks that syncing the same ruleset again keeps the table
// and its base chain and does not duplicate the rules.
func TestTable_Resync(t *testing.T) {
	enterNetns(t)
	table := NewTable(tableName, nftables.TableFamilyINet)
	sync := func() {
		t.Helper()
		tx := newConn(t)
		tb := table.Begin(tx)
		chain := tx.AddChain(outputChain(tb))
		tx.AddRule(udpQueueRule(tb, chain))
		if err := table.Commit(tx); err != nil {
			t.Fatalf("Commit() error = %v", err)
		}
	}

	sync()
	before := handles(t)
	for range 3 {
		sync()
	}
	if diff := cmp.Diff(before, handles(t)); diff != "" {
		t.Errorf("resync recreated the table or its chain (-first +resync):\n%s", diff)
	}
	out := run(t, "nft", "list", "table", "inet", tableName)
	if n := strings.Count(out, "udp dport 12345 queue"); n != 1 {
		t.Errorf("expected the rule once, found it %d times:\n%s", n, out)
	}
}

// TestReplaceSet checks that the elements of hash and interval sets are
// replaced on resync while the rules keep referencing them.
func TestReplaceSet(t *testing.T) {
	enterNetns(t)
	table := NewTable(tableName, nftables.TableFamilyINet)
	hash := &nftables.Set{Table: table.Table, Name: "hash", KeyType: nftables.TypeIPAddr}
	interval := &nftables.Set{Table: table.Table, Name: "interval", KeyType: nftables.TypeIPAddr, Interval: true, AutoMerge: true}
	sync := func(addrs, cidrs []string) {
		t.Helper()
		tx := newConn(t)
		tb := table.Begin(tx)
		if err := ReplaceSet(tx, hash, addrElements(addrs...)); err != nil {
			t.Fatalf("ReplaceSet(%s) error = %v", hash.Name, err)
		}
		if err := ReplaceSet(tx, interval, intervalElements(cidrs...)); err != nil {
			t.Fatalf("ReplaceSet(%s) error = %v", interval.Name, err)
		}
		chain := tx.AddChain(outputChain(tb))
		tx.AddRule(daddrInSetRule(tb, chain, hash))
		tx.AddRule(daddrInSetRule(tb, chain, interval))
		if err := table.Commit(tx); err != nil {
			t.Fatalf("Commit() error = %v", err)
		}
	}

	sync([]string{"10.0.0.1", "10.0.0.2"}, []string{"10.1.0.0/24", "10.2.0.0/24"})
	before := handles(t)
	sync([]string{"10.0.0.2", "10.0.0.3"}, []string{"10.2.0.0/24", "10.3.0.0/16"})
	if diff := cmp.Diff(before, handles(t)); diff != "" {
		t.Errorf("replacing the sets recreated the table or its chain (-first +resync):\n%s", diff)
	}

	out := run(t, "nft", "list", "table", "inet", tableName)
	for _, want := range []string{"10.0.0.2", "10.0.0.3", "10.2.0.0/24", "10.3.0.0/16", "ip daddr @hash accept", "ip daddr @interval accept"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing after the resync:\n%s", want, out)
		}
	}
	for _, stale := range []string{"10.0.0.1", "10.1.0.0/24"} {
		if strings.Contains(out, stale) {
			t.Errorf("stale element %q left after the resync:\n%s", stale, out)
		}
	}
}

// TestTable_FirstCommitRecreates checks that the first sync of a Table
// replaces whatever a previous version left, including a base chain with
// another priority that can not be updated in place, and that later syncs
// keep the table.
func TestTable_FirstCommitRecreates(t *testing.T) {
	enterNetns(t)
	// leftover creates the table as an older version could have left it.
	leftover := func() {
		t.Helper()
		tx := newConn(t)
		old := tx.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet})
		chain := outputChain(old)
		chain.Priority = nftables.ChainPriorityFilter
		tx.AddChain(chain)
		tx.AddChain(&nftables.Chain{Name: "stale", Table: old})
		if err := tx.AddSet(&nftables.Set{Table: old, Name: "stale", KeyType: nftables.TypeIPAddr}, nil); err != nil {
			t.Fatal(err)
		}
		if err := tx.Flush(); err != nil {
			t.Fatalf("failed to create the leftover table: %v", err)
		}
	}
	sync := func(table *Table) error {
		tx := newConn(t)
		tb := table.Begin(tx)
		chain := tx.AddChain(outputChain(tb))
		tx.AddRule(udpQueueRule(tb, chain))
		return table.Commit(tx)
	}

	leftover()
	table := NewTable(tableName, nftables.TableFamilyINet)
	if err := sync(table); err != nil {
		t.Fatalf("first sync over the leftover table error = %v", err)
	}
	out := run(t, "nft", "list", "table", "inet", tableName)
	if !strings.Contains(out, "priority raw") || strings.Contains(out, "stale") {
		t.Errorf("first sync did not replace the leftover table:\n%s", out)
	}
	before := handles(t)
	if err := sync(table); err != nil {
		t.Fatalf("second sync error = %v", err)
	}
	if diff := cmp.Diff(before, handles(t)); diff != "" {
		t.Errorf("second sync recreated the table or its chain (-first +second):\n%s", diff)
	}

	// Without the recreation the transaction fails, the hook of a base chain
	// can not be changed.
	tx := newConn(t)
	tx.DelTable(table.Table)
	if err := tx.Flush(); err != nil {
		t.Fatal(err)
	}
	leftover()
	table = NewTable(tableName, nftables.TableFamilyINet)
	table.recreated = true
	if err := sync(table); err == nil {
		t.Error("sync over a base chain with another priority succeeded without recreating the table")
	}
}

// TestTable_KeepsQueuedPackets checks that a packet waiting in an nfqueue for
// its verdict survives a resync, and that it does not survive the recreation
// of the table, which unregisters the hook of its base chain.
func TestTable_KeepsQueuedPackets(t *testing.T) {
	enterNetns(t)
	run(t, "ip", "link", "set", "lo", "up")
	table := NewTable(tableName, nftables.TableFamilyINet)
	sync := func() {
		t.Helper()
		tx := newConn(t)
		tb := table.Begin(tx)
		chain := tx.AddChain(outputChain(tb))
		tx.AddRule(udpQueueRule(tb, chain))
		if err := table.Commit(tx); err != nil {
			t.Fatalf("Commit() error = %v", err)
		}
	}
	sync()

	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 128,
		MaxQueueLen:  64,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	queued := make(chan uint32, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The verdict is not set here, the packet waits in the queue.
	err = nf.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int { queued <- *a.PacketID; return 0 },
		func(error) int { return 0 })
	if err != nil {
		t.Fatal(err)
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpPort}
	server, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// sendAndHold sends a packet and returns its id once it waits in the queue.
	sendAndHold := func() uint32 {
		t.Helper()
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		select {
		case id := <-queued:
			return id
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the packet to reach the queue")
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
	sync()
	if err := nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
		t.Fatal(err)
	}
	if !received(5 * time.Second) {
		t.Fatal("the packet waiting in the queue was dropped by the resync")
	}

	// add + delete + add, what the agents did before.
	id = sendAndHold()
	tx := newConn(t)
	tx.AddTable(table.Table)
	tx.DelTable(table.Table)
	tx.AddTable(table.Table)
	chain := tx.AddChain(outputChain(table.Table))
	tx.AddRule(udpQueueRule(table.Table, chain))
	if err := tx.Flush(); err != nil {
		t.Fatal(err)
	}
	// The verdict returns no error, the kernel answers ENOENT asynchronously.
	if err := nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
		t.Fatal(err)
	}
	if received(time.Second) {
		t.Fatal("expected the recreation of the table to drop the packet waiting in the queue")
	}
}

// TestTable_Flowtable checks that adding a device to an existing flowtable
// does not recreate it.
func TestTable_Flowtable(t *testing.T) {
	enterNetns(t)
	run(t, "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
	table := NewTable(tableName, nftables.TableFamilyINet)
	sync := func(devices ...string) {
		t.Helper()
		tx := newConn(t)
		tb := table.Begin(tx)
		tx.AddFlowtable(&nftables.Flowtable{Table: tb, Name: "ft", Devices: devices})
		chain := tx.AddChain(&nftables.Chain{
			Name:     "forward",
			Table:    tb,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
		})
		tx.AddRule(&nftables.Rule{Table: tb, Chain: chain, Exprs: []expr.Any{&expr.FlowOffload{Name: "ft"}}})
		if err := table.Commit(tx); err != nil {
			t.Fatalf("Commit(%v) error = %v", devices, err)
		}
	}

	sync("veth0")
	before := handles(t)
	sync("veth0", "veth1")
	if diff := cmp.Diff(before, handles(t)); diff != "" {
		t.Errorf("adding a device recreated the table, its chain or its flowtable (-first +resync):\n%s", diff)
	}
	out := run(t, "nft", "list", "flowtable", "inet", tableName, "ft")
	for _, dev := range []string{"veth0", "veth1"} {
		if !strings.Contains(out, dev) {
			t.Errorf("device %s missing from the flowtable:\n%s", dev, out)
		}
	}
}
