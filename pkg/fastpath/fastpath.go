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
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kindnet/pkg/network"
)

const (
	tableName         = "kindnet-fastpath"
	kindnetFlowtable  = "kindnet-flowtables"
	kindnetSetDevices = "kindnet-set-devices"
	fastPathChain     = "kindnet-fastpath-chain"
)

// chainPolicyAccept is declared on the base chain so a sync over a chain left
// with another policy resets it, the kernel updates the policy in place.
var chainPolicyAccept = nftables.ChainPolicyAccept

func NewFastpathAgent(packetThresold int) (*FastPathAgent, error) {
	if packetThresold > math.MaxUint32 {
		packetThresold = math.MaxUint32
	}
	return &FastPathAgent{
		packetThresold: uint32(packetThresold),
	}, nil
}

type FastPathAgent struct {
	packetThresold uint32
}

func (ma *FastPathAgent) Run(ctx context.Context) error {
	minInterval := 5 * time.Second
	maxInterval := 1 * time.Minute
	rateLimiter := rate.NewLimiter(rate.Every(minInterval), 1)
	// Resources are published periodically or if there is a netlink notification
	// indicating a new interfaces was added or changed
	nlChannel := make(chan netlink.LinkUpdate)
	doneCh := make(chan struct{})
	defer close(doneCh)
	if err := netlink.LinkSubscribe(nlChannel, doneCh); err != nil {
		klog.Error(err, "error subscribing to netlink interfaces, only syncing periodically", "interval", maxInterval.String())
	}

	currentIf := sets.Set[string]{}
	for {
		err := rateLimiter.Wait(ctx)
		if err != nil {
			klog.Error(err, "unexpected rate limited error trying to get system interfaces")
		}
		ifnames, err := ma.getNodeInterfaces()
		if err != nil {
			klog.Error(err, "failed to list system network interfaces")
		}

		if len(ifnames) > 0 && !ifnames.Equal(currentIf) {
			err := ma.syncRules(ctx, ifnames.UnsortedList())
			if err != nil {
				klog.Error(err, "failed to add network interfaces to the flowtable")
			} else {
				currentIf = ifnames
			}
		}

		select {
		// trigger a reconcile
		case <-nlChannel:
			// drain the channel so we only sync once
			for len(nlChannel) > 0 {
				<-nlChannel
			}
		case <-time.After(maxInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

func (ma *FastPathAgent) getNodeInterfaces() (sets.Set[string], error) {
	ifNames := sets.New[string]()

	links, err := netlink.LinkList()
	if err != nil && !errors.Is(err, unix.EINTR) {
		return ifNames, err
	}

	for _, link := range links {
		klog.V(7).InfoS("Checking network interface", "name", link.Attrs().Name)
		// skip down interfaces
		if link.Attrs().OperState != netlink.OperUp {
			continue
		}
		// skip loopback interfaces
		if link.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}

		klog.V(7).InfoS("Checking network interface", "name", link.Attrs().Name)
		ifNames.Insert(link.Attrs().Name)
	}
	return ifNames, nil
}

func (ma *FastPathAgent) syncRules(ctx context.Context, devices []string) error {
	klog.V(2).Info("Syncing kindnet-fastpath nftables rules")
	logger := klog.FromContext(ctx)

	// Replace the rules in place: the table, its base chain and its flowtable
	// are kept, so their netfilter hooks stay registered. Unregistering a hook
	// makes the kernel drop every packet waiting in any nfqueue of the network
	// namespace.
	// https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
	err := ma.writeRules(devices, false)
	if err == nil {
		return nil
	}
	if !network.IsNetlinkRejection(err) {
		// The kernel reply was not read, the batch may have been committed.
		// The next interface change or periodic sync retries in place again.
		return err
	}
	// The kernel rejected the transaction and applied nothing. A base chain,
	// set or flowtable left by a previous version with another definition can
	// not be updated in place, recreating the table is the only way out. If the
	// error has another cause the second transaction is rejected as well and,
	// again, nothing is applied.
	logger.Info("nftables rules can not be updated in place, recreating the table", "error", err)
	if err := ma.writeRules(devices, true); err != nil {
		return err
	}
	logger.Info("nftables table recreated, any packet waiting in an nfqueue of the namespace was dropped")
	return nil
}

// writeRules sends the whole ruleset in one transaction. With recreate the
// table is deleted and created again in the same transaction, otherwise its
// rules are flushed and the base chain and flowtable kept.
func (ma *FastPathAgent) writeRules(devices []string, recreate bool) error {
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("fastpath failure, can not start nftables:%v", err)
	}

	fastpathTable := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(fastpathTable)
	if recreate {
		nft.DelTable(fastpathTable)
		nft.AddTable(fastpathTable)
	} else {
		nft.FlushTable(fastpathTable)
	}

	devicesSet := &nftables.Set{
		Table:        fastpathTable,
		Name:         kindnetSetDevices,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
	}

	elements := []nftables.SetElement{}
	for _, dev := range devices {
		elements = append(elements, nftables.SetElement{
			Key: ifname(dev),
		})
	}

	// flush table does not touch the sets, delete and recreate it with the new
	// elements. add + delete so the delete succeeds whether or not the set
	// exists; the flush above released the references the rules held on it.
	if err := nft.AddSet(devicesSet, nil); err != nil {
		return fmt.Errorf("failed to add Set %s : %v", devicesSet.Name, err)
	}
	nft.DelSet(devicesSet)
	if err := nft.AddSet(devicesSet, elements); err != nil {
		return fmt.Errorf("failed to add Set %s : %v", devicesSet.Name, err)
	}

	// Adding an existing flowtable registers the devices it does not have yet
	// (Linux 5.13+), the kernel removes the ones that disappear. Deleting it
	// would unregister its hooks like deleting a base chain does.
	flowtable := &nftables.Flowtable{
		Table:    fastpathTable,
		Name:     kindnetFlowtable,
		Devices:  devices,
		Hooknum:  nftables.FlowtableHookIngress,
		Priority: nftables.FlowtablePriorityRef(5),
	}
	nft.AddFlowtable(flowtable)

	chain := nft.AddChain(&nftables.Chain{
		Name:     fastPathChain,
		Table:    fastpathTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle, // before DNAT
		Policy:   &chainPolicyAccept,
	})

	// only offload devices that are being tracked
	// TODO: check if this is really needed, we are using a set in addition
	// to the flowtable.
	nft.AddRule(&nftables.Rule{
		Table: fastpathTable,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, SourceRegister: false, Register: 0x1},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetName: kindnetSetDevices, Invert: true},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	nft.AddRule(&nftables.Rule{
		Table: fastpathTable,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, SourceRegister: false, Register: 0x1},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetName: kindnetSetDevices, Invert: true},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	//  ct packets > packetThresold flow add @kindnet-flowtables counter
	nft.AddRule(&nftables.Rule{
		Table: fastpathTable,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeySTATE, Direction: 0x0},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: 0x1, Register: 0x1, Data: []uint8{0x0, 0x0, 0x0, 0x0}},
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeyPKTS, Direction: 0x0},
			&expr.Cmp{Op: expr.CmpOpGt, Register: 0x1, Data: binaryutil.NativeEndian.PutUint64(uint64(ma.packetThresold))},
			&expr.FlowOffload{Name: kindnetFlowtable},
			&expr.Counter{},
		},
	})

	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create kindnet-fastpath table: %w", err)
	}
	return nil
}

func CleanRules() {
	nft, err := nftables.New()
	if err != nil {
		klog.Infof("fastpath cleanup failure, can not start nftables:%v", err)
		return
	}
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	fastpathTable := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	nft.DelTable(fastpathTable)

	err = nft.Flush()
	if err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}
