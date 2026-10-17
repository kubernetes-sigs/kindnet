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

package multicast

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

type MulticastAgent struct {
	sync.RWMutex
	// groupToIfaces tracks multicast groups to pod interface names
	groupToIfaces map[string]map[string]bool
	// activeJoins tracks active UDP listeners that keep the upstream multicast membership alive
	activeJoins map[string]interface{}
	// upstreamIfIndex is the interface index of the host's default gateway interface
	upstreamIfIndex int
	upstreamName    string

	// Low-level multicast routing sockets
	mcastSocket4 int
	mcastSocket6 int

	// VIF tracking
	vifMap  map[string]uint16
	vifUsed [32]bool
}

func NewMulticastAgent() (*MulticastAgent, error) {
	return &MulticastAgent{
		groupToIfaces: make(map[string]map[string]bool),
		activeJoins:   make(map[string]interface{}),
		vifMap:        make(map[string]uint16),
	}, nil
}

func (ma *MulticastAgent) initSockets() error {
	// Initialize sysctls first
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("0"), 0644)

	// IPv4 Socket
	fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IGMP)
	if err != nil {
		return fmt.Errorf("failed to open raw IPv4 IGMP socket: %w", err)
	}
	ma.mcastSocket4 = fd4

	// Enable IPv4 multicast routing
	if err := unix.SetsockoptInt(fd4, unix.IPPROTO_IP, MRT_INIT, 1); err != nil {
		_ = syscall.Close(fd4)
		ma.mcastSocket4 = 0
		return fmt.Errorf("failed to initialize IPv4 multicast routing (MRT_INIT): %w", err)
	}

	// IPv6 Socket
	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		klog.Warningf("failed to open raw IPv6 ICMPv6 socket: %v", err)
	} else {
		ma.mcastSocket6 = fd6
		// Enable IPv6 multicast routing
		if err := unix.SetsockoptInt(fd6, unix.IPPROTO_IPV6, MRT6_INIT, 1); err != nil {
			_ = syscall.Close(fd6)
			ma.mcastSocket6 = 0
			klog.Warningf("failed to initialize IPv6 multicast routing (MRT6_INIT): %v", err)
		}
	}
	return nil
}

func (ma *MulticastAgent) cleanupSockets() {
	ma.Lock()
	defer ma.Unlock()

	if ma.mcastSocket4 != 0 {
		_ = unix.SetsockoptInt(ma.mcastSocket4, unix.IPPROTO_IP, MRT_DONE, 0)
		_ = syscall.Close(ma.mcastSocket4)
		ma.mcastSocket4 = 0
	}
	if ma.mcastSocket6 != 0 {
		_ = unix.SetsockoptInt(ma.mcastSocket6, unix.IPPROTO_IPV6, MRT6_DONE, 0)
		_ = syscall.Close(ma.mcastSocket6)
		ma.mcastSocket6 = 0
	}
}

func (ma *MulticastAgent) registerInterface(ifaceName string, ifIndex int) (uint16, error) {
	if idx, exists := ma.vifMap[ifaceName]; exists {
		return idx, nil
	}

	var vifIdx int = -1
	if ifaceName == ma.upstreamName {
		vifIdx = 0
	} else {
		for i := 1; i < 32; i++ {
			if !ma.vifUsed[i] {
				vifIdx = i
				break
			}
		}
	}

	if vifIdx == -1 {
		return 0, fmt.Errorf("no available VIF index for interface %s", ifaceName)
	}

	// Configure sysctl to disable reverse path filtering on the new interface
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifaceName), []byte("0"), 0644)

	// Register with IPv4
	if ma.mcastSocket4 != 0 {
		vif := vifctl{
			vifc_vifi:        uint16(vifIdx),
			vifc_flags:       VIFF_USE_IFINDEX,
			vifc_threshold:   1,
			vifc_rate_limit:  0,
			vifc_lcl_ifindex: int32(ifIndex),
		}
		ptr := unsafe.Pointer(&vif)
		size := unsafe.Sizeof(vif)
		buf := unsafe.Slice((*byte)(ptr), size)
		err := unix.SetsockoptString(ma.mcastSocket4, unix.IPPROTO_IP, MRT_ADD_VIF, string(buf))
		if err != nil {
			klog.Errorf("failed to add IPv4 VIF for %s (vifi %d): %v", ifaceName, vifIdx, err)
		} else {
			klog.Infof("Successfully added IPv4 VIF for %s (vifi %d)", ifaceName, vifIdx)
		}
	}

	// Register with IPv6
	if ma.mcastSocket6 != 0 {
		mif := mif6ctl{
			mif6c_mifi:      uint16(vifIdx),
			mif6c_flags:     0,
			vifc_threshold:  1,
			mif6c_pifi:      uint16(ifIndex),
			vifc_rate_limit: 0,
		}
		ptr := unsafe.Pointer(&mif)
		size := unsafe.Sizeof(mif)
		buf := unsafe.Slice((*byte)(ptr), size)
		err := unix.SetsockoptString(ma.mcastSocket6, unix.IPPROTO_IPV6, MRT6_ADD_MIF, string(buf))
		if err != nil {
			klog.Errorf("failed to add IPv6 MIF for %s (mifi %d): %v", ifaceName, vifIdx, err)
		} else {
			klog.Infof("Successfully added IPv6 MIF for %s (mifi %d)", ifaceName, vifIdx)
		}
	}

	ma.vifMap[ifaceName] = uint16(vifIdx)
	ma.vifUsed[vifIdx] = true
	return uint16(vifIdx), nil
}

func (ma *MulticastAgent) unregisterInterface(ifaceName string) {
	vifIdx, exists := ma.vifMap[ifaceName]
	if !exists {
		return
	}

	// Unregister with IPv4
	if ma.mcastSocket4 != 0 {
		vif := vifctl{
			vifc_vifi: vifIdx,
		}
		ptr := unsafe.Pointer(&vif)
		size := unsafe.Sizeof(vif)
		buf := unsafe.Slice((*byte)(ptr), size)
		_ = unix.SetsockoptString(ma.mcastSocket4, unix.IPPROTO_IP, MRT_DEL_VIF, string(buf))
	}

	// Unregister with IPv6
	if ma.mcastSocket6 != 0 {
		mif := mif6ctl{
			mif6c_mifi: vifIdx,
		}
		ptr := unsafe.Pointer(&mif)
		size := unsafe.Sizeof(mif)
		buf := unsafe.Slice((*byte)(ptr), size)
		_ = unix.SetsockoptString(ma.mcastSocket6, unix.IPPROTO_IPV6, MRT6_DEL_MIF, string(buf))
	}

	delete(ma.vifMap, ifaceName)
	ma.vifUsed[vifIdx] = false
	klog.Infof("Successfully removed VIF/MIF for %s (index %d)", ifaceName, vifIdx)
}

func (ma *MulticastAgent) addMfc(src, grp net.IP, parentVif uint16, outgoingVifs []uint16) error {
	if ma.mcastSocket4 == 0 {
		return fmt.Errorf("IPv4 multicast socket not initialized")
	}

	var mfc mfcctl
	copy(mfc.mfcc_origin[:], src.To4())
	copy(mfc.mfcc_mcastgrp[:], grp.To4())
	mfc.mfcc_parent = parentVif

	for i := range mfc.mfcc_ttls {
		mfc.mfcc_ttls[i] = 0
	}
	for _, vif := range outgoingVifs {
		if vif < 32 {
			mfc.mfcc_ttls[vif] = 1
		}
	}

	ptr := unsafe.Pointer(&mfc)
	size := unsafe.Sizeof(mfc)
	buf := unsafe.Slice((*byte)(ptr), size)

	err := unix.SetsockoptString(ma.mcastSocket4, unix.IPPROTO_IP, MRT_ADD_MFC, string(buf))
	if err != nil {
		return fmt.Errorf("failed to add IPv4 MFC entry: %w", err)
	}
	klog.V(2).Infof("Successfully added IPv4 MFC entry for (%s, %s) parent VIF %d", src, grp, parentVif)
	return nil
}

func (ma *MulticastAgent) addMfc6(src, grp net.IP, parentMif uint16, outgoingMifs []uint16) error {
	if ma.mcastSocket6 == 0 {
		return fmt.Errorf("IPv6 multicast socket not initialized")
	}

	var mfc mf6cctl
	mfc.mf6cc_origin.sin6_family = unix.AF_INET6
	copy(mfc.mf6cc_origin.sin6_addr[:], src.To16())
	mfc.mf6cc_mcastgrp.sin6_family = unix.AF_INET6
	copy(mfc.mf6cc_mcastgrp.sin6_addr[:], grp.To16())
	mfc.mf6cc_parent = parentMif

	for _, mif := range outgoingMifs {
		if mif < 256 {
			word := mif / 32
			bit := mif % 32
			mfc.mf6cc_ifset[word] |= (1 << bit)
		}
	}

	ptr := unsafe.Pointer(&mfc)
	size := unsafe.Sizeof(mfc)
	buf := unsafe.Slice((*byte)(ptr), size)

	err := unix.SetsockoptString(ma.mcastSocket6, unix.IPPROTO_IPV6, MRT6_ADD_MFC, string(buf))
	if err != nil {
		return fmt.Errorf("failed to add IPv6 MFC entry: %w", err)
	}
	klog.V(2).Infof("Successfully added IPv6 MFC entry for (%s, %s) parent MIF %d", src, grp, parentMif)
	return nil
}

func (ma *MulticastAgent) deleteMfc(src, grp net.IP) error {
	if ma.mcastSocket4 == 0 {
		return nil
	}
	var mfc mfcctl
	copy(mfc.mfcc_origin[:], src.To4())
	copy(mfc.mfcc_mcastgrp[:], grp.To4())

	ptr := unsafe.Pointer(&mfc)
	size := unsafe.Sizeof(mfc)
	buf := unsafe.Slice((*byte)(ptr), size)

	_ = unix.SetsockoptString(ma.mcastSocket4, unix.IPPROTO_IP, MRT_DEL_MFC, string(buf))
	return nil
}

func (ma *MulticastAgent) deleteMfc6(src, grp net.IP) error {
	if ma.mcastSocket6 == 0 {
		return nil
	}
	var mfc mf6cctl
	mfc.mf6cc_origin.sin6_family = unix.AF_INET6
	copy(mfc.mf6cc_origin.sin6_addr[:], src.To16())
	mfc.mf6cc_mcastgrp.sin6_family = unix.AF_INET6
	copy(mfc.mf6cc_mcastgrp.sin6_addr[:], grp.To16())

	ptr := unsafe.Pointer(&mfc)
	size := unsafe.Sizeof(mfc)
	buf := unsafe.Slice((*byte)(ptr), size)

	_ = unix.SetsockoptString(ma.mcastSocket6, unix.IPPROTO_IPV6, MRT6_DEL_MFC, string(buf))
	return nil
}

func (ma *MulticastAgent) handleNoCacheIPv4(src, grp net.IP, parentVif uint16) {
	groupStr := grp.String()
	ma.RLock()
	ifaces, exists := ma.groupToIfaces[groupStr]
	if !exists || len(ifaces) == 0 {
		ma.RUnlock()
		return
	}

	outgoingVifs := make([]uint16, 0, len(ifaces))
	for ifaceName := range ifaces {
		if vif, registered := ma.vifMap[ifaceName]; registered {
			outgoingVifs = append(outgoingVifs, vif)
		}
	}
	ma.RUnlock()

	if len(outgoingVifs) > 0 {
		_ = ma.addMfc(src, grp, parentVif, outgoingVifs)
	}
}

func (ma *MulticastAgent) handleNoCacheIPv6(src, grp net.IP, parentMif uint16) {
	groupStr := grp.String()
	ma.RLock()
	ifaces, exists := ma.groupToIfaces[groupStr]
	if !exists || len(ifaces) == 0 {
		ma.RUnlock()
		return
	}

	outgoingMifs := make([]uint16, 0, len(ifaces))
	for ifaceName := range ifaces {
		if mif, registered := ma.vifMap[ifaceName]; registered {
			outgoingMifs = append(outgoingMifs, mif)
		}
	}
	ma.RUnlock()

	if len(outgoingMifs) > 0 {
		_ = ma.addMfc6(src, grp, parentMif, outgoingMifs)
	}
}

func (ma *MulticastAgent) Run(ctx context.Context) error {
	klog.Info("Starting Multicast Agent")

	// Initialize multicast routing sockets
	if err := ma.initSockets(); err != nil {
		return fmt.Errorf("failed to initialize multicast routing sockets: %w", err)
	}
	defer ma.cleanupSockets()

	// Find default upstream interface
	upstream, err := getUpstreamInterface()
	if err != nil {
		klog.Warningf("Could not find upstream interface: %v. Retrying in background...", err)
	} else {
		ma.Lock()
		ma.upstreamIfIndex = upstream.Index
		ma.upstreamName = upstream.Name
		ma.Unlock()
		klog.Infof("Using upstream interface: %s (index %d)", upstream.Name, upstream.Index)
		_, _ = ma.registerInterface(upstream.Name, upstream.Index)
	}

	// Set up netlink subscriber to monitor interface changes
	nlChannel := make(chan netlink.LinkUpdate)
	doneCh := make(chan struct{})
	defer close(doneCh)
	if err := netlink.LinkSubscribe(nlChannel, doneCh); err != nil {
		klog.Errorf("Error subscribing to netlink interfaces: %v", err)
	}

	// Periodically reconcile upstream interface in case default route changes
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-nlChannel:
			case <-ticker.C:
			}
			up, err := getUpstreamInterface()
			if err == nil {
				ma.Lock()
				if ma.upstreamIfIndex != up.Index {
					klog.Infof("Upstream interface changed from %s to %s", ma.upstreamName, up.Name)
					ma.unregisterInterface(ma.upstreamName)
					ma.upstreamIfIndex = up.Index
					ma.upstreamName = up.Name
					_, _ = ma.registerInterface(up.Name, up.Index)
				}
				ma.Unlock()
			}
		}
	}()

	// Read IPv4 upcalls
	go func() {
		if ma.mcastSocket4 == 0 {
			return
		}
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := syscall.Read(ma.mcastSocket4, buf)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				klog.Errorf("Error reading from IPv4 multicast socket: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if n >= 20 {
				var msg igmpmsg
				ptr := unsafe.Pointer(&buf[0])
				msg = *(*igmpmsg)(ptr)
				if msg.im_msgtype == 1 { // IGMPMSG_NOCACHE
					src := net.IP(msg.im_src[:])
					grp := net.IP(msg.im_dst[:])
					ma.handleNoCacheIPv4(src, grp, uint16(msg.im_vif))
				}
			}
		}
	}()

	// Read IPv6 upcalls
	go func() {
		if ma.mcastSocket6 == 0 {
			return
		}
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := syscall.Read(ma.mcastSocket6, buf)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				klog.Errorf("Error reading from IPv6 multicast socket: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if n >= 40 {
				var msg mrt6msg
				ptr := unsafe.Pointer(&buf[0])
				msg = *(*mrt6msg)(ptr)
				if msg.im6_msgtype == 1 { // MRT6MSG_NOCACHE
					src := net.IP(msg.im6_src[:])
					grp := net.IP(msg.im6_dst[:])
					ma.handleNoCacheIPv6(src, grp, msg.im6_mif)
				}
			}
		}
	}()

	// Open the raw packet socket for capturing Pod IGMP/MLD reports
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("failed to open raw packet socket: %w", err)
	}
	defer func() {
		_ = syscall.Close(fd)
	}()

	// Set non-blocking mode so we can poll or easily close
	if err := syscall.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("failed to set socket non-blocking: %w", err)
	}

	// Packet parsing loop
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			klog.Errorf("Error reading from raw socket: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		sll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok {
			continue
		}

		ma.handlePacket(buf[:n], sll)
	}
}

func (ma *MulticastAgent) handlePacket(packet []byte, sll *syscall.SockaddrLinklayer) {
	// Resolve interface name
	iface, err := net.InterfaceByIndex(sll.Ifindex)
	if err != nil {
		return
	}

	isPodIface := strings.HasPrefix(iface.Name, "knet")

	// Ethernet Header parsing: minimum 14 bytes
	if len(packet) < 14 {
		return
	}

	etherType := binary.BigEndian.Uint16(packet[12:14])
	ipPayload := packet[14:]

	// Process IGMP / MLD Reports from Pods
	if isPodIface {
		if etherType == unix.ETH_P_IP && len(ipPayload) >= 20 { // IPv4
			proto := ipPayload[9]
			if proto == 2 { // IGMP
				ipHeaderLen := int(ipPayload[0]&0x0F) * 4
				if len(ipPayload) >= ipHeaderLen+8 {
					ma.parseAndHandleIGMP(ipPayload[ipHeaderLen:], iface.Name)
				}
			}
		} else if etherType == unix.ETH_P_IPV6 && len(ipPayload) >= 40 { // IPv6
			nextHeader := ipPayload[6]
			payload := ipPayload[40:]
			if nextHeader == 58 { // ICMPv6
				ma.parseAndHandleMLD(payload, iface.Name)
			}
		}
	}
}

func (ma *MulticastAgent) joinGroup(groupIP net.IP, ifaceName string) {
	groupStr := groupIP.String()
	klog.Infof("Pod interface %s joined multicast group: %s", ifaceName, groupStr)

	ma.Lock()
	defer ma.Unlock()

	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		klog.Warningf("Warning: interface %s not found on system: %v", ifaceName, err)
	} else {
		_, err = ma.registerInterface(ifaceName, ifi.Index)
		if err != nil {
			klog.Errorf("Error registering interface %s: %v", ifaceName, err)
		}
	}

	if _, exists := ma.groupToIfaces[groupStr]; !exists {
		ma.groupToIfaces[groupStr] = make(map[string]bool)
	}
	ma.groupToIfaces[groupStr][ifaceName] = true

	if ma.upstreamIfIndex != 0 && ma.upstreamName != "" {
		_, _ = ma.registerInterface(ma.upstreamName, ma.upstreamIfIndex)
	}

	// Join group on upstream interface
	if _, active := ma.activeJoins[groupStr]; !active && ma.upstreamIfIndex != 0 {
		ifiUp, err := net.InterfaceByIndex(ma.upstreamIfIndex)
		if err == nil {
			if groupIP.To4() != nil {
				c, err := net.ListenPacket("udp4", "0.0.0.0:0")
				if err == nil {
					p := ipv4.NewPacketConn(c)
					err = p.JoinGroup(ifiUp, &net.UDPAddr{IP: groupIP})
					if err == nil {
						ma.activeJoins[groupStr] = c
						klog.Infof("Successfully joined IPv4 group %s on upstream %s", groupStr, ifiUp.Name)
					} else {
						_ = c.Close()
						klog.Errorf("Error joining IPv4 group %s on upstream: %v", groupStr, err)
					}
				}
			} else {
				c, err := net.ListenPacket("udp6", "[::]:0")
				if err == nil {
					p := ipv6.NewPacketConn(c)
					err = p.JoinGroup(ifiUp, &net.UDPAddr{IP: groupIP})
					if err == nil {
						ma.activeJoins[groupStr] = c
						klog.Infof("Successfully joined IPv6 group %s on upstream %s", groupStr, ifiUp.Name)
					} else {
						_ = c.Close()
						klog.Errorf("Error joining IPv6 group %s on upstream: %v", groupStr, err)
					}
				}
			}
		}
	}
}

func (ma *MulticastAgent) leaveGroup(groupIP net.IP, ifaceName string) {
	groupStr := groupIP.String()
	klog.Infof("Pod interface %s left multicast group: %s", ifaceName, groupStr)

	ma.Lock()
	defer ma.Unlock()

	if ifaces, exists := ma.groupToIfaces[groupStr]; exists {
		delete(ifaces, ifaceName)
		if len(ifaces) == 0 {
			delete(ma.groupToIfaces, groupStr)
			if c, active := ma.activeJoins[groupStr]; active {
				if conn, ok := c.(net.PacketConn); ok {
					_ = conn.Close()
				}
				delete(ma.activeJoins, groupStr)
				klog.Infof("Left group %s on upstream interface", groupStr)
			}
		}
	}

	inUse := false
	for _, ifaces := range ma.groupToIfaces {
		if ifaces[ifaceName] {
			inUse = true
			break
		}
	}
	if !inUse {
		ma.unregisterInterface(ifaceName)
	}
}

func CleanRules() {
	// Independent agent doesn't install firewall rules, so cleanup is a no-op.
}

func getUpstreamInterface() (*net.Interface, error) {
	filter := &netlink.Route{
		Table: unix.RT_TABLE_MAIN,
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	minMetricV4 := math.MaxInt32
	minMetricV6 := math.MaxInt32

	var bestIfaceV4 *net.Interface
	var bestIfaceV6 *net.Interface

	for _, r := range routes {
		if r.Family != netlink.FAMILY_V4 && r.Family != netlink.FAMILY_V6 {
			continue
		}

		// Identify default route: Dst is nil, or Dst is 0.0.0.0/0 or ::/0
		if r.Dst != nil {
			ones, bits := r.Dst.Mask.Size()
			if !r.Dst.IP.IsUnspecified() || ones != 0 || (bits != 32 && bits != 128) {
				continue
			}
		}

		metric := r.Priority

		// Gather link indices
		var linkIndices []int
		if len(r.MultiPath) > 0 {
			for _, nh := range r.MultiPath {
				linkIndices = append(linkIndices, nh.LinkIndex)
			}
		} else {
			linkIndices = append(linkIndices, r.LinkIndex)
		}

		for _, linkIndex := range linkIndices {
			ifi, err := net.InterfaceByIndex(linkIndex)
			if err != nil {
				continue
			}

			if r.Family == netlink.FAMILY_V4 {
				if int(metric) < minMetricV4 {
					minMetricV4 = int(metric)
					bestIfaceV4 = ifi
				}
			} else {
				if int(metric) < minMetricV6 {
					minMetricV6 = int(metric)
					bestIfaceV6 = ifi
				}
			}
		}
	}

	if bestIfaceV4 != nil {
		return bestIfaceV4, nil
	}
	if bestIfaceV6 != nil {
		return bestIfaceV6, nil
	}

	return nil, fmt.Errorf("default gateway interface not found")
}

func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}
