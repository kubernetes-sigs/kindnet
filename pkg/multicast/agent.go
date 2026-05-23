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
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

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
}

func NewMulticastAgent() (*MulticastAgent, error) {
	return &MulticastAgent{
		groupToIfaces: make(map[string]map[string]bool),
		activeJoins:   make(map[string]interface{}),
	}, nil
}

func (ma *MulticastAgent) Run(ctx context.Context) error {
	klog.Info("Starting Multicast Agent")

	// Find default upstream interface
	upstream, err := getUpstreamInterface()
	if err != nil {
		klog.Warningf("Could not find upstream interface: %v. Retrying in background...", err)
	} else {
		ma.upstreamIfIndex = upstream.Index
		ma.upstreamName = upstream.Name
		klog.Infof("Using upstream interface: %s (index %d)", upstream.Name, upstream.Index)
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
					ma.upstreamIfIndex = up.Index
					ma.upstreamName = up.Name
				}
				ma.Unlock()
			}
		}
	}()

	// Open the raw packet socket for capturing all packet traffic
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
		return
	}

	// Process Multicast Data from Upstream Interface
	ma.RLock()
	isUpstream := sll.Ifindex == ma.upstreamIfIndex
	ma.RUnlock()

	if isUpstream {
		var dstIP net.IP
		var groupStr string

		if etherType == unix.ETH_P_IP && len(ipPayload) >= 20 {
			dstIP = net.IP(ipPayload[16:20])
			if dstIP.IsMulticast() && !isLinkLocalMulticastIPv4(dstIP) {
				groupStr = dstIP.String()
			}
		} else if etherType == unix.ETH_P_IPV6 && len(ipPayload) >= 40 {
			dstIP = net.IP(ipPayload[24:40])
			if dstIP.IsMulticast() && !isLinkLocalMulticastIPv6(dstIP) {
				groupStr = dstIP.String()
			}
		}

		if groupStr != "" {
			ma.RLock()
			ifaces, exists := ma.groupToIfaces[groupStr]
			if exists && len(ifaces) > 0 {
				// Forward this packet to all interested pod interfaces
				for ifaceName := range ifaces {
					targetIface, err := net.InterfaceByName(ifaceName)
					if err == nil {
						ma.forwardRawPacket(packet, targetIface.Index, etherType)
					}
				}
			}
			ma.RUnlock()
		}
	}
}

func (ma *MulticastAgent) parseAndHandleIGMP(igmpData []byte, ifaceName string) {
	if len(igmpData) < 8 {
		return
	}
	igmpType := igmpData[0]
	groupIP := net.IP(igmpData[4:8])

	switch igmpType {
	case 0x16: // IGMPv2 Membership Report
		ma.joinGroup(groupIP, ifaceName)
	case 0x17: // IGMPv2 Leave Group
		ma.leaveGroup(groupIP, ifaceName)
	case 0x22: // IGMPv3 Membership Report
		// Parse group records
		if len(igmpData) >= 8 {
			numRecords := binary.BigEndian.Uint16(igmpData[6:8])
			offset := 8
			for i := 0; i < int(numRecords); i++ {
				if len(igmpData) < offset+8 {
					break
				}
				recordType := igmpData[offset]
				numSources := binary.BigEndian.Uint16(igmpData[offset+2 : offset+4])
				mcastAddr := net.IP(igmpData[offset+4 : offset+8])

				// Record types: 1 = MODE_IS_INCLUDE, 2 = MODE_IS_EXCLUDE, 3 = CHANGE_TO_INCLUDE_MODE, 4 = CHANGE_TO_EXCLUDE_MODE, 5 = ALLOW_NEW_SOURCES, 6 = BLOCK_OLD_SOURCES
				switch recordType {
				case 1, 2, 3, 4, 5:
					if recordType == 1 && numSources == 0 {
						// INCLUDE with 0 sources is equivalent to leaving the group
						ma.leaveGroup(mcastAddr, ifaceName)
					} else {
						ma.joinGroup(mcastAddr, ifaceName)
					}
				case 6:
					ma.leaveGroup(mcastAddr, ifaceName)
				}
				offset += 8 + int(numSources)*4
			}
		}
	}
}

func (ma *MulticastAgent) parseAndHandleMLD(icmpv6Data []byte, ifaceName string) {
	if len(icmpv6Data) < 8 {
		return
	}
	icmpType := icmpv6Data[0]

	// MLDv1: 131 = Multicast Listener Report, 132 = Multicast Listener Done
	// MLDv2: 143 = Multicast Listener Report v2
	switch icmpType {
	case 131:
		if len(icmpv6Data) >= 24 {
			groupIP := net.IP(icmpv6Data[8:24])
			ma.joinGroup(groupIP, ifaceName)
		}
	case 132:
		if len(icmpv6Data) >= 24 {
			groupIP := net.IP(icmpv6Data[8:24])
			ma.leaveGroup(groupIP, ifaceName)
		}
	case 143:
		if len(icmpv6Data) >= 6 {
			numRecords := binary.BigEndian.Uint16(icmpv6Data[6:8])
			offset := 8
			for i := 0; i < int(numRecords); i++ {
				if len(icmpv6Data) < offset+20 {
					break
				}
				recordType := icmpv6Data[offset]
				numSources := binary.BigEndian.Uint16(icmpv6Data[offset+2 : offset+4])
				mcastAddr := net.IP(icmpv6Data[offset+4 : offset+20])

				switch recordType {
				case 1, 2, 3, 4, 5:
					if recordType == 1 && numSources == 0 {
						ma.leaveGroup(mcastAddr, ifaceName)
					} else {
						ma.joinGroup(mcastAddr, ifaceName)
					}
				case 6:
					ma.leaveGroup(mcastAddr, ifaceName)
				}
				offset += 20 + int(numSources)*16
			}
		}
	}
}

func (ma *MulticastAgent) joinGroup(groupIP net.IP, ifaceName string) {
	groupStr := groupIP.String()
	klog.Infof("Pod interface %s joined multicast group: %s", ifaceName, groupStr)

	ma.Lock()
	defer ma.Unlock()

	if _, exists := ma.groupToIfaces[groupStr]; !exists {
		ma.groupToIfaces[groupStr] = make(map[string]bool)
	}
	ma.groupToIfaces[groupStr][ifaceName] = true

	// Join group on upstream interface if not already done
	if _, active := ma.activeJoins[groupStr]; !active && ma.upstreamIfIndex != 0 {
		ifi, err := net.InterfaceByIndex(ma.upstreamIfIndex)
		if err == nil {
			if groupIP.To4() != nil {
				c, err := net.ListenPacket("udp4", "0.0.0.0:0")
				if err == nil {
					p := ipv4.NewPacketConn(c)
					err = p.JoinGroup(ifi, &net.UDPAddr{IP: groupIP})
					if err == nil {
						ma.activeJoins[groupStr] = c
						klog.Infof("Successfully joined IPv4 group %s on upstream %s", groupStr, ifi.Name)
					} else {
						_ = c.Close()
						klog.Errorf("Error joining IPv4 group %s on upstream: %v", groupStr, err)
					}
				}
			} else {
				c, err := net.ListenPacket("udp6", "[::]:0")
				if err == nil {
					p := ipv6.NewPacketConn(c)
					err = p.JoinGroup(ifi, &net.UDPAddr{IP: groupIP})
					if err == nil {
						ma.activeJoins[groupStr] = c
						klog.Infof("Successfully joined IPv6 group %s on upstream %s", groupStr, ifi.Name)
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
			// Leave group on upstream interface
			if c, active := ma.activeJoins[groupStr]; active {
				if conn, ok := c.(net.PacketConn); ok {
					_ = conn.Close()
				}
				delete(ma.activeJoins, groupStr)
				klog.Infof("Left group %s on upstream interface", groupStr)
			}
		}
	}
}

func (ma *MulticastAgent) forwardRawPacket(packet []byte, targetIfIndex int, etherType uint16) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherType)))
	if err != nil {
		return
	}
	defer func() {
		_ = syscall.Close(fd)
	}()

	broadcastMAC := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  targetIfIndex,
		Hatype:   syscall.ARPHRD_ETHER,
		Pkttype:  syscall.PACKET_OUTGOING,
		Halen:    6,
	}
	copy(addr.Addr[:6], broadcastMAC)

	// Rewrite Ethernet header destination to broadcast
	copy(packet[0:6], broadcastMAC)

	_ = syscall.Sendto(fd, packet, 0, addr)
}

func CleanRules() {
	// Independent agent doesn't install firewall rules in user space mode,
	// so cleanup is a no-op.
}

func getUpstreamInterface() (*net.Interface, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) || r.Dst.IP.Equal(net.IPv6zero) {
			ifi, err := net.InterfaceByIndex(r.LinkIndex)
			if err == nil {
				return ifi, nil
			}
		}
	}
	return nil, fmt.Errorf("default gateway interface not found")
}

func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}

func isLinkLocalMulticastIPv4(ip net.IP) bool {
	return ip[0] == 224 && ip[1] == 0 && ip[2] == 0
}

func isLinkLocalMulticastIPv6(ip net.IP) bool {
	return ip[0] == 0xff && (ip[1]&0x0f) <= 0x02
}
