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
	"encoding/binary"
	"net"
)

// parseAndHandleIGMP parses IPv4 IGMP messages (Join / Leave) and triggers agent group changes.
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

// parseAndHandleMLD parses IPv6 MLD messages (Join / Done / Report v2) and triggers agent group changes.
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
