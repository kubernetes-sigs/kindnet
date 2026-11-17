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

const (
	MRT_BASE    = 200
	MRT_INIT    = MRT_BASE
	MRT_DONE    = MRT_BASE + 1
	MRT_ADD_VIF = MRT_BASE + 2
	MRT_DEL_VIF = MRT_BASE + 3
	MRT_ADD_MFC = MRT_BASE + 4
	MRT_DEL_MFC = MRT_BASE + 5

	MRT6_BASE    = 200
	MRT6_INIT    = MRT6_BASE
	MRT6_DONE    = MRT6_BASE + 1
	MRT6_ADD_MIF = MRT6_BASE + 2
	MRT6_DEL_MIF = MRT6_BASE + 3
	MRT6_ADD_MFC = MRT6_BASE + 4
	MRT6_DEL_MFC = MRT6_BASE + 5

	VIFF_USE_IFINDEX = 0x8
)

// vifctl represents the C `struct vifctl` used in MRT_ADD_VIF/MRT_DEL_VIF.
type vifctl struct {
	vifc_vifi        uint16  // Index of VIF
	vifc_flags       uint8   // VIFF_ flags
	vifc_threshold   uint8   // TTL threshold
	vifc_rate_limit  uint32  // Rate limit
	vifc_lcl_ifindex int32   // Local interface index (using VIFF_USE_IFINDEX)
	vifc_rmt_addr    [4]byte // Remote interface IP address (for tunnels)
}

// mfcctl represents the C `struct mfcctl` used in MRT_ADD_MFC/MRT_DEL_MFC.
type mfcctl struct {
	mfcc_origin   [4]byte  // Source IP address (Unicast)
	mfcc_mcastgrp [4]byte  // Multicast Group IP address
	mfcc_parent   uint16   // Incoming VIF index
	mfcc_ttls     [32]uint8 // TTL to joints/VIFs (index maps to VIF ID; 0 means do not forward, >0 is TTL threshold)
	_             uint16   // Padding to align next fields to 4-byte boundary
	mfcc_pkt_cnt  uint32
	mfcc_byte_cnt uint32
	mfcc_wrong_if uint32
	mfcc_expire   int32
}

// mif6ctl represents the C `struct mif6ctl` used in MRT6_ADD_MIF/MRT6_DEL_MIF.
type mif6ctl struct {
	mif6c_mifi      uint16
	mif6c_flags     uint8
	vifc_threshold  uint8
	mif6c_pifi      uint16
	_               uint16 // padding
	vifc_rate_limit uint32
}

// sockaddr_in6 represents the C `struct sockaddr_in6` used in IPv6 multicast routing structures.
type sockaddr_in6 struct {
	sin6_family   uint16
	sin6_port     uint16
	sin6_flowinfo uint32
	sin6_addr     [16]byte
	sin6_scope_id uint32
}

// mf6cctl represents the C `struct mf6cctl` used in MRT6_ADD_MFC/MRT6_DEL_MFC.
type mf6cctl struct {
	mf6cc_origin   sockaddr_in6
	mf6cc_mcastgrp sockaddr_in6
	mf6cc_parent   uint16
	_              uint16 // padding
	mf6cc_ifset    [8]uint32
}

// igmpmsg represents the C `struct igmpmsg` used for IPv4 multicast routing upcalls.
type igmpmsg struct {
	unused1    uint32
	unused2    uint32
	im_msgtype uint8
	im_mbz     uint8
	im_vif     uint8
	im_vif_hi  uint8
	im_src     [4]byte
	im_dst     [4]byte
}

// mrt6msg represents the C `struct mrt6msg` used for IPv6 multicast routing upcalls.
type mrt6msg struct {
	im6_mbz     uint8
	im6_msgtype uint8
	im6_mif     uint16
	im6_pad     uint32
	im6_src     [16]byte
	im6_dst     [16]byte
}
