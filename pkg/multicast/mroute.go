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
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MulticastRouter handles low-level kernel multicast routing using setsockopt.
type MulticastRouter struct {
	fd int
}

// NewMulticastRouter creates a raw socket and registers it as the multicast router.
func NewMulticastRouter() (*MulticastRouter, error) {
	// Ensure general IPv4 forward/all.rp_filter sysctls are set correctly for routing
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("0"), 0644)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_IGMP)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw IGMP socket: %w", err)
	}

	// Enable multicast routing in the kernel
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, MRT_INIT, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("failed to initialize multicast routing (MRT_INIT): %w", err)
	}

	return &MulticastRouter{fd: fd}, nil
}

// Close deinitializes multicast routing and closes the routing socket.
func (mr *MulticastRouter) Close() error {
	if mr.fd == 0 {
		return nil
	}
	// Disable multicast routing
	_ = unix.SetsockoptInt(mr.fd, unix.IPPROTO_IP, MRT_DONE, 0)
	err := syscall.Close(mr.fd)
	mr.fd = 0
	return err
}

// RegisterInterface registers a physical or virtual network interface as a VIF.
func (mr *MulticastRouter) RegisterInterface(ifaceName string, vifIdx uint16) error {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// Disable Reverse Path filtering on this interface to avoid dropping multicast packets
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifaceName), []byte("0"), 0644)

	vif := vifctl{
		vifc_vifi:      vifIdx,
		vifc_flags:     VIFF_USE_IFINDEX,
		vifc_threshold: 1,
		vifc_rate_limit: 0,
	}
	// Set local interface index when VIFF_USE_IFINDEX is enabled
	*(*int32)(unsafe.Pointer(&vif.vifc_lcl_ifindex)) = int32(ifi.Index)

	ptr := unsafe.Pointer(&vif)
	size := unsafe.Sizeof(vif)
	buf := unsafe.Slice((*byte)(ptr), size)

	err = unix.SetsockoptString(mr.fd, unix.IPPROTO_IP, MRT_ADD_VIF, string(buf))
	if err != nil {
		return fmt.Errorf("failed to add VIF %d for interface %s: %w", vifIdx, ifaceName, err)
	}

	return nil
}

// UnregisterInterface removes a VIF from the multicast routing engine.
func (mr *MulticastRouter) UnregisterInterface(vifIdx uint16) error {
	vif := vifctl{
		vifc_vifi: vifIdx,
	}

	ptr := unsafe.Pointer(&vif)
	size := unsafe.Sizeof(vif)
	buf := unsafe.Slice((*byte)(ptr), size)

	err := unix.SetsockoptString(mr.fd, unix.IPPROTO_IP, MRT_DEL_VIF, string(buf))
	if err != nil {
		return fmt.Errorf("failed to delete VIF %d: %w", vifIdx, err)
	}

	return nil
}

// AddMfc adds a Multicast Forwarding Cache (MFC) entry to the kernel.
func (mr *MulticastRouter) AddMfc(src, grp net.IP, parentVif uint16, outgoingVifs []uint16) error {
	var mfc mfcctl
	copy(mfc.mfcc_origin[:], src.To4())
	copy(mfc.mfcc_mcastgrp[:], grp.To4())
	mfc.mfcc_parent = parentVif

	// Initialize all TTLs to 0 (do not forward)
	for i := range mfc.mfcc_ttls {
		mfc.mfcc_ttls[i] = 0
	}
	// Set TTL to 1 for outgoing interfaces to enable forwarding
	for _, vif := range outgoingVifs {
		if vif < 32 {
			mfc.mfcc_ttls[vif] = 1
		}
	}

	ptr := unsafe.Pointer(&mfc)
	size := unsafe.Sizeof(mfc)
	buf := unsafe.Slice((*byte)(ptr), size)

	err := unix.SetsockoptString(mr.fd, unix.IPPROTO_IP, MRT_ADD_MFC, string(buf))
	if err != nil {
		return fmt.Errorf("failed to add MFC entry for (%s, %s) via parent VIF %d: %w", src, grp, parentVif, err)
	}

	return nil
}

// DeleteMfc removes an MFC entry from the kernel.
func (mr *MulticastRouter) DeleteMfc(src, grp net.IP) error {
	var mfc mfcctl
	copy(mfc.mfcc_origin[:], src.To4())
	copy(mfc.mfcc_mcastgrp[:], grp.To4())

	ptr := unsafe.Pointer(&mfc)
	size := unsafe.Sizeof(mfc)
	buf := unsafe.Slice((*byte)(ptr), size)

	err := unix.SetsockoptString(mr.fd, unix.IPPROTO_IP, MRT_DEL_MFC, string(buf))
	if err != nil {
		return fmt.Errorf("failed to delete MFC entry for (%s, %s): %w", src, grp, err)
	}

	return nil
}
