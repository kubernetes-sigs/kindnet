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
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestMulticastRouter_Integration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current network namespace
	origNs, err := netns.Get()
	if err != nil {
		t.Fatalf("failed to get current namespace: %v", err)
	}
	defer origNs.Close()

	// Create a new network namespace for the integration test
	newNs, err := netns.New()
	if err != nil {
		t.Fatalf("failed to create new namespace: %v", err)
	}
	defer newNs.Close()

	// Set up dummy interfaces inside the new namespace
	ethAttrs := netlink.NewLinkAttrs()
	ethAttrs.Name = "eth0"
	ethLink := &netlink.Dummy{LinkAttrs: ethAttrs}
	if err := netlink.LinkAdd(ethLink); err != nil {
		t.Fatalf("failed to add dummy interface eth0: %v", err)
	}
	if err := netlink.LinkSetUp(ethLink); err != nil {
		t.Fatalf("failed to set eth0 up: %v", err)
	}

	cniAttrs := netlink.NewLinkAttrs()
	cniAttrs.Name = "cni0"
	cniLink := &netlink.Dummy{LinkAttrs: cniAttrs}
	if err := netlink.LinkAdd(cniLink); err != nil {
		t.Fatalf("failed to add dummy interface cni0: %v", err)
	}
	if err := netlink.LinkSetUp(cniLink); err != nil {
		t.Fatalf("failed to set cni0 up: %v", err)
	}

	// Initialize the MulticastRouter
	router, err := NewMulticastRouter()
	if err != nil {
		t.Fatalf("failed to create MulticastRouter: %v", err)
	}
	defer func() {
		if err := router.Close(); err != nil {
			t.Errorf("failed to close router: %v", err)
		}
		// Switch back to original namespace
		_ = netns.Set(origNs)
	}()

	// Register VIFs
	if err := router.RegisterInterface("eth0", 0); err != nil {
		t.Fatalf("failed to register VIF 0 (eth0): %v", err)
	}
	if err := router.RegisterInterface("cni0", 1); err != nil {
		t.Fatalf("failed to register VIF 1 (cni0): %v", err)
	}

	// Check /proc/net/ip_mr_vif for registered interfaces
	vifData, err := os.ReadFile("/proc/net/ip_mr_vif")
	if err != nil {
		t.Fatalf("failed to read /proc/net/ip_mr_vif: %v", err)
	}
	vifStr := string(vifData)
	if !strings.Contains(vifStr, "eth0") {
		t.Errorf("expected eth0 to be present in ip_mr_vif, got:\n%s", vifStr)
	}
	if !strings.Contains(vifStr, "cni0") {
		t.Errorf("expected cni0 to be present in ip_mr_vif, got:\n%s", vifStr)
	}

	// Program an MFC route entry
	srcIP := []byte{192, 168, 100, 10}
	grpIP := []byte{239, 10, 10, 10}
	if err := router.AddMfc(srcIP, grpIP, 0, []uint16{1}); err != nil {
		t.Fatalf("failed to add MFC entry: %v", err)
	}

	// Check /proc/net/ip_mr_cache for registered route
	cacheData, err := os.ReadFile("/proc/net/ip_mr_cache")
	if err != nil {
		t.Fatalf("failed to read /proc/net/ip_mr_cache: %v", err)
	}
	cacheStr := string(cacheData)

	if !strings.Contains(cacheStr, "0") { // incoming iif 0
		t.Errorf("expected input interface index 0 to be present in ip_mr_cache, got:\n%s", cacheStr)
	}

	// Delete the MFC route entry
	if err := router.DeleteMfc(srcIP, grpIP); err != nil {
		t.Fatalf("failed to delete MFC entry: %v", err)
	}

	// Unregister interface VIFs
	if err := router.UnregisterInterface(0); err != nil {
		t.Fatalf("failed to unregister VIF 0: %v", err)
	}
	if err := router.UnregisterInterface(1); err != nil {
		t.Fatalf("failed to unregister VIF 1: %v", err)
	}
}
