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
	"net"
	"testing"
)

func TestIGMPParsing(t *testing.T) {
	ma, err := NewMulticastAgent()
	if err != nil {
		t.Fatalf("failed to create multicast agent: %v", err)
	}

	// Test IGMPv2 Join (Type 0x16) for 239.1.1.1
	igmpv2Join := []byte{
		0x16,       // Type: IGMPv2 Report
		0x00,       // Max Response Time
		0x00, 0x00, // Checksum
		0xef, 0x01, 0x01, 0x01, // Group: 239.1.1.1
	}

	ma.parseAndHandleIGMP(igmpv2Join, "knet-test-if")

	ma.RLock()
	ifaces, exists := ma.groupToIfaces["239.1.1.1"]
	ma.RUnlock()

	if !exists || !ifaces["knet-test-if"] {
		t.Errorf("expected knet-test-if to be joined to 239.1.1.1")
	}

	// Test IGMPv2 Leave (Type 0x17) for 239.1.1.1
	igmpv2Leave := []byte{
		0x17,       // Type: IGMPv2 Leave
		0x00,       // Max Response Time
		0x00, 0x00, // Checksum
		0xef, 0x01, 0x01, 0x01, // Group: 239.1.1.1
	}

	ma.parseAndHandleIGMP(igmpv2Leave, "knet-test-if")

	ma.RLock()
	_, exists = ma.groupToIfaces["239.1.1.1"]
	ma.RUnlock()

	if exists {
		t.Errorf("expected 239.1.1.1 group record to be removed")
	}
}

func TestIGMPv3Parsing(t *testing.T) {
	ma, err := NewMulticastAgent()
	if err != nil {
		t.Fatalf("failed to create multicast agent: %v", err)
	}

	// Test IGMPv3 Report (Type 0x22)
	igmpv3Join := []byte{
		0x22,       // Type: IGMPv3 Report
		0x00,       // Reserved
		0x00, 0x00, // Checksum
		0x00, 0x00, // Reserved
		0x00, 0x01, // Number of Group Records (1)
		// Group Record
		0x04,       // Record Type: CHANGE_TO_EXCLUDE_MODE (4)
		0x00,       // Aux Data Len
		0x00, 0x00, // Number of Sources (0)
		0xef, 0x02, 0x02, 0x02, // Multicast Address: 239.2.2.2
	}

	ma.parseAndHandleIGMP(igmpv3Join, "knet-test-if")

	ma.RLock()
	ifaces, exists := ma.groupToIfaces["239.2.2.2"]
	ma.RUnlock()

	if !exists || !ifaces["knet-test-if"] {
		t.Errorf("expected knet-test-if to be joined to 239.2.2.2")
	}
}

func TestMLDParsing(t *testing.T) {
	ma, err := NewMulticastAgent()
	if err != nil {
		t.Fatalf("failed to create multicast agent: %v", err)
	}

	// Test MLDv1 Join (Type 131)
	mldv1Join := []byte{
		131,        // Type: MLDv1 Report
		0x00,       // Code
		0x00, 0x00, // Checksum
		0x00, 0x00, 0x00, 0x00, // Max Response Delay
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Multicast Address ff02::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	ma.parseAndHandleMLD(mldv1Join, "knet-test-if")

	ma.RLock()
	targetIP := net.ParseIP("ff02::1").String()
	ifaces, exists := ma.groupToIfaces[targetIP]
	ma.RUnlock()

	if !exists || !ifaces["knet-test-if"] {
		t.Errorf("expected knet-test-if to be joined to %s", targetIP)
	}
}
