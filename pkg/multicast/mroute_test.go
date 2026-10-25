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
	"testing"
	"unsafe"
)

func TestStructSizes(t *testing.T) {
	// struct vifctl in C is exactly 16 bytes.
	if size := unsafe.Sizeof(vifctl{}); size != 16 {
		t.Errorf("expected vifctl size to be 16 bytes, got %d", size)
	}

	// struct mfcctl in C is exactly 60 bytes.
	if size := unsafe.Sizeof(mfcctl{}); size != 60 {
		t.Errorf("expected mfcctl size to be 60 bytes, got %d", size)
	}
}
