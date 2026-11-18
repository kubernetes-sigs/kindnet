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

package main

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRetryOnIntr(t *testing.T) {
	tests := []struct {
		name  string
		errs  []error
		calls int
	}{
		{name: "success", errs: []error{nil}, calls: 1},
		{name: "other error", errs: []error{errors.New("fail")}, calls: 1},
		{name: "interrupted once", errs: []error{netlink.ErrDumpInterrupted, nil}, calls: 2},
		{name: "always interrupted", calls: maxAttempts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			retryOnIntr(func() error {
				calls++
				if calls > len(tt.errs) {
					return netlink.ErrDumpInterrupted
				}
				return tt.errs[calls-1]
			})
			if calls != tt.calls {
				t.Errorf("got %d calls, want %d", calls, tt.calls)
			}
		})
	}
}
