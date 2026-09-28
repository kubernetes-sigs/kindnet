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

package network

import (
	"errors"
	"syscall"

	"github.com/mdlayher/netlink"
)

// IsNetlinkRejection reports whether err is an error the kernel sent in reply
// to a netlink request: the request was rejected and nothing was applied, so
// the caller can send a different request. Any other error (a failed system
// call, a deadline) means the reply was not read and the request may have been
// applied, the caller can only retry the same request later.
//
// mdlayher/netlink sets a bare errno for an error message from the kernel and
// wraps system call errors in *os.SyscallError.
func IsNetlinkRejection(err error) bool {
	var opErr *netlink.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	_, ok := opErr.Err.(syscall.Errno)
	return ok
}
