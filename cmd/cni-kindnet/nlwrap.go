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

	"github.com/vishvananda/netlink"
)

// limit of attempts at a netlink call that is repeatedly interrupted
const maxAttempts = 5

// retryOnIntr calls f again while it returns netlink.ErrDumpInterrupted.
// based on https://github.com/kubernetes-sigs/dranet/tree/main/internal/nlwrap
func retryOnIntr(f func() error) {
	for range maxAttempts {
		if err := f(); !errors.Is(err, netlink.ErrDumpInterrupted) {
			return
		}
	}
}

// linkByName calls h.LinkByName, which dumps all the links on old kernels.
func linkByName(h *netlink.Handle, name string) (netlink.Link, error) {
	var link netlink.Link
	var err error
	retryOnIntr(func() error {
		link, err = h.LinkByName(name)
		return err
	})
	return link, err
}

func routeListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	var routes []netlink.Route
	var err error
	retryOnIntr(func() error {
		routes, err = netlink.RouteListFiltered(family, filter, filterMask)
		return err
	})
	return routes, err
}
