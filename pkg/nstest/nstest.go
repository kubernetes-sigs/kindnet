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

// Package nstest runs tests that configure the network stack in their own
// user and network namespaces, without root and without touching the host.
package nstest

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

const subprocessEnvKey = "KINDNET_TEST_SUBPROCESS"

// ExecInUserns runs f as the "subprocess" subtest of t in a copy of the test
// binary started in a new user namespace, with the current user mapped to
// root, and a new network namespace. Every thread of that process is in the
// new namespaces, so f and its subtests can run on any goroutine and use nft,
// ip and netlink sockets freely, and they can not touch the namespaces of the
// test runner. The test fails when unprivileged user namespaces are not
// available, a skip would hide it.
func ExecInUserns(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	if os.Getenv(subprocessEnvKey) == "1" {
		t.Run("subprocess", f)
		return
	}
	if !unprivilegedUserns() {
		t.Fatal("unprivileged user namespaces are not available: sysctl kernel.unprivileged_userns_clone=1 and kernel.apparmor_restrict_unprivileged_userns=0")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v=true")
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-test.testlogfile=") || strings.HasPrefix(arg, "-test.timeout=") {
			cmd.Args = append(cmd.Args, arg)
		}
	}
	cmd.Env = append(os.Environ(), subprocessEnvKey+"=1")
	// nft and ip live in sbin directories that an unprivileged PATH may lack.
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/sbin:/sbin:"+os.Getenv("PATH"))
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

// unprivilegedUserns reports whether this process can create a user namespace.
func unprivilegedUserns() bool {
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	return cmd.Run() == nil
}
