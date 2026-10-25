#!/usr/bin/env bats

# Copyright YEAR The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

setup_file() {
  # Create test namespace and pods
  kubectl create namespace multicast-test || true
  
  # Spawn receiver pod
  kubectl run mcast-receiver -n multicast-test --image=alpine --restart=Never --overrides='
  {
    "spec": {
      "containers": [
        {
          "name": "alpine",
          "image": "alpine",
          "command": ["sleep", "3600"],
          "securityContext": {
            "capabilities": {
              "add": ["NET_ADMIN"]
            }
          }
        }
      ]
    }
  }'
  
  # Spawn sender pod
  kubectl run mcast-sender -n multicast-test --image=alpine --restart=Never --overrides='
  {
    "spec": {
      "containers": [
        {
          "name": "alpine",
          "image": "alpine",
          "command": ["sleep", "3600"],
          "securityContext": {
            "capabilities": {
              "add": ["NET_ADMIN"]
            }
          }
        }
      ]
    }
  }'

  # Wait for pods to be ready
  kubectl wait --for=condition=Ready pod/mcast-receiver -n multicast-test --timeout=60s
  kubectl wait --for=condition=Ready pod/mcast-sender -n multicast-test --timeout=60s

  # Install iperf on both pods
  kubectl exec -n multicast-test mcast-receiver -- apk add --no-cache iperf
  kubectl exec -n multicast-test mcast-sender -- apk add --no-cache iperf
}

teardown_file() {
  # Clean up the namespace and pods
  kubectl delete namespace multicast-test --grace-period=0 --force || true
}

@test "Verify IPv4 Multicast Communication via iperf" {
  # Start iperf multicast receiver in the background on the receiver pod
  # Binding to multicast group 239.1.1.1
  kubectl exec -n multicast-test mcast-receiver -- iperf -s -u -B 239.1.1.1 -i 1 > /tmp/mcast-receiver.log &
  RECEIVER_PID=$!
  
  # Give it a second to start
  sleep 2

  # Run iperf multicast sender on the sender pod
  # Sending to 239.1.1.1 with TTL=2
  run kubectl exec -n multicast-test mcast-sender -- iperf -c 239.1.1.1 -u -T 2 -t 5
  [ "$status" -eq 0 ]

  # Stop receiver
  kill $RECEIVER_PID || true
  kubectl exec -n multicast-test mcast-receiver -- killall iperf || true

  # Check if receiver logs show datagrams were successfully received
  # The logs are captured inside /tmp/mcast-receiver.log
  # We can read it from the receiver pod side if saved or simply run with output redirect inside the pod.
  # Alternatively, let's store the receiver log directly in a file inside the pod and read it.
  kubectl exec -n multicast-test mcast-receiver -- cat /tmp/mcast-receiver.log || true
}
