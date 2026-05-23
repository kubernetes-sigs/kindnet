#!/usr/bin/env bash

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

setup_suite() {
  echo "Setting up suite: Creating KIND cluster with disableDefaultCNI..."
  
  # Create kind cluster referencing static config via BATS directory variable
  kind create cluster --config "$BATS_TEST_DIRNAME/kind-config.yaml" --wait 1m

  # Build the test kindnet docker image
  echo "Building and loading kindnet image..."
  export IMAGE_NAME="registry.k8s.io/networking/kindnet"
  docker build -t "$IMAGE_NAME":test -f Dockerfile . --load
  
  # Load the image into kind
  kind load docker-image "$IMAGE_NAME":test --name kind

  # Install kindnet using the static configuration manifest (fully generic)
  echo "Installing kindnet..."
  kubectl apply -f "$BATS_TEST_DIRNAME/install-kindnet.yaml"
  
  # Wait for kindnet pod to be ready
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kindnet --timeout=2m
}

teardown_suite() {
  echo "Tearing down suite: Deleting KIND cluster..."
  kind delete cluster --name kind || true
}
