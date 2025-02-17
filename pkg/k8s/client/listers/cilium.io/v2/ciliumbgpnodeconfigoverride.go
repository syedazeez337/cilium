// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v2

import (
	ciliumiov2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// CiliumBGPNodeConfigOverrideLister helps list CiliumBGPNodeConfigOverrides.
// All objects returned here must be treated as read-only.
type CiliumBGPNodeConfigOverrideLister interface {
	// List lists all CiliumBGPNodeConfigOverrides in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*ciliumiov2.CiliumBGPNodeConfigOverride, err error)
	// Get retrieves the CiliumBGPNodeConfigOverride from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*ciliumiov2.CiliumBGPNodeConfigOverride, error)
	CiliumBGPNodeConfigOverrideListerExpansion
}

// ciliumBGPNodeConfigOverrideLister implements the CiliumBGPNodeConfigOverrideLister interface.
type ciliumBGPNodeConfigOverrideLister struct {
	listers.ResourceIndexer[*ciliumiov2.CiliumBGPNodeConfigOverride]
}

// NewCiliumBGPNodeConfigOverrideLister returns a new CiliumBGPNodeConfigOverrideLister.
func NewCiliumBGPNodeConfigOverrideLister(indexer cache.Indexer) CiliumBGPNodeConfigOverrideLister {
	return &ciliumBGPNodeConfigOverrideLister{listers.New[*ciliumiov2.CiliumBGPNodeConfigOverride](indexer, ciliumiov2.Resource("ciliumbgpnodeconfigoverride"))}
}
