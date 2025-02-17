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

// CiliumBGPAdvertisementLister helps list CiliumBGPAdvertisements.
// All objects returned here must be treated as read-only.
type CiliumBGPAdvertisementLister interface {
	// List lists all CiliumBGPAdvertisements in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*ciliumiov2.CiliumBGPAdvertisement, err error)
	// Get retrieves the CiliumBGPAdvertisement from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*ciliumiov2.CiliumBGPAdvertisement, error)
	CiliumBGPAdvertisementListerExpansion
}

// ciliumBGPAdvertisementLister implements the CiliumBGPAdvertisementLister interface.
type ciliumBGPAdvertisementLister struct {
	listers.ResourceIndexer[*ciliumiov2.CiliumBGPAdvertisement]
}

// NewCiliumBGPAdvertisementLister returns a new CiliumBGPAdvertisementLister.
func NewCiliumBGPAdvertisementLister(indexer cache.Indexer) CiliumBGPAdvertisementLister {
	return &ciliumBGPAdvertisementLister{listers.New[*ciliumiov2.CiliumBGPAdvertisement](indexer, ciliumiov2.Resource("ciliumbgpadvertisement"))}
}
