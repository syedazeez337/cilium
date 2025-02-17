// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2

import (
	context "context"

	ciliumiov2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CiliumBGPNodeConfigOverridesGetter has a method to return a CiliumBGPNodeConfigOverrideInterface.
// A group's client should implement this interface.
type CiliumBGPNodeConfigOverridesGetter interface {
	CiliumBGPNodeConfigOverrides() CiliumBGPNodeConfigOverrideInterface
}

// CiliumBGPNodeConfigOverrideInterface has methods to work with CiliumBGPNodeConfigOverride resources.
type CiliumBGPNodeConfigOverrideInterface interface {
	Create(ctx context.Context, ciliumBGPNodeConfigOverride *ciliumiov2.CiliumBGPNodeConfigOverride, opts v1.CreateOptions) (*ciliumiov2.CiliumBGPNodeConfigOverride, error)
	Update(ctx context.Context, ciliumBGPNodeConfigOverride *ciliumiov2.CiliumBGPNodeConfigOverride, opts v1.UpdateOptions) (*ciliumiov2.CiliumBGPNodeConfigOverride, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*ciliumiov2.CiliumBGPNodeConfigOverride, error)
	List(ctx context.Context, opts v1.ListOptions) (*ciliumiov2.CiliumBGPNodeConfigOverrideList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *ciliumiov2.CiliumBGPNodeConfigOverride, err error)
	CiliumBGPNodeConfigOverrideExpansion
}

// ciliumBGPNodeConfigOverrides implements CiliumBGPNodeConfigOverrideInterface
type ciliumBGPNodeConfigOverrides struct {
	*gentype.ClientWithList[*ciliumiov2.CiliumBGPNodeConfigOverride, *ciliumiov2.CiliumBGPNodeConfigOverrideList]
}

// newCiliumBGPNodeConfigOverrides returns a CiliumBGPNodeConfigOverrides
func newCiliumBGPNodeConfigOverrides(c *CiliumV2Client) *ciliumBGPNodeConfigOverrides {
	return &ciliumBGPNodeConfigOverrides{
		gentype.NewClientWithList[*ciliumiov2.CiliumBGPNodeConfigOverride, *ciliumiov2.CiliumBGPNodeConfigOverrideList](
			"ciliumbgpnodeconfigoverrides",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *ciliumiov2.CiliumBGPNodeConfigOverride { return &ciliumiov2.CiliumBGPNodeConfigOverride{} },
			func() *ciliumiov2.CiliumBGPNodeConfigOverrideList {
				return &ciliumiov2.CiliumBGPNodeConfigOverrideList{}
			},
		),
	}
}
