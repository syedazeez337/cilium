// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestParseIPv6EgressGatewayPolicy(t *testing.T) {
	// Test with IPv6 egress IP and IPv6 destination CIDR
	t.Run("IPv6 egress IP with IPv6 destination CIDR", func(t *testing.T) {
		policy := &v2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-policy",
			},
			Spec: v2.CiliumEgressGatewayPolicySpec{
				DestinationCIDRs: []v2.CIDR{"2001:db8::/32"},
				EgressGateway: &v2.EgressGateway{
					EgressIP: "2001:db8::1",
					NodeSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"node-role.kubernetes.io/gateway": "true",
						},
					},
				},
				Selectors: []v2.EgressRule{
					{
						PodSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
					},
				},
			},
		}

		config, err := ParseCEGP(policy)
		require.NoError(t, err)
		assert.Equal(t, types.NamespacedName{Name: "test-policy"}, config.id)
		assert.Equal(t, 1, len(config.dstCIDRs))
		assert.Equal(t, netip.MustParsePrefix("2001:db8::/32"), config.dstCIDRs[0])
		assert.Equal(t, netip.MustParseAddr("2001:db8::1"), config.policyGwConfig.egressIP)
		assert.True(t, config.policyGwConfig.v6needed)
	})

	// Test with IPv4 egress IP and IPv6 destination CIDR (should fail)
	t.Run("IPv4 egress IP with IPv6 destination CIDR", func(t *testing.T) {
		policy := &v2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-policy",
			},
			Spec: v2.CiliumEgressGatewayPolicySpec{
				DestinationCIDRs: []v2.CIDR{"2001:db8::/32"},
				EgressGateway: &v2.EgressGateway{
					EgressIP: "192.168.1.1",
					NodeSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"node-role.kubernetes.io/gateway": "true",
						},
					},
				},
				Selectors: []v2.EgressRule{
					{
						PodSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
					},
				},
			},
		}

		_, err := ParseCEGP(policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IPv4 egress IP 192.168.1.1 cannot be used with only IPv6 destination CIDRs")
	})

	// Test with IPv6 egress IP and IPv4 destination CIDR (should fail)
	t.Run("IPv6 egress IP with IPv4 destination CIDR", func(t *testing.T) {
		policy := &v2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-policy",
			},
			Spec: v2.CiliumEgressGatewayPolicySpec{
				DestinationCIDRs: []v2.CIDR{"192.168.0.0/16"},
				EgressGateway: &v2.EgressGateway{
					EgressIP: "2001:db8::1",
					NodeSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"node-role.kubernetes.io/gateway": "true",
						},
					},
				},
				Selectors: []v2.EgressRule{
					{
						PodSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
					},
				},
			},
		}

		_, err := ParseCEGP(policy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IPv6 egress IP 2001:db8::1 cannot be used with only IPv4 destination CIDRs")
	})

	// Test with IPv6 egress IP and mixed destination CIDRs (should pass)
	t.Run("IPv6 egress IP with mixed destination CIDRs", func(t *testing.T) {
		policy := &v2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-policy",
			},
			Spec: v2.CiliumEgressGatewayPolicySpec{
				DestinationCIDRs: []v2.CIDR{"192.168.0.0/16", "2001:db8::/32"},
				EgressGateway: &v2.EgressGateway{
					EgressIP: "2001:db8::1",
					NodeSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"node-role.kubernetes.io/gateway": "true",
						},
					},
				},
				Selectors: []v2.EgressRule{
					{
						PodSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
					},
				},
			},
		}

		config, err := ParseCEGP(policy)
		require.NoError(t, err)
		assert.Equal(t, types.NamespacedName{Name: "test-policy"}, config.id)
		assert.Equal(t, 2, len(config.dstCIDRs))
		assert.Equal(t, netip.MustParseAddr("2001:db8::1"), config.policyGwConfig.egressIP)
		assert.True(t, config.policyGwConfig.v6needed)
	})

	// Test with IPv4 egress IP and mixed destination CIDRs (should pass)
	t.Run("IPv4 egress IP with mixed destination CIDRs", func(t *testing.T) {
		policy := &v2.CiliumEgressGatewayPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-policy",
			},
			Spec: v2.CiliumEgressGatewayPolicySpec{
				DestinationCIDRs: []v2.CIDR{"192.168.0.0/16", "2001:db8::/32"},
				EgressGateway: &v2.EgressGateway{
					EgressIP: "192.168.1.1",
					NodeSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"node-role.kubernetes.io/gateway": "true",
						},
					},
				},
				Selectors: []v2.EgressRule{
					{
						PodSelector: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
					},
				},
			},
		}

		config, err := ParseCEGP(policy)
		require.NoError(t, err)
		assert.Equal(t, types.NamespacedName{Name: "test-policy"}, config.id)
		assert.Equal(t, 2, len(config.dstCIDRs))
		assert.Equal(t, netip.MustParseAddr("192.168.1.1"), config.policyGwConfig.egressIP)
		assert.True(t, config.policyGwConfig.v6needed)
	})
}
