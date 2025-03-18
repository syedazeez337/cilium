// Code generated by dpgen. DO NOT EDIT.

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// BPFLXC is a configuration struct for a Cilium datapath object. Warning: do
// not instantiate directly! Always use [NewBPFLXC] to ensure the default values
// configured in the ELF are honored.
type BPFLXC struct {
	// MTU of the device the bpf program is attached to (default: MTU set in
	// node_config.h by agent).
	DeviceMTU uint16 `config:"device_mtu"`
	// The endpoint's security ID.
	EndpointID uint16 `config:"endpoint_id"`
	// The endpoint's IPv4 address.
	EndpointIPv4 uint32 `config:"endpoint_ipv4"`
	// The endpoint's IPv6 address.
	EndpointIPv6 [16]byte `config:"endpoint_ipv6"`
	// The endpoint's network namespace cookie.
	EndpointNetNSCookie uint64 `config:"endpoint_netns_cookie"`
	// Ifindex of the interface the bpf program is attached to.
	InterfaceIfindex uint32 `config:"interface_ifindex"`
	// First 32 bits of the MAC address of the interface the bpf program is
	// attached to.
	InterfaceMAC1 uint32 `config:"interface_mac_1"`
	// Latter 16 bits of the MAC address of the interface the bpf program is
	// attached to.
	InterfaceMAC2 uint16 `config:"interface_mac_2"`
	// Masquerade address for IPv4 traffic.
	NATIPv4Masquerade uint32 `config:"nat_ipv4_masquerade"`
	// First half of the masquerade address for IPv6 traffic.
	NATIPv6Masquerade1 uint64 `config:"nat_ipv6_masquerade_1"`
	// Second half of the masquerade address for IPv6 traffic.
	NATIPv6Masquerade2 uint64 `config:"nat_ipv6_masquerade_2"`
	// The log level for policy verdicts in workload endpoints.
	PolicyVerdictLogFilter uint32 `config:"policy_verdict_log_filter"`
	// The endpoint's security label.
	SecurityLabel uint32 `config:"security_label"`

	Node
}

func NewBPFLXC(node Node) *BPFLXC {
	return &BPFLXC{0x5dc, 0x0, 0x0,
		[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, node}
}
