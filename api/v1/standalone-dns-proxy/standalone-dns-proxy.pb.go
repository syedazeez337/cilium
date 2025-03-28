// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v6.30.1
// source: standalone-dns-proxy/standalone-dns-proxy.proto

package standalonednsproxy

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Response code returned by RPC methods.
type ResponseCode int32

const (
	ResponseCode_RESPONSE_CODE_UNSPECIFIED     ResponseCode = 0
	ResponseCode_RESPONSE_CODE_NO_ERROR        ResponseCode = 1
	ResponseCode_RESPONSE_CODE_FORMAT_ERROR    ResponseCode = 2
	ResponseCode_RESPONSE_CODE_SERVER_FAILURE  ResponseCode = 3
	ResponseCode_RESPONSE_CODE_NOT_IMPLEMENTED ResponseCode = 4
	ResponseCode_RESPONSE_CODE_REFUSED         ResponseCode = 5
)

// Enum value maps for ResponseCode.
var (
	ResponseCode_name = map[int32]string{
		0: "RESPONSE_CODE_UNSPECIFIED",
		1: "RESPONSE_CODE_NO_ERROR",
		2: "RESPONSE_CODE_FORMAT_ERROR",
		3: "RESPONSE_CODE_SERVER_FAILURE",
		4: "RESPONSE_CODE_NOT_IMPLEMENTED",
		5: "RESPONSE_CODE_REFUSED",
	}
	ResponseCode_value = map[string]int32{
		"RESPONSE_CODE_UNSPECIFIED":     0,
		"RESPONSE_CODE_NO_ERROR":        1,
		"RESPONSE_CODE_FORMAT_ERROR":    2,
		"RESPONSE_CODE_SERVER_FAILURE":  3,
		"RESPONSE_CODE_NOT_IMPLEMENTED": 4,
		"RESPONSE_CODE_REFUSED":         5,
	}
)

func (x ResponseCode) Enum() *ResponseCode {
	p := new(ResponseCode)
	*p = x
	return p
}

func (x ResponseCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ResponseCode) Descriptor() protoreflect.EnumDescriptor {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_enumTypes[0].Descriptor()
}

func (ResponseCode) Type() protoreflect.EnumType {
	return &file_standalone_dns_proxy_standalone_dns_proxy_proto_enumTypes[0]
}

func (x ResponseCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ResponseCode.Descriptor instead.
func (ResponseCode) EnumDescriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{0}
}

// Ack sent from SDP to Agent on processing DNS policy rules
type PolicyStateResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Response      ResponseCode           `protobuf:"varint,1,opt,name=response,proto3,enum=standalonednsproxy.ResponseCode" json:"response,omitempty"`
	RequestId     string                 `protobuf:"bytes,2,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"` // Request ID for which response is sent to
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PolicyStateResponse) Reset() {
	*x = PolicyStateResponse{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PolicyStateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PolicyStateResponse) ProtoMessage() {}

func (x *PolicyStateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PolicyStateResponse.ProtoReflect.Descriptor instead.
func (*PolicyStateResponse) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{0}
}

func (x *PolicyStateResponse) GetResponse() ResponseCode {
	if x != nil {
		return x.Response
	}
	return ResponseCode_RESPONSE_CODE_UNSPECIFIED
}

func (x *PolicyStateResponse) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

// FQDN-IP mapping goalstate sent from SDP to agent
type FQDNMapping struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Fqdn           string                 `protobuf:"bytes,1,opt,name=fqdn,proto3" json:"fqdn,omitempty"`                                            // dns name
	RecordIp       [][]byte               `protobuf:"bytes,2,rep,name=record_ip,json=recordIp,proto3" json:"record_ip,omitempty"`                    // List of IPs corresponding to dns name
	Ttl            uint32                 `protobuf:"varint,3,opt,name=ttl,proto3" json:"ttl,omitempty"`                                             // TTL of DNS record
	SourceIdentity uint32                 `protobuf:"varint,4,opt,name=source_identity,json=sourceIdentity,proto3" json:"source_identity,omitempty"` // Identity of the client making the DNS request
	SourceIp       []byte                 `protobuf:"bytes,5,opt,name=source_ip,json=sourceIp,proto3" json:"source_ip,omitempty"`                    // IP address of the client making the DNS request
	ResponseCode   uint32                 `protobuf:"varint,6,opt,name=response_code,json=responseCode,proto3" json:"response_code,omitempty"`       // DNS Response code as specified in RFC2316
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *FQDNMapping) Reset() {
	*x = FQDNMapping{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FQDNMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FQDNMapping) ProtoMessage() {}

func (x *FQDNMapping) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FQDNMapping.ProtoReflect.Descriptor instead.
func (*FQDNMapping) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{1}
}

func (x *FQDNMapping) GetFqdn() string {
	if x != nil {
		return x.Fqdn
	}
	return ""
}

func (x *FQDNMapping) GetRecordIp() [][]byte {
	if x != nil {
		return x.RecordIp
	}
	return nil
}

func (x *FQDNMapping) GetTtl() uint32 {
	if x != nil {
		return x.Ttl
	}
	return 0
}

func (x *FQDNMapping) GetSourceIdentity() uint32 {
	if x != nil {
		return x.SourceIdentity
	}
	return 0
}

func (x *FQDNMapping) GetSourceIp() []byte {
	if x != nil {
		return x.SourceIp
	}
	return nil
}

func (x *FQDNMapping) GetResponseCode() uint32 {
	if x != nil {
		return x.ResponseCode
	}
	return 0
}

// Ack returned by cilium agent to SDP on receiving FQDN-IP mapping update
type UpdateMappingResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Response      ResponseCode           `protobuf:"varint,1,opt,name=response,proto3,enum=standalonednsproxy.ResponseCode" json:"response,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UpdateMappingResponse) Reset() {
	*x = UpdateMappingResponse{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UpdateMappingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateMappingResponse) ProtoMessage() {}

func (x *UpdateMappingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateMappingResponse.ProtoReflect.Descriptor instead.
func (*UpdateMappingResponse) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{2}
}

func (x *UpdateMappingResponse) GetResponse() ResponseCode {
	if x != nil {
		return x.Response
	}
	return ResponseCode_RESPONSE_CODE_UNSPECIFIED
}

// DNServer identity, port and protocol the requests be allowed to
type DNSServer struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	DnsServerIdentity uint32                 `protobuf:"varint,1,opt,name=dns_server_identity,json=dnsServerIdentity,proto3" json:"dns_server_identity,omitempty"` // Identity of destination DNS server
	DnsServerPort     uint32                 `protobuf:"varint,2,opt,name=dns_server_port,json=dnsServerPort,proto3" json:"dns_server_port,omitempty"`
	DnsServerProto    uint32                 `protobuf:"varint,3,opt,name=dns_server_proto,json=dnsServerProto,proto3" json:"dns_server_proto,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *DNSServer) Reset() {
	*x = DNSServer{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DNSServer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DNSServer) ProtoMessage() {}

func (x *DNSServer) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DNSServer.ProtoReflect.Descriptor instead.
func (*DNSServer) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{3}
}

func (x *DNSServer) GetDnsServerIdentity() uint32 {
	if x != nil {
		return x.DnsServerIdentity
	}
	return 0
}

func (x *DNSServer) GetDnsServerPort() uint32 {
	if x != nil {
		return x.DnsServerPort
	}
	return 0
}

func (x *DNSServer) GetDnsServerProto() uint32 {
	if x != nil {
		return x.DnsServerProto
	}
	return 0
}

// L7 DNS policy specifying which requests are permitted to which DNS server
type DNSPolicy struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	SourceEndpointId uint32                 `protobuf:"varint,1,opt,name=source_endpoint_id,json=sourceEndpointId,proto3" json:"source_endpoint_id,omitempty"` // Endpoint ID of the workload this L7 DNS policy should apply to
	DnsPattern       []string               `protobuf:"bytes,2,rep,name=dns_pattern,json=dnsPattern,proto3" json:"dns_pattern,omitempty"`                      // Allowed DNS pattern this identity is allowed to resolve.
	DnsServers       []*DNSServer           `protobuf:"bytes,3,rep,name=dns_servers,json=dnsServers,proto3" json:"dns_servers,omitempty"`                      // List of DNS servers to be allowed to connect.
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *DNSPolicy) Reset() {
	*x = DNSPolicy{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DNSPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DNSPolicy) ProtoMessage() {}

func (x *DNSPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DNSPolicy.ProtoReflect.Descriptor instead.
func (*DNSPolicy) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{4}
}

func (x *DNSPolicy) GetSourceEndpointId() uint32 {
	if x != nil {
		return x.SourceEndpointId
	}
	return 0
}

func (x *DNSPolicy) GetDnsPattern() []string {
	if x != nil {
		return x.DnsPattern
	}
	return nil
}

func (x *DNSPolicy) GetDnsServers() []*DNSServer {
	if x != nil {
		return x.DnsServers
	}
	return nil
}

// L7 DNS policy snapshot of all local endpoints and identity to ip mapping of source
// and destinatione egress endpoints enforcing fqdn rules.
type PolicyState struct {
	state                     protoimpl.MessageState       `protogen:"open.v1"`
	EgressL7DnsPolicy         []*DNSPolicy                 `protobuf:"bytes,1,rep,name=egress_l7_dns_policy,json=egressL7DnsPolicy,proto3" json:"egress_l7_dns_policy,omitempty"`
	RequestId                 string                       `protobuf:"bytes,2,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`                                                     // Random UUID based identifier which will be referenced in ACKs
	IdentityToEndpointMapping []*IdentityToEndpointMapping `protobuf:"bytes,3,rep,name=identity_to_endpoint_mapping,json=identityToEndpointMapping,proto3" json:"identity_to_endpoint_mapping,omitempty"` // Identity to Endpoint mapping for the DNS server and the source identity
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *PolicyState) Reset() {
	*x = PolicyState{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PolicyState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PolicyState) ProtoMessage() {}

func (x *PolicyState) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PolicyState.ProtoReflect.Descriptor instead.
func (*PolicyState) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{5}
}

func (x *PolicyState) GetEgressL7DnsPolicy() []*DNSPolicy {
	if x != nil {
		return x.EgressL7DnsPolicy
	}
	return nil
}

func (x *PolicyState) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (x *PolicyState) GetIdentityToEndpointMapping() []*IdentityToEndpointMapping {
	if x != nil {
		return x.IdentityToEndpointMapping
	}
	return nil
}

// Cilium Identity ID to IP address mapping
type IdentityToEndpointMapping struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Identity      uint32                 `protobuf:"varint,1,opt,name=identity,proto3" json:"identity,omitempty"`
	EndpointInfo  []*EndpointInfo        `protobuf:"bytes,2,rep,name=endpoint_info,json=endpointInfo,proto3" json:"endpoint_info,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *IdentityToEndpointMapping) Reset() {
	*x = IdentityToEndpointMapping{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IdentityToEndpointMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdentityToEndpointMapping) ProtoMessage() {}

func (x *IdentityToEndpointMapping) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdentityToEndpointMapping.ProtoReflect.Descriptor instead.
func (*IdentityToEndpointMapping) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{6}
}

func (x *IdentityToEndpointMapping) GetIdentity() uint32 {
	if x != nil {
		return x.Identity
	}
	return 0
}

func (x *IdentityToEndpointMapping) GetEndpointInfo() []*EndpointInfo {
	if x != nil {
		return x.EndpointInfo
	}
	return nil
}

// cilium endpoint ipaddress and ID
type EndpointInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            uint64                 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Ip            [][]byte               `protobuf:"bytes,2,rep,name=ip,proto3" json:"ip,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EndpointInfo) Reset() {
	*x = EndpointInfo{}
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EndpointInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EndpointInfo) ProtoMessage() {}

func (x *EndpointInfo) ProtoReflect() protoreflect.Message {
	mi := &file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EndpointInfo.ProtoReflect.Descriptor instead.
func (*EndpointInfo) Descriptor() ([]byte, []int) {
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP(), []int{7}
}

func (x *EndpointInfo) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *EndpointInfo) GetIp() [][]byte {
	if x != nil {
		return x.Ip
	}
	return nil
}

var File_standalone_dns_proxy_standalone_dns_proxy_proto protoreflect.FileDescriptor

var file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDesc = string([]byte{
	0x0a, 0x2f, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x2d, 0x64, 0x6e, 0x73,
	0x2d, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e,
	0x65, 0x2d, 0x64, 0x6e, 0x73, 0x2d, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x12, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x22, 0x72, 0x0a, 0x13, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3c, 0x0a, 0x08,
	0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20,
	0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x43, 0x6f, 0x64, 0x65,
	0x52, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x22, 0xbb, 0x01, 0x0a, 0x0b, 0x46, 0x51,
	0x44, 0x4e, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x71, 0x64,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x71, 0x64, 0x6e, 0x12, 0x1b, 0x0a,
	0x09, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x5f, 0x69, 0x70, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x08, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x49, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x74,
	0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x74, 0x74, 0x6c, 0x12, 0x27, 0x0a, 0x0f,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f,
	0x69, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x49, 0x70, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x22, 0x55, 0x0a, 0x15, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x3c, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x20, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64,
	0x6e, 0x73, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x43, 0x6f, 0x64, 0x65, 0x52, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x8d,
	0x01, 0x0a, 0x09, 0x44, 0x4e, 0x53, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x13,
	0x64, 0x6e, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11, 0x64, 0x6e, 0x73, 0x53, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x26, 0x0a, 0x0f,
	0x64, 0x6e, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x64, 0x6e, 0x73, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x50, 0x6f, 0x72, 0x74, 0x12, 0x28, 0x0a, 0x10, 0x64, 0x6e, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e,
	0x64, 0x6e, 0x73, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9a,
	0x01, 0x0a, 0x09, 0x44, 0x4e, 0x53, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x2c, 0x0a, 0x12,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x64, 0x6e,
	0x73, 0x5f, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0a, 0x64, 0x6e, 0x73, 0x50, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x12, 0x3e, 0x0a, 0x0b, 0x64,
	0x6e, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1d, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x44, 0x4e, 0x53, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52,
	0x0a, 0x64, 0x6e, 0x73, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x22, 0xec, 0x01, 0x0a, 0x0b,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x4e, 0x0a, 0x14, 0x65,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x6c, 0x37, 0x5f, 0x64, 0x6e, 0x73, 0x5f, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x73, 0x74, 0x61, 0x6e,
	0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x44,
	0x4e, 0x53, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x11, 0x65, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x4c, 0x37, 0x44, 0x6e, 0x73, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x6e, 0x0a, 0x1c, 0x69, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x74, 0x6f, 0x5f, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x2d, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x54, 0x6f,
	0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52,
	0x19, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x45, 0x6e, 0x64, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x22, 0x7e, 0x0a, 0x19, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x12, 0x45, 0x0a, 0x0d, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f,
	0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x73, 0x74, 0x61,
	0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0c, 0x65, 0x6e,
	0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x22, 0x2e, 0x0a, 0x0c, 0x45, 0x6e,
	0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x69, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x70, 0x2a, 0xc9, 0x01, 0x0a, 0x0c, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x1d, 0x0a, 0x19, 0x52,
	0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1a, 0x0a, 0x16, 0x52, 0x45,
	0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x4e, 0x4f, 0x5f, 0x45,
	0x52, 0x52, 0x4f, 0x52, 0x10, 0x01, 0x12, 0x1e, 0x0a, 0x1a, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e,
	0x53, 0x45, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x46, 0x4f, 0x52, 0x4d, 0x41, 0x54, 0x5f, 0x45,
	0x52, 0x52, 0x4f, 0x52, 0x10, 0x02, 0x12, 0x20, 0x0a, 0x1c, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e,
	0x53, 0x45, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f, 0x46,
	0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x03, 0x12, 0x21, 0x0a, 0x1d, 0x52, 0x45, 0x53, 0x50,
	0x4f, 0x4e, 0x53, 0x45, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x49, 0x4d,
	0x50, 0x4c, 0x45, 0x4d, 0x45, 0x4e, 0x54, 0x45, 0x44, 0x10, 0x04, 0x12, 0x19, 0x0a, 0x15, 0x52,
	0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x52, 0x45, 0x46,
	0x55, 0x53, 0x45, 0x44, 0x10, 0x05, 0x32, 0xd5, 0x01, 0x0a, 0x08, 0x46, 0x51, 0x44, 0x4e, 0x44,
	0x61, 0x74, 0x61, 0x12, 0x63, 0x0a, 0x11, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x27, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64,
	0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x1a, 0x1f, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e,
	0x73, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x12, 0x64, 0x0a, 0x14, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1f, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x46, 0x51, 0x44, 0x4e, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e,
	0x67, 0x1a, 0x29, 0x2e, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e,
	0x73, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x70,
	0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x34,
	0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x69, 0x6c,
	0x69, 0x75, 0x6d, 0x2f, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76,
	0x31, 0x2f, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x6e, 0x73, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescOnce sync.Once
	file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescData []byte
)

func file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescGZIP() []byte {
	file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescOnce.Do(func() {
		file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDesc), len(file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDesc)))
	})
	return file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDescData
}

var file_standalone_dns_proxy_standalone_dns_proxy_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_standalone_dns_proxy_standalone_dns_proxy_proto_goTypes = []any{
	(ResponseCode)(0),                 // 0: standalonednsproxy.ResponseCode
	(*PolicyStateResponse)(nil),       // 1: standalonednsproxy.PolicyStateResponse
	(*FQDNMapping)(nil),               // 2: standalonednsproxy.FQDNMapping
	(*UpdateMappingResponse)(nil),     // 3: standalonednsproxy.UpdateMappingResponse
	(*DNSServer)(nil),                 // 4: standalonednsproxy.DNSServer
	(*DNSPolicy)(nil),                 // 5: standalonednsproxy.DNSPolicy
	(*PolicyState)(nil),               // 6: standalonednsproxy.PolicyState
	(*IdentityToEndpointMapping)(nil), // 7: standalonednsproxy.IdentityToEndpointMapping
	(*EndpointInfo)(nil),              // 8: standalonednsproxy.EndpointInfo
}
var file_standalone_dns_proxy_standalone_dns_proxy_proto_depIdxs = []int32{
	0, // 0: standalonednsproxy.PolicyStateResponse.response:type_name -> standalonednsproxy.ResponseCode
	0, // 1: standalonednsproxy.UpdateMappingResponse.response:type_name -> standalonednsproxy.ResponseCode
	4, // 2: standalonednsproxy.DNSPolicy.dns_servers:type_name -> standalonednsproxy.DNSServer
	5, // 3: standalonednsproxy.PolicyState.egress_l7_dns_policy:type_name -> standalonednsproxy.DNSPolicy
	7, // 4: standalonednsproxy.PolicyState.identity_to_endpoint_mapping:type_name -> standalonednsproxy.IdentityToEndpointMapping
	8, // 5: standalonednsproxy.IdentityToEndpointMapping.endpoint_info:type_name -> standalonednsproxy.EndpointInfo
	1, // 6: standalonednsproxy.FQDNData.StreamPolicyState:input_type -> standalonednsproxy.PolicyStateResponse
	2, // 7: standalonednsproxy.FQDNData.UpdateMappingRequest:input_type -> standalonednsproxy.FQDNMapping
	6, // 8: standalonednsproxy.FQDNData.StreamPolicyState:output_type -> standalonednsproxy.PolicyState
	3, // 9: standalonednsproxy.FQDNData.UpdateMappingRequest:output_type -> standalonednsproxy.UpdateMappingResponse
	8, // [8:10] is the sub-list for method output_type
	6, // [6:8] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_standalone_dns_proxy_standalone_dns_proxy_proto_init() }
func file_standalone_dns_proxy_standalone_dns_proxy_proto_init() {
	if File_standalone_dns_proxy_standalone_dns_proxy_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDesc), len(file_standalone_dns_proxy_standalone_dns_proxy_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_standalone_dns_proxy_standalone_dns_proxy_proto_goTypes,
		DependencyIndexes: file_standalone_dns_proxy_standalone_dns_proxy_proto_depIdxs,
		EnumInfos:         file_standalone_dns_proxy_standalone_dns_proxy_proto_enumTypes,
		MessageInfos:      file_standalone_dns_proxy_standalone_dns_proxy_proto_msgTypes,
	}.Build()
	File_standalone_dns_proxy_standalone_dns_proxy_proto = out.File
	file_standalone_dns_proxy_standalone_dns_proxy_proto_goTypes = nil
	file_standalone_dns_proxy_standalone_dns_proxy_proto_depIdxs = nil
}
