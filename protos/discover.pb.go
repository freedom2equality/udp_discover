// Code generated by protoc-gen-go. DO NOT EDIT.
// source: discover.proto

package protos

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Peer struct {
	IP                   string   `protobuf:"bytes,1,opt,name=IP,proto3" json:"IP,omitempty"`
	UDP                  uint32   `protobuf:"varint,2,opt,name=UDP,proto3" json:"UDP,omitempty"`
	TCP                  uint32   `protobuf:"varint,3,opt,name=TCP,proto3" json:"TCP,omitempty"`
	ID                   []byte   `protobuf:"bytes,4,opt,name=ID,proto3" json:"ID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Peer) Reset()         { *m = Peer{} }
func (m *Peer) String() string { return proto.CompactTextString(m) }
func (*Peer) ProtoMessage()    {}
func (*Peer) Descriptor() ([]byte, []int) {
	return fileDescriptor_discover_eb522dbd55fefdf1, []int{0}
}
func (m *Peer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Peer.Unmarshal(m, b)
}
func (m *Peer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Peer.Marshal(b, m, deterministic)
}
func (dst *Peer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Peer.Merge(dst, src)
}
func (m *Peer) XXX_Size() int {
	return xxx_messageInfo_Peer.Size(m)
}
func (m *Peer) XXX_DiscardUnknown() {
	xxx_messageInfo_Peer.DiscardUnknown(m)
}

var xxx_messageInfo_Peer proto.InternalMessageInfo

func (m *Peer) GetIP() string {
	if m != nil {
		return m.IP
	}
	return ""
}

func (m *Peer) GetUDP() uint32 {
	if m != nil {
		return m.UDP
	}
	return 0
}

func (m *Peer) GetTCP() uint32 {
	if m != nil {
		return m.TCP
	}
	return 0
}

func (m *Peer) GetID() []byte {
	if m != nil {
		return m.ID
	}
	return nil
}

type Endpoint struct {
	IP                   string   `protobuf:"bytes,1,opt,name=IP,proto3" json:"IP,omitempty"`
	UDP                  uint32   `protobuf:"varint,2,opt,name=UDP,proto3" json:"UDP,omitempty"`
	TCP                  uint32   `protobuf:"varint,3,opt,name=TCP,proto3" json:"TCP,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Endpoint) Reset()         { *m = Endpoint{} }
func (m *Endpoint) String() string { return proto.CompactTextString(m) }
func (*Endpoint) ProtoMessage()    {}
func (*Endpoint) Descriptor() ([]byte, []int) {
	return fileDescriptor_discover_eb522dbd55fefdf1, []int{1}
}
func (m *Endpoint) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Endpoint.Unmarshal(m, b)
}
func (m *Endpoint) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Endpoint.Marshal(b, m, deterministic)
}
func (dst *Endpoint) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Endpoint.Merge(dst, src)
}
func (m *Endpoint) XXX_Size() int {
	return xxx_messageInfo_Endpoint.Size(m)
}
func (m *Endpoint) XXX_DiscardUnknown() {
	xxx_messageInfo_Endpoint.DiscardUnknown(m)
}

var xxx_messageInfo_Endpoint proto.InternalMessageInfo

func (m *Endpoint) GetIP() string {
	if m != nil {
		return m.IP
	}
	return ""
}

func (m *Endpoint) GetUDP() uint32 {
	if m != nil {
		return m.UDP
	}
	return 0
}

func (m *Endpoint) GetTCP() uint32 {
	if m != nil {
		return m.TCP
	}
	return 0
}

type Ping struct {
	Version              uint32    `protobuf:"varint,1,opt,name=Version,proto3" json:"Version,omitempty"`
	From                 *Endpoint `protobuf:"bytes,2,opt,name=From,proto3" json:"From,omitempty"`
	To                   *Endpoint `protobuf:"bytes,3,opt,name=To,proto3" json:"To,omitempty"`
	Expiration           uint64    `protobuf:"varint,4,opt,name=Expiration,proto3" json:"Expiration,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *Ping) Reset()         { *m = Ping{} }
func (m *Ping) String() string { return proto.CompactTextString(m) }
func (*Ping) ProtoMessage()    {}
func (*Ping) Descriptor() ([]byte, []int) {
	return fileDescriptor_discover_eb522dbd55fefdf1, []int{2}
}
func (m *Ping) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ping.Unmarshal(m, b)
}
func (m *Ping) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ping.Marshal(b, m, deterministic)
}
func (dst *Ping) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ping.Merge(dst, src)
}
func (m *Ping) XXX_Size() int {
	return xxx_messageInfo_Ping.Size(m)
}
func (m *Ping) XXX_DiscardUnknown() {
	xxx_messageInfo_Ping.DiscardUnknown(m)
}

var xxx_messageInfo_Ping proto.InternalMessageInfo

func (m *Ping) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Ping) GetFrom() *Endpoint {
	if m != nil {
		return m.From
	}
	return nil
}

func (m *Ping) GetTo() *Endpoint {
	if m != nil {
		return m.To
	}
	return nil
}

func (m *Ping) GetExpiration() uint64 {
	if m != nil {
		return m.Expiration
	}
	return 0
}

type Pong struct {
	To                   *Endpoint `protobuf:"bytes,1,opt,name=To,proto3" json:"To,omitempty"`
	ReplyTok             []byte    `protobuf:"bytes,2,opt,name=ReplyTok,proto3" json:"ReplyTok,omitempty"`
	Expiration           uint64    `protobuf:"varint,3,opt,name=Expiration,proto3" json:"Expiration,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *Pong) Reset()         { *m = Pong{} }
func (m *Pong) String() string { return proto.CompactTextString(m) }
func (*Pong) ProtoMessage()    {}
func (*Pong) Descriptor() ([]byte, []int) {
	return fileDescriptor_discover_eb522dbd55fefdf1, []int{3}
}
func (m *Pong) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Pong.Unmarshal(m, b)
}
func (m *Pong) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Pong.Marshal(b, m, deterministic)
}
func (dst *Pong) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Pong.Merge(dst, src)
}
func (m *Pong) XXX_Size() int {
	return xxx_messageInfo_Pong.Size(m)
}
func (m *Pong) XXX_DiscardUnknown() {
	xxx_messageInfo_Pong.DiscardUnknown(m)
}

var xxx_messageInfo_Pong proto.InternalMessageInfo

func (m *Pong) GetTo() *Endpoint {
	if m != nil {
		return m.To
	}
	return nil
}

func (m *Pong) GetReplyTok() []byte {
	if m != nil {
		return m.ReplyTok
	}
	return nil
}

func (m *Pong) GetExpiration() uint64 {
	if m != nil {
		return m.Expiration
	}
	return 0
}

type Findnode struct {
	Target               []byte   `protobuf:"bytes,1,opt,name=Target,proto3" json:"Target,omitempty"`
	Expiration           uint64   `protobuf:"varint,2,opt,name=Expiration,proto3" json:"Expiration,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Findnode) Reset()         { *m = Findnode{} }
func (m *Findnode) String() string { return proto.CompactTextString(m) }
func (*Findnode) ProtoMessage()    {}
func (*Findnode) Descriptor() ([]byte, []int) {
	return fileDescriptor_discover_eb522dbd55fefdf1, []int{4}
}
func (m *Findnode) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Findnode.Unmarshal(m, b)
}
func (m *Findnode) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Findnode.Marshal(b, m, deterministic)
}
func (dst *Findnode) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Findnode.Merge(dst, src)
}
func (m *Findnode) XXX_Size() int {
	return xxx_messageInfo_Findnode.Size(m)
}
func (m *Findnode) XXX_DiscardUnknown() {
	xxx_messageInfo_Findnode.DiscardUnknown(m)
}

var xxx_messageInfo_Findnode proto.InternalMessageInfo

func (m *Findnode) GetTarget() []byte {
	if m != nil {
		return m.Target
	}
	return nil
}

func (m *Findnode) GetExpiration() uint64 {
	if m != nil {
		return m.Expiration
	}
	return 0
}

type Neighbors struct {
	Peers                []*Peer  `protobuf:"bytes,1,rep,name=Peers,proto3" json:"Peers,omitempty"`
	Expiration           uint64   `protobuf:"varint,2,opt,name=Expiration,proto3" json:"Expiration,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Neighbors) Reset()         { *m = Neighbors{} }
func (m *Neighbors) String() string { return proto.CompactTextString(m) }
func (*Neighbors) ProtoMessage()    {}
func (*Neighbors) Descriptor() ([]byte, []int) {
	return fileDescriptor_discover_eb522dbd55fefdf1, []int{5}
}
func (m *Neighbors) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Neighbors.Unmarshal(m, b)
}
func (m *Neighbors) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Neighbors.Marshal(b, m, deterministic)
}
func (dst *Neighbors) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Neighbors.Merge(dst, src)
}
func (m *Neighbors) XXX_Size() int {
	return xxx_messageInfo_Neighbors.Size(m)
}
func (m *Neighbors) XXX_DiscardUnknown() {
	xxx_messageInfo_Neighbors.DiscardUnknown(m)
}

var xxx_messageInfo_Neighbors proto.InternalMessageInfo

func (m *Neighbors) GetPeers() []*Peer {
	if m != nil {
		return m.Peers
	}
	return nil
}

func (m *Neighbors) GetExpiration() uint64 {
	if m != nil {
		return m.Expiration
	}
	return 0
}

func init() {
	proto.RegisterType((*Peer)(nil), "protos.Peer")
	proto.RegisterType((*Endpoint)(nil), "protos.Endpoint")
	proto.RegisterType((*Ping)(nil), "protos.Ping")
	proto.RegisterType((*Pong)(nil), "protos.Pong")
	proto.RegisterType((*Findnode)(nil), "protos.Findnode")
	proto.RegisterType((*Neighbors)(nil), "protos.Neighbors")
}

func init() { proto.RegisterFile("discover.proto", fileDescriptor_discover_eb522dbd55fefdf1) }

var fileDescriptor_discover_eb522dbd55fefdf1 = []byte{
	// 300 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0xcf, 0x4b, 0xc3, 0x30,
	0x14, 0xc7, 0x49, 0x5a, 0xe7, 0xf6, 0xd6, 0x8d, 0x91, 0x83, 0x14, 0x0f, 0x52, 0x8a, 0x87, 0x9e,
	0x76, 0x98, 0x77, 0x0f, 0xee, 0x07, 0xcc, 0x83, 0x86, 0x10, 0xbd, 0x6f, 0x36, 0xd4, 0xa0, 0xe6,
	0x95, 0xa4, 0x88, 0xfe, 0x07, 0xfe, 0xd9, 0x92, 0x74, 0x15, 0xd9, 0x44, 0xc1, 0x53, 0xf2, 0xfd,
	0xbe, 0xe4, 0xf3, 0x7d, 0x8f, 0x04, 0xc6, 0xa5, 0x76, 0x0f, 0xf8, 0xaa, 0xec, 0xb4, 0xb6, 0xd8,
	0x20, 0xeb, 0x85, 0xc5, 0xe5, 0xd7, 0x10, 0x73, 0xa5, 0x2c, 0x1b, 0x03, 0x5d, 0xf3, 0x94, 0x64,
	0xa4, 0x18, 0x08, 0xba, 0xe6, 0x6c, 0x02, 0xd1, 0xdd, 0x82, 0xa7, 0x34, 0x23, 0xc5, 0x48, 0xf8,
	0xad, 0x77, 0xe4, 0x9c, 0xa7, 0x51, 0xeb, 0xc8, 0x39, 0x0f, 0x77, 0x16, 0x69, 0x9c, 0x91, 0x22,
	0x11, 0x74, 0xbd, 0xc8, 0x2f, 0xa1, 0xbf, 0x34, 0x65, 0x8d, 0xda, 0x34, 0xff, 0xe1, 0xe5, 0x1f,
	0x04, 0x62, 0xae, 0x4d, 0xc5, 0x52, 0x38, 0xbe, 0x57, 0xd6, 0x69, 0x34, 0x81, 0x30, 0x12, 0x9d,
	0x64, 0xe7, 0x10, 0xaf, 0x2c, 0xbe, 0x04, 0xce, 0x70, 0x36, 0x69, 0x87, 0x71, 0xd3, 0x2e, 0x56,
	0x84, 0x2a, 0xcb, 0x80, 0x4a, 0x0c, 0xe4, 0x9f, 0xce, 0x50, 0x89, 0xec, 0x0c, 0x60, 0xf9, 0x56,
	0x6b, 0xbb, 0x69, 0x7c, 0x88, 0x1f, 0x21, 0x16, 0xdf, 0x9c, 0xbc, 0x84, 0x98, 0xa3, 0xa9, 0x76,
	0x24, 0xf2, 0x0b, 0xe9, 0x14, 0xfa, 0x42, 0xd5, 0xcf, 0xef, 0x12, 0x9f, 0x42, 0x57, 0x89, 0xf8,
	0xd2, 0x7b, 0x29, 0xd1, 0x41, 0xca, 0x15, 0xf4, 0x57, 0xda, 0x94, 0x06, 0x4b, 0xc5, 0x4e, 0xa0,
	0x27, 0x37, 0xb6, 0x52, 0x4d, 0x48, 0x4b, 0xc4, 0x4e, 0xed, 0x31, 0xe8, 0x01, 0xe3, 0x16, 0x06,
	0x37, 0x4a, 0x57, 0x8f, 0x5b, 0xb4, 0x8e, 0xe5, 0x70, 0xe4, 0x5f, 0xd3, 0xa5, 0x24, 0x8b, 0x8a,
	0xe1, 0x2c, 0xe9, 0x3a, 0xf6, 0xa6, 0x68, 0x4b, 0x7f, 0x01, 0xb7, 0xed, 0xcf, 0xb8, 0xf8, 0x0c,
	0x00, 0x00, 0xff, 0xff, 0xd9, 0x38, 0xac, 0x6c, 0x32, 0x02, 0x00, 0x00,
}