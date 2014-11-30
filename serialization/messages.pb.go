// Code generated by protoc-gen-go.
// source: messages.proto
// DO NOT EDIT!

/*
Package serialization is a generated protocol buffer package.

It is generated from these files:
	messages.proto

It has these top-level messages:
	DiffieExchange
	TextMessage
*/
package serialization

import proto "github.com/golang/protobuf/proto"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = math.Inf

type DiffieExchange struct {
	Diffie           []byte `protobuf:"bytes,1,req,name=diffie" json:"diffie,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *DiffieExchange) Reset()         { *m = DiffieExchange{} }
func (m *DiffieExchange) String() string { return proto.CompactTextString(m) }
func (*DiffieExchange) ProtoMessage()    {}

func (m *DiffieExchange) GetDiffie() []byte {
	if m != nil {
		return m.Diffie
	}
	return nil
}

type TextMessage struct {
	Encrypted        []byte `protobuf:"bytes,1,req,name=encrypted" json:"encrypted,omitempty"`
	Diffie           []byte `protobuf:"bytes,2,req,name=diffie" json:"diffie,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *TextMessage) Reset()         { *m = TextMessage{} }
func (m *TextMessage) String() string { return proto.CompactTextString(m) }
func (*TextMessage) ProtoMessage()    {}

func (m *TextMessage) GetEncrypted() []byte {
	if m != nil {
		return m.Encrypted
	}
	return nil
}

func (m *TextMessage) GetDiffie() []byte {
	if m != nil {
		return m.Diffie
	}
	return nil
}

func init() {
}