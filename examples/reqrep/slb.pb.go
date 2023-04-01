// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.14.0
// source: slb.proto

package main

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// todo: new_sa() may call netlink UPDATE_SA, but update_sa()
// just call del() and new() sa
type AddSaReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HostSrc     []byte `protobuf:"bytes,1,opt,name=host_src,json=hostSrc,proto3" json:"host_src,omitempty"`
	HostDst     []byte `protobuf:"bytes,2,opt,name=host_dst,json=hostDst,proto3" json:"host_dst,omitempty"`
	TmplHostSrc []byte `protobuf:"bytes,3,opt,name=tmpl_host_src,json=tmplHostSrc,proto3" json:"tmpl_host_src,omitempty"`
	TmplHostDst []byte `protobuf:"bytes,4,opt,name=tmpl_host_dst,json=tmplHostDst,proto3" json:"tmpl_host_dst,omitempty"`
	Spi         uint32 `protobuf:"varint,5,opt,name=spi,proto3" json:"spi,omitempty"`
}

func (x *AddSaReq) Reset() {
	*x = AddSaReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_slb_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddSaReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddSaReq) ProtoMessage() {}

func (x *AddSaReq) ProtoReflect() protoreflect.Message {
	mi := &file_slb_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddSaReq.ProtoReflect.Descriptor instead.
func (*AddSaReq) Descriptor() ([]byte, []int) {
	return file_slb_proto_rawDescGZIP(), []int{0}
}

func (x *AddSaReq) GetHostSrc() []byte {
	if x != nil {
		return x.HostSrc
	}
	return nil
}

func (x *AddSaReq) GetHostDst() []byte {
	if x != nil {
		return x.HostDst
	}
	return nil
}

func (x *AddSaReq) GetTmplHostSrc() []byte {
	if x != nil {
		return x.TmplHostSrc
	}
	return nil
}

func (x *AddSaReq) GetTmplHostDst() []byte {
	if x != nil {
		return x.TmplHostDst
	}
	return nil
}

func (x *AddSaReq) GetSpi() uint32 {
	if x != nil {
		return x.Spi
	}
	return 0
}

type DelSaReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Spi uint32 `protobuf:"varint,1,opt,name=spi,proto3" json:"spi,omitempty"`
}

func (x *DelSaReq) Reset() {
	*x = DelSaReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_slb_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DelSaReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DelSaReq) ProtoMessage() {}

func (x *DelSaReq) ProtoReflect() protoreflect.Message {
	mi := &file_slb_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DelSaReq.ProtoReflect.Descriptor instead.
func (*DelSaReq) Descriptor() ([]byte, []int) {
	return file_slb_proto_rawDescGZIP(), []int{1}
}

func (x *DelSaReq) GetSpi() uint32 {
	if x != nil {
		return x.Spi
	}
	return 0
}

// The response message containing the greetings
type StatusResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status int64 `protobuf:"varint,1,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *StatusResp) Reset() {
	*x = StatusResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_slb_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatusResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusResp) ProtoMessage() {}

func (x *StatusResp) ProtoReflect() protoreflect.Message {
	mi := &file_slb_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusResp.ProtoReflect.Descriptor instead.
func (*StatusResp) Descriptor() ([]byte, []int) {
	return file_slb_proto_rawDescGZIP(), []int{2}
}

func (x *StatusResp) GetStatus() int64 {
	if x != nil {
		return x.Status
	}
	return 0
}

var File_slb_proto protoreflect.FileDescriptor

var file_slb_proto_rawDesc = []byte{
	0x0a, 0x09, 0x73, 0x6c, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x03, 0x73, 0x6c, 0x62,
	0x22, 0x9a, 0x01, 0x0a, 0x08, 0x41, 0x64, 0x64, 0x53, 0x61, 0x52, 0x65, 0x71, 0x12, 0x19, 0x0a,
	0x08, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x73, 0x72, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x07, 0x68, 0x6f, 0x73, 0x74, 0x53, 0x72, 0x63, 0x12, 0x19, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74,
	0x5f, 0x64, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x68, 0x6f, 0x73, 0x74,
	0x44, 0x73, 0x74, 0x12, 0x22, 0x0a, 0x0d, 0x74, 0x6d, 0x70, 0x6c, 0x5f, 0x68, 0x6f, 0x73, 0x74,
	0x5f, 0x73, 0x72, 0x63, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x74, 0x6d, 0x70, 0x6c,
	0x48, 0x6f, 0x73, 0x74, 0x53, 0x72, 0x63, 0x12, 0x22, 0x0a, 0x0d, 0x74, 0x6d, 0x70, 0x6c, 0x5f,
	0x68, 0x6f, 0x73, 0x74, 0x5f, 0x64, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b,
	0x74, 0x6d, 0x70, 0x6c, 0x48, 0x6f, 0x73, 0x74, 0x44, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x73,
	0x70, 0x69, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x73, 0x70, 0x69, 0x22, 0x1c, 0x0a,
	0x08, 0x44, 0x65, 0x6c, 0x53, 0x61, 0x52, 0x65, 0x71, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x70, 0x69,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x73, 0x70, 0x69, 0x22, 0x24, 0x0a, 0x0a, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2f, 0x6d, 0x61, 0x69, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_slb_proto_rawDescOnce sync.Once
	file_slb_proto_rawDescData = file_slb_proto_rawDesc
)

func file_slb_proto_rawDescGZIP() []byte {
	file_slb_proto_rawDescOnce.Do(func() {
		file_slb_proto_rawDescData = protoimpl.X.CompressGZIP(file_slb_proto_rawDescData)
	})
	return file_slb_proto_rawDescData
}

var file_slb_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_slb_proto_goTypes = []interface{}{
	(*AddSaReq)(nil),   // 0: slb.AddSaReq
	(*DelSaReq)(nil),   // 1: slb.DelSaReq
	(*StatusResp)(nil), // 2: slb.StatusResp
}
var file_slb_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_slb_proto_init() }
func file_slb_proto_init() {
	if File_slb_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_slb_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddSaReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_slb_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DelSaReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_slb_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatusResp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_slb_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_slb_proto_goTypes,
		DependencyIndexes: file_slb_proto_depIdxs,
		MessageInfos:      file_slb_proto_msgTypes,
	}.Build()
	File_slb_proto = out.File
	file_slb_proto_rawDesc = nil
	file_slb_proto_goTypes = nil
	file_slb_proto_depIdxs = nil
}
